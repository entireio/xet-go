package xorb

import (
	"errors"
	"fmt"

	"github.com/jmwoliver/xet-go/chunker"
	"github.com/jmwoliver/xet-go/xethash"
)

const (
	// MaxNetworkSize is the largest canonical footerless xorb emitted by the
	// protocol encoder: the maximum raw payload plus one header per chunk.
	MaxNetworkSize = MaxRawSize + MaxChunks*HeaderSize
	// MaxCompleteSize adds the largest canonical V1 metadata footer to a
	// MaxNetworkSize content section.
	MaxCompleteSize = MaxNetworkSize + footerV1BaseSize + 40*MaxChunks + 4
)

// ErrHashMismatch reports a well-formed xorb, or xorb layout, whose chunks
// hash to a xorb other than the expected one. Errors that wrap it keep the
// text "xorb: hash mismatch" or "xorb: ingested hash mismatch".
var ErrHashMismatch = errors.New("xorb: hash mismatch")

// hashMismatchError has its own text and wraps ErrHashMismatch.
type hashMismatchError struct{ text string }

func (e *hashMismatchError) Error() string { return e.text }
func (e *hashMismatchError) Unwrap() error { return ErrHashMismatch }

// IngestedChunk is the storage metadata derived from one validated network
// xorb chunk. Serialized ranges address the footerless/complete xorb content
// section; uncompressed ranges address the logical xorb data.
type IngestedChunk struct {
	Hash               xethash.Hash
	SerializedOffset   uint32
	SerializedLength   uint32
	UncompressedOffset uint32
	UncompressedLength uint32
}

// Ingested is the canonical durable form of a footerless network xorb.
// Complete contains an exact V1 XETBLOB footer with the canonical zero nonce.
type Ingested struct {
	Hash             xethash.Hash
	NetworkBytes     uint32
	UncompressedSize uint32
	Complete         []byte
	Chunks           []IngestedChunk
}

// IngestNetwork validates a footerless upload, recomputes its identities, and
// returns the canonical complete/cache representation and range metadata. It
// accepts only the network form (see DecodeNetwork): a legacy trailer or a
// complete/cache footer fails as malformed chunk data. A well-formed body whose
// chunks hash to another xorb fails with an error that wraps ErrHashMismatch.
//
// IngestNetwork decodes body once and does not retain it: Complete is a new
// slice, so the caller may reuse or change body afterwards. It holds every
// decoded chunk at once. VerifyNetwork checks the same body with one chunk of
// scratch, and AppendFooter then builds the complete form in place.
func IngestNetwork(body []byte, expected xethash.Hash) (*Ingested, error) {
	if len(body) > MaxNetworkSize {
		return nil, fmt.Errorf("xorb: network object size %d exceeds maximum %d", len(body), MaxNetworkSize)
	}
	if len(body) == 0 {
		return nil, fmt.Errorf("xorb: ingest network object: %w", &FormatError{Reason: "empty object"})
	}
	// Uncompressed chunk data aliases body. No chunk data leaves this call.
	object, err := decodeContent(body)
	if err != nil {
		return nil, fmt.Errorf("xorb: ingest network object: %w", err)
	}
	if object.Hash != expected {
		return nil, fmt.Errorf("%w: expected %s, computed %s", ErrHashMismatch, expected, object.Hash)
	}
	result := &Ingested{
		Hash:             object.Hash,
		NetworkBytes:     uint32(len(body)),
		UncompressedSize: object.UncompressedSize,
		Complete:         appendComplete(body, object, [4]byte{}),
		Chunks:           make([]IngestedChunk, len(object.Chunks)),
	}
	for i, chunk := range object.Chunks {
		result.Chunks[i] = IngestedChunk{
			Hash:               chunk.Hash,
			SerializedOffset:   chunk.SerializedOffset,
			SerializedLength:   chunk.SerializedLength,
			UncompressedOffset: chunk.UncompressedOffset,
			UncompressedLength: chunk.UncompressedLength,
		}
	}
	return result, nil
}

// VerifyNetwork checks body as IngestNetwork does: body must be a footerless
// network xorb whose chunks hash to want. It returns the V1 footer of body
// with a zero nonce, so AppendFooter(body, footer) is the complete form that
// IngestNetwork returns. When body has room for FooterSize more bytes,
// AppendFooter writes the footer in place and does not copy body.
//
// VerifyNetwork decompresses each chunk into scratch buffers that it reuses
// and hashes the chunks in batches of up to 16, so it holds a few MiB at most
// whatever the size of body. It does not retain body. A well-formed body whose
// chunks hash to another xorb fails with an error that wraps ErrHashMismatch.
// Every other failure is a FormatError whose offset counts from the start of
// body; unlike IngestNetwork, that includes an oversized body.
func VerifyNetwork(body []byte, want xethash.Hash) (*Footer, error) {
	if len(body) > MaxNetworkSize {
		return nil, &FormatError{Reason: fmt.Sprintf("network object size %d exceeds maximum %d", len(body), MaxNetworkSize)}
	}
	if len(body) == 0 {
		return nil, &FormatError{Reason: "empty object"}
	}
	table := newTableBuilder()
	for offset := 0; offset < len(body); {
		end, err := table.add(body, offset)
		if err != nil {
			return nil, err
		}
		offset = end
	}
	return table.seal(want)
}

// ValidateIngested verifies persisted Xorb layout metadata without reading or
// decompressing the backing object. It returns the exact byte length of the
// canonical complete/cache object described by the layout. Complete, when
// present on a freshly ingested value, must have that length; durable indexes
// may omit it after publishing the immutable bytes. Chunk metadata that hashes
// to a xorb other than value.Hash fails with an error that wraps
// ErrHashMismatch.
func ValidateIngested(value *Ingested) (int64, error) {
	if value == nil {
		return 0, errors.New("xorb: nil ingested layout")
	}
	if value.Hash == xethash.Zero || value.NetworkBytes == 0 || value.NetworkBytes > MaxNetworkSize {
		return 0, errors.New("xorb: invalid ingested identity or network length")
	}
	if value.UncompressedSize == 0 || value.UncompressedSize > MaxRawSize {
		return 0, errors.New("xorb: invalid ingested uncompressed length")
	}
	if len(value.Chunks) == 0 || len(value.Chunks) > MaxChunks {
		return 0, fmt.Errorf("xorb: invalid ingested chunk count %d", len(value.Chunks))
	}
	nodes := make([]xethash.Node, len(value.Chunks))
	var serializedEnd, uncompressedEnd uint64
	for i, chunk := range value.Chunks {
		if chunk.Hash == xethash.Zero {
			return 0, fmt.Errorf("xorb: ingested chunk %d has a zero identity", i)
		}
		if uint64(chunk.SerializedOffset) != serializedEnd ||
			chunk.SerializedLength <= HeaderSize ||
			chunk.SerializedLength > MaxSerializedChunk {
			return 0, fmt.Errorf("xorb: ingested chunk %d has a non-contiguous serialized range", i)
		}
		if uint64(chunk.UncompressedOffset) != uncompressedEnd ||
			chunk.UncompressedLength == 0 || chunk.UncompressedLength > chunker.MaxSize {
			return 0, fmt.Errorf("xorb: ingested chunk %d has a non-contiguous uncompressed range", i)
		}
		serializedEnd += uint64(chunk.SerializedLength)
		uncompressedEnd += uint64(chunk.UncompressedLength)
		if serializedEnd > uint64(value.NetworkBytes) || uncompressedEnd > uint64(value.UncompressedSize) {
			return 0, fmt.Errorf("xorb: ingested chunk %d exceeds declared bounds", i)
		}
		nodes[i] = xethash.Node{Hash: chunk.Hash, Size: uint64(chunk.UncompressedLength)}
	}
	if serializedEnd != uint64(value.NetworkBytes) || uncompressedEnd != uint64(value.UncompressedSize) {
		return 0, errors.New("xorb: ingested terminal ranges differ from declared lengths")
	}
	if computed := xethash.Xorb(nodes); computed != value.Hash {
		return 0, &hashMismatchError{fmt.Sprintf("xorb: ingested hash mismatch: declared %s, computed %s", value.Hash, computed)}
	}
	completeSize := int64(value.NetworkBytes) + int64(FooterSize(len(value.Chunks)))
	if value.Complete != nil && int64(len(value.Complete)) != completeSize {
		return 0, fmt.Errorf("xorb: complete object length %d, expected %d", len(value.Complete), completeSize)
	}
	return completeSize, nil
}
