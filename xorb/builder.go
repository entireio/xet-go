package xorb

import (
	"errors"
	"fmt"

	"github.com/entireio/xet-go/chunker"
	"github.com/entireio/xet-go/xethash"
)

// ErrFull reports a chunk that does not fit in the xorb that a Builder
// holds. Seal the xorb and add the chunk to the next one.
var ErrFull = errors.New("xorb: builder is full")

// appendChunk compresses data, one chunk, with scheme and appends the
// serialized chunk to dst: the bytes that Encode writes for the chunk. hash
// is the Xet chunk hash of data, which appendChunk does not compute again.
// The returned Chunk has SerializedOffset len(dst) before the call, a zero
// UncompressedOffset and no Data.
func appendChunk(dst, data []byte, hash xethash.Hash, scheme Scheme) ([]byte, Chunk, error) {
	if len(data) == 0 || len(data) > chunker.MaxSize {
		return dst, Chunk{}, fmt.Errorf("xorb: chunk length %d outside [1,%d]", len(data), chunker.MaxSize)
	}
	used, payload, err := encodeChunkPayload(data, scheme)
	if err != nil {
		return dst, Chunk{}, fmt.Errorf("xorb: %w", err)
	}
	chunk := Chunk{
		Hash:               hash,
		Scheme:             used,
		SerializedOffset:   uint32(len(dst)),
		SerializedLength:   uint32(HeaderSize + len(payload)),
		UncompressedLength: uint32(len(data)),
	}
	return appendSerializedChunk(dst, used, payload, len(data)), chunk, nil
}

// Builder assembles one network xorb a chunk at a time. It holds the
// serialized chunks and the chunk table, and no copy of the unpacked data.
// Its body equals the Encode body for the same chunks and schemes. The zero
// value is an empty Builder.
type Builder struct {
	body   []byte
	footer Footer
	raw    int
}

// Reset empties b. The next xorb grows into the memory of buf, for example a
// body that Seal returned earlier and that the caller no longer uses.
// Footers that b returned earlier stay valid.
func (b *Builder) Reset(buf []byte) {
	*b = Builder{body: buf[:0]}
}

// Len returns the number of chunks in b.
func (b *Builder) Len() int { return len(b.footer.ChunkHashes) }

// ChunkHash returns the hash of chunk i. i must be less than Len.
func (b *Builder) ChunkHash(i int) xethash.Hash { return b.footer.ChunkHashes[i] }

// Fits reports whether a chunk of n unpacked bytes fits in b: the xorb then
// holds at most MaxChunks chunks and MaxRawSize unpacked bytes.
func (b *Builder) Fits(n int) bool {
	return b.Len() < MaxChunks && b.raw+n <= MaxRawSize
}

// Add hashes data, one chunk, compresses it with scheme, and appends it. See
// AddHashed. A caller that holds the chunk hash already, or that can hash
// many chunks at once with xethash.Chunks, saves a hash per chunk with
// AddHashed.
func (b *Builder) Add(data []byte, scheme Scheme) (Chunk, error) {
	return b.AddHashed(data, xethash.Chunk(data), scheme)
}

// AddHashed compresses data, one chunk, with scheme and appends it. hash is
// the Xet chunk hash of data, as xethash.Chunk computes it. AddHashed does
// not check it: a wrong hash makes a xorb whose identity differs from its
// data, which VerifyNetwork and IngestNetwork reject.
//
// AddHashed returns the chunk with its offsets in the xorb and no Data. It
// fails with ErrFull when the chunk does not fit (see Fits), and leaves b
// unchanged on any error.
func (b *Builder) AddHashed(data []byte, hash xethash.Hash, scheme Scheme) (Chunk, error) {
	if !b.Fits(len(data)) {
		return Chunk{}, ErrFull
	}
	body := b.body
	if room := HeaderSize + len(data); cap(body)-len(body) < room {
		// Doubling up to the largest complete xorb copies the bytes of a
		// full xorb about once.
		body = make([]byte, len(b.body), min(max(2*cap(body), len(body)+room, 64<<10), MaxCompleteSize))
		copy(body, b.body)
	}
	body, chunk, err := appendChunk(body, data, hash, scheme)
	if err != nil {
		return Chunk{}, err
	}
	chunk.UncompressedOffset = uint32(b.raw)
	b.body = body
	b.raw += len(data)
	b.footer.ChunkHashes = append(b.footer.ChunkHashes, hash)
	b.footer.ChunkBoundaryOffsets = append(b.footer.ChunkBoundaryOffsets, uint32(len(body)))
	b.footer.UnpackedChunkOffsets = append(b.footer.UnpackedChunkOffsets, uint32(b.raw))
	return chunk, nil
}

// Truncate keeps the first n chunks of b and drops the rest. It does
// nothing when n is negative or at least Len. Footers that b returned
// earlier stay valid after later calls to Add.
func (b *Builder) Truncate(n int) {
	if n < 0 || n >= b.Len() {
		return
	}
	var serialized, unpacked uint32
	if n > 0 {
		serialized, unpacked = b.footer.ChunkBoundaryOffsets[n-1], b.footer.UnpackedChunkOffsets[n-1]
	}
	b.body = b.body[:serialized]
	b.raw = int(unpacked)
	// Full slice expressions make the next Add copy the table instead of
	// writing over a Footer that b returned.
	b.footer.ChunkHashes = b.footer.ChunkHashes[:n:n]
	b.footer.ChunkBoundaryOffsets = b.footer.ChunkBoundaryOffsets[:n:n]
	b.footer.UnpackedChunkOffsets = b.footer.UnpackedChunkOffsets[:n:n]
}

// Footer returns the chunk table of the chunks added so far: the chunk
// hashes, serialized ends and unpacked ends. Version and XorbHash are zero;
// Seal computes them. Later calls to Add and Truncate do not change it.
func (b *Builder) Footer() *Footer {
	n := b.Len()
	return &Footer{
		ChunkHashes:          b.footer.ChunkHashes[:n:n],
		ChunkBoundaryOffsets: b.footer.ChunkBoundaryOffsets[:n:n],
		UnpackedChunkOffsets: b.footer.UnpackedChunkOffsets[:n:n],
	}
}

// Seal ends the xorb and empties b. It returns the network body and the V1
// footer with a zero nonce; footer.XorbHash is the xorb hash. The caller owns
// both. AppendFooter(body, footer) then gives the complete form, in place
// when the body has room. Seal fails on an empty Builder.
func (b *Builder) Seal() ([]byte, *Footer, error) {
	if b.Len() == 0 {
		return nil, nil, errors.New("xorb: cannot seal an empty builder")
	}
	footer := b.footer
	sealFooter(&footer)
	body := b.body
	*b = Builder{}
	return body, &footer, nil
}
