package xorb

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"slices"

	"github.com/jmwoliver/xet-go/chunker"
	"github.com/jmwoliver/xet-go/xethash"
)

// MaxSerializedChunk is the largest serialized chunk that the decoders accept:
// its header and a payload of at most twice the largest chunk.
const MaxSerializedChunk = HeaderSize + 2*chunker.MaxSize

// footerTrailerSize is the length of the trailer after a footer. The trailer
// holds the footer length without the trailer.
const footerTrailerSize = 4

// FooterSize returns the length of the V1 footer of a xorb of nChunks chunks,
// with its trailer.
func FooterSize(nChunks int) int {
	return footerV1BaseSize + 40*nChunks + footerTrailerSize
}

// FooterLength reads the trailer at the end of tail, the last bytes of a
// complete xorb, and returns the length of the V1 footer with its trailer.
// It accepts only the length of a V1 footer of 1 to MaxChunks chunks. The
// caller checks that the object is longer than the footer. FormatError
// offsets count from the start of tail.
func FooterLength(tail []byte) (int, error) {
	if len(tail) < footerTrailerSize {
		return 0, &FormatError{Reason: "no footer trailer"}
	}
	offset := len(tail) - footerTrailerSize
	infoLength := int64(binary.LittleEndian.Uint32(tail[offset:]))
	if infoLength < footerV1BaseSize+40 || infoLength > footerV1BaseSize+40*MaxChunks ||
		(infoLength-footerV1BaseSize)%40 != 0 {
		return 0, &FormatError{Offset: offset, Reason: fmt.Sprintf("invalid V1 footer length %d", infoLength)}
	}
	return int(infoLength) + footerTrailerSize, nil
}

// ParseFooter parses b, exactly one V1 footer with its trailer as
// AppendFooter writes it. It checks the layout of the footer but not what the
// footer describes, so the result is unverified: call Validate with the
// expected xorb hash before trusting it. Like Decode, it does not read the
// twelve reserved bytes. FormatError offsets count from the start of b.
func ParseFooter(b []byte) (*Footer, error) {
	n, err := FooterLength(b)
	if err != nil {
		return nil, err
	}
	if n != len(b) {
		return nil, &FormatError{Reason: fmt.Sprintf("footer of %d bytes in %d bytes", n, len(b))}
	}
	if !bytes.Equal(b[:len(footerMagic)], footerMagic[:]) {
		return nil, &FormatError{Reason: "invalid footer magic"}
	}
	if b[7] != 1 {
		return nil, &FormatError{Offset: 7, Reason: fmt.Sprintf("unsupported footer version %d", b[7])}
	}
	return parseFooter(b[:len(b)-footerTrailerSize], 0)
}

// Validate checks that f is a chunk table that the xorb xorbHash can have.
// The three lists have the same length, from 1 to MaxChunks. Each chunk has
// a serialized size from HeaderSize+1 to MaxSerializedChunk and an unpacked
// size from 1 to chunker.MaxSize, and the xorb has at most MaxRawSize
// unpacked bytes. f.XorbHash is xorbHash, and the chunk hashes and unpacked
// sizes hash to it.
//
// The xorb hash does not cover the serialized ends, so Validate proves only
// that they are well formed. A chunk table that hashes to another xorb fails
// with an error that wraps ErrHashMismatch. Every other failure is a
// FormatError whose offset is that of the field in the V1 layout.
func (f *Footer) Validate(xorbHash xethash.Hash) error {
	n := len(f.ChunkHashes)
	if n < 1 || n > MaxChunks || len(f.ChunkBoundaryOffsets) != n || len(f.UnpackedChunkOffsets) != n {
		return &FormatError{Offset: 48, Reason: fmt.Sprintf("chunk table of %d hashes, %d serialized ends and %d unpacked ends",
			n, len(f.ChunkBoundaryOffsets), len(f.UnpackedChunkOffsets))}
	}
	storedEnds, unpackedEnds := 64+32*n, 64+36*n
	nodes := make([]xethash.Node, n)
	var serialized, unpacked uint32
	for i := range n {
		if size := int64(f.ChunkBoundaryOffsets[i]) - int64(serialized); size <= HeaderSize || size > MaxSerializedChunk {
			return &FormatError{Offset: storedEnds + 4*i, Reason: fmt.Sprintf("chunk %d has %d serialized bytes", i, size)}
		}
		size := int64(f.UnpackedChunkOffsets[i]) - int64(unpacked)
		if size < 1 || size > chunker.MaxSize {
			return &FormatError{Offset: unpackedEnds + 4*i, Reason: fmt.Sprintf("chunk %d has %d unpacked bytes", i, size)}
		}
		nodes[i] = xethash.Node{Hash: f.ChunkHashes[i], Size: uint64(size)}
		serialized, unpacked = f.ChunkBoundaryOffsets[i], f.UnpackedChunkOffsets[i]
	}
	if unpacked > MaxRawSize {
		return &FormatError{Offset: unpackedEnds + 4*(n-1), Reason: "raw object size exceeds limit"}
	}
	if computed := xethash.Xorb(nodes); computed != xorbHash {
		return fmt.Errorf("%w: expected %s, computed %s", ErrHashMismatch, xorbHash, computed)
	}
	if f.XorbHash != xorbHash {
		return &FormatError{Offset: 8, Reason: "footer xorb hash mismatch"}
	}
	return nil
}

// AppendFooter appends footer to dst as a V1 footer with its trailer, the
// bytes that EncodeComplete writes after the content section. It writes V1
// whatever footer.Version holds, and it derives the chunk counts and the jump
// offsets from len(footer.ChunkHashes). The three chunk lists must have the
// same length; Validate checks them. When dst has room for FooterSize more
// bytes, AppendFooter writes in place.
func AppendFooter(dst []byte, footer *Footer) []byte {
	n := len(footer.ChunkHashes)
	infoLength := footerV1BaseSize + 40*n
	dst = slices.Grow(dst, FooterSize(n))
	dst = append(dst, footerMagic[:]...)
	dst = append(dst, 1)
	dst = append(dst, footer.XorbHash[:]...)
	dst = append(dst, footerHashesMagic[:]...)
	dst = append(dst, 0)
	dst = binary.LittleEndian.AppendUint32(dst, uint32(n))
	for _, hash := range footer.ChunkHashes {
		dst = append(dst, hash[:]...)
	}
	dst = append(dst, footerBoundsMagic[:]...)
	dst = append(dst, 1)
	dst = binary.LittleEndian.AppendUint32(dst, uint32(n))
	for _, boundary := range footer.ChunkBoundaryOffsets {
		dst = binary.LittleEndian.AppendUint32(dst, boundary)
	}
	for _, boundary := range footer.UnpackedChunkOffsets {
		dst = binary.LittleEndian.AppendUint32(dst, boundary)
	}
	dst = binary.LittleEndian.AppendUint32(dst, uint32(n))
	dst = binary.LittleEndian.AppendUint32(dst, uint32(52+40*n))
	dst = binary.LittleEndian.AppendUint32(dst, uint32(40+8*n))
	dst = append(dst, footer.UniquenessNonce[:]...)
	dst = append(dst, make([]byte, 12)...) // reserved
	return binary.LittleEndian.AppendUint32(dst, uint32(infoLength))
}
