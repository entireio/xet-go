package xorb

import (
	"fmt"
	"runtime"

	"github.com/jmwoliver/xet-go/chunker"
	"github.com/jmwoliver/xet-go/xethash"
)

// hashSlotSize is the capacity of one decoded chunk held for hashing. The
// BLAKE3 hasher copies the tail of an input that has no spare capacity; 16
// KiB past the largest chunk avoids that copy.
const hashSlotSize = chunker.MaxSize + 16<<10

// maxHashWindow bounds the decoded chunks that a tableBuilder holds before
// it hashes them as one batch.
const maxHashWindow = 16

// sealFooter completes footer, whose chunk lists are filled, as a V1 footer
// with a zero nonce: it computes the xorb hash and the jump offsets.
func sealFooter(footer *Footer) {
	n := len(footer.ChunkHashes)
	nodes := make([]xethash.Node, n)
	var previous uint32
	for i, end := range footer.UnpackedChunkOffsets {
		nodes[i] = xethash.Node{Hash: footer.ChunkHashes[i], Size: uint64(end - previous)}
		previous = end
	}
	footer.Version = 1
	footer.XorbHash = xethash.Xorb(nodes)
	footer.UniquenessNonce = [4]byte{}
	footer.HashesOffsetFromEnd = uint32(52 + 40*n)
	footer.BoundariesOffsetFromEnd = uint32(40 + 8*n)
}

// tableBuilder decodes the chunks of a content section in order and keeps
// only the chunk table. It decodes into reused scratch buffers and copies
// each decoded chunk into a reused slot, so the caller may reuse the
// serialized bytes at once. It hashes the slots in batches of up to
// maxHashWindow chunks, which xethash.Chunks spreads across cores.
type tableBuilder struct {
	decoder  payloadDecoder
	footer   Footer
	end      int
	unpacked uint32
	window   int
	slots    [][]byte
	pending  [][]byte
}

func newTableBuilder() *tableBuilder {
	return &tableBuilder{
		decoder: payloadDecoder{reuse: true},
		window:  max(1, min(maxHashWindow, runtime.GOMAXPROCS(0))),
	}
}

// count returns the number of chunks added so far.
func (t *tableBuilder) count() int { return len(t.footer.ChunkBoundaryOffsets) }

// add decodes the chunk at offset in content, appends it to the table, and
// returns the end of its payload in content. FormatError offsets count from
// the start of content.
func (t *tableBuilder) add(content []byte, offset int) (int, error) {
	scheme, payloadEnd, uncompressedLen, err := chunkAt(content, offset, t.count())
	if err != nil {
		return 0, err
	}
	if uint64(t.unpacked)+uint64(uncompressedLen) > MaxRawSize {
		return 0, &FormatError{Offset: offset, Reason: "raw object size exceeds limit"}
	}
	data, err := t.decoder.decode(content[offset+HeaderSize:payloadEnd], scheme, uncompressedLen)
	if err != nil {
		return 0, &FormatError{Offset: offset + HeaderSize, Reason: err.Error()}
	}
	i := len(t.pending)
	if i == len(t.slots) {
		t.slots = append(t.slots, make([]byte, hashSlotSize))
	}
	slot := t.slots[i][:len(data)]
	copy(slot, data)
	t.pending = append(t.pending, slot)
	t.end += payloadEnd - offset
	t.unpacked += uint32(uncompressedLen)
	t.footer.ChunkBoundaryOffsets = append(t.footer.ChunkBoundaryOffsets, uint32(t.end))
	t.footer.UnpackedChunkOffsets = append(t.footer.UnpackedChunkOffsets, t.unpacked)
	if len(t.pending) == t.window {
		t.flush()
	}
	return payloadEnd, nil
}

// flush hashes the pending chunks.
func (t *tableBuilder) flush() {
	t.footer.ChunkHashes = append(t.footer.ChunkHashes, xethash.Chunks(t.pending)...)
	t.pending = t.pending[:0]
}

// seal returns the V1 footer of the chunks added so far, which must hash to
// want.
func (t *tableBuilder) seal(want xethash.Hash) (*Footer, error) {
	t.flush()
	footer := t.footer
	sealFooter(&footer)
	if footer.XorbHash != want {
		return nil, fmt.Errorf("%w: expected %s, computed %s", ErrHashMismatch, want, footer.XorbHash)
	}
	return &footer, nil
}
