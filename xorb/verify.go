package xorb

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"runtime"

	"github.com/entireio/xet-go/chunker"
	"github.com/entireio/xet-go/xethash"
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
	if t.count() == 0 {
		return nil, &FormatError{Reason: "no chunks"}
	}
	t.flush()
	footer := t.footer
	sealFooter(&footer)
	if footer.XorbHash != want {
		return nil, fmt.Errorf("%w: expected %s, computed %s", ErrHashMismatch, want, footer.XorbHash)
	}
	return &footer, nil
}

// shiftOffset moves the offset of a FormatError by base.
func shiftOffset(err error, base int) error {
	var formatErr *FormatError
	if errors.As(err, &formatErr) {
		return &FormatError{Offset: formatErr.Offset + base, Reason: formatErr.Reason}
	}
	return err
}

// sourceError is a failure of the reader that holds a xorb, not of the xorb.
type sourceError struct{ err error }

func (e *sourceError) Error() string { return "xorb: read: " + e.err.Error() }
func (e *sourceError) Unwrap() error { return e.err }

// sourceReader passes reads to r and keeps the first error of r other than
// io.EOF. A read that fails because r failed then reports that error, even
// when it surfaces as a short read: an HTTP body cut short returns
// io.ErrUnexpectedEOF, which is a failure of the source, not a truncated
// xorb.
type sourceReader struct {
	r   io.Reader
	err error
}

func (s *sourceReader) Read(p []byte) (int, error) {
	n, err := s.r.Read(p)
	if err != nil && !errors.Is(err, io.EOF) && s.err == nil {
		s.err = err
	}
	return n, err
}

// check returns err, or the source error when r failed.
func (s *sourceReader) check(err error) error {
	if err != nil && s.err != nil {
		return &sourceError{err: s.err}
	}
	return err
}

// readFull reads len(buf) bytes from r and reports a short read at offset
// as a FormatError. The caller turns it into a sourceError when the source
// failed.
func readFull(r io.Reader, buf []byte, offset int, what string) error {
	if n, err := io.ReadFull(r, buf); err != nil {
		return &FormatError{Offset: offset + n, Reason: "truncated " + what}
	}
	return nil
}

// readSerializedChunk reads one serialized chunk, the chunk after count
// others, from r into scratch, which has room for MaxSerializedChunk bytes.
// It checks the header before it reads the payload, so a header cannot make
// it read more than one chunk. offset is the position of the chunk in the
// object, and FormatError offsets count from the start of the object.
func readSerializedChunk(r io.Reader, scratch []byte, offset, count int) ([]byte, error) {
	header := scratch[:HeaderSize]
	if err := readFull(r, header, offset, "chunk header"); err != nil {
		return nil, err
	}
	compressedLen := int(getUint24(header[1:4]))
	if compressedLen == 0 || compressedLen > MaxSerializedChunk-HeaderSize {
		_, _, _, err := chunkAt(header, 0, count)
		return nil, shiftOffset(err, offset)
	}
	serialized := scratch[:HeaderSize+compressedLen]
	if err := readFull(r, serialized[HeaderSize:], offset+HeaderSize, "chunk payload"); err != nil {
		return nil, err
	}
	return serialized, nil
}

// VerifyComplete reads a complete xorb of size bytes from r to its end and
// checks that it is the xorb want: it decompresses and hashes every chunk,
// and checks the V1 footer against the chunks. A negative size means that
// the size is unknown. It returns the footer as stored, nonce included.
//
// VerifyComplete holds one serialized chunk, a few decoded chunks and the
// chunk table. Every length it reads is bounded by MaxSerializedChunk,
// MaxChunks and MaxCompleteSize before it allocates. Chunks that hash to
// another xorb fail with an error that wraps ErrHashMismatch. A failure of r,
// including an io.ErrUnexpectedEOF from r, comes back wrapped and is not a
// FormatError. A nil r fails with a plain error. Every other failure is a
// FormatError whose offset counts from the start of the object.
func VerifyComplete(r io.Reader, want xethash.Hash, size int64) (*Footer, error) {
	if r == nil {
		return nil, errors.New("xorb: nil complete xorb reader")
	}
	if size > MaxCompleteSize {
		return nil, &FormatError{Reason: fmt.Sprintf("complete object size %d exceeds maximum %d", size, MaxCompleteSize)}
	}
	src := &sourceReader{r: r}
	footer, err := verifyComplete(src, want, size)
	if err = src.check(err); err != nil {
		return nil, err
	}
	return footer, nil
}

func verifyComplete(src io.Reader, want xethash.Hash, size int64) (*Footer, error) {
	limit := int64(MaxCompleteSize)
	if size >= 0 {
		limit = size
	}
	br := bufio.NewReaderSize(io.LimitReader(src, limit+1), 64<<10)
	table := newTableBuilder()
	scratch := make([]byte, MaxSerializedChunk)
	for {
		next, err := br.Peek(1)
		if err != nil {
			return nil, &FormatError{Offset: table.end, Reason: "no footer"}
		}
		if next[0] != 0 {
			break
		}
		offset := table.end
		serialized, err := readSerializedChunk(br, scratch, offset, table.count())
		if err != nil {
			return nil, err
		}
		if _, err := table.add(serialized, 0); err != nil {
			return nil, shiftOffset(err, offset)
		}
	}
	computed, err := table.seal(want)
	if err != nil {
		return nil, err
	}
	stored := make([]byte, FooterSize(len(computed.ChunkHashes)))
	if err := readFull(br, stored, table.end, "footer"); err != nil {
		return nil, err
	}
	footer, err := ParseFooter(stored)
	if err != nil {
		return nil, shiftOffset(err, table.end)
	}
	if err := matchFooter(footer, computed, table.end); err != nil {
		return nil, err
	}
	if _, err := br.ReadByte(); err == nil {
		return nil, &FormatError{Offset: table.end + len(stored), Reason: "bytes after the footer"}
	} else if !errors.Is(err, io.EOF) {
		return nil, err
	}
	if total := int64(table.end + len(stored)); size >= 0 && total != size {
		return nil, &FormatError{Offset: int(total), Reason: fmt.Sprintf("complete object of %d bytes, want %d", total, size)}
	}
	return footer, nil
}

// matchFooter checks that the stored footer at offset describes the chunks
// that computed describes.
func matchFooter(stored, computed *Footer, offset int) error {
	if stored.XorbHash != computed.XorbHash {
		return &FormatError{Offset: offset + 8, Reason: "footer xorb hash mismatch"}
	}
	for i := range computed.ChunkHashes {
		switch {
		case stored.ChunkHashes[i] != computed.ChunkHashes[i]:
			return &FormatError{Offset: offset, Reason: fmt.Sprintf("footer chunk hash %d mismatch", i)}
		case stored.ChunkBoundaryOffsets[i] != computed.ChunkBoundaryOffsets[i]:
			return &FormatError{Offset: offset, Reason: fmt.Sprintf("footer chunk boundary %d mismatch", i)}
		case stored.UnpackedChunkOffsets[i] != computed.UnpackedChunkOffsets[i]:
			return &FormatError{Offset: offset, Reason: fmt.Sprintf("footer unpacked boundary %d mismatch", i)}
		}
	}
	return nil
}

// ReadFooter reads the V1 footer at the end of a complete xorb of size bytes
// in r and checks it against want: its layout, that its chunks end where the
// footer starts, and Validate(want). It does not read the chunks;
// CheckHeaders and ChunkRangeReader check them against the footer. A table
// that hashes to another xorb fails with an error that wraps
// ErrHashMismatch, and a failure of r comes back wrapped. Every other failure
// is a FormatError whose offset counts from the start of the object.
func ReadFooter(r io.ReaderAt, size int64, want xethash.Hash) (*Footer, error) {
	if r == nil {
		return nil, errors.New("xorb: nil complete xorb reader")
	}
	if size > MaxCompleteSize {
		return nil, &FormatError{Reason: fmt.Sprintf("complete object size %d exceeds maximum %d", size, MaxCompleteSize)}
	}
	if size < int64(FooterSize(1)+HeaderSize+1) {
		return nil, &FormatError{Reason: fmt.Sprintf("complete object of %d bytes holds no chunk and footer", size)}
	}
	var trailer [footerTrailerSize]byte
	if err := readAt(r, trailer[:], size-footerTrailerSize); err != nil {
		return nil, err
	}
	n, err := FooterLength(trailer[:])
	if err != nil {
		return nil, shiftOffset(err, int(size)-footerTrailerSize)
	}
	contentEnd := size - int64(n)
	if contentEnd < HeaderSize+1 {
		return nil, &FormatError{Reason: fmt.Sprintf("footer of %d bytes in %d bytes", n, size)}
	}
	b := make([]byte, n)
	if err := readAt(r, b, contentEnd); err != nil {
		return nil, err
	}
	footer, err := ParseFooter(b)
	if err != nil {
		return nil, shiftOffset(err, int(contentEnd))
	}
	if end := footer.ChunkBoundaryOffsets[len(footer.ChunkBoundaryOffsets)-1]; int64(end) != contentEnd {
		return nil, &FormatError{Offset: int(contentEnd), Reason: fmt.Sprintf("chunks end at %d, footer starts at %d", end, contentEnd)}
	}
	if err := footer.Validate(want); err != nil {
		return nil, shiftOffset(err, int(contentEnd))
	}
	return footer, nil
}

func readAt(r io.ReaderAt, buf []byte, offset int64) error {
	n, err := r.ReadAt(buf, offset)
	if n == len(buf) {
		return nil
	}
	if err == nil || errors.Is(err, io.EOF) {
		return &FormatError{Offset: int(offset) + n, Reason: "object shorter than its size"}
	}
	return &sourceError{err: err}
}

// CheckHeaders checks every chunk header of content, the content section of
// a complete xorb, against footer, without decompressing: content ends where
// the footer says, and each header has version 0, a known scheme, and the
// serialized and unpacked lengths that the footer gives. An uncompressed
// chunk stores exactly its unpacked length. footer must come from
// VerifyComplete, ReadFooter, or ParseFooter followed by Validate;
// CheckHeaders proves only that content matches it. A nil footer fails with
// a plain error. Every other failure is a FormatError whose offset counts
// from the start of content.
func CheckHeaders(content []byte, footer *Footer) error {
	if footer == nil {
		return errors.New("xorb: nil footer")
	}
	n := len(footer.ChunkHashes)
	if n == 0 || len(footer.ChunkBoundaryOffsets) != n || len(footer.UnpackedChunkOffsets) != n {
		return &FormatError{Reason: "invalid footer chunk table"}
	}
	if end := footer.ChunkBoundaryOffsets[n-1]; int64(end) != int64(len(content)) {
		return &FormatError{Offset: len(content), Reason: fmt.Sprintf("content of %d bytes, footer says %d", len(content), end)}
	}
	var start, unpacked uint32
	for i := range n {
		end := footer.ChunkBoundaryOffsets[i]
		if end <= start || int64(end) > int64(len(content)) {
			return &FormatError{Offset: int(start), Reason: fmt.Sprintf("footer chunk boundary %d mismatch", i)}
		}
		scheme, payloadEnd, uncompressedLen, err := chunkAt(content[:end], int(start), i)
		wantUnpacked := int64(footer.UnpackedChunkOffsets[i]) - int64(unpacked)
		switch {
		case err != nil:
			return err
		case payloadEnd != int(end):
			return &FormatError{Offset: int(start) + 1, Reason: fmt.Sprintf("chunk %d header gives %d serialized bytes, footer gives %d", i, payloadEnd-int(start), end-start)}
		case int64(uncompressedLen) != wantUnpacked:
			return &FormatError{Offset: int(start) + 5, Reason: fmt.Sprintf("chunk %d header gives %d unpacked bytes, footer gives %d", i, uncompressedLen, wantUnpacked)}
		case scheme != None && scheme != LZ4 && scheme != BG4LZ4:
			return &FormatError{Offset: int(start) + 4, Reason: fmt.Sprintf("unknown compression scheme %d", scheme)}
		case scheme == None && payloadEnd-int(start)-HeaderSize != uncompressedLen:
			return &FormatError{Offset: int(start) + HeaderSize, Reason: fmt.Sprintf("uncompressed payload length %d, want %d", payloadEnd-int(start)-HeaderSize, uncompressedLen)}
		}
		start, unpacked = end, footer.UnpackedChunkOffsets[i]
	}
	return nil
}

// ChunkRangeReader reads the unpacked data of chunks [start, end) of a
// complete xorb, in order. It decompresses one chunk at a time and checks its
// serialized length, unpacked length and hash against the footer before it
// returns any of its bytes. A chunk that does not match fails with a
// FormatError whose offset counts from the start of the object. A failure of
// the source comes back wrapped and is not a FormatError.
type ChunkRangeReader struct {
	src     *sourceReader
	br      *bufio.Reader
	footer  *Footer
	decoder payloadDecoder
	scratch []byte
	next    int
	end     int
	data    []byte
	err     error
}

// NewChunkRangeReader returns a ChunkRangeReader over chunks [start, end).
// r yields the serialized chunks from the header of chunk start, for
// example a ranged read of the stored xorb. ChunkRangeReader reads no byte
// of r past chunk end-1. footer must come from VerifyComplete, ReadFooter,
// or ParseFooter followed by Validate.
func NewChunkRangeReader(r io.Reader, footer *Footer, start, end int) (*ChunkRangeReader, error) {
	if r == nil {
		return nil, errors.New("xorb: nil chunk source")
	}
	if footer == nil {
		return nil, errors.New("xorb: nil footer")
	}
	n := len(footer.ChunkHashes)
	if len(footer.ChunkBoundaryOffsets) != n || len(footer.UnpackedChunkOffsets) != n {
		return nil, errors.New("xorb: invalid footer chunk table")
	}
	if start < 0 || start >= end || end > n {
		return nil, fmt.Errorf("xorb: chunk range [%d, %d) outside a xorb of %d chunks", start, end, n)
	}
	var first int64
	if start > 0 {
		first = int64(footer.ChunkBoundaryOffsets[start-1])
	}
	last := int64(footer.ChunkBoundaryOffsets[end-1])
	if last <= first {
		return nil, errors.New("xorb: invalid footer chunk table")
	}
	src := &sourceReader{r: r}
	return &ChunkRangeReader{
		src:     src,
		br:      bufio.NewReaderSize(io.LimitReader(src, last-first), 64<<10),
		footer:  footer,
		decoder: payloadDecoder{reuse: true},
		next:    start,
		end:     end,
	}, nil
}

// Read implements io.Reader.
func (c *ChunkRangeReader) Read(p []byte) (int, error) {
	for len(c.data) == 0 {
		if c.err != nil {
			return 0, c.err
		}
		if c.next == c.end {
			return 0, io.EOF
		}
		c.data, c.err = c.chunk(c.next)
		c.err = c.src.check(c.err)
		c.next++
	}
	n := copy(p, c.data)
	c.data = c.data[n:]
	return n, nil
}

// chunk reads and checks chunk i. The data is valid until the next call.
func (c *ChunkRangeReader) chunk(i int) ([]byte, error) {
	var serializedStart, unpackedStart uint32
	if i > 0 {
		serializedStart, unpackedStart = c.footer.ChunkBoundaryOffsets[i-1], c.footer.UnpackedChunkOffsets[i-1]
	}
	if c.scratch == nil {
		c.scratch = make([]byte, MaxSerializedChunk)
	}
	serialized, err := readSerializedChunk(c.br, c.scratch, int(serializedStart), 0)
	if err != nil {
		return nil, err
	}
	scheme, _, uncompressedLen, err := chunkAt(serialized, 0, 0)
	if err != nil {
		return nil, shiftOffset(err, int(serializedStart))
	}
	wantSerialized := int64(c.footer.ChunkBoundaryOffsets[i]) - int64(serializedStart)
	wantUnpacked := int64(c.footer.UnpackedChunkOffsets[i]) - int64(unpackedStart)
	switch {
	case int64(len(serialized)) != wantSerialized:
		return nil, &FormatError{Offset: int(serializedStart), Reason: fmt.Sprintf("chunk %d has %d serialized bytes, footer says %d", i, len(serialized), wantSerialized)}
	case int64(uncompressedLen) != wantUnpacked:
		return nil, &FormatError{Offset: int(serializedStart), Reason: fmt.Sprintf("chunk %d has %d unpacked bytes, footer says %d", i, uncompressedLen, wantUnpacked)}
	}
	data, err := c.decoder.decode(serialized[HeaderSize:], scheme, uncompressedLen)
	if err != nil {
		return nil, &FormatError{Offset: int(serializedStart) + HeaderSize, Reason: err.Error()}
	}
	if got := xethash.Chunk(data); got != c.footer.ChunkHashes[i] {
		return nil, &FormatError{Offset: int(serializedStart), Reason: fmt.Sprintf("chunk %d hashes to %s, footer says %s", i, got, c.footer.ChunkHashes[i])}
	}
	return data, nil
}
