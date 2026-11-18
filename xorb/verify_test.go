package xorb

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/jmwoliver/xet-go/chunker"
	"github.com/jmwoliver/xet-go/xethash"
)

var errSource = errors.New("source failed")

// failingReaderAt fails every read that starts before fail.
type failingReaderAt struct {
	r    *bytes.Reader
	fail int64
}

func (f failingReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off < f.fail {
		return 0, errSource
	}
	return f.r.ReadAt(p, off)
}

// verifyFixture returns a complete xorb of chunks in every scheme, with a
// chunk whose data is itself a complete xorb, and the unpacked chunks.
func verifyFixture(t *testing.T) (*Object, []byte, [][]byte) {
	t.Helper()
	inner, err := Encode([][]byte{[]byte("inner")}, None)
	if err != nil {
		t.Fatal(err)
	}
	innerComplete, err := EncodeComplete(inner, [4]byte{})
	if err != nil {
		t.Fatal(err)
	}
	structured := make([]byte, 50_001)
	for i := range structured {
		structured[i] = byte(i / 4)
	}
	chunks := [][]byte{[]byte("tiny"), bytes.Repeat([]byte("text "), 4000), structured, innerComplete, networkBodyEndingIn(t, legacyTrailer[:]).Chunks[0].Data}
	schemes := []Scheme{None, LZ4, BG4LZ4, None, Auto}
	object, err := encode(chunks, schemes)
	if err != nil {
		t.Fatal(err)
	}
	complete, err := EncodeComplete(object, [4]byte{5, 6, 7, 8})
	if err != nil {
		t.Fatal(err)
	}
	return object, complete, chunks
}

// requireSourceError fails t unless err wraps source and is not a
// FormatError.
func requireSourceError(t *testing.T, what string, err, source error) {
	t.Helper()
	var formatErr *FormatError
	if !errors.Is(err, source) || errors.As(err, &formatErr) || !strings.Contains(err.Error(), source.Error()) {
		t.Fatalf("%s = %v, want the source error only", what, err)
	}
}

func TestVerifyCompleteAcceptsCompleteXorbs(t *testing.T) {
	object, complete, _ := verifyFixture(t)
	want, err := ParseFooter(complete[len(object.Body):])
	if err != nil {
		t.Fatal(err)
	}
	for _, size := range []int64{int64(len(complete)), -1} {
		footer, err := VerifyComplete(iotest.HalfReader(bytes.NewReader(complete)), object.Hash, size)
		if err != nil {
			t.Fatalf("size %d: %v", size, err)
		}
		if !reflect.DeepEqual(footer, want) {
			t.Fatalf("size %d: footer = %+v, want %+v", size, footer, want)
		}
	}
	read, err := ReadFooter(bytes.NewReader(complete), int64(len(complete)), object.Hash)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(read, want) {
		t.Fatalf("ReadFooter = %+v, want %+v", read, want)
	}
	if err := CheckHeaders(complete[:len(object.Body)], read); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyCompleteRejects(t *testing.T) {
	object, complete, _ := verifyFixture(t)
	size := int64(len(complete))
	if _, err := VerifyComplete(bytes.NewReader(complete), xethash.Zero, size); !errors.Is(err, ErrHashMismatch) {
		t.Fatalf("wrong hash = %v", err)
	}
	if _, err := VerifyComplete(nil, object.Hash, size); err == nil {
		t.Fatal("nil reader succeeded")
	}
	footerStart := len(object.Body)
	n := len(object.Chunks)
	lz4Zero, err := Encode([][]byte{make([]byte, chunker.MaxSize)}, LZ4)
	if err != nil {
		t.Fatal(err)
	}
	var many Builder
	for range MaxChunks {
		if _, err := many.Add([]byte{1}, None); err != nil {
			t.Fatal(err)
		}
	}
	manyBody, manyFooter, err := many.Seal()
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]struct {
		body []byte
		size int64
	}{
		"network form":      {object.Body, int64(len(object.Body))},
		"no chunks":         {complete[footerStart:], int64(n)},
		"oversized":         {complete, MaxCompleteSize + 1},
		"short size":        {complete, size - 1},
		"long size":         {complete, size + 1},
		"trailing byte":     {append(append([]byte(nil), complete...), 0), -1},
		"footer xorb hash":  {flipByte(complete, footerStart+8), size},
		"footer chunk hash": {flipByte(complete, footerStart+52), size},
		"footer stored end": {flipByte(complete, footerStart+64+32*n), size},
		"footer unpacked":   {flipByte(complete, footerStart+64+36*n), size},
		"footer trailer":    {flipByte(complete, len(complete)-1), size},
		"chunk header":      {flipByte(complete, 1), size},
		"chunk version":     {flipByte(complete, 0), size},
		"lz4 payload":       {flipByte(complete, int(object.Chunks[1].SerializedOffset)+HeaderSize+8), size},
		"raw limit":         {bytes.Repeat(lz4Zero.Body, MaxRawSize/chunker.MaxSize+1), -1},
		"too many chunks":   {append(append([]byte(nil), manyBody...), manyBody[:HeaderSize+1]...), -1},
		"zero payload":      {zeroLength(complete, 0), size},
	}
	for i := range complete {
		cases[fmt.Sprintf("truncated at %d", i)] = struct {
			body []byte
			size int64
		}{complete[:i], -1}
	}
	for name, tc := range cases {
		want := object.Hash
		if name == "too many chunks" {
			want = manyFooter.XorbHash
		}
		_, err := VerifyComplete(bytes.NewReader(tc.body), want, tc.size)
		requireFormatError(t, name, err)
	}
	for _, at := range []int{0, 1, HeaderSize + 2, footerStart, len(complete) - 2, len(complete)} {
		r := io.MultiReader(bytes.NewReader(complete[:at]), iotest.ErrReader(errSource))
		_, err := VerifyComplete(r, object.Hash, -1)
		requireSourceError(t, fmt.Sprintf("source error at %d", at), err, errSource)
	}
}

func TestReadFooterRejects(t *testing.T) {
	object, complete, _ := verifyFixture(t)
	size := int64(len(complete))
	if _, err := ReadFooter(nil, size, object.Hash); err == nil {
		t.Fatal("nil reader succeeded")
	}
	trailer := append([]byte(nil), complete...)
	trailer[len(trailer)-1] = 0xff
	cases := map[string]struct {
		body []byte
		size int64
	}{
		"oversized":       {complete, MaxCompleteSize + 1},
		"too small":       {complete, int64(FooterSize(1) + HeaderSize)},
		"bad trailer":     {trailer, size},
		"footer only":     {complete[len(object.Body)-HeaderSize:], size - int64(len(object.Body)) + HeaderSize},
		"shifted content": {append([]byte{0}, complete...), size + 1},
		"short object":    {complete[:len(complete)-1], size},
		"bad footer":      {append(append([]byte(nil), complete[:len(object.Body)]...), flipByte(complete[len(object.Body):], 0)...), size},
	}
	for name, tc := range cases {
		_, err := ReadFooter(bytes.NewReader(tc.body), tc.size, object.Hash)
		requireFormatError(t, name, err)
	}
	for _, fail := range []int64{size, size - 4} {
		_, err := ReadFooter(failingReaderAt{r: bytes.NewReader(complete), fail: fail}, size, object.Hash)
		requireSourceError(t, fmt.Sprintf("source error at %d", fail), err, errSource)
	}
}

// zeroLength returns b with a zero payload length in the chunk header at
// offset.
func zeroLength(b []byte, offset int) []byte {
	out := append([]byte(nil), b...)
	putUint24(out[offset+1:offset+4], 0)
	return out
}

func TestCheckHeaders(t *testing.T) {
	object, complete, _ := verifyFixture(t)
	content := complete[:len(object.Body)]
	footer, err := ParseFooter(complete[len(object.Body):])
	if err != nil {
		t.Fatal(err)
	}
	lz4Start := int(object.Chunks[1].SerializedOffset)
	backwards := *footer
	backwards.ChunkBoundaryOffsets = append([]uint32(nil), footer.ChunkBoundaryOffsets...)
	backwards.ChunkBoundaryOffsets[1] = uint32(len(content)) + 1
	empty := Footer{}
	longFirst := *footer
	longFirst.ChunkBoundaryOffsets = append([]uint32(nil), footer.ChunkBoundaryOffsets...)
	longFirst.ChunkBoundaryOffsets[0]++
	noneLZ4 := append([]byte(nil), content...)
	noneLZ4[lz4Start+4] = byte(None)
	cases := map[string]struct {
		content []byte
		footer  *Footer
	}{
		"short content":      {content[:len(content)-1], footer},
		"version":            {flipByte(content, 0), footer},
		"serialized length":  {flipByte(content, 1), footer},
		"unpacked length":    {flipByte(content, 5), footer},
		"unknown scheme":     {flipByte(content, 4), footer},
		"uncompressed lz4":   {noneLZ4, footer},
		"long first chunk":   {content, &longFirst},
		"backwards boundary": {content, &backwards},
		"empty table":        {content, &empty},
	}
	for name, tc := range cases {
		requireFormatError(t, name, CheckHeaders(tc.content, tc.footer))
	}
}

func TestChunkRangeReader(t *testing.T) {
	object, complete, chunks := verifyFixture(t)
	footer, err := ReadFooter(bytes.NewReader(complete), int64(len(complete)), object.Hash)
	if err != nil {
		t.Fatal(err)
	}
	section := func(start, end int) io.Reader {
		first := object.Chunks[start].SerializedOffset
		last := object.Chunks[end-1].SerializedOffset + object.Chunks[end-1].SerializedLength
		return bytes.NewReader(complete[first:last])
	}
	for start := range chunks {
		for end := start + 1; end <= len(chunks); end++ {
			r, err := NewChunkRangeReader(section(start, end), footer, start, end)
			if err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(iotest.OneByteReader(r))
			if err != nil {
				t.Fatalf("[%d, %d): %v", start, end, err)
			}
			if want := bytes.Join(chunks[start:end], nil); !bytes.Equal(got, want) {
				t.Fatalf("[%d, %d) data differs", start, end)
			}
		}
	}

	for name, rng := range map[string][2]int{"empty": {1, 1}, "negative": {-1, 1}, "past end": {0, len(chunks) + 1}} {
		if _, err := NewChunkRangeReader(bytes.NewReader(complete), footer, rng[0], rng[1]); err == nil {
			t.Fatalf("%s range succeeded", name)
		}
	}
	if _, err := NewChunkRangeReader(nil, footer, 0, 1); err == nil {
		t.Fatal("nil source succeeded")
	}
	if _, err := NewChunkRangeReader(bytes.NewReader(complete), &Footer{ChunkHashes: footer.ChunkHashes}, 0, 1); err == nil {
		t.Fatal("inconsistent footer succeeded")
	}

	wrongLengths := *footer
	wrongLengths.ChunkBoundaryOffsets = append([]uint32(nil), footer.ChunkBoundaryOffsets...)
	wrongLengths.ChunkBoundaryOffsets[0]++
	wrongUnpacked := *footer
	wrongUnpacked.UnpackedChunkOffsets = append([]uint32(nil), footer.UnpackedChunkOffsets...)
	wrongUnpacked.UnpackedChunkOffsets[0]++
	noneStart := int(object.Chunks[0].SerializedOffset)
	lz4Start := int(object.Chunks[1].SerializedOffset)
	faults := map[string]struct {
		body   []byte
		footer *Footer
	}{
		"serialized length": {complete, &wrongLengths},
		"unpacked length":   {complete, &wrongUnpacked},
		"chunk data":        {flipByte(complete, noneStart+HeaderSize), footer},
		"lz4 payload":       {flipByte(complete, lz4Start+HeaderSize+8), footer},
		"chunk header":      {flipByte(complete, noneStart), footer},
		"truncated":         {complete[:noneStart+HeaderSize+1], footer},
		"zero payload":      {zeroLength(complete, noneStart), footer},
	}
	for name, tc := range faults {
		r, err := NewChunkRangeReader(bytes.NewReader(tc.body), tc.footer, 0, 2)
		if err != nil {
			t.Fatal(err)
		}
		_, err = io.ReadAll(r)
		requireFormatError(t, name, err)
		if _, again := r.Read(make([]byte, 1)); !errors.Is(again, err) && again.Error() != err.Error() {
			t.Fatalf("%s: second Read = %v, want %v", name, again, err)
		}
	}
	r, err := NewChunkRangeReader(io.MultiReader(bytes.NewReader(complete[:3]), iotest.ErrReader(errSource)), footer, 0, 1)
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.ReadAll(r)
	requireSourceError(t, "source error", err, errSource)
}

// FuzzVerifyComplete checks that VerifyComplete, ReadFooter and
// CheckHeaders accept only complete xorbs that Decode accepts, and that
// ChunkRangeReader returns the data that Decode returns.
func FuzzVerifyComplete(f *testing.F) {
	object, err := Encode([][]byte{bytes.Repeat([]byte("xet"), 4096), []byte("second")}, Auto)
	if err != nil {
		f.Fatal(err)
	}
	complete, err := EncodeComplete(object, [4]byte{1})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(complete)
	f.Add(object.Body)
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 2<<20 {
			return
		}
		decoded, decodeErr := Decode(data)
		var want xethash.Hash
		if decodeErr == nil {
			want = decoded.Hash
		}
		footer, err := VerifyComplete(bytes.NewReader(data), want, int64(len(data)))
		if err != nil {
			if read, readErr := ReadFooter(bytes.NewReader(data), int64(len(data)), want); readErr == nil {
				if CheckHeaders(data[:len(data)-FooterSize(len(read.ChunkHashes))], read) == nil && decodeErr == nil && decoded.Footer != nil && decoded.Footer.Version == 1 {
					t.Fatalf("VerifyComplete rejected a complete xorb that the other checks accept: %v", err)
				}
			}
			return
		}
		if decodeErr != nil || decoded.Footer == nil || decoded.Footer.Version != 1 || decoded.LegacyTrailer {
			t.Fatalf("VerifyComplete accepted what Decode reads as %+v, %v", decoded, decodeErr)
		}
		read, err := ReadFooter(bytes.NewReader(data), int64(len(data)), want)
		if err != nil || !reflect.DeepEqual(read, footer) ||
			CheckHeaders(data[:decoded.FooterOffset], read) != nil {
			t.Fatalf("ReadFooter = %+v, %v; VerifyComplete footer %+v", read, err, footer)
		}
		r, err := NewChunkRangeReader(bytes.NewReader(data), footer, 0, len(footer.ChunkHashes))
		if err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(r)
		if err != nil {
			t.Fatal(err)
		}
		var wantData []byte
		for _, chunk := range decoded.Chunks {
			wantData = append(wantData, chunk.Data...)
		}
		if !bytes.Equal(got, wantData) {
			t.Fatal("ChunkRangeReader data differs from Decode")
		}
	})
}

// A reused LZ4 reader kept the window of the previous chunk, so the complete
// verifiers accepted a chunk that refers to another chunk's data.
func TestCompleteVerifiersDecodeEachChunkAlone(t *testing.T) {
	body, want := crossChunkLZ4Body()
	end := HeaderSize + int(getUint24(body[1:4]))
	firstOnly, err := DecodeNetwork(body[:end])
	if err != nil {
		t.Fatal(err)
	}
	first := firstOnly.Chunks[0].Data
	second := append(first[:19:19], "hello"...)
	footer := &Footer{
		ChunkHashes:          []xethash.Hash{xethash.Chunk(first), xethash.Chunk(second)},
		ChunkBoundaryOffsets: []uint32{uint32(end), uint32(len(body))},
		UnpackedChunkOffsets: []uint32{uint32(len(first)), uint32(len(first) + len(second))},
	}
	sealFooter(footer)
	if footer.XorbHash != want {
		t.Fatal("the footer does not name the cross-chunk xorb")
	}
	complete := AppendFooter(append([]byte(nil), body...), footer)
	_, err = VerifyComplete(bytes.NewReader(complete), want, int64(len(complete)))
	requireFormatError(t, "VerifyComplete", err)
	r, err := NewChunkRangeReader(bytes.NewReader(complete), footer, 0, 2)
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.ReadAll(r)
	requireFormatError(t, "ChunkRangeReader", err)
}

// A source that fails with io.ErrUnexpectedEOF, as a short HTTP body does,
// was reported as a truncated xorb when it failed inside a chunk.
func TestVerifiersReportShortSourceReads(t *testing.T) {
	object, complete, _ := verifyFixture(t)
	errShort := fmt.Errorf("short body: %w", io.ErrUnexpectedEOF)
	cuts := map[string]int{
		"inside a chunk":    HeaderSize + 2,
		"at a chunk end":    int(object.Chunks[0].SerializedLength),
		"inside the footer": len(object.Body) + 10,
	}
	for name, at := range cuts {
		r := io.MultiReader(bytes.NewReader(complete[:at]), iotest.ErrReader(errShort))
		_, err := VerifyComplete(r, object.Hash, int64(len(complete)))
		requireSourceError(t, "VerifyComplete cut "+name, err, errShort)
		if at > len(object.Body) {
			continue
		}
		rr, err := NewChunkRangeReader(io.MultiReader(bytes.NewReader(complete[:at]), iotest.ErrReader(errShort)), &Footer{
			ChunkHashes:          []xethash.Hash{object.Chunks[0].Hash, object.Chunks[1].Hash},
			ChunkBoundaryOffsets: []uint32{object.Chunks[0].SerializedLength, object.Chunks[1].SerializedOffset + object.Chunks[1].SerializedLength},
			UnpackedChunkOffsets: []uint32{object.Chunks[0].UncompressedLength, object.Chunks[1].UncompressedOffset + object.Chunks[1].UncompressedLength},
		}, 0, 2)
		if err != nil {
			t.Fatal(err)
		}
		_, err = io.ReadAll(rr)
		requireSourceError(t, "ChunkRangeReader cut "+name, err, errShort)
	}
}

// countingReader counts the bytes read through it.
type countingReader struct {
	r io.Reader
	n int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}

func TestChunkRangeReaderStopsAtTheRange(t *testing.T) {
	object, complete, chunks := verifyFixture(t)
	footer, err := ReadFooter(bytes.NewReader(complete), int64(len(complete)), object.Hash)
	if err != nil {
		t.Fatal(err)
	}
	src := &countingReader{r: bytes.NewReader(complete[object.Chunks[1].SerializedOffset:])}
	r, err := NewChunkRangeReader(src, footer, 1, 3)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(r)
	if err != nil || !bytes.Equal(got, bytes.Join(chunks[1:3], nil)) {
		t.Fatalf("range [1, 3) = %v", err)
	}
	if want := int(footer.ChunkBoundaryOffsets[2] - footer.ChunkBoundaryOffsets[0]); src.n != want {
		t.Fatalf("read %d bytes of the source for a range of %d", src.n, want)
	}
}

func TestVerifierNilAndForeignInputs(t *testing.T) {
	object, complete, _ := verifyFixture(t)
	if _, err := ReadFooter(bytes.NewReader(complete), int64(len(complete)), xethash.Zero); !errors.Is(err, ErrHashMismatch) {
		t.Fatalf("ReadFooter for another xorb = %v", err)
	}
	if _, err := NewChunkRangeReader(bytes.NewReader(complete), nil, 0, 1); err == nil {
		t.Fatal("NewChunkRangeReader with a nil footer succeeded")
	}
	backwards := &Footer{
		ChunkHashes:          make([]xethash.Hash, 2),
		ChunkBoundaryOffsets: []uint32{10, 5},
		UnpackedChunkOffsets: []uint32{1, 2},
	}
	if _, err := NewChunkRangeReader(bytes.NewReader(complete), backwards, 1, 2); err == nil {
		t.Fatal("NewChunkRangeReader over a backwards range succeeded")
	}
	if err := CheckHeaders(complete[:len(object.Body)], nil); err == nil {
		t.Fatal("CheckHeaders with a nil footer succeeded")
	}
}

func BenchmarkVerifyComplete(b *testing.B) {
	object := ingestBenchmarkBody(b)
	complete, err := EncodeComplete(object, [4]byte{})
	if err != nil {
		b.Fatal(err)
	}
	b.SetBytes(int64(len(complete)))
	b.ReportAllocs()
	for b.Loop() {
		if _, err := VerifyComplete(bytes.NewReader(complete), object.Hash, int64(len(complete))); err != nil {
			b.Fatal(err)
		}
	}
}
