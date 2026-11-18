package xorb

import (
	"bytes"
	"errors"
	"math/rand"
	"reflect"
	"slices"
	"testing"

	"github.com/entireio/xet-go/chunker"
	"github.com/entireio/xet-go/xethash"
)

// builderChunks returns chunks of text, random and four-byte structured
// data, with a scheme for each that cycles through every scheme.
func builderChunks() ([][]byte, []Scheme) {
	rng := rand.New(rand.NewSource(17))
	var chunks [][]byte
	var schemes []Scheme
	all := []Scheme{None, LZ4, BG4LZ4, Auto}
	for i := range 40 {
		data := make([]byte, 1+rng.Intn(chunker.MaxSize))
		switch i % 3 {
		case 0:
			copy(data, bytes.Repeat([]byte("builder text "), len(data)))
		case 1:
			_, _ = rng.Read(data)
		default:
			for j := range data {
				data[j] = byte(j / 4)
			}
		}
		chunks = append(chunks, data)
		schemes = append(schemes, all[i%len(all)])
	}
	return chunks, schemes
}

func TestBuilderMatchesEncode(t *testing.T) {
	chunks, schemes := builderChunks()
	want, err := encode(chunks, schemes)
	if err != nil {
		t.Fatal(err)
	}
	wantComplete, err := EncodeComplete(want, [4]byte{})
	if err != nil {
		t.Fatal(err)
	}
	wantFooter, err := ParseFooter(wantComplete[len(want.Body):])
	if err != nil {
		t.Fatal(err)
	}

	var appended []byte
	var b Builder
	for i, data := range chunks {
		var chunk Chunk
		appended, chunk, err = appendChunk(appended, data, want.Chunks[i].Hash, schemes[i])
		if err != nil {
			t.Fatal(err)
		}
		if chunk.Hash != want.Chunks[i].Hash || chunk.Scheme != want.Chunks[i].Scheme ||
			chunk.SerializedOffset != want.Chunks[i].SerializedOffset ||
			chunk.SerializedLength != want.Chunks[i].SerializedLength ||
			chunk.UncompressedLength != want.Chunks[i].UncompressedLength || chunk.Data != nil {
			t.Fatalf("appendChunk %d = %+v", i, chunk)
		}
		add := b.Add
		if i%2 == 0 {
			add = func(data []byte, scheme Scheme) (Chunk, error) { return b.AddHashed(data, want.Chunks[i].Hash, scheme) }
		}
		chunk, err = add(data, schemes[i])
		if err != nil {
			t.Fatal(err)
		}
		if chunk.UncompressedOffset != want.Chunks[i].UncompressedOffset || chunk.SerializedOffset != want.Chunks[i].SerializedOffset {
			t.Fatalf("Builder chunk %d = %+v", i, chunk)
		}
		if b.ChunkHash(i) != want.Chunks[i].Hash {
			t.Fatalf("ChunkHash(%d) = %s", i, b.ChunkHash(i))
		}
	}
	if !bytes.Equal(appended, want.Body) {
		t.Fatal("appendChunk body differs from Encode")
	}
	if b.Len() != len(chunks) {
		t.Fatalf("Builder holds %d chunks", b.Len())
	}
	table := b.Footer()
	if table.XorbHash != (xethash.Hash{}) || !reflect.DeepEqual(table.ChunkHashes, wantFooter.ChunkHashes) ||
		!reflect.DeepEqual(table.ChunkBoundaryOffsets, wantFooter.ChunkBoundaryOffsets) ||
		!reflect.DeepEqual(table.UnpackedChunkOffsets, wantFooter.UnpackedChunkOffsets) {
		t.Fatalf("Footer = %+v", table)
	}
	body, footer, err := b.Seal()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(body, want.Body) || footer.XorbHash != want.Hash || !reflect.DeepEqual(footer, wantFooter) {
		t.Fatal("Seal differs from Encode and EncodeComplete")
	}
	if b.Len() != 0 || !b.Fits(MaxRawSize) {
		t.Fatal("Seal did not empty the builder")
	}
	if complete := AppendFooter(body, footer); !bytes.Equal(complete, wantComplete) {
		t.Fatal("AppendFooter of the sealed xorb differs from EncodeComplete")
	}
}

func TestBuilderTruncate(t *testing.T) {
	chunks, schemes := builderChunks()
	var b Builder
	for i, data := range chunks[:10] {
		if _, err := b.Add(data, schemes[i]); err != nil {
			t.Fatal(err)
		}
	}
	snapshot := b.Footer()
	kept := *snapshot
	kept.ChunkHashes = slices.Clone(snapshot.ChunkHashes)
	kept.ChunkBoundaryOffsets = slices.Clone(snapshot.ChunkBoundaryOffsets)
	kept.UnpackedChunkOffsets = slices.Clone(snapshot.UnpackedChunkOffsets)

	b.Truncate(-1)
	b.Truncate(10)
	if b.Len() != 10 {
		t.Fatalf("Truncate out of range changed the builder to %d chunks", b.Len())
	}
	b.Truncate(6)
	if b.Len() != 6 || !b.Fits(MaxRawSize-int(snapshot.UnpackedChunkOffsets[5])) || b.Fits(MaxRawSize-int(snapshot.UnpackedChunkOffsets[5])+1) {
		t.Fatalf("Truncate(6) left %d chunks", b.Len())
	}
	for i := 10; i < 14; i++ {
		if _, err := b.Add(chunks[i], schemes[i]); err != nil {
			t.Fatal(err)
		}
	}
	if !reflect.DeepEqual(snapshot, &kept) {
		t.Fatal("Truncate and Add changed a Footer returned earlier")
	}
	keptChunks := append(slices.Clone(chunks[:6]), chunks[10:14]...)
	keptSchemes := append(slices.Clone(schemes[:6]), schemes[10:14]...)
	want, err := encode(keptChunks, keptSchemes)
	if err != nil {
		t.Fatal(err)
	}
	body, footer, err := b.Seal()
	if err != nil || !bytes.Equal(body, want.Body) || footer.XorbHash != want.Hash {
		t.Fatalf("Truncate then Add differs from Encode: %v", err)
	}

	for i, data := range chunks[:3] {
		if _, err := b.Add(data, schemes[i]); err != nil {
			t.Fatal(err)
		}
	}
	b.Truncate(0)
	if b.Len() != 0 {
		t.Fatalf("Truncate(0) left %d chunks", b.Len())
	}
	if _, _, err := b.Seal(); err == nil {
		t.Fatal("sealed a builder truncated to nothing")
	}
}

func TestBuilderLimits(t *testing.T) {
	var b Builder
	zero := make([]byte, chunker.MaxSize)
	for range MaxRawSize / chunker.MaxSize {
		if _, err := b.Add(zero, LZ4); err != nil {
			t.Fatal(err)
		}
	}
	if b.Fits(1) {
		t.Fatal("a full raw size fits another byte")
	}
	if _, err := b.Add([]byte{1}, None); !errors.Is(err, ErrFull) {
		t.Fatalf("Add past MaxRawSize = %v", err)
	}
	body, footer, err := b.Seal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyNetwork(body, footer.XorbHash); err != nil {
		t.Fatalf("a full raw xorb does not verify: %v", err)
	}

	b.Reset(body)
	for range MaxChunks {
		if _, err := b.Add([]byte{7}, None); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := b.Add([]byte{7}, None); !errors.Is(err, ErrFull) {
		t.Fatalf("Add past MaxChunks = %v", err)
	}
	body, footer, err = b.Seal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyNetwork(body, footer.XorbHash); err != nil {
		t.Fatalf("a xorb of MaxChunks chunks does not verify: %v", err)
	}
}

func TestBuilderRejectsInput(t *testing.T) {
	var b Builder
	if _, _, err := b.Seal(); err == nil {
		t.Fatal("sealed an empty builder")
	}
	for name, add := range map[string]func() (Chunk, error){
		"empty chunk":    func() (Chunk, error) { return b.Add(nil, None) },
		"oversized":      func() (Chunk, error) { return b.Add(make([]byte, chunker.MaxSize+1), None) },
		"unknown scheme": func() (Chunk, error) { return b.Add([]byte("x"), Scheme(42)) },
	} {
		if _, err := add(); err == nil || errors.Is(err, ErrFull) {
			t.Fatalf("%s: Add = %v", name, err)
		}
		if b.Len() != 0 {
			t.Fatalf("%s: a failed Add changed the builder", name)
		}
	}
}

func TestBuilderMatchesEncodePerScheme(t *testing.T) {
	chunks, _ := builderChunks()
	for _, scheme := range []Scheme{None, LZ4, BG4LZ4, Auto} {
		t.Run(scheme.String(), func(t *testing.T) {
			want, err := Encode(chunks, scheme)
			if err != nil {
				t.Fatal(err)
			}
			var b Builder
			for _, data := range chunks {
				if _, err := b.Add(data, scheme); err != nil {
					t.Fatal(err)
				}
			}
			body, footer, err := b.Seal()
			if err != nil || footer.XorbHash != want.Hash || !bytes.Equal(body, want.Body) {
				t.Fatalf("Builder differs from Encode: %v", err)
			}
		})
	}
}
