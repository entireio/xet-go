package xorb

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"
	"reflect"
	"strings"
	"testing"

	"github.com/jmwoliver/xet-go/chunker"
	"github.com/jmwoliver/xet-go/xethash"
)

func TestIngestNetworkCanonicalizesAndDescribesXorb(t *testing.T) {
	chunks := [][]byte{
		bytes.Repeat([]byte("canonical-ingestion"), 2_000),
		bytes.Repeat([]byte{0x7a}, 17_000),
	}
	object, err := Encode(chunks, LZ4)
	if err != nil {
		t.Fatal(err)
	}
	ingested, err := IngestNetwork(object.Body, object.Hash)
	if err != nil {
		t.Fatal(err)
	}
	if ingested.Hash != object.Hash || ingested.NetworkBytes != uint32(len(object.Body)) ||
		ingested.UncompressedSize != object.UncompressedSize || len(ingested.Chunks) != len(object.Chunks) {
		t.Fatalf("ingested metadata = %#v", ingested)
	}
	for i, chunk := range ingested.Chunks {
		want := object.Chunks[i]
		if chunk.Hash != want.Hash || chunk.SerializedOffset != want.SerializedOffset ||
			chunk.SerializedLength != want.SerializedLength || chunk.UncompressedOffset != want.UncompressedOffset ||
			chunk.UncompressedLength != want.UncompressedLength {
			t.Fatalf("chunk %d = %#v, want %#v", i, chunk, want)
		}
	}
	complete, err := Decode(ingested.Complete)
	if err != nil {
		t.Fatal(err)
	}
	if complete.Footer == nil || complete.Footer.Version != 1 || complete.Footer.UniquenessNonce != [4]byte{} ||
		complete.FooterOffset != uint32(len(object.Body)) || complete.Hash != object.Hash {
		t.Fatalf("complete object = %#v", complete)
	}
	if !bytes.Equal(ingested.Complete[:ingested.NetworkBytes], object.Body) {
		t.Fatal("complete object changed the uploaded content section")
	}
	if len(ingested.Complete) > MaxCompleteSize ||
		MaxCompleteSize != MaxNetworkSize+footerV1BaseSize+40*MaxChunks+4 {
		t.Fatalf("complete size/bound = %d/%d", len(ingested.Complete), MaxCompleteSize)
	}
}

func TestIngestNetworkRejectsWrongIdentityAndNonNetworkForms(t *testing.T) {
	object, err := Encode([][]byte{[]byte("ingestion contracts")}, None)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := IngestNetwork(object.Body, xethash.Zero); err == nil {
		t.Fatal("wrong route identity succeeded")
	}
	complete, err := EncodeComplete(object, [4]byte{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := IngestNetwork(complete, object.Hash); err == nil {
		t.Fatal("complete xorb accepted as a network upload")
	}
	legacy := append(append([]byte(nil), object.Body...), legacyTrailer[:]...)
	if _, err := IngestNetwork(legacy, object.Hash); err == nil {
		t.Fatal("legacy xorb accepted as a network upload")
	}
	if _, err := IngestNetwork(nil, object.Hash); err == nil {
		t.Fatal("empty network upload succeeded")
	}
}

func TestValidateIngestedAcceptsCanonicalAndOmittedComplete(t *testing.T) {
	object, err := Encode([][]byte{
		bytes.Repeat([]byte("persisted layout"), 100),
		bytes.Repeat([]byte{0x8a}, 4_096),
	}, LZ4)
	if err != nil {
		t.Fatal(err)
	}
	ingested, err := IngestNetwork(object.Body, object.Hash)
	if err != nil {
		t.Fatal(err)
	}
	want := int64(len(ingested.Complete))
	if got, err := ValidateIngested(ingested); err != nil || got != want {
		t.Fatalf("fresh ingested layout length = %d, %v; want %d", got, err, want)
	}
	persisted := cloneIngested(ingested)
	persisted.Complete = nil
	if got, err := ValidateIngested(persisted); err != nil || got != want {
		t.Fatalf("persisted ingested layout length = %d, %v; want %d", got, err, want)
	}
	persisted.Complete = make([]byte, want-1)
	if _, err := ValidateIngested(persisted); err == nil {
		t.Fatal("wrong complete object length succeeded")
	}
}

func TestValidateIngestedRejectsInvalidMetadata(t *testing.T) {
	object, err := Encode([][]byte{[]byte("persisted layout validation")}, None)
	if err != nil {
		t.Fatal(err)
	}
	valid, err := IngestNetwork(object.Body, object.Hash)
	if err != nil {
		t.Fatal(err)
	}
	valid.Complete = nil
	tests := map[string]func(*Ingested){
		"zero identity":       func(value *Ingested) { value.Hash = xethash.Zero },
		"zero network length": func(value *Ingested) { value.NetworkBytes = 0 },
		"oversized network length": func(value *Ingested) {
			value.NetworkBytes = MaxNetworkSize + 1
		},
		"zero uncompressed length": func(value *Ingested) { value.UncompressedSize = 0 },
		"oversized uncompressed length": func(value *Ingested) {
			value.UncompressedSize = MaxRawSize + 1
		},
		"no chunks": func(value *Ingested) { value.Chunks = nil },
		"too many chunks": func(value *Ingested) {
			value.Chunks = make([]IngestedChunk, MaxChunks+1)
		},
		"zero chunk identity": func(value *Ingested) { value.Chunks[0].Hash = xethash.Zero },
		"zero serialized payload": func(value *Ingested) {
			value.Chunks[0].SerializedLength = HeaderSize
		},
		"oversized serialized payload": func(value *Ingested) {
			value.Chunks[0].SerializedLength = HeaderSize + 2*chunker.MaxSize + 1
		},
		"serialized offset gap":   func(value *Ingested) { value.Chunks[0].SerializedOffset = 1 },
		"zero uncompressed chunk": func(value *Ingested) { value.Chunks[0].UncompressedLength = 0 },
		"oversized uncompressed chunk": func(value *Ingested) {
			value.Chunks[0].UncompressedLength = chunker.MaxSize + 1
		},
		"uncompressed offset gap":              func(value *Ingested) { value.Chunks[0].UncompressedOffset = 1 },
		"serialized total mismatch":            func(value *Ingested) { value.NetworkBytes++ },
		"uncompressed total mismatch":          func(value *Ingested) { value.UncompressedSize++ },
		"declared serialized bound exceeded":   func(value *Ingested) { value.NetworkBytes-- },
		"declared uncompressed bound exceeded": func(value *Ingested) { value.UncompressedSize-- },
		"Xorb identity mismatch": func(value *Ingested) {
			value.Hash = xethash.Chunk([]byte("different persisted Xorb"))
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			value := cloneIngested(valid)
			mutate(value)
			if _, err := ValidateIngested(value); err == nil {
				t.Fatal("invalid persisted layout succeeded")
			}
		})
	}
	if _, err := ValidateIngested(nil); err == nil {
		t.Fatal("nil persisted layout succeeded")
	}
}

func cloneIngested(value *Ingested) *Ingested {
	result := *value
	result.Complete = append([]byte(nil), value.Complete...)
	result.Chunks = append([]IngestedChunk(nil), value.Chunks...)
	return &result
}

func TestIngestNetworkAcceptsBodiesThatLookFramed(t *testing.T) {
	inner, err := Encode([][]byte{[]byte("an inner xorb")}, None)
	if err != nil {
		t.Fatal(err)
	}
	innerComplete, err := EncodeComplete(inner, [4]byte{})
	if err != nil {
		t.Fatal(err)
	}
	fakeFooter, err := Encode([][]byte{innerComplete}, None)
	if err != nil {
		t.Fatal(err)
	}
	for name, object := range map[string]*Object{
		"legacy trailer": networkBodyEndingIn(t, legacyTrailer[:]),
		"complete xorb":  fakeFooter,
	} {
		t.Run(name, func(t *testing.T) {
			ingested, err := IngestNetwork(object.Body, object.Hash)
			if err != nil {
				t.Fatal(err)
			}
			if ingested.NetworkBytes != uint32(len(object.Body)) || len(ingested.Chunks) != 1 {
				t.Fatalf("ingested %+v", ingested)
			}
			complete, err := Decode(ingested.Complete)
			if err != nil || complete.Footer == nil || complete.Hash != object.Hash {
				t.Fatalf("complete form = %+v, %v", complete, err)
			}
		})
	}
}

func TestHashMismatchIsDetectable(t *testing.T) {
	object, err := Encode([][]byte{[]byte("hash mismatch sentinel")}, None)
	if err != nil {
		t.Fatal(err)
	}
	other := xethash.Chunk([]byte("another xorb"))
	_, err = IngestNetwork(object.Body, other)
	if !errors.Is(err, ErrHashMismatch) || !strings.HasPrefix(err.Error(), "xorb: hash mismatch: expected ") {
		t.Fatalf("IngestNetwork = %v", err)
	}
	_, err = IngestNetwork(object.Body[:len(object.Body)-1], object.Hash)
	requireFormatError(t, "malformed IngestNetwork", err)

	ingested, err := IngestNetwork(object.Body, object.Hash)
	if err != nil {
		t.Fatal(err)
	}
	ingested.Hash = other
	_, err = ValidateIngested(ingested)
	if !errors.Is(err, ErrHashMismatch) || !strings.HasPrefix(err.Error(), "xorb: ingested hash mismatch: declared ") {
		t.Fatalf("ValidateIngested = %v", err)
	}
}

func TestIngestNetworkDoesNotRetainBody(t *testing.T) {
	object, err := Encode([][]byte{[]byte("caller keeps the body"), bytes.Repeat([]byte("lz4"), 500)}, Auto)
	if err != nil {
		t.Fatal(err)
	}
	body := append([]byte(nil), object.Body...)
	ingested, err := IngestNetwork(body, object.Hash)
	if err != nil {
		t.Fatal(err)
	}
	want, err := EncodeComplete(object, [4]byte{})
	if err != nil {
		t.Fatal(err)
	}
	for i := range body {
		body[i] ^= 0xff
	}
	if !bytes.Equal(ingested.Complete, want) {
		t.Fatal("complete object changed when the caller changed the body")
	}
}

// ingestBenchmarkBody returns a network xorb of 256 chunks of 64 KiB: half
// compressible text stored with LZ4 and half random data stored uncompressed.
func ingestBenchmarkBody(b *testing.B) *Object {
	b.Helper()
	rng := rand.New(rand.NewSource(3))
	chunks := make([][]byte, 256)
	for i := range chunks {
		chunk := make([]byte, 64<<10)
		if i%2 == 0 {
			copy(chunk, bytes.Repeat([]byte(fmt.Sprintf("line %d of a text file\n", i)), len(chunk)))
		} else {
			_, _ = rng.Read(chunk)
		}
		chunks[i] = chunk
	}
	object, err := Encode(chunks, Auto)
	if err != nil {
		b.Fatal(err)
	}
	return object
}

func BenchmarkIngestNetwork(b *testing.B) {
	object := ingestBenchmarkBody(b)
	b.SetBytes(int64(len(object.Body)))
	b.ReportAllocs()
	for b.Loop() {
		if _, err := IngestNetwork(object.Body, object.Hash); err != nil {
			b.Fatal(err)
		}
	}
}

func TestVerifyNetworkMatchesIngestNetwork(t *testing.T) {
	inner, err := Encode([][]byte{[]byte("an inner xorb")}, None)
	if err != nil {
		t.Fatal(err)
	}
	innerComplete, err := EncodeComplete(inner, [4]byte{})
	if err != nil {
		t.Fatal(err)
	}
	structured := make([]byte, 100_003)
	for i := range structured {
		structured[i] = byte(i / 4)
	}
	random := make([]byte, chunker.MaxSize)
	_, _ = rand.New(rand.NewSource(5)).Read(random)
	objects := map[string]*Object{"legacy trailer bytes": networkBodyEndingIn(t, legacyTrailer[:])}
	for _, scheme := range []Scheme{None, LZ4, BG4LZ4, Auto} {
		object, err := Encode([][]byte{[]byte("tiny"), structured, random, innerComplete, structured}, scheme)
		if err != nil {
			t.Fatal(err)
		}
		objects[scheme.String()] = object
	}
	for name, object := range objects {
		t.Run(name, func(t *testing.T) {
			ingested, err := IngestNetwork(object.Body, object.Hash)
			if err != nil {
				t.Fatal(err)
			}
			body := make([]byte, len(object.Body), len(object.Body)+FooterSize(len(object.Chunks)))
			copy(body, object.Body)
			footer, err := VerifyNetwork(body, object.Hash)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := ParseFooter(ingested.Complete[ingested.NetworkBytes:])
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(footer, parsed) {
				t.Fatalf("VerifyNetwork footer = %+v, want %+v", footer, parsed)
			}
			complete := AppendFooter(body, footer)
			if !bytes.Equal(complete, ingested.Complete) {
				t.Fatal("AppendFooter(body, VerifyNetwork footer) differs from IngestNetwork")
			}
			if &complete[0] != &body[0] {
				t.Fatal("AppendFooter copied a body with room for the footer")
			}
		})
	}
}

func TestVerifyNetworkRejects(t *testing.T) {
	object, err := Encode([][]byte{bytes.Repeat([]byte("verify"), 3000), []byte("network")}, LZ4)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyNetwork(object.Body, xethash.Zero); !errors.Is(err, ErrHashMismatch) ||
		!strings.HasPrefix(err.Error(), "xorb: hash mismatch: expected ") {
		t.Fatalf("wrong hash = %v", err)
	}
	complete, err := EncodeComplete(object, [4]byte{})
	if err != nil {
		t.Fatal(err)
	}
	lz4Zero, err := Encode([][]byte{make([]byte, chunker.MaxSize)}, LZ4)
	if err != nil {
		t.Fatal(err)
	}
	bodies := map[string][]byte{
		"empty":     nil,
		"oversized": make([]byte, MaxNetworkSize+1),
		"complete":  complete,
		"legacy":    append(append([]byte(nil), object.Body...), legacyTrailer[:]...),
		"raw limit": bytes.Repeat(lz4Zero.Body, MaxRawSize/chunker.MaxSize+1),
		"lz4 frame": flipByte(object.Body, HeaderSize+8),
	}
	for i := range len(object.Body) {
		if i != int(object.Chunks[0].SerializedLength) {
			bodies[fmt.Sprintf("truncated at %d", i)] = object.Body[:i]
		}
	}
	for name, body := range bodies {
		_, err := VerifyNetwork(body, object.Hash)
		requireFormatError(t, name, err)
	}
}

func BenchmarkVerifyNetwork(b *testing.B) {
	object := ingestBenchmarkBody(b)
	b.SetBytes(int64(len(object.Body)))
	b.ReportAllocs()
	for b.Loop() {
		if _, err := VerifyNetwork(object.Body, object.Hash); err != nil {
			b.Fatal(err)
		}
	}
}

// crossChunkLZ4Body returns a network xorb of two LZ4 chunks whose frames use
// dependent blocks, and the xorb hash of the data that a decoder gets when it
// keeps the first frame's window. Chunk 1 is one stored block of 1000 bytes.
// Chunk 2 is one compressed block: a 19-byte match at distance 1000, then the
// literals "hello". The match reaches into chunk 1, so a valid decoder
// rejects chunk 2.
func crossChunkLZ4Body() ([]byte, xethash.Hash) {
	// FLG 0x40: version 1, dependent blocks, no checksums. BD 0x40: 64 KiB
	// blocks. 0xc0 is the header checksum of those two bytes.
	frame := func(block []byte, stored bool) []byte {
		out := []byte{0x04, 0x22, 0x4d, 0x18, 0x40, 0x40, 0xc0}
		size := uint32(len(block))
		if stored {
			size |= 1 << 31
		}
		out = binary.LittleEndian.AppendUint32(out, size)
		out = append(out, block...)
		return binary.LittleEndian.AppendUint32(out, 0)
	}
	first := make([]byte, 1000)
	for i := range first {
		first[i] = byte(i * 7)
	}
	second := append(append([]byte(nil), first[:19]...), "hello"...)
	chunk := func(payload []byte, rawLen int) []byte {
		header := make([]byte, HeaderSize)
		putUint24(header[1:4], uint32(len(payload)))
		header[4] = byte(LZ4)
		putUint24(header[5:8], uint32(rawLen))
		return append(header, payload...)
	}
	body := append(chunk(frame(first, true), len(first)),
		chunk(frame([]byte{0x0f, 0xe8, 0x03, 0x00, 0x50, 'h', 'e', 'l', 'l', 'o'}, false), len(second))...)
	return body, xethash.Xorb([]xethash.Node{
		{Hash: xethash.Chunk(first), Size: uint64(len(first))},
		{Hash: xethash.Chunk(second), Size: uint64(len(second))},
	})
}

// A reused LZ4 reader kept the window of the previous chunk, so VerifyNetwork
// accepted a chunk that refers to another chunk's data.
func TestVerifyNetworkDecodesEachChunkAlone(t *testing.T) {
	body, want := crossChunkLZ4Body()
	_, err := DecodeNetwork(body)
	requireFormatError(t, "DecodeNetwork", err)
	_, err = VerifyNetwork(body, want)
	requireFormatError(t, "VerifyNetwork", err)
}
