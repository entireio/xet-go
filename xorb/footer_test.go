package xorb

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"reflect"
	"slices"
	"testing"

	"github.com/jmwoliver/xet-go/chunker"
	"github.com/jmwoliver/xet-go/xethash"
)

// completeForTest returns an object and its complete form with nonce.
func completeForTest(t *testing.T, chunks [][]byte, scheme Scheme, nonce [4]byte) (*Object, []byte) {
	t.Helper()
	object, err := Encode(chunks, scheme)
	if err != nil {
		t.Fatal(err)
	}
	complete, err := EncodeComplete(object, nonce)
	if err != nil {
		t.Fatal(err)
	}
	return object, complete
}

// The golden footer pins the V1 layout for one 6-byte chunk: magic and
// version, xorb hash, hash section, bounds section with stored end 14 and
// unpacked end 6, counts and jump offsets 92 and 48, nonce, reserved bytes,
// and the trailer 132.
const goldenFooter = "584554424c4f4201" +
	"6afd60778aa08c35d09128c01b9f4509d1403b31217148264d84e15587993480" +
	"58424c424853480001000000" +
	"6afd60778aa08c35d09128c01b9f4509d1403b31217148264d84e15587993480" +
	"58424c42424e440101000000" + "0e000000" + "06000000" +
	"01000000" + "5c000000" + "30000000" + "01020304" + "000000000000000000000000" +
	"84000000"

func TestFooterGolden(t *testing.T) {
	object, complete := completeForTest(t, [][]byte{[]byte("golden")}, None, [4]byte{1, 2, 3, 4})
	want, err := hex.DecodeString(goldenFooter)
	if err != nil {
		t.Fatal(err)
	}
	if got := complete[len(object.Body):]; !bytes.Equal(got, want) {
		t.Fatalf("EncodeComplete footer = %x, want %x", got, want)
	}
	footer, err := ParseFooter(want)
	if err != nil {
		t.Fatal(err)
	}
	if got := AppendFooter(nil, footer); !bytes.Equal(got, want) {
		t.Fatalf("AppendFooter = %x, want %x", got, want)
	}
	if err := footer.Validate(object.Hash); err != nil {
		t.Fatal(err)
	}
}

func TestFooterCodecMatchesEncodeComplete(t *testing.T) {
	many := make([][]byte, 300)
	for i := range many {
		many[i] = bytes.Repeat([]byte{byte(i), 1, 2, byte(i >> 3)}, 100+i)
	}
	cases := map[string]struct {
		chunks [][]byte
		scheme Scheme
		nonce  [4]byte
	}{
		"one chunk":   {[][]byte{[]byte("one")}, None, [4]byte{}},
		"many chunks": {many, Auto, [4]byte{}},
		"nonce":       {[][]byte{bytes.Repeat([]byte("nonce"), 1000), []byte("tail")}, LZ4, [4]byte{9, 8, 7, 6}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			object, complete := completeForTest(t, tc.chunks, tc.scheme, tc.nonce)
			tail := complete[len(object.Body):]
			if len(tail) != FooterSize(len(object.Chunks)) {
				t.Fatalf("footer of %d bytes, FooterSize = %d", len(tail), FooterSize(len(object.Chunks)))
			}
			n, err := FooterLength(complete)
			if err != nil || n != len(tail) {
				t.Fatalf("FooterLength = %d, %v; want %d", n, err, len(tail))
			}
			parsed, err := ParseFooter(tail)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := Decode(complete)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(parsed, decoded.Footer) {
				t.Fatalf("ParseFooter = %+v, Decode footer = %+v", parsed, decoded.Footer)
			}
			if err := parsed.Validate(object.Hash); err != nil {
				t.Fatal(err)
			}
			body := append(make([]byte, 0, len(complete)), object.Body...)
			appended := AppendFooter(body, parsed)
			if !bytes.Equal(appended, complete) {
				t.Fatal("AppendFooter(body) differs from EncodeComplete")
			}
			if &appended[0] != &body[0] {
				t.Fatal("AppendFooter copied a body with room for the footer")
			}
		})
	}
	if MaxCompleteSize != MaxNetworkSize+FooterSize(MaxChunks) {
		t.Fatalf("MaxCompleteSize = %d, want %d", MaxCompleteSize, MaxNetworkSize+FooterSize(MaxChunks))
	}
}

func TestAppendFooterWritesV1ForV0(t *testing.T) {
	object, complete := completeForTest(t, [][]byte{[]byte("v0 footer"), []byte("second")}, None, [4]byte{})
	footer, err := ParseFooter(complete[len(object.Body):])
	if err != nil {
		t.Fatal(err)
	}
	footer.Version = 0
	if got := AppendFooter(nil, footer); !bytes.Equal(got, complete[len(object.Body):]) {
		t.Fatal("AppendFooter honoured a V0 version")
	}
}

func TestFooterLengthRejects(t *testing.T) {
	trailer := func(n uint32) []byte { return binary.LittleEndian.AppendUint32(nil, n) }
	for name, tail := range map[string][]byte{
		"short":        {1, 2, 3},
		"no chunks":    trailer(footerV1BaseSize),
		"too small":    trailer(footerV1BaseSize - 40),
		"misaligned":   trailer(footerV1BaseSize + 41),
		"too many":     trailer(footerV1BaseSize + 40*(MaxChunks+1)),
		"V0 length":    trailer(footerV0BaseSize + 36),
		"legacy bytes": legacyTrailer[:],
	} {
		t.Run(name, func(t *testing.T) {
			_, err := FooterLength(tail)
			requireFormatError(t, "FooterLength", err)
		})
	}
}

func TestParseFooterRejects(t *testing.T) {
	object, complete := completeForTest(t, [][]byte{[]byte("parse footer"), []byte("rejects")}, None, [4]byte{})
	footer := complete[len(object.Body):]
	for name, b := range map[string][]byte{
		"with content":   complete,
		"bad trailer":    flipByte(footer, len(footer)-1),
		"magic":          flipByte(footer, 0),
		"version":        flipByte(footer, 7),
		"hash section":   flipByte(footer, 40),
		"chunk count":    flipByte(footer, 48),
		"bounds section": flipByte(footer, 52+32*2),
		"terminal count": flipByte(footer, 64+40*2),
		"jump offset":    flipByte(footer, 68+40*2),
		"truncated":      footer[1:],
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ParseFooter(b)
			requireFormatError(t, "ParseFooter", err)
		})
	}
}

func TestFooterValidate(t *testing.T) {
	object, complete := completeForTest(t, [][]byte{bytes.Repeat([]byte("v"), 100), []byte("second")}, None, [4]byte{})
	valid, err := ParseFooter(complete[len(object.Body):])
	if err != nil {
		t.Fatal(err)
	}
	clone := func() *Footer {
		f := *valid
		f.ChunkHashes = slices.Clone(valid.ChunkHashes)
		f.ChunkBoundaryOffsets = slices.Clone(valid.ChunkBoundaryOffsets)
		f.UnpackedChunkOffsets = slices.Clone(valid.UnpackedChunkOffsets)
		return &f
	}
	formatFaults := map[string]func(*Footer){
		"no chunks":               func(f *Footer) { f.ChunkHashes, f.ChunkBoundaryOffsets, f.UnpackedChunkOffsets = nil, nil, nil },
		"short serialized ends":   func(f *Footer) { f.ChunkBoundaryOffsets = f.ChunkBoundaryOffsets[:1] },
		"short unpacked ends":     func(f *Footer) { f.UnpackedChunkOffsets = f.UnpackedChunkOffsets[:1] },
		"empty serialized chunk":  func(f *Footer) { f.ChunkBoundaryOffsets[0] = HeaderSize },
		"huge serialized chunk":   func(f *Footer) { f.ChunkBoundaryOffsets[1] = f.ChunkBoundaryOffsets[0] + MaxSerializedChunk + 1 },
		"backward serialized end": func(f *Footer) { f.ChunkBoundaryOffsets[1] = 0 },
		"empty unpacked chunk":    func(f *Footer) { f.UnpackedChunkOffsets[1] = f.UnpackedChunkOffsets[0] },
		"huge unpacked chunk":     func(f *Footer) { f.UnpackedChunkOffsets[1] = f.UnpackedChunkOffsets[0] + chunker.MaxSize + 1 },
		"named xorb":              func(f *Footer) { f.XorbHash = xethash.Zero },
	}
	for name, mutate := range formatFaults {
		t.Run(name, func(t *testing.T) {
			f := clone()
			mutate(f)
			requireFormatError(t, "Validate", f.Validate(object.Hash))
		})
	}
	for name, mutate := range map[string]func(*Footer){
		"chunk hash":    func(f *Footer) { f.ChunkHashes[1] = xethash.Zero },
		"unpacked size": func(f *Footer) { f.UnpackedChunkOffsets[1]++ },
	} {
		t.Run(name, func(t *testing.T) {
			f := clone()
			mutate(f)
			if err := f.Validate(object.Hash); !errors.Is(err, ErrHashMismatch) {
				t.Fatalf("Validate = %v, want ErrHashMismatch", err)
			}
		})
	}
	if err := valid.Validate(xethash.Zero); !errors.Is(err, ErrHashMismatch) {
		t.Fatalf("Validate against another xorb = %v", err)
	}

	big := &Footer{}
	for i := range MaxRawSize/chunker.MaxSize + 1 {
		big.ChunkHashes = append(big.ChunkHashes, xethash.Zero)
		big.ChunkBoundaryOffsets = append(big.ChunkBoundaryOffsets, uint32((i+1)*(HeaderSize+chunker.MaxSize)))
		big.UnpackedChunkOffsets = append(big.UnpackedChunkOffsets, uint32((i+1)*chunker.MaxSize))
	}
	requireFormatError(t, "Validate of too many raw bytes", big.Validate(xethash.Zero))
}
