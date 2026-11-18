package xorb

import (
	"errors"
	"testing"
)

// requireFormatError fails t unless err is a FormatError and does not wrap
// ErrHashMismatch.
func requireFormatError(t testing.TB, what string, err error) {
	t.Helper()
	var formatErr *FormatError
	if !errors.As(err, &formatErr) || errors.Is(err, ErrHashMismatch) {
		t.Fatalf("%s = %v, want a FormatError", what, err)
	}
}

// flipByte returns a copy of b with the byte at offset inverted.
func flipByte(b []byte, offset int) []byte {
	out := append([]byte(nil), b...)
	out[offset] ^= 0xff
	return out
}
