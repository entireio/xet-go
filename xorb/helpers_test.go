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
