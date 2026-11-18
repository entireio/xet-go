package xorb

import (
	"errors"
	"testing"
)

// requireFormatError fails t unless err is a FormatError.
func requireFormatError(t testing.TB, what string, err error) {
	t.Helper()
	var formatErr *FormatError
	if !errors.As(err, &formatErr) {
		t.Fatalf("%s = %v, want a FormatError", what, err)
	}
}
