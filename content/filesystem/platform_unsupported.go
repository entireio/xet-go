//go:build !linux && !darwin

package filesystem

import "github.com/entireio/xet-go/content"

func checkDurabilitySupported() error { return content.ErrDurabilityUnsupported }

func syncDirectory(string) error { return content.ErrDurabilityUnsupported }

func classifyDirectorySyncError(error) error { return content.ErrDurabilityUnsupported }
