//go:build !linux

package health

import (
	"errors"
	"os"
)

// setNoCOW is Linux only (partition_pause_nocow_linux.go).
func setNoCOW(*os.File) error { return errors.New("FS_NOCOW_FL is Linux only") }
