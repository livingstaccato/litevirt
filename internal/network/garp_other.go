//go:build !linux

package network

import (
	"errors"
	"time"
)

func sendRawFrames(int, []byte, int, time.Duration) error {
	return errors.New("raw frames are sent on Linux only")
}
