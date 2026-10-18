package corrosion

import (
	"context"
	"errors"
	"os"
	"strings"
	"syscall"
	"testing"
)

func TestReceiverEstablishedSpoolActualENOSPC(t *testing.T) {
	s, err := newReceiverEstablishedSpool()
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	// Fault injection replaces only this private test owner's FD. /dev/full
	// returns a genuine write ENOSPC without filling the shared ext4 filesystem.
	if err = s.file.Close(); err != nil {
		t.Fatal(err)
	}
	s.file, err = os.OpenFile("/dev/full", os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	err = s.add(context.Background(), strings.Repeat("a", 64), strings.Repeat("b", 64), []byte("prepared-public-artifact"))
	if !errors.Is(err, syscall.ENOSPC) {
		t.Fatalf("real failed write lost: %v", err)
	}
	if s.count != 0 || s.size != 0 || s.digest != "" {
		t.Fatal("failed write published a prepared artifact")
	}
}
