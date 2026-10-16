package network

import (
	"errors"
	"testing"
)

func TestSendGARP_EmptyArgs(t *testing.T) {
	// Should be a no-op.
	if err := SendGARP("", "10.0.0.1"); err != nil {
		t.Errorf("SendGARP empty bridge: %v", err)
	}
	if err := SendGARP("br0", ""); err != nil {
		t.Errorf("SendGARP empty ip: %v", err)
	}
}

func TestSendGARP_Success(t *testing.T) {
	var calls [][]string
	execCommand = func(name string, args ...string) ([]byte, error) {
		calls = append(calls, append([]string{name}, args...))
		return nil, nil
	}
	defer func() { execCommand = defaultExec }()

	if err := SendGARP("br0", "10.0.0.1"); err != nil {
		t.Fatalf("SendGARP: %v", err)
	}
	if len(calls) != 1 {
		t.Fatalf("expected 1 call, got %d", len(calls))
	}
	if calls[0][0] != "arping" {
		t.Errorf("expected arping, got %q", calls[0][0])
	}
}

func TestSendGARPBestEffort_NoError(t *testing.T) {
	execCommand = func(name string, args ...string) ([]byte, error) {
		return []byte("error"), errors.New("exit 1")
	}
	defer func() { execCommand = defaultExec }()

	// Should not panic or return error; it's best-effort.
	SendGARPBestEffort("br0", "10.0.0.1")
}
