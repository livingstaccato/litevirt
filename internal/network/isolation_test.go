package network

import (
	"testing"
)

func TestEnableIPForwarding(t *testing.T) {
	var calls [][]string
	execCommand = func(name string, args ...string) ([]byte, error) {
		calls = append(calls, append([]string{name}, args...))
		return nil, nil
	}
	defer func() { execCommand = defaultExec }()

	if err := EnableIPForwarding(); err != nil {
		t.Fatalf("EnableIPForwarding: %v", err)
	}
	if len(calls) != 1 || calls[0][0] != "sysctl" || calls[0][len(calls[0])-1] != "net.ipv4.ip_forward=1" {
		t.Errorf("expected one sysctl ip_forward=1 call, got: %v", calls)
	}
}
