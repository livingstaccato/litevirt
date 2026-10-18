package main

import (
	"errors"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// An older daemon answers the new RPCs Unimplemented; lv says the build is
// older and to upgrade, not just the gRPC code. Any other error passes
// through, named.
func TestOlderDaemonError_SaysTheDaemonIsOlder(t *testing.T) {
	err := olderDaemonError("list set-aside overlays", status.Error(codes.Unimplemented, "unknown method ListSetAsideOverlays"))
	if !strings.Contains(err.Error(), "older build") || !strings.Contains(err.Error(), "upgrade") {
		t.Errorf("Unimplemented = %q, want it to say the daemon is older", err)
	}
	other := errors.New("boom")
	if err := olderDaemonError("x", other); !errors.Is(err, other) || strings.Contains(err.Error(), "older build") {
		t.Errorf("another error = %q", err)
	}
}
