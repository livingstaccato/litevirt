package grpcapi

import (
	"bytes"
	"context"
	"crypto/x509"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/testkit/slogtest"
)

// A peer call whose caller has already gone (a forward whose client was
// killed) is refused without an ERROR: the host row was not unreadable, the
// call ended. A host row that cannot be read while the call is live still
// logs the refusal at ERROR.
//
// Mutations: drop the gone-caller branch — the cancelled case logs ERROR;
// demote any ended context — the deadline case logs DEBUG.
func TestPeerTrust_AGoneCallerIsRefusedWithoutAnError(t *testing.T) {
	var buf bytes.Buffer
	slogtest.Swap(t, slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	s := trustFixture(t)

	ctx, cancel := context.WithCancel(certCtx("node-2", x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth))
	cancel()
	if s.isTrustedHostCN(ctx, "node-2") {
		t.Fatal("a call whose caller went away before its host row was read was trusted")
	}
	if out := buf.String(); strings.Contains(out, "level=ERROR") {
		t.Errorf("a gone caller logged an ERROR:\n%s", out)
	} else if !strings.Contains(out, "level=DEBUG") || !strings.Contains(out, "ended before its host row was read") {
		t.Errorf("a gone caller's refusal is not logged at DEBUG:\n%s", out)
	}

	// A caller whose deadline ran out is a row read too slow: ERROR.
	buf.Reset()
	dctx, dcancel := context.WithDeadline(certCtx("node-2", x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth), time.Now().Add(-time.Second))
	defer dcancel()
	if s.isTrustedHostCN(dctx, "node-2") {
		t.Fatal("a call whose deadline ran out before its host row was read was trusted")
	}
	if out := buf.String(); !strings.Contains(out, "level=ERROR") || !strings.Contains(out, "could not read the host row") {
		t.Errorf("a deadline that ran out before the host row was read is not logged at ERROR:\n%s", out)
	}

	buf.Reset()
	if err := s.db.Close(); err != nil {
		t.Fatal(err)
	}
	if s.isTrustedHostCN(certCtx("node-2", x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth), "node-2") {
		t.Fatal("a peer whose host row could not be read was trusted")
	}
	if out := buf.String(); !strings.Contains(out, "level=ERROR") || !strings.Contains(out, "could not read the host row") {
		t.Errorf("an unreadable host row on a live call is not logged at ERROR:\n%s", out)
	}
}
