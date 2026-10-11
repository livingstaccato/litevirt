package grpcapi

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// A cached "quarantined" answer is trusted for its TTL, and a peer that
// cannot be asked keeps its last answer; one never heard from is not
// reported (no peer client here: every ask fails).
func TestPeerReportsWALQuarantined_CacheAndUnreachable(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	if s.PeerReportsWALQuarantined(ctx, "never-heard") {
		t.Fatal("a peer never heard from is reported quarantined")
	}
	s.notePeerWALQuarantined("rolled-back", true)
	if !s.PeerReportsWALQuarantined(ctx, "rolled-back") {
		t.Fatal("a fresh quarantined answer was not trusted")
	}
	s.peerWALQ["rolled-back"] = peerWALQAnswer{quarantined: true, at: time.Now().Add(-time.Hour)}
	if !s.PeerReportsWALQuarantined(ctx, "rolled-back") {
		t.Fatal("an unreachable peer lost its last (quarantined) answer")
	}
}

// m4 of the switch review: the not-point-in-time notice is per VM
// incarnation, so a VM re-created under the same name is news at once.
//
// Mutation "key by name only" — red.
func TestNotPITKey_ARecreatedVMIsAnotherKey(t *testing.T) {
	s := testServer(t)
	d := &corrosion.DiskRecord{DiskName: "root"}
	a := &corrosion.VMRecord{Name: "web", Spec: `{"name":"web","uuid":"u-1"}`}
	b := &corrosion.VMRecord{Name: "web", Spec: `{"name":"web","uuid":"u-2"}`}
	if s.notPITKey(a, d) == s.notPITKey(b, d) {
		t.Fatal("two incarnations of web share a not-point-in-time notice key")
	}
}
