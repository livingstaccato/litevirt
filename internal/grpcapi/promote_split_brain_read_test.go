package grpcapi

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// The promotion's split-brain guard refuses as retryable when a read it
// needs fails: a rename's check for a VM of the new name, and a same-name
// takeover's check that the original's host is no longer healthy. Taken as
// "no such VM" or "no such host", the promotion would define and start a
// guest over another VM's name, or a second copy of a VM still running.
//
// Mutations: either read error ignored (the guard run only on a successful
// read) — the promotion goes ahead, red.
func TestPromoteSplitBrainRefusal_UnreadableReadRefusesAsRetryable(t *testing.T) {
	s, _ := provableCreateServer(t)
	vm := &corrosion.VMRecord{Name: "vm1", HostName: "peer", State: "running"}
	gone, cancel := context.WithCancel(adminCtx())
	cancel() // every read on it fails

	for _, tc := range []struct {
		name    string
		target  string
		renamed bool
	}{
		{"rename onto a name", "vm1-new", true},
		{"same-name takeover from a host", "vm1", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := s.promoteSplitBrainRefusal(gone, vm, tc.target, tc.renamed, false)
			if status.Code(err) != codes.Unavailable {
				t.Fatalf("split-brain guard with its read failing = %v; want Unavailable, retryable", err)
			}
			// The same guard with the read answering lets it through: the
			// refusal above is the read's, not the scenario's.
			if err := s.promoteSplitBrainRefusal(adminCtx(), vm, tc.target, tc.renamed, false); err != nil {
				t.Fatalf("split-brain guard with nothing in the way = %v; want nil", err)
			}
		})
	}
	// --force skips the healthy-host check, and with it its read.
	if err := s.promoteSplitBrainRefusal(gone, vm, "vm1", false, true); err != nil {
		t.Fatalf("forced same-name takeover = %v; want nil", err)
	}
}
