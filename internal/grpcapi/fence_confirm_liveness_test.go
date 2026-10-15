package grpcapi

import (
	"context"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// `lv host fence-confirm` records that a host is powered off, and the failover
// coordinator may then recover its workloads elsewhere. On the lab an operator
// confirmed a node that was alive and answering, and the cluster recorded it
// fenced. A confirmation of a host that is evidently up is refused, on the
// evidence the coordinator reads before it resumes from a fence (a fresh
// healthy or unready verdict from another observer) and on this node reaching
// it now; a host that is genuinely down is still confirmed.
//
// Mutations: drop the precondition call in FenceHost — every "refused" case
// records a fence and goes red; ignore the freshness cutoff — "stale healthy
// verdict" is refused and goes red; count the host's own row — "only its own
// row" goes red; drop the unready clause — "answers unready" goes red; drop
// the peerUp check — "this node reaches it" goes red; drop the self check —
// "self" goes red.
func TestFenceConfirm_RefusesAHostThatIsAnswering(t *testing.T) {
	type hh struct {
		observer string
		status   string
		failures int
		age      time.Duration
	}
	for _, tc := range []struct {
		name    string
		target  string
		rows    []hh
		healthy []string
		refuse  bool
	}{
		{"down: every observer sees it fail", "peer", []hh{{"obs-1", "suspect", 3, time.Second}, {"obs-2", "suspect", 4, 2 * time.Second}}, nil, false},
		{"no observations", "peer", nil, nil, false},
		{"healthy verdict from one observer", "peer", []hh{{"obs-1", "healthy", 0, 3 * time.Second}, {"obs-2", "suspect", 4, time.Second}}, nil, true},
		{"answers unready", "peer", []hh{{"obs-1", health.StatusUnready, 1, time.Second}}, nil, true},
		{"stale healthy verdict", "peer", []hh{{"obs-1", "healthy", 0, 2 * fenceConfirmLivenessWindow}, {"obs-2", "suspect", 3, time.Second}}, nil, false},
		{"only its own row", "peer", []hh{{"peer", "healthy", 0, time.Second}}, nil, false},
		{"this node reaches it", "peer", nil, []string{"peer"}, true},
		{"self", "test-host", nil, nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := testServer(t)
			s.SetGate(fakeServerGate{execOK: true, healthy: tc.healthy,
				enforcedTok: map[string]bool{capabilities.SharedStorageFenceV1: false}})
			ctx := context.Background()
			if tc.target != "test-host" {
				if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{
					Name: tc.target, Address: "10.0.0.2", SSHUser: "root", SSHPort: 22, GRPCPort: 7443,
					State: "active", FenceStrategy: "manual",
				}); err != nil {
					t.Fatal(err)
				}
			} else if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{
				Name: "test-host", Address: "10.0.0.1", SSHUser: "root", SSHPort: 22, GRPCPort: 7443,
				State: "active", FenceStrategy: "manual",
			}); err != nil {
				t.Fatal(err)
			}
			for _, r := range tc.rows {
				ts := time.Now().Add(-r.age).UTC().Format(time.RFC3339Nano)
				if err := s.db.Execute(ctx,
					`INSERT INTO host_health (observer, target, status, consecutive_failures, last_seen, updated_at)
					 VALUES (?, ?, ?, ?, ?, ?)`, r.observer, tc.target, r.status, r.failures, ts, ts); err != nil {
					t.Fatal(err)
				}
			}
			_, err := s.FenceHost(adminCtx(), &pb.FenceHostRequest{Name: tc.target, Confirmed: true, ConfirmManualOnly: true})
			h, herr := corrosion.GetHost(ctx, s.db, tc.target)
			if herr != nil || h == nil {
				t.Fatalf("read host: %+v %v", h, herr)
			}
			if !tc.refuse {
				if err != nil {
					t.Fatalf("fence-confirm of a host nothing sees answer: %v", err)
				}
				if h.State != "fenced" {
					t.Fatalf("host state %q after the confirmation, want fenced", h.State)
				}
				return
			}
			if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "Power it off first") {
				t.Fatalf("fence-confirm of a host that is up = %v, want FailedPrecondition telling the operator to power it off", err)
			}
			if h.State != "active" {
				t.Fatalf("a refused confirmation changed the host state to %q", h.State)
			}
			rows, qerr := s.db.Query(ctx, `SELECT id FROM fencing_log WHERE host_name = ?`, tc.target)
			if qerr != nil || len(rows) != 0 {
				t.Fatalf("a refused confirmation wrote fencing_log rows: %d (%v)", len(rows), qerr)
			}
		})
	}
}

// A host that is up has a healthy verdict re-stamped every
// health.HeartbeatInterval, so the window must hold two of them, or a live
// host between beats could be confirmed off.
func TestFenceConfirmLivenessWindowCoversTheHeartbeat(t *testing.T) {
	if 2*health.HeartbeatInterval > fenceConfirmLivenessWindow {
		t.Fatalf("health.HeartbeatInterval = %v, fenceConfirmLivenessWindow = %v: want 2*heartbeat <= window",
			health.HeartbeatInterval, fenceConfirmLivenessWindow)
	}
}
