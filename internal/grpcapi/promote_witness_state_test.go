package grpcapi

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// A witness takes an operator's promote only while it is active: one that is
// draining or in maintenance takes on no VM, and refuses before anything is
// defined. An active witness is not refused for its state (the control, so the
// refusal below is the state check and not a fixture failure).
//
// The refusal says how to go on: return the witness to active with
// `lv host undrain <host>`.
//
// Mutation: remove the `self.State != "active"` check in doPromoteLocal — the
// draining and maintenance rows go red; drop the hint from the message — the
// same rows go red.
func TestPromoteReplica_WitnessNotActiveRefused(t *testing.T) {
	for _, tc := range []struct {
		state   string
		refused bool
	}{
		{"draining", true},
		{"maintenance", true},
		{"active", false},
	} {
		t.Run(tc.state, func(t *testing.T) {
			s := testServer(t)
			s.dataDir = t.TempDir()
			poolDir := seedPromotableVM(t, s, "dead-host", "fenced", "", 1, 512)
			if err := corrosion.InsertHost(context.Background(), s.db, corrosion.HostRecord{
				Name: s.hostName, Address: "10.0.0.1", State: tc.state, Role: "witness",
			}); err != nil {
				t.Fatal(err)
			}
			err := promoteVM(s, &pb.PromoteReplicaRequest{VmName: "vm1"})
			stateRefusal := err != nil && strings.Contains(err.Error(), "takes on no VM")
			if tc.refused {
				if status.Code(err) != codes.FailedPrecondition || !stateRefusal || !strings.Contains(err.Error(), tc.state) {
					t.Fatalf("promote on a %s witness = %v, want FailedPrecondition naming the state", tc.state, err)
				}
				// The way forward: undrain returns a draining host or one in
				// maintenance to active (cmd/litevirt/host.go, `undrain <host>`).
				if want := "`lv host undrain " + s.hostName + "`"; !strings.Contains(err.Error(), want) {
					t.Errorf("refusal %q does not give the way forward %s", err, want)
				}
				assertNoPromotedArtifacts(t, s, poolDir, "vm1")
				return
			}
			if stateRefusal {
				t.Fatalf("promote on an active witness was refused for its state: %v", err)
			}
		})
	}
}
