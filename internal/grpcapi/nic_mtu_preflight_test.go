package grpcapi

import (
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// The cold-move preflight's EnsureDisks can be refused for something other
// than an MTU (the target's installer ISO or ceph-secret checks run after the
// MTUs matched). Such a refusal is reported as the target refusing the move,
// with its code and its words, not as a failure to check the MTUs; a target
// that could not be asked at all still says so.
//
// Mutation: restore the single "could not check the NIC MTUs" wording — the
// refusal case goes red.
func TestNICMTUPreflightError_Wording(t *testing.T) {
	refused := nicMTUPreflightError("node-1", "web",
		status.Error(codes.FailedPrecondition, "installer ISO debian.iso is not on node-1"))
	if status.Code(refused) != codes.FailedPrecondition ||
		status.Convert(refused).Message() != `node-1 refused the move of VM "web": installer ISO debian.iso is not on node-1` {
		t.Errorf("refusal: %v", refused)
	}
	down := nicMTUPreflightError("node-1", "web", status.Error(codes.Unavailable, "connection reset"))
	if status.Code(down) != codes.Unavailable || !strings.Contains(down.Error(), "could not ask node-1 to check the NIC MTUs") {
		t.Errorf("unreachable target: %v", down)
	}
}
