package grpcapi

import (
	"context"
	"slices"
	"testing"

	"github.com/litevirt/litevirt/internal/capabilities"
)

// TestAdvertise_HostRuntimeRetireWaitsForTheFirstPass: host_runtime_retire_v1
// is mandatory, but a node advertises it only once it is live on the runtime
// split. So the latch, which needs every replication recipient's
// advertisement, cannot form while any of them still reports to hosts alone or
// reads only hosts.
func TestAdvertise_HostRuntimeRetireWaitsForTheFirstPass(t *testing.T) {
	s := testServer(t)
	if slices.Contains(s.advertisedCapabilities(), capabilities.HostRuntimeRetireV1) {
		t.Fatal("host_runtime_retire_v1 advertised before this node completed a runtime split pass")
	}
	if !slices.Contains(s.advertisedCapabilities(), capabilities.HostRuntimeSplitV1) {
		t.Fatal("host_runtime_split_v1 must be advertised unconditionally")
	}
	s.db.SetHostRuntimeGate(func() bool { return true })
	if _, err := s.db.SplitHostRuntime(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(s.advertisedCapabilities(), capabilities.HostRuntimeRetireV1) {
		t.Error("host_runtime_retire_v1 still withheld after the first complete pass")
	}
}
