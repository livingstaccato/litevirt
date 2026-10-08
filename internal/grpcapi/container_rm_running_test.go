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

// `lv ct rm` is documented as "Delete a stopped container", but the runtime
// delete is lxc-destroy -f, which stops a running container first: the lab
// deleted a running container silently. A running container is refused.
func TestDeleteContainer_RunningIsRefused(t *testing.T) {
	s := testServer(t)
	s.hostName = "host-a"
	rt := &fakeCTRuntime{stateByName: map[string]string{"ct1": "running"}}
	s.SetContainerRuntime(rt)
	if err := corrosion.UpsertContainer(context.Background(), s.db, corrosion.ContainerRecord{
		HostName: "host-a", Name: "ct1", State: "running",
	}); err != nil {
		t.Fatal(err)
	}
	_, err := s.DeleteContainer(adminCtx(), &pb.DeleteContainerRequest{Name: "ct1"})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "lv ct stop") {
		t.Fatalf("delete of a running container: got %v, want FailedPrecondition naming lv ct stop", err)
	}
	if len(rt.deleteCalls) != 0 {
		t.Fatalf("runtime delete called: %v", rt.deleteCalls)
	}
	if row, _ := corrosion.GetContainer(context.Background(), s.db, "host-a", "ct1"); row == nil {
		t.Fatal("the row was tombstoned")
	}
}

func runningCT(t *testing.T, s *Server, host, name string) {
	t.Helper()
	if err := corrosion.UpsertContainer(context.Background(), s.db, corrosion.ContainerRecord{
		HostName: host, Name: name, State: "running",
	}); err != nil {
		t.Fatal(err)
	}
}

// --force keeps the old behaviour: the running container is deleted.
func TestDeleteContainer_ForceDeletesRunning(t *testing.T) {
	s := testServer(t)
	s.hostName = "host-a"
	rt := &fakeCTRuntime{stateByName: map[string]string{"ct1": "running"}}
	s.SetContainerRuntime(rt)
	runningCT(t, s, "host-a", "ct1")
	if _, err := s.DeleteContainer(adminCtx(), &pb.DeleteContainerRequest{Name: "ct1", Force: true}); err != nil {
		t.Fatalf("forced delete: %v", err)
	}
	if len(rt.deleteCalls) != 1 {
		t.Fatalf("runtime delete calls = %v", rt.deleteCalls)
	}
}

// A remote peer's delete is not refused: a current entry node judged it before
// forwarding, and an older node mid-upgrade drives compose and relocation
// deletes that never carried force.
func TestDeleteContainer_RemotePeerCallIsNotRefused(t *testing.T) {
	s := newPeerAuthServer(t) // hostName "self", knows peer "peer-1"
	rt := &fakeCTRuntime{stateByName: map[string]string{"ct1": "running"}}
	s.SetContainerRuntime(rt)
	runningCT(t, s, "self", "ct1")
	if _, err := s.DeleteContainer(mtlsAdminCtx("peer-1"), &pb.DeleteContainerRequest{Name: "ct1", HostName: "self"}); err != nil {
		t.Fatalf("peer delete: %v", err)
	}
	if len(rt.deleteCalls) != 1 {
		t.Fatalf("runtime delete calls = %v", rt.deleteCalls)
	}
}

// The entry node refuses before forwarding when the owner's row says running,
// and forwards force when it is set.
func TestDeleteContainer_EntryNodeJudgesARemoteRunningContainer(t *testing.T) {
	s := testServer(t)
	s.SetContainerRuntime(&fakeCTRuntime{})
	fake := &fakeCTDeletePeer{replica: s.db}
	s.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) {
		return fake, func() {}, nil
	}
	runningCT(t, s, "other-host", "w1")
	_, err := s.DeleteContainer(adminCtx(), &pb.DeleteContainerRequest{Name: "w1"})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("unforced delete of a remote running container: %v", err)
	}
	fake.mu.Lock()
	n := len(fake.calls)
	fake.mu.Unlock()
	if n != 0 {
		t.Fatalf("forwarded %d times", n)
	}
	if _, err := s.DeleteContainer(adminCtx(), &pb.DeleteContainerRequest{Name: "w1", Force: true}); err != nil {
		t.Fatalf("forced: %v", err)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.calls) != 1 || !fake.calls[0].Force {
		t.Fatalf("forwarded calls = %+v, want one carrying force", fake.calls)
	}
}
