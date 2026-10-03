package grpcapi

import (
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// A memory snapshot suspends the guest and RESUMES it when done. A VM this
// host's partition pause holds must stay stopped, so the snapshot is refused
// before libvirt is touched (docs/design/partition-pause.md §3.3).
//
// Mutation: drop the pause-record check — the snapshot runs (and would resume
// the VM) and this goes red.
func TestCreateSnapshot_RefusesAMemorySnapshotOfAPartitionPausedVM(t *testing.T) {
	s := testServer(t)
	fake := libvirtfake.New()
	s.virt = fake
	s.dataDir = t.TempDir()
	ctx := adminCtx()
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "lvm", HostName: s.hostName, Spec: `{"name":"lvm"}`, State: "running",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	fake.SetState("lvm", libvirtfake.StateRunning)
	fake.SetPaused("lvm")
	if err := writePauseRecordForTest(s.dataDir, "lvm", s.hostName); err != nil {
		t.Fatal(err)
	}
	_, err := s.CreateSnapshot(ctx, &pb.CreateSnapshotRequest{VmName: "lvm", Name: "s1", WithMemory: true})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("CreateSnapshot = %v, want FailedPrecondition for a partition-paused VM", err)
	}
	if st, _ := fake.RawState("lvm"); st != libvirtfake.StatePaused {
		t.Fatalf("lvm is %s after the refused snapshot", st)
	}
}

func writePauseRecordForTest(dataDir, vm, host string) error {
	return health.WritePauseRecordForTests(dataDir, health.PauseRecord{Kind: health.PauseKindVM, Name: vm, Host: host,
		Incarnation: "inc", Reason: "test"})
}
