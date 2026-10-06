package grpcapi

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"google.golang.org/grpc"
)

// Pruning keeps the newest N of ONE schedule's recorded replicas of one disk
// and touches nothing else: not another schedule's, not another disk's, not a
// file with no record, and not one a VM disk is backed by.
func TestPruneRecordedReplicas(t *testing.T) {
	s := testServer(t)
	dir := replicaPoolDir(t, s, "dr")
	ctx := context.Background()
	seed := func(disk, sched, taken string) string {
		rec := newReplicaRecord("", "vm1", disk, sched, taken, "qcow2")
		path, err := publishRecordedReplica(ctx, dir, rec, func(tmp string) error {
			return os.WriteFile(tmp, []byte("x"), 0o600)
		})
		if err != nil {
			t.Fatal(err)
		}
		return path
	}
	var mine []string
	for _, ts := range []string{"20260101-000000", "20260102-000000", "20260103-000000", "20260104-000000", "20260105-000000"} {
		mine = append(mine, seed("root", "vm1/dr", ts))
	}
	otherSched := seed("root", "fleet/dr", "20260101-000001")
	otherDisk := seed("data", "vm1/dr", "20260101-000000")
	unrecorded := filepath.Join(replicaOwnerDir(dir, "", "vm1"), "root-20251231-000000.qcow2")
	if err := os.WriteFile(unrecorded, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The second-oldest is the base of a --no-localize promotion's overlay.
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "vm1-promoted", HostName: s.hostName, State: "running"}, nil,
		[]corrosion.DiskRecord{{VMName: "vm1-promoted", DiskName: "root", HostName: s.hostName, Path: "/live.qcow2", BackingDisk: mine[1]}}); err != nil {
		t.Fatal(err)
	}

	// Keep the newest 2: the three oldest are candidates, the pinned one stays.
	got, err := s.pruneRecordedReplicas(ctx, "dr", "", "vm1", "root", "vm1/dr", 2)
	if err != nil || got != 2 {
		t.Fatalf("pruned %d (%v), want 2", got, err)
	}
	for _, p := range []string{mine[1], mine[3], mine[4], otherSched, otherDisk, unrecorded} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("%s should survive: %v", filepath.Base(p), err)
		}
	}
	for _, p := range []string{mine[0], mine[2]} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("%s should have been pruned", filepath.Base(p))
		}
		if _, err := os.Stat(p + ".json"); !os.IsNotExist(err) {
			t.Errorf("%s's record should have been removed", filepath.Base(p))
		}
	}
	// keep=0 keeps all.
	if got, _ := s.pruneRecordedReplicas(ctx, "dr", "", "vm1", "root", "vm1/dr", 0); got != 0 {
		t.Errorf("keep=0 should prune nothing, got %d", got)
	}
}

func TestIsSharedDriver(t *testing.T) {
	for _, d := range []string{"nfs", "ceph", "iscsi"} {
		if !isSharedDriver(d) {
			t.Errorf("%s should be shared", d)
		}
	}
	for _, d := range []string{"local", "dir", "btrfs", ""} {
		if isSharedDriver(d) {
			t.Errorf("%s should not be shared", d)
		}
	}
}

// fakeReplClient records the PruneReplicas call a cross-host prune makes.
type fakeReplClient struct {
	pb.LiteVirtClient
	got *pb.PruneReplicasRequest
}

func (f *fakeReplClient) PruneReplicas(_ context.Context, in *pb.PruneReplicasRequest, _ ...grpc.CallOption) (*pb.PruneReplicasResponse, error) {
	f.got = in
	return &pb.PruneReplicasResponse{Deleted: 2}, nil
}

// A cross-host prune names the VM's project, the disk and the schedule, so the
// peer prunes exactly that schedule's records — never a listing by name.
func TestPruneReplicasAnywhere_Remote(t *testing.T) {
	s := testServer(t)
	c := &fakeReplClient{}
	s.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) {
		return c, func() {}, nil
	}
	n := s.pruneReplicasAnywhere(context.Background(), "dr", "host-b", "acme", "vm1", "root", "vm1/dr", 1)
	if n != 2 || c.got == nil {
		t.Fatalf("pruned %d, request %+v", n, c.got)
	}
	if c.got.GetProject() != "acme" || c.got.GetVm() != "vm1" || c.got.GetDisk() != "root" ||
		c.got.GetSchedule() != "vm1/dr" || c.got.GetKeep() != 1 || c.got.GetHost() != "host-b" {
		t.Errorf("PruneReplicas request = %+v", c.got)
	}
}
