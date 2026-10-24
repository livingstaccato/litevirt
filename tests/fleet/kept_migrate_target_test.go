package fleet

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// A migration target writes the VM's disk at its recorded path,
// <disks>/<vm>-<disk>.qcow2. On a host that kept an overlay of a deleted VM of
// the name, that path can be the overlay's missing base, and the VM's disk
// would become it. A migration onto such a host gets the kept-create check:
// the cold copy's ReceiveMigrationDisk refuses in its check_only preflight and
// again at the write, and the live copy's EnsureDisks refuses before any stub
// is made. While the target cannot read its kept state, the disk files there
// decide, as for a create. (Laptop re-review 2, finding 1.)
//
// Red before the check. Mutations: skip the check in ReceiveMigrationDisk
// for a check_only header - "check_only" red; for a real receive - "the
// write" red; drop it from EnsureDisks - "live" red; check only the first
// stub - "live, the second of two disks" red.

// keepOverlayMissing records on sc's node n a kept overlay of a deleted VM
// whose missing backing file is base (a file name on n), and returns the
// overlay's file on n. A record names a disk by its path as every host
// spells it, which the scenario maps onto n's own root (sc.file).
func keepOverlayMissing(t *testing.T, sc *coldStoppedScenario, n *Node, base string) string {
	t.Helper()
	recorded := filepath.Join(t.TempDir(), "old-kept-top.qcow2")
	top := sc.file(n, recorded)
	if err := os.MkdirAll(filepath.Dir(top), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := qcow2.CreateWithBackingFormat(top, base, "raw", 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	n.Server.RecordKeptDiskForTest(context.Background(), "old", "root", recorded)
	return top
}

func wantKeptRefusal(t *testing.T, what string, err error, named string) {
	t.Helper()
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), named) {
		t.Fatalf("%s = %v; want FailedPrecondition naming %s", what, err, named)
	}
}

func receiveHeaderOnly(sc *coldStoppedScenario, checkOnly bool) error {
	up, err := sc.c.PeerClient(sc.src, sc.dst).ReceiveMigrationDisk(context.Background())
	if err != nil {
		return err
	}
	if err := up.Send(&pb.ReceiveMigrationDiskRequest{
		VmName: "os1", Path: sc.disk, SizeBytes: int64(len(sc.payload)), CheckOnly: checkOnly,
	}); err != nil {
		_, rerr := up.CloseAndRecv()
		return rerr
	}
	_, err = up.CloseAndRecv()
	return err
}

func TestFleet_MigrationTargetsGetTheKeptCreateCheck(t *testing.T) {
	t.Run("check_only", func(t *testing.T) {
		sc := newColdStoppedScenario(t)
		base := sc.file(sc.dst, sc.disk)
		top := keepOverlayMissing(t, sc, sc.dst, base)
		wantKeptRefusal(t, "a check_only receive", receiveHeaderOnly(sc, true), top)
	})
	t.Run("the write", func(t *testing.T) {
		sc := newColdStoppedScenario(t)
		base := sc.file(sc.dst, sc.disk)
		top := keepOverlayMissing(t, sc, sc.dst, base)
		wantKeptRefusal(t, "a receive", receiveHeaderOnly(sc, false), top)
		if _, err := os.Lstat(base); err == nil {
			t.Fatal("a refused receive wrote the kept overlay's missing base")
		}
	})
	t.Run("cold migration", func(t *testing.T) {
		sc := newColdStoppedScenario(t)
		base := sc.file(sc.dst, sc.disk)
		top := keepOverlayMissing(t, sc, sc.dst, base)
		wantKeptRefusal(t, "cold migrate", sc.migrateCold(t), top)
		if _, err := os.Lstat(base); err == nil {
			t.Fatal("a refused migration wrote the kept overlay's missing base")
		}
		if vm := sc.vm(t); vm.HostName != sc.src.Name {
			t.Fatalf("a refused migration moved the VM to %s", vm.HostName)
		}
	})
	// While the target cannot read its kept state, the disk files there
	// decide, as for a create: an overlay on the target backing on the disk's
	// path refuses the migration, and with none the migration goes ahead.
	t.Run("kept state unreadable", func(t *testing.T) {
		sc := newColdStoppedScenario(t)
		base := sc.file(sc.dst, sc.disk)
		// In the target's disk directory as the scan lists it, backing on the
		// path the receive writes (the scenario maps each node's writes under
		// a root of its own).
		overlay := filepath.Join(sc.dst.Server.DataDir(), "disks", "db-snap1.qcow2")
		if err := os.MkdirAll(filepath.Dir(overlay), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := qcow2.CreateWithBackingFormat(overlay, base, "raw", 1<<20, nil); err != nil {
			t.Fatal(err)
		}
		f := filepath.Join(sc.dst.Server.DataDir(), "kept-disks.json")
		if err := os.WriteFile(f, []byte("[not json"), 0o600); err != nil {
			t.Fatal(err)
		}
		wantKeptRefusal(t, "cold migrate", sc.migrateCold(t), f)
		if _, err := os.Lstat(base); err == nil {
			t.Fatal("a refused migration wrote the overlay's missing base")
		}
	})
	t.Run("kept state unreadable, nothing on the target names the disk", func(t *testing.T) {
		sc := newColdStoppedScenario(t)
		f := filepath.Join(sc.dst.Server.DataDir(), "kept-disks.json")
		if err := os.WriteFile(f, []byte("[not json"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := sc.migrateCold(t); err != nil {
			t.Fatalf("cold migrate while kept-disks.json cannot be read, with no file on the target naming the disk: %v", err)
		}
		if vm := sc.vm(t); vm.HostName != sc.dst.Name {
			t.Fatalf("the migration did not move the VM: it is on %s", vm.HostName)
		}
	})
	t.Run("a kept overlay naming another path does not hold it", func(t *testing.T) {
		sc := newColdStoppedScenario(t)
		keepOverlayMissing(t, sc, sc.dst, filepath.Join(t.TempDir(), "elsewhere.raw"))
		if err := sc.migrateCold(t); err != nil {
			t.Fatalf("cold migrate: %v", err)
		}
	})
	t.Run("live", func(t *testing.T) {
		sc := newColdStoppedScenario(t)
		// EnsureDisks makes the stub at the path it is given (no per-node root).
		top := keepOverlayMissing(t, sc, sc.dst, sc.disk)
		_, err := sc.c.PeerClient(sc.src, sc.dst).EnsureDisks(context.Background(), &pb.EnsureDisksRequest{
			VmName: "os1", Disks: []*pb.DiskStub{{Path: sc.disk, SizeBytes: 1 << 20}},
		})
		wantKeptRefusal(t, "EnsureDisks", err, top)
		if _, err := os.Lstat(sc.disk); err == nil {
			t.Fatal("a refused EnsureDisks made a stub at the kept overlay's missing base")
		}
	})
	t.Run("live, the second of two disks", func(t *testing.T) {
		sc := newColdStoppedScenario(t)
		first := filepath.Join(filepath.Dir(sc.disk), "os1-a.qcow2")
		second := filepath.Join(filepath.Dir(sc.disk), "os1-b.qcow2")
		top := keepOverlayMissing(t, sc, sc.dst, second)
		_, err := sc.c.PeerClient(sc.src, sc.dst).EnsureDisks(context.Background(), &pb.EnsureDisksRequest{
			VmName: "os1", Disks: []*pb.DiskStub{{Path: first, SizeBytes: 1 << 20}, {Path: second, SizeBytes: 1 << 20}},
		})
		wantKeptRefusal(t, "EnsureDisks", err, top)
		for _, p := range []string{first, second} {
			if _, err := os.Lstat(p); err == nil {
				t.Fatalf("a refused EnsureDisks made a stub at %s", p)
			}
		}
	})
}
