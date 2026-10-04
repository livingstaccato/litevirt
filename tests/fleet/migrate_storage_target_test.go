// Fleet scenarios for what a migrate --with-storage may do to the TARGET's
// disk files before and after the copy.
//
// Before the copy the source asks the target to make every host-local disk
// path exist (EnsureDisks). libvirt then block-mirrors the source disk into
// whatever file is at that path. So the target must never hand an existing
// file to the mirror as if it were a fresh stub — a disk partition settle kept
// there (drill D1) would be overwritten whenever the sizes happen to match —
// and a failed attempt must never delete a file the attempt did not create,
// whichever build the source runs.
//
// Multi-node by construction: the source decides, the target holds the files,
// and they meet over real gRPC.

package fleet

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/qcow2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// storageMigrationVM records a running VM "pp1" on src with one host-local disk
// at path, recorded at recordedSize bytes.
func storageMigrationVM(t *testing.T, src *Node, path string, recordedSize int64) {
	t.Helper()
	spec, err := json.Marshal(&pb.VMSpec{Name: "pp1", Cpu: 1, MemoryMib: 256})
	if err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertVM(context.Background(), src.DB, corrosion.VMRecord{
		Name: "pp1", HostName: src.Name, State: "running", Spec: string(spec), CPUActual: 1, MemActual: 256,
	}, nil, []corrosion.DiskRecord{{
		VMName: "pp1", DiskName: "root", HostName: src.Name, Path: path,
		SizeBytes: recordedSize, StorageType: "local", TargetDev: "vda",
	}}); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	src.Virt.SetState("pp1", "running")
}

// migrateCalls counts the libvirt migrations src started.
func migrateCalls(n *Node) int {
	k := 0
	for _, e := range n.Virt.EventLog() {
		if e.Op == "migrate" {
			k++
		}
	}
	return k
}

// writeDisk makes a qcow2 at path holding one recognisable byte pattern after
// the header, so a test can tell the file was neither replaced nor rewritten.
func writeDisk(t *testing.T, path string, size uint64) []byte {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := qcow2.Create(path, size, nil); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("settle kept this disk")); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// A disk file the target already holds is never handed to the mirror. The
// migration is refused before libvirt is asked to copy anything, the refusal
// names the file and the host, and the file is left exactly as it was.
//
// Sizes match on purpose: with matching sizes drive-mirror raises no error, so
// before the fix this migration succeeded and overwrote the kept disk.
//
// Mutation: let EnsureDisks reuse an existing file again (skip it, as before) —
// the migration succeeds and the test goes red on migrateCalls.
func TestFleet_StorageMigrationRefusesATargetDiskItDidNotCreate(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	defer c.Stop()
	src, dst := c.Nodes[0], c.Nodes[1]

	path := filepath.Join(c.tmpRoot, dst.Name, "data", "disks", "pp1-root.qcow2")
	before := writeDisk(t, path, 20<<30)
	storageMigrationVM(t, src, path, 20<<30)

	err := migrateWithStorageAt(t, c, src, "pp1", dst.Name)
	if err == nil {
		t.Fatal("the migration went ahead over a disk file the target already held")
	}
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), path) ||
		!strings.Contains(err.Error(), dst.Name) {
		t.Fatalf("refusal = %v, want FailedPrecondition naming %s on %s", err, path, dst.Name)
	}
	if n := migrateCalls(src); n != 0 {
		t.Fatalf("libvirt was asked to migrate %d time(s); the refusal must come before the copy", n)
	}
	after, rerr := os.ReadFile(path)
	if rerr != nil || !bytes.Equal(before, after) {
		t.Fatalf("the target's existing disk changed (err %v)", rerr)
	}
	if vm, _ := corrosion.GetVM(context.Background(), src.DB, "pp1"); vm == nil || vm.HostName != src.Name || vm.State != "running" {
		t.Fatalf("pp1 after the refusal = %+v, want it still running on %s", vm, src.Name)
	}
}

// When the target cannot make the disk paths exist, the migration stops there
// with an error that says so, instead of handing libvirt a domain whose disks
// are missing on the target.
//
// The path is outside every disk-artifact root on the target, which EnsureDisks
// refuses (InvalidArgument).
//
// Mutation: make ensureDisksOnTarget best-effort again (log and continue) — the
// fake libvirt migration succeeds and the test goes red.
func TestFleet_StorageMigrationStopsWhenTheTargetCannotPrepareDisks(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	defer c.Stop()
	src, dst := c.Nodes[0], c.Nodes[1]

	path := filepath.Join(c.tmpRoot, "elsewhere", "pp1-root.qcow2")
	storageMigrationVM(t, src, path, 1<<30)

	err := migrateWithStorageAt(t, c, src, "pp1", dst.Name)
	if err == nil {
		t.Fatal("the migration went ahead although the target could not prepare its disks")
	}
	if !strings.Contains(err.Error(), "prepare") || !strings.Contains(err.Error(), dst.Name) {
		t.Fatalf("error = %v, want one saying the disks could not be prepared on %s", err, dst.Name)
	}
	if n := migrateCalls(src); n != 0 {
		t.Fatalf("libvirt was asked to migrate %d time(s) after the disk preparation failed", n)
	}
}

// A source disk whose virtual size differs from its recorded size is refused
// before anything is done on the target, with both sizes in the message —
// rather than surfacing from deep inside drive-mirror as "Source and target
// image have different sizes".
//
// The shape is drill D1's: an overlay rebuilt at its backing image's size
// (112 MiB) for a disk recorded at 20 GiB.
//
// Mutation: drop the preflight — the target's EnsureDisks answers instead,
// with a message that names neither size, and the test goes red.
func TestFleet_StorageMigrationRefusesADiskThatDisagreesWithItsRecord(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	defer c.Stop()
	src, dst := c.Nodes[0], c.Nodes[1]

	// One filesystem serves every node here, so the source disk is a file the
	// target's EnsureDisks would also see.
	path := filepath.Join(c.tmpRoot, dst.Name, "data", "disks", "pp1-root.qcow2")
	writeDisk(t, path, 112<<20)
	storageMigrationVM(t, src, path, 20<<30)

	err := migrateWithStorageAt(t, c, src, "pp1", dst.Name)
	if err == nil {
		t.Fatal("the migration went ahead with a disk that disagrees with its record")
	}
	if status.Code(err) != codes.FailedPrecondition ||
		!strings.Contains(err.Error(), "117440512") || !strings.Contains(err.Error(), "21474836480") {
		t.Fatalf("error = %v, want FailedPrecondition naming the disk's 117440512 bytes and the recorded 21474836480", err)
	}
	if n := migrateCalls(src); n != 0 {
		t.Fatalf("libvirt was asked to migrate %d time(s)", n)
	}
}

// The cleanup after a failed attempt is decided on the target, not trusted to
// the source. A source built before EnsureDisks reported what it created names
// every disk path in CleanupMigrationArtifacts; the target removes only a stub
// it created itself for that VM and leaves any other file alone.
//
// The old source is modelled by its request: the cleanup RPC sent straight to
// the target, from the source's own host certificate, naming both paths.
//
// Mutation: remove disk paths without asking whether this host created them
// (the old behaviour) — the kept disk is deleted and the test goes red. Drop
// the stub removal altogether — the stub stays and the test goes red.
func TestFleet_TargetRemovesOnlyStubsItCreatedWhateverTheSourceAsks(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	defer c.Stop()
	ctx := context.Background()
	src, dst := c.Nodes[0], c.Nodes[1]

	disks := filepath.Join(c.tmpRoot, dst.Name, "data", "disks")
	kept := filepath.Join(disks, "pp1-root.qcow2")
	stub := filepath.Join(disks, "pp1-data.qcow2")
	before := writeDisk(t, kept, 1<<30)
	storageMigrationVM(t, src, kept, 1<<30)

	toTarget := c.PeerClient(src, dst)
	if _, err := toTarget.EnsureDisks(ctx, &pb.EnsureDisksRequest{
		VmName: "pp1", Disks: []*pb.DiskStub{{Path: stub, SizeBytes: 1 << 30}},
	}); err != nil {
		t.Fatalf("EnsureDisks: %v", err)
	}
	if _, err := toTarget.CleanupMigrationArtifacts(ctx, &pb.CleanupMigrationArtifactsRequest{
		VmName: "pp1", DiskPaths: []string{kept, stub}, RemoveCloudInit: true,
	}); err != nil {
		t.Fatalf("CleanupMigrationArtifacts: %v", err)
	}

	if after, err := os.ReadFile(kept); err != nil || !bytes.Equal(before, after) {
		t.Fatalf("the target deleted or changed a disk it did not create (err %v)", err)
	}
	if _, err := os.Stat(stub); !os.IsNotExist(err) {
		t.Fatalf("the stub the target created for this VM was left behind (stat err %v)", err)
	}
}
