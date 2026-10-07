package grpcapi

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pbsstore"
)

// Fix round 5 (restore-iso-rereview-4.md).

// m-9: a memory snapshot's revert reopens the definition its saved image
// carries. Its installer CD-ROM is judged on this host and the restore is
// handed the file judged; a saved image whose CD-ROM is now a link to the host
// key is refused before anything is torn down.
func TestISORound5_AMemoryRevertIsHandedTheJudgedFile(t *testing.T) {
	ctx := context.Background()
	s, fake, key := isoServer(t)
	dir := t.TempDir()
	real := filepath.Join(dir, "virtio-win-0.1.240.iso")
	writeLibFile(t, real, isoBody)
	link := filepath.Join(dir, "virtio-win.iso")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	legacyVM(t, s, fake, "win", link)
	vmstate := filepath.Join(t.TempDir(), "win.vmstate")
	if err := corrosion.InsertSnapshot(ctx, s.db, corrosion.SnapshotRecord{
		ID: "s1", VMName: "win", HostName: s.hostName, Name: "snap1", State: "ready", Type: "memory", VMStatePath: vmstate,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := fake.CreateSnapshot("win", "snap1"); err != nil {
		t.Fatal(err)
	}
	// The image was saved while the domain carried the link (a main-era save).
	fake.SetSavedImageXML(vmstate, fake.DefinedXML("win"))
	if _, err := s.RestoreSnapshot(adminCtx(), &pb.RestoreSnapshotRequest{VmName: "win", SnapshotName: "snap1"}); err != nil {
		t.Fatalf("revert to a memory snapshot: %v", err)
	}
	var note string
	for _, e := range fake.EventLog() {
		if e.Op == "revert-live" {
			note = e.Note
		}
	}
	if !strings.Contains(note, "dxml=") || !strings.Contains(note, mustEval(t, real)) {
		t.Fatalf("the restore was not handed the judged file: %q", note)
	}
	if got := s.domainInstallerISOs("win", fake.DefinedXML("win")); len(got) != 1 || got[0] != mustEval(t, real) {
		t.Fatalf("the reverted definition's CD-ROM is %v", got)
	}
	// Red: the saved image's CD-ROM is a link to the host key. (No spec ISO,
	// so the CD-ROM is judged as itself, and only the saved image names it.)
	evil := filepath.Join(dir, "evil.iso")
	if err := os.Symlink(key, evil); err != nil {
		t.Fatal(err)
	}
	spec := vmSpecFor(vmRecord(t, s, "win"))
	spec.Iso = ""
	b, _ := json.Marshal(spec)
	if err := s.db.Execute(ctx, `UPDATE vms SET spec = ? WHERE name = 'win'`, string(b)); err != nil {
		t.Fatal(err)
	}
	fake.SetSavedImageXML(vmstate, strings.ReplaceAll(fake.DefinedXML("win"), mustEval(t, real), evil))
	if _, err := s.RestoreSnapshot(adminCtx(), &pb.RestoreSnapshotRequest{VmName: "win", SnapshotName: "snap1"}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("revert to a saved image whose CD-ROM links to the host key: got %v, want FailedPrecondition", err)
	}
}

// C-3 restore: a backup's restore onto a host where another project's pool
// maps the VM's library directory — after the VM was deleted, so no record is
// left — defines and starts the VM. A restored domain carries no installer
// CD-ROM (as on main: only a create attaches one), so no file of the shared
// directory is opened, and nothing is refused.
func TestISORound5_ARestoreAfterDeleteOntoASharedDirectoryStarts(t *testing.T) {
	ctx := context.Background()
	s, fake, _ := isoServer(t)
	_ = acmeOperator(t, s)
	lib := projectLibrary(t, s, "acme-isos", "acme")
	writeLibFile(t, filepath.Join(lib, "install.iso"), isoBody)
	if _, err := s.CreateVM(adminCtx(), isoCreate("vm1", "acme-isos/install.iso", "acme")); err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	spec := vmSpecFor(vmRecord(t, s, "vm1"))
	if _, err := s.DeleteVM(adminCtx(), &pb.DeleteVMRequest{Name: "vm1"}); err != nil {
		t.Fatalf("DeleteVM: %v", err)
	}
	if got := identityFiles(t, s); len(got) != 0 {
		t.Fatalf("test setup: records left %v", got)
	}
	if err := corrosion.UpsertStoragePool(ctx, s.db, corrosion.StoragePoolRecord{
		HostName: s.hostName, Name: "o-disks", Driver: "dir", Target: lib, Project: "other", State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	spec.Network = nil
	specJSON, _ := json.Marshal(spec)
	repoDir, ts := seedLiveRepo(t, make([]byte, pbsstore.ChunkSize), string(specJSON))
	stream, cancel, done := runRestoreLiveUntil(t, s, &pb.RestoreLiveRequest{
		RepoPath: repoDir, VmName: "vm1", DiskName: "root", Timestamp: ts,
		TargetPath: filepath.Join(t.TempDir(), "live.qcow2"), AutoStart: true,
	}, pb.RestoreLiveProgress_STARTED)
	defer func() { cancel(); <-done }()
	if !sawPhase(stream, pb.RestoreLiveProgress_STARTED) {
		select {
		case err := <-done:
			done <- err
			t.Fatalf("restore after delete onto a shared directory did not start: %v", err)
		default:
			t.Fatal("restore after delete onto a shared directory did not start")
		}
	}
	if got := s.domainInstallerISOs("vm1", fake.DefinedXML("vm1")); len(got) != 0 {
		t.Fatalf("the restored domain carries installer CD-ROMs %v", got)
	}
}
