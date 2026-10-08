package grpcapi

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/pbsstore"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// I-B (final-rereview-integrate-3.md): a VM booted by a live restore runs on
// an overlay backed by the restore's NBD export (restore_live.go builds it
// with qcow2.CreateWithBackingURI). Until it is localized, a restart — lv vm
// restart, a stop and a start, the reconciler after a crash — reconnects to
// that export, as on main. The start admits exactly the export the restore
// recorded for that overlay, and no other protocol backing.

func TestStart_ALiveRestoredVMRestartsBeforeItIsLocalized(t *testing.T) {
	s := testServer(t)
	s.hostName = "host-a"
	s.dataDir = t.TempDir()
	s.virt = libvirtfake.New()
	data := make([]byte, pbsstore.ChunkSize)
	repoDir, ts := seedLiveRepo(t, data, testSpecJSON(t, "vm1"))
	target := filepath.Join(t.TempDir(), "live.qcow2")
	_, cancel, done := runRestoreLiveUntil(t, s, &pb.RestoreLiveRequest{
		RepoPath: repoDir, VmName: "vm1", DiskName: "root", Timestamp: ts,
		TargetPath: target, AutoStart: true,
	}, pb.RestoreLiveProgress_STARTED)
	defer func() { cancel(); <-done }()
	if info, err := qcow2.Info(target); err != nil || !looksLikeProtocol(info.BackingFile) {
		t.Fatalf("the live-restore overlay names %q (%v), want its nbd:// export", info.BackingFile, err)
	}
	vm := vmRecord(t, s, "vm1")
	if err := s.verifyImageBasesForStart(context.Background(), vm); err != nil {
		t.Fatalf("a restart of a live-restored VM before it is localized: %v", err)
	}

	// The record is the overlay's: another VM's overlay naming the same
	// export, or any other nbd:// export, is refused.
	same, _ := qcow2.Info(target)
	other := filepath.Join(t.TempDir(), "copy.qcow2")
	if err := qcow2.CreateWithBackingURI(other, same.BackingFile, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	foreign := filepath.Join(t.TempDir(), "foreign.qcow2")
	if err := qcow2.CreateWithBackingURI(foreign, "nbd://127.0.0.1:10809/vm1-root", 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	for name, disk := range map[string]string{"cp": other, "foreign": foreign} {
		spec, _ := json.Marshal(&pb.VMSpec{Name: name, Cpu: 1, MemoryMib: 256})
		if err := corrosion.InsertVM(context.Background(), s.db,
			corrosion.VMRecord{Name: name, HostName: s.hostName, State: "stopped", Spec: string(spec)}, nil,
			[]corrosion.DiskRecord{{VMName: name, DiskName: "root", HostName: s.hostName, Path: disk, StorageType: "local"}}); err != nil {
			t.Fatal(err)
		}
		startRefused(t, s, vmRecord(t, s, name), "a VM whose overlay names an nbd:// export no restore recorded for it ("+name+")")
	}

	// The overlay itself, its header rewritten in place to name another
	// export, is refused; named back, it is admitted again.
	if qemuImgAvailable() {
		fmtArgs := func(url string) []string {
			args := []string{"rebase", "-u", "-f", "qcow2", "-b", url}
			if same.BackingFormat != "" {
				args = append(args, "-F", same.BackingFormat)
			}
			return append(args, target)
		}
		runQemuImg(t, fmtArgs("nbd://127.0.0.1:10809/vm1-root")...)
		startRefused(t, s, vm, "the restore's overlay rewritten to name another export")
		runQemuImg(t, fmtArgs(same.BackingFile)...)
		if err := s.verifyImageBasesForStart(context.Background(), vm); err != nil {
			t.Fatalf("the overlay naming its export again: %v", err)
		}
	}

	// Once the restore ends its export is gone, and so is the record.
	cancel()
	<-done
	done <- nil
	startRefused(t, s, vm, "a live-restored VM whose restore has ended, still on its export")
}

// The record names the overlay the restore created, not its path: a file put
// at that path afterwards, naming the same export, is not admitted.
func TestLiveRestoreExport_AFileReplacedAtTheOverlaysPathIsNotTheRestores(t *testing.T) {
	s := testServer(t)
	target := filepath.Join(t.TempDir(), "live.qcow2")
	const url = "nbd://127.0.0.1:10809/vm1-root"
	if err := qcow2.CreateWithBackingURI(target, url, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	forget := s.recordLiveRestoreExport(target, url)
	defer forget()
	if !s.liveRestoreExportOf(target, url) {
		t.Fatal("the recorded overlay is not admitted")
	}
	// Moved aside, not removed, so the new file cannot reuse its inode.
	if err := os.Rename(target, target+".old"); err != nil {
		t.Fatal(err)
	}
	if err := qcow2.CreateWithBackingURI(target, url, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	if s.liveRestoreExportOf(target, url) {
		t.Fatal("a file put at the overlay's path afterwards is admitted as the restore's overlay")
	}
}
