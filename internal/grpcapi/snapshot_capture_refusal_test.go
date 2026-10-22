package grpcapi

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// A memory snapshot that fails before libvirt switched any disk (here its
// memory image cannot be written) took nothing: no overlay, no libvirt
// snapshot. It is a refusal, not a failed snapshot: no "error" row implying
// a partial snapshot is written, the disks stay where they were, and a retry
// under the same name is not blocked by a leftover row.
//
// Mutation: CreateSnapshot treats every capture error as taken (the old
// snapCreated = true) — an error row is written; red.
func TestCreateSnapshot_AMemorySnapshotRefusedBeforeTheSwitchWritesNoErrorRow(t *testing.T) {
	s, fake := plainMemoryVM(t, libvirtfake.MemoryModel{RAMBytes: 1 << 30, WriteBps: 1 << 30, DirtyBps: 32 << 20, ReportBps: 32 << 20})
	fake.SetDiskSource("pm", "vda", filepath.Join(s.dataDir, "pm-root.qcow2"))
	before, _ := fake.DomainDiskSources("pm")
	img, err := lv.SafeVMStatePath(s.dataDir, "pm", "s1")
	if err != nil {
		t.Fatal(err)
	}
	// A directory where the image goes: the memory write fails, before the
	// disks switch.
	if err := os.MkdirAll(img, 0o755); err != nil {
		t.Fatal(err)
	}
	_, err = s.CreateSnapshot(adminCtx(), &pb.CreateSnapshotRequest{VmName: "pm", Name: "s1", WithMemory: true})
	if err == nil {
		t.Fatal("a capture whose memory image could not be written succeeded")
	}
	if c := status.Code(err); c != codes.Aborted {
		t.Fatalf("code %v, want Aborted (nothing taken): %v", c, err)
	}
	evs, _ := corrosion.ListVMEvents(adminCtx(), s.db, "pm", 50, "")
	refused := false
	for _, e := range evs {
		if e.Type == "snapshot.created" && e.Result == "refused" && strings.Contains(e.Detail, "s1") {
			refused = true
		}
	}
	if !refused {
		t.Fatalf("no snapshot.created/refused event recorded: %+v", evs)
	}
	if rec, _ := corrosion.GetSnapshot(adminCtx(), s.db, "pm", "s1"); rec != nil {
		t.Fatalf("a capture refused before the disk switch left a snapshot row %+v", rec)
	}
	after, _ := fake.DomainDiskSources("pm")
	if len(after) != len(before) || after["vda"] != before["vda"] {
		t.Fatalf("disks moved %v -> %v", before, after)
	}
	if st, _ := fake.RawState("pm"); st != libvirtfake.StateRunning {
		t.Fatalf("pm is %s after the refused capture, want running", st)
	}

	// The cause gone, the same name is taken.
	if err := os.Remove(img); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateSnapshot(adminCtx(), &pb.CreateSnapshotRequest{VmName: "pm", Name: "s1", WithMemory: true}); err != nil {
		t.Fatalf("the retry: %v", err)
	}
	if rec, _ := corrosion.GetSnapshot(adminCtx(), s.db, "pm", "s1"); rec == nil || rec.State != "ok" {
		t.Fatalf("the retry's row = %+v", rec)
	}
}

// A failure AFTER libvirt switched the disks is still a snapshot that
// exists: its row is recorded "error" so it stays visible and deletable.
func TestCreateSnapshot_AMemorySnapshotFailingAfterTheSwitchKeepsItsErrorRow(t *testing.T) {
	s, fake := plainMemoryVM(t, libvirtfake.MemoryModel{RAMBytes: 1 << 30, WriteBps: 1 << 30, DirtyBps: 32 << 20, ReportBps: 32 << 20})
	fake.SetDiskSource("pm", "vda", filepath.Join(s.dataDir, "pm-root.qcow2"))
	fake.FailCreateLiveSnapshot = func(_, _ string) error { return errors.New("boom after the switch") }
	if _, err := s.CreateSnapshot(adminCtx(), &pb.CreateSnapshotRequest{VmName: "pm", Name: "s1", WithMemory: true}); err == nil {
		t.Fatal("the failed capture succeeded")
	}
	rec, _ := corrosion.GetSnapshot(adminCtx(), s.db, "pm", "s1")
	if rec == nil || rec.State != "error" {
		t.Fatalf("a capture that failed after the disk switch has row %+v, want an error row", rec)
	}
	if rec.VMStatePath == "" {
		t.Fatalf("the error row names no image: %+v", rec)
	}
}
