package grpcapi

import (
	"os"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// crashPromote runs a promotion of db that dies (a panic standing in for the
// daemon's crash) where crash is hooked, leaving whatever it made by then.
func crashPromote(t *testing.T, s *Server, req *pb.PromoteReplicaRequest) {
	t.Helper()
	defer func() {
		if r := recover(); r != "crash" {
			t.Fatalf("the first attempt did not crash where hooked: %v", r)
		}
	}()
	_ = s.PromoteReplica(req, &streamRecorder[pb.PromoteReplicaProgress]{ctx: adminCtx()})
}

// A promotion that recorded its live disk's name and built it, then died
// before it finished (here at the domain's define), is retried. The retry
// reuses the recorded file: the VM runs from it, no second live disk is
// built beside it, and the record is gone once the rows name the disk.
//
// Mutation "journal ignored" (planPromotedDisk never reuses an entry) — red:
// a second live disk is built and the first is left an orphan.
// Mutation "journal kept" (no clearPromoteDisks after the rows persist) — red.
func TestPromote_ARetryReusesTheLiveDiskItsNameWasRecordedFor(t *testing.T) {
	s := testServer(t)
	poolDir := setPromoteVMRows(t, s, "db", nil)
	seedReplica(t, poolDir, "", "db", "root", stamp(10*time.Minute), "raw", 1<<20)
	req := &pb.PromoteReplicaRequest{VmName: "db", TargetPool: "dr", Force: true, NoLocalize: true}
	f := s.virt.(*libvirtfake.Fake)
	f.FailDefineDomain = func(string) error { panic("crash") }
	crashPromote(t, s, req)
	f.FailDefineDomain = nil

	built := promotedFiles(t, poolDir, "db")
	if len(built) != 1 {
		t.Fatalf("the crashed attempt left %v, want exactly its one live disk", built)
	}
	journal := s.readPromoteDisks("db")
	if e := journal["root"]; e.Path != built[0] {
		t.Fatalf("journal = %+v, want the root's name %s recorded", journal, built[0])
	}

	promoteSet(t, s, req)

	if got := promotedFiles(t, poolDir, "db"); len(got) != 1 || got[0] != built[0] {
		t.Errorf("after the retry the pool holds %v, want only %s (no orphan)", got, built[0])
	}
	if root := diskRowsOf(t, s, "db")["root"]; root.HostName != s.hostName || root.Path != built[0] {
		t.Errorf("root row = %+v, want the recorded live disk %s", root, built[0])
	}
	if _, err := os.Stat(s.promoteDiskJournalPath("db")); !os.IsNotExist(err) {
		t.Errorf("the journal is left after the promotion finished (err=%v)", err)
	}
}

// A promotion that recorded the name and died before it created the file
// leaves nothing to clean: the retry builds once and leaves one live disk.
//
// Mutation "a recorded name is trusted without its file" (reuse with no
// regular-file check) — red: the row names a file never built.
func TestPromote_ARetryAfterARecordedNameWithNoFileBuildsOnce(t *testing.T) {
	s := testServer(t)
	poolDir := setPromoteVMRows(t, s, "db", nil)
	replica := seedReplica(t, poolDir, "", "db", "root", stamp(10*time.Minute), "raw", 1<<20)
	gone := s.freshPromotedPath(poolDir, "db", replica)
	if err := s.recordPromoteDisk("db", promotedDiskEntry{Disk: "root", Path: gone, Replica: replica}); err != nil {
		t.Fatal(err)
	}

	promoteSet(t, s, &pb.PromoteReplicaRequest{VmName: "db", TargetPool: "dr", Force: true, NoLocalize: true})

	got := promotedFiles(t, poolDir, "db")
	root := diskRowsOf(t, s, "db")["root"]
	if len(got) != 1 || root.Path != got[0] {
		t.Errorf("pool holds %v, root row %+v: want exactly the one live disk the row names", got, root)
	}
}

// A promotion that started the domain and died before it persisted the rows
// is adopted by the retry, which takes the live disk the domain runs from —
// its recorded fresh name, not one derived again — for the root's row.
//
// Mutation "adoption derives the name" (adoptedPromotedDisk returns "") —
// red: the row names a path that was never built.
func TestPromote_AnAdoptedRetryRecordsTheDiskTheDomainRunsFrom(t *testing.T) {
	s := testServer(t)
	poolDir := setPromoteVMRows(t, s, "db", nil)
	seedReplica(t, poolDir, "", "db", "root", stamp(10*time.Minute), "raw", 1<<20)
	req := &pb.PromoteReplicaRequest{VmName: "db", TargetPool: "dr", Force: true, NoLocalize: true}
	f := s.virt.(*libvirtfake.Fake)
	f.FailStartDomain = func(name string) error {
		f.SetState(name, libvirtfake.StateRunning) // qemu is up; the daemon dies
		panic("crash")
	}
	crashPromote(t, s, req)
	f.FailStartDomain = nil
	built := promotedFiles(t, poolDir, "db")
	if len(built) != 1 {
		t.Fatalf("the crashed attempt left %v, want exactly its one live disk", built)
	}

	promoteSet(t, s, req)

	if root := diskRowsOf(t, s, "db")["root"]; root.HostName != s.hostName || root.Path != built[0] {
		t.Errorf("root row = %+v, want the disk the adopted domain runs from, %s", root, built[0])
	}
	if got := promotedFiles(t, poolDir, "db"); len(got) != 1 {
		t.Errorf("after the adopted retry the pool holds %v, want one live disk", got)
	}
}
