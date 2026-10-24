package grpcapi

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/image"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// incarnateDB replaces db's rows with a VM db of uuid on dead-host.
func incarnateDB(t *testing.T, s *Server, uuid string) {
	t.Helper()
	_ = corrosion.DeleteVM(context.Background(), s.db, "db")
	spec, _ := json.Marshal(&pb.VMSpec{Name: "db", Uuid: uuid, Cpu: 1, MemoryMib: 256})
	if err := corrosion.InsertVM(context.Background(), s.db, corrosion.VMRecord{Name: "db", HostName: "dead-host", State: "running", Spec: string(spec)}, nil,
		[]corrosion.DiskRecord{{VMName: "db", DiskName: "root", HostName: "dead-host", Path: "/dead/db-root.qcow2",
			SizeBytes: 1 << 20, StorageType: "local", TargetDev: "vda", Bus: "virtio"}}); err != nil {
		t.Fatal(err)
	}
}

// B-R1: a second promotion of a target that reaches this host while the
// first runs (a second `lv promote db --force`, a CLI retry after a client
// timeout) is refused, and changes nothing: the first finishes on the live
// disk it built, which stays.
//
// Red on 6f5c40b38: the second adopts the first's live disk through its
// marker and journal, the first's start then fails and removes that disk
// under the second's VM, whose rows name a file that is gone.
// Mutation "no in-flight register" (beginPromote always admits) — red.
func TestPromote_ASecondPromotionOfTheTargetIsRefusedWhileTheFirstRuns(t *testing.T) {
	s := testServer(t)
	poolDir := setPromoteVMRows(t, s, "db", nil)
	seedReplica(t, poolDir, "", "db", "root", stamp(10*time.Minute), "raw", 1<<20)
	req := &pb.PromoteReplicaRequest{VmName: "db", TargetPool: "dr", Force: true, NoLocalize: true}
	f := s.virt.(*libvirtfake.Fake)
	var errB error
	once := false
	f.FailStartDomain = func(string) error {
		if once {
			return nil
		}
		once = true
		// B runs entirely while A is between its marker and its start.
		errB = s.PromoteReplica(req, &streamRecorder[pb.PromoteReplicaProgress]{ctx: adminCtx()})
		if a, _ := f.DomainIsActive("db"); a {
			return errors.New("Requested operation is not valid: domain is already running")
		}
		return nil
	}
	errA := s.PromoteReplica(req, &streamRecorder[pb.PromoteReplicaProgress]{ctx: adminCtx()})
	if errA != nil {
		t.Fatalf("the first promotion: %v", errA)
	}
	if status.Code(errB) != codes.Aborted {
		t.Errorf("the second promotion = %v, want Aborted", errB)
	}
	root := diskRowsOf(t, s, "db")["root"]
	if root.HostName != s.hostName || filepath.Dir(root.Path) != poolDir {
		t.Fatalf("root row = %+v, want a live disk in %s", root, poolDir)
	}
	if !isRegularFile(root.Path) {
		t.Errorf("the root row names %s, which is gone", root.Path)
	}
	if running, _ := f.DomainIsActive("db"); !running {
		t.Error("the promoted domain does not run")
	}
}

// B-R2: an error return after the start (here "re-home vm record": the VM's
// row was deleted while the promotion ran) leaves the marker and the journal
// for a retry to adopt. When none comes, the stray domain is torn down and a
// new VM of the name (a new uuid) is promoted from the same replica, the
// stray run's live disk is never its root: it builds fresh, and the stray
// file is left exactly as it was and reported as left.
//
// Red on 6f5c40b38: the stray run's disk becomes the new VM's root.
// Mutation "no uuid" together with "no definition check" — red; each alone
// is pinned by TestPromoteJournal_OnlyThisVMsPromotionInProgressReadsIt.
func TestPromote_ALaterVMOfTheNameNeverTakesAStrayRunsDisk(t *testing.T) {
	s := testServer(t)
	poolDir := setPromoteVMRows(t, s, "db", nil)
	seedReplica(t, poolDir, "", "db", "root", stamp(10*time.Minute), "raw", 1<<20)
	incarnateDB(t, s, "aaaaaaaa-0000-0000-0000-0000000000a1")
	req := &pb.PromoteReplicaRequest{VmName: "db", TargetPool: "dr", Force: true, NoLocalize: true}
	f := s.virt.(*libvirtfake.Fake)
	f.FailStartDomain = func(string) error {
		// lv rm db (forced, its host is down) lands while the promotion runs.
		if err := corrosion.DeleteVM(context.Background(), s.db, "db"); err != nil {
			t.Fatal(err)
		}
		return nil
	}
	if err := s.PromoteReplica(req, &streamRecorder[pb.PromoteReplicaProgress]{ctx: adminCtx()}); err == nil {
		t.Fatal("the first promotion did not fail at its commit; the setup is not the one this test needs")
	}
	f.FailStartDomain = nil
	if !s.promoteMarkerPresent("db") {
		t.Fatal("the failed commit left no marker; the setup is not the one this test needs")
	}
	built := promotedFiles(t, poolDir, "db")
	if len(built) != 1 {
		t.Fatalf("built %v", built)
	}
	stray := built[0]
	if err := os.WriteFile(stray, []byte("the deleted VM's stray run wrote this"), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = f.DestroyDomain("db")
	_ = f.UndefineDomain("db", false)

	incarnateDB(t, s, "aaaaaaaa-0000-0000-0000-0000000000a2")
	promoteSet(t, s, req)

	root := diskRowsOf(t, s, "db")["root"]
	if root.Path == stray {
		t.Fatalf("the new VM's root row names the stray run's disk %s", stray)
	}
	if root.HostName != s.hostName || filepath.Dir(root.Path) != poolDir {
		t.Errorf("root row = %+v, want a fresh live disk in %s", root, poolDir)
	}
	if b, err := os.ReadFile(stray); err != nil || string(b) != "the deleted VM's stray run wrote this" {
		t.Errorf("the stray run's disk was touched: %q, %v", b, err)
	}
	left := false
	for _, ev := range vmEventsOf(t, s, "db", "vm.disk.left") {
		left = left || strings.Contains(ev.Detail, stray)
	}
	if !left {
		t.Errorf("no vm.disk.left event names %s", stray)
	}
}

// B-R2: a delete of the VM on this host clears the name's promote marker and
// journal, so nothing a promotion of it left outlives the VM: the main
// delete, the delete of a VM whose domain is gone everywhere, and the delete
// of a VM recorded on a removed host.
//
// Mutations, each red in the subtest named: no forgetPromoteRecords in the
// main delete ("main"), in the no-domain delete ("no domain"), in the
// removed-host delete ("removed host").
func TestDeleteVM_ClearsThePromoteMarkerAndJournalOfTheName(t *testing.T) {
	for _, how := range []string{"main", "no domain", "removed host"} {
		t.Run(how, func(t *testing.T) {
			s := testServer(t)
			poolDir := setPromoteVMRows(t, s, "db", nil)
			seedReplica(t, poolDir, "", "db", "root", stamp(10*time.Minute), "raw", 1<<20)
			promoteSet(t, s, &pb.PromoteReplicaRequest{VmName: "db", TargetPool: "dr", Force: true, NoLocalize: true})
			// What an error return after the start would have left.
			if err := s.writePromoteMarkerFor("db", "", ""); err != nil {
				t.Fatal(err)
			}
			if err := s.recordPromoteDisk("db", map[string]promotedDiskEntry{},
				promotedDiskEntry{Disk: "root", Path: filepath.Join(poolDir, "db-promoted-gone.qcow2")}); err != nil {
				t.Fatal(err)
			}
			s.images = image.NewStore(s.dataDir)
			s.images.Init()
			var err error
			switch how {
			case "main":
				_, err = s.DeleteVM(adminCtx(), &pb.DeleteVMRequest{Name: "db", Force: true})
			case "no domain":
				_ = s.virt.(*libvirtfake.Fake).DestroyDomain("db")
				_ = s.virt.(*libvirtfake.Fake).UndefineDomain("db", false)
				_, err = s.DeleteVM(adminCtx(), &pb.DeleteVMRequest{Name: "db", Force: true})
			case "removed host":
				vm, gerr := corrosion.GetVM(context.Background(), s.db, "db")
				if gerr != nil || vm == nil {
					t.Fatalf("GetVM: %v", gerr)
				}
				_, err = s.deleteVMOnRemovedHost(adminCtx(), vm)
			}
			if err != nil {
				t.Fatalf("delete: %v", err)
			}
			if vm, _ := corrosion.GetVM(context.Background(), s.db, "db"); vm != nil {
				t.Fatalf("the delete left the row %+v; the path is not the one this subtest needs", vm)
			}
			if s.promoteMarkerPresent("db") {
				t.Error("the promote marker outlived the VM's delete")
			}
			if _, err := os.Stat(s.promoteDiskJournalPath("db")); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("the journal outlived the VM's delete (err=%v)", err)
			}
		})
	}
}

// NB-R3: adopting a domain an earlier attempt started whose definition is
// read but names no live disk built from the replica chosen now is refused:
// the root row never names a file the domain does not run from — here an
// older build's kept disk at the replica's earlier fixed name.
//
// Red on 6f5c40b38: the root row names the kept disk.
// Mutation "legacy fallback" (livePath = legacyPromotedPath when nothing
// matches) — red.
func TestPromote_AnAdoptedDomainRunningFromNoMatchingDiskIsRefused(t *testing.T) {
	s := testServer(t)
	poolDir := setPromoteVMRows(t, s, "db", nil)
	r1 := seedReplica(t, poolDir, "", "db", "root", stamp(20*time.Minute), "raw", 1<<20)
	r2 := seedReplica(t, poolDir, "", "db", "root", stamp(10*time.Minute), "raw", 1<<20)
	f := s.virt.(*libvirtfake.Fake)
	f.FailStartDomain = func(name string) error {
		f.SetState(name, libvirtfake.StateRunning)
		panic("crash")
	}
	crashPromote(t, s, &pb.PromoteReplicaRequest{VmName: "db", TargetPool: "dr", Force: true, NoLocalize: true, Replica: r1})
	f.FailStartDomain = nil
	if err := os.WriteFile(s.promoteDiskJournalPath("db"), []byte("{torn"), 0o600); err != nil {
		t.Fatal(err)
	}
	legacy := legacyPromotedPath(poolDir, "db", r2)
	if err := os.WriteFile(legacy, []byte("an older build's promoted disk, kept"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := health.NoteKeptDisks(s.dataDir, "olddb", []string{legacy}); err != nil {
		t.Fatal(err)
	}
	err := s.PromoteReplica(&pb.PromoteReplicaRequest{VmName: "db", TargetPool: "dr", Force: true, NoLocalize: true, Replica: r2},
		&streamRecorder[pb.PromoteReplicaProgress]{ctx: adminCtx()})
	if err == nil {
		t.Fatal("the adoption went ahead from a replica the domain does not run from")
	}
	if root := diskRowsOf(t, s, "db")["root"]; root.Path == legacy || root.HostName == s.hostName {
		t.Errorf("root row = %+v after a refused adoption, want it unchanged", root)
	}
	if running, _ := f.DomainIsActive("db"); !running {
		t.Error("the refused adoption stopped the running domain")
	}
}

// NB-R5 (r1): adopting a domain whose definition cannot be read never takes
// a journal entry built from another replica than the one chosen now.
//
// Mutation r1 (no replica check in adoptedPromotedDisk's unread branch) — red.
func TestPromote_AnUnreadAdoptionNeverTakesAnEntryOfAnotherReplica(t *testing.T) {
	s := testServer(t)
	poolDir := setPromoteVMRows(t, s, "db", nil)
	seedReplica(t, poolDir, "", "db", "root", stamp(10*time.Minute), "raw", 1<<20)
	req := &pb.PromoteReplicaRequest{VmName: "db", TargetPool: "dr", Force: true, NoLocalize: true}
	f := s.virt.(*libvirtfake.Fake)
	f.FailStartDomain = func(name string) error {
		f.SetState(name, libvirtfake.StateRunning)
		panic("crash")
	}
	crashPromote(t, s, req)
	f.FailStartDomain = nil
	j := s.readPromoteDisks("db")
	e := j["root"]
	e.Replica = filepath.Join(replicaOwnerDir(poolDir, "", "db"), "root-20200101-000000.raw")
	if err := s.recordPromoteDisk("db", map[string]promotedDiskEntry{}, e); err != nil {
		t.Fatal(err)
	}
	f.FailDumpXML = func(string) error { return errors.New("libvirt: connection reset") }
	err := s.PromoteReplica(req, &streamRecorder[pb.PromoteReplicaProgress]{ctx: adminCtx()})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("adoption = %v, want Unavailable", err)
	}
	if root := diskRowsOf(t, s, "db")["root"]; root.HostName == s.hostName {
		t.Errorf("root row = %+v after a refused adoption, want it unchanged", root)
	}
}

// strayDefinedRetry is B-R2 with the stray domain only destroyed (stopped,
// still defined), as `virsh destroy` or a crash leaves it: a promotion of db
// (uuid u1) fails at its commit and leaves its marker and journal, db is
// deleted, and a new db (uuid u2) is promoted from the same replica. It
// returns the stray run's disk and the new VM's root path.
func strayDefinedRetry(t *testing.T, u1, u2 string) (stray, root string) {
	t.Helper()
	s := testServer(t)
	poolDir := setPromoteVMRows(t, s, "db", nil)
	seedReplica(t, poolDir, "", "db", "root", stamp(10*time.Minute), "raw", 1<<20)
	incarnateDB(t, s, u1)
	req := &pb.PromoteReplicaRequest{VmName: "db", TargetPool: "dr", Force: true, NoLocalize: true}
	f := s.virt.(*libvirtfake.Fake)
	f.FailStartDomain = func(string) error {
		_ = corrosion.DeleteVM(context.Background(), s.db, "db")
		return nil
	}
	if err := s.PromoteReplica(req, &streamRecorder[pb.PromoteReplicaProgress]{ctx: adminCtx()}); err == nil {
		t.Fatal("the first promotion did not fail at its commit; the setup is not the one this test needs")
	}
	f.FailStartDomain = nil
	built := promotedFiles(t, poolDir, "db")
	if len(built) != 1 || !s.promoteMarkerPresent("db") {
		t.Fatalf("setup: built=%v marker=%v", built, s.promoteMarkerPresent("db"))
	}
	stray = built[0]
	if err := os.WriteFile(stray, []byte("the deleted VM's stray run wrote this"), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = f.DestroyDomain("db") // stopped, still defined
	incarnateDB(t, s, u2)
	promoteSet(t, s, req)
	if b, err := os.ReadFile(stray); err != nil || string(b) != "the deleted VM's stray run wrote this" {
		t.Errorf("the stray run's disk was touched: %q, %v", b, err)
	}
	return stray, diskRowsOf(t, s, "db")["root"].Path
}

// B-1: a VM without a uuid (a plain `lv import` makes one) gets no journal
// reuse at all: a stray run's disk whose stopped domain is still defined and
// names it is never the new VM's root. With uuids the uuid check refuses it.
//
// Red on bb1b709a0 ("no uuid"): the new VM's root row is the stray disk.
// Mutation "empty matches empty" (no check that both uuids are set) — red.
func TestPromote_AStrayDefinedDomainsDiskIsNeverReused(t *testing.T) {
	t.Run("no uuid", func(t *testing.T) {
		if stray, root := strayDefinedRetry(t, "", ""); root == stray {
			t.Fatalf("the new VM's root row names the stray run's disk %s", stray)
		}
	})
	t.Run("uuids", func(t *testing.T) {
		if stray, root := strayDefinedRetry(t, "aaaaaaaa-0000-0000-0000-0000000000a1", "aaaaaaaa-0000-0000-0000-0000000000a2"); root == stray {
			t.Fatalf("the new VM's root row names the stray run's disk %s", stray)
		}
	})
}

// NB-1: a delete's clear of the promote records holds the name's promotion
// flight: while a promotion of the name runs it leaves that promotion's
// marker and journal, and once none runs it removes them.
//
// Mutation "no flight" (forgetPromoteRecords acts without beginPromote) — red.
func TestDeleteVM_TheClearLeavesARunningPromotionsRecords(t *testing.T) {
	s := testServer(t)
	s.virt = libvirtfake.New()
	if err := s.writePromoteMarkerFor("db", "", testVMUUID("db")); err != nil {
		t.Fatal(err)
	}
	if err := s.recordPromoteDisk("db", map[string]promotedDiskEntry{},
		promotedDiskEntry{Disk: "root", Path: "/nowhere/db-promoted-x.qcow2", UUID: testVMUUID("db")}); err != nil {
		t.Fatal(err)
	}
	end, err := s.beginPromote("db")
	if err != nil {
		t.Fatal(err)
	}
	s.forgetPromoteRecords(adminCtx(), "db")
	if !s.promoteMarkerPresent("db") {
		t.Error("a delete removed the marker of a promotion running here")
	}
	if _, err := os.Stat(s.promoteDiskJournalPath("db")); err != nil {
		t.Errorf("a delete removed the journal of a promotion running here: %v", err)
	}
	end()
	s.forgetPromoteRecords(adminCtx(), "db")
	if s.promoteMarkerPresent("db") {
		t.Error("the marker is left once no promotion runs")
	}
	if _, err := s.beginPromote("db"); err != nil {
		t.Errorf("the clear left the name's flight held: %v", err)
	}
}

// NB-3: when the marker is the only evidence that a domain running under the
// name is an earlier attempt of this promotion, it counts only when it names
// the VM's uuid (in place) or the running domain's (renamed). A marker of
// another uuid is not ours; one where either side names no uuid refuses.
//
// Mutation "presence is enough" (promoteMarkerIsOurs returns the marker's
// presence) — red.
func TestPromote_TheMarkerCountsOnlyForItsUUID(t *testing.T) {
	const vmU, otherU = "aaaaaaaa-0000-0000-0000-0000000000c1", "aaaaaaaa-0000-0000-0000-0000000000c2"
	cases := []struct {
		name              string
		markerU, vmUUID   string
		renamed, noMarker bool
		want              bool
		wantCode          codes.Code
	}{
		{name: "in place, its uuid", markerU: vmU, vmUUID: vmU, want: true},
		{name: "in place, another uuid", markerU: otherU, vmUUID: vmU},
		{name: "in place, marker names none", markerU: "", vmUUID: vmU, wantCode: codes.FailedPrecondition},
		{name: "in place, VM has none", markerU: vmU, vmUUID: "", wantCode: codes.FailedPrecondition},
		{name: "renamed, the domain's uuid", markerU: vmU, vmUUID: "minted-now", renamed: true, want: true},
		{name: "renamed, another uuid", markerU: otherU, vmUUID: "minted-now", renamed: true},
		{name: "no marker", noMarker: true, vmUUID: vmU},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := testServer(t)
			s.virt = libvirtfake.New()
			defineDomainNaming(t, s, "db", vmU)
			if !c.noMarker {
				if err := s.writePromoteMarkerFor("db", "", c.markerU); err != nil {
					t.Fatal(err)
				}
			}
			got, err := s.promoteMarkerIsOurs("db", c.vmUUID, c.renamed, true)
			if status.Code(err) != c.wantCode {
				t.Fatalf("err = %v, want code %v", err, c.wantCode)
			}
			if err == nil && got != c.want {
				t.Errorf("ours = %v, want %v", got, c.want)
			}
		})
	}
}

// NB-3, end to end: a stale marker of another VM of the name does not make a
// running stranger domain, one that even runs from a promoted live disk of
// this replica, this promotion's to adopt: --force refuses to replace a
// running domain that is not the VM's own, and nothing is changed.
//
// Red on bb1b709a0: the stranger is adopted and the VM's root row names its
// disk.
func TestPromote_AStaleMarkerOfAnotherVMAdoptsNoRunningDomain(t *testing.T) {
	s := testServer(t)
	poolDir := setPromoteVMRows(t, s, "db", nil)
	seedReplica(t, poolDir, "", "db", "root", "20260101-000000", "raw", 1<<20)
	const stranger = "aaaaaaaa-0000-0000-0000-0000000000d9"
	f := s.virt.(*libvirtfake.Fake)
	if err := f.DefineDomain("<domain type='kvm'><name>db</name><uuid>" + stranger + "</uuid><devices>" +
		adoptablePromotedDisk(t, s, "dr", "db") + "</devices></domain>"); err != nil {
		t.Fatal(err)
	}
	if err := f.StartDomain("db"); err != nil {
		t.Fatal(err)
	}
	if err := s.writePromoteMarkerFor("db", "", stranger); err != nil {
		t.Fatal(err)
	}
	err := s.PromoteReplica(&pb.PromoteReplicaRequest{VmName: "db", TargetPool: "dr", Force: true, NoLocalize: true},
		&streamRecorder[pb.PromoteReplicaProgress]{ctx: adminCtx()})
	if err == nil {
		t.Fatalf("the promotion adopted a running domain of another VM; root row = %+v", diskRowsOf(t, s, "db")["root"])
	}
	if root := diskRowsOf(t, s, "db")["root"]; root.HostName == s.hostName {
		t.Errorf("root row = %+v after the refusal, want it unchanged", root)
	}
	if running, _ := f.DomainIsActive("db"); !running {
		t.Error("the refusal stopped the running domain")
	}
}
