package grpcapi

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// Fix round 2 of fix/iscsi-one-disk-per-lun: re-review 1's N-1..N-4 and
// m-1..m-5, and ruling 5 (no adopted voter generation).

// decideForeign decides allocation g of LUN lun for VM vm on host.
func decideForeign(t *testing.T, s *Server, lun string, g int64, vm, host string) {
	t.Helper()
	ctx := context.Background()
	if _, err := s.decideLUN(ctx, lunGrant(t), corrosion.LUNAllocation{LUN: lun, Generation: g,
		ClaimID: vm + "-claim", VMID: vm + "-uuid", VMName: vm, Disk: "root", Host: host}); err != nil {
		t.Fatalf("decide allocation %d: %v", g, err)
	}
}

// N-1: a host this replica holds no row for is not a removed host. An earlier
// allocation by it stays held — Unavailable, naming it — until it answers or
// its removal is proven (a tombstone).
//
// Mutation: release an allocation whose host has no live row here — the
// unknown-host case goes red.
func TestCreateVM_ISCSI_AnUnknownAllocatingHostHoldsItsLUN(t *testing.T) {
	for _, tc := range []struct {
		name     string
		setup    func(t *testing.T, s *Server)
		answer   error
		wantCode codes.Code
	}{
		{"never heard of, not answering", func(*testing.T, *Server) {}, errors.New("dial: no such host"), codes.Unavailable},
		{"removed (tombstone)", func(t *testing.T, s *Server) {
			ctx := context.Background()
			if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{Name: "peer-host", Address: "10.0.0.10", State: "active"}); err != nil {
				t.Fatal(err)
			}
			if err := corrosion.DeleteHost(ctx, s.db, "peer-host"); err != nil {
				t.Fatal(err)
			}
		}, errors.New("dial: no such host"), codes.OK},
		{"removed from the voters, no row here", func(t *testing.T, s *Server) {
			ctx := context.Background()
			inc, _ := s.db.VoterIncarnation(ctx)
			for g, members := range map[int64][]corrosion.VoterMember{
				2: {{Name: s.hostName, Incarnation: inc}, {Name: "peer-host", Incarnation: "p"}},
				3: {{Name: s.hostName, Incarnation: inc}},
			} {
				val := corrosion.VoterConfigValue{Generation: g, Members: corrosion.SortMembers(members),
					Change: corrosion.VoterChangeGenesis, CreatedBy: "test", CreatedAt: "test"}
				if err := corrosion.WriteVoterConfig(ctx, s.db, val, corrosion.ClaimCertificate{}); err != nil {
					t.Fatal(err)
				}
			}
			for _, g := range []int64{2, 3} {
				if err := corrosion.RecordVoterAdoption(ctx, s.db, g); err != nil {
					t.Fatal(err)
				}
			}
		}, errors.New("dial: no such host"), codes.OK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := lunTestServer(t)
			tc.setup(t, s)
			decideForeign(t, s, mustLUNKey(t, "10.0.0.1", "0"), 0, "far", "peer-host")
			s.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) {
				return nil, nil, tc.answer
			}
			_, err := s.CreateVM(adminCtx(), lunVM("b", "lun0"))
			if status.Code(err) != tc.wantCode || (tc.wantCode != codes.OK && !strings.Contains(err.Error(), "peer-host")) {
				t.Fatalf("got %v, want %v naming peer-host", err, tc.wantCode)
			}
		})
	}
}

// N-2: a create that took a LUN and could not record its row is undone — no
// guest left running on the LUN with no row and no registration.
//
// Mutation: keep the "log and continue" for a LUN create — this goes red.
func TestCreateVM_ISCSI_ARowInsertFailureAborts(t *testing.T) {
	s := lunTestServer(t)
	ctx := adminCtx()
	if err := s.db.Execute(ctx, `CREATE TRIGGER test_fail_vm_insert BEFORE INSERT ON vms
		BEGIN SELECT RAISE(ABORT, 'induced vm persist failure'); END`); err != nil {
		t.Fatal(err)
	}
	_, err := s.CreateVM(ctx, lunVM("a", "lun0"))
	if err == nil {
		t.Fatal("an iscsi create whose row could not be written succeeded")
	}
	if s.virt.DomainExists("a") {
		t.Error("the aborted create left its domain defined")
	}
}

// N-2: a domain on the answering host that uses the LUN holds it, row or no
// row — the host's own runtime is the authority.
//
// Mutation: answer from rows and registrations only — this goes red.
func TestCreateVM_ISCSI_ADomainWithoutARowHoldsItsLUN(t *testing.T) {
	s := lunTestServer(t)
	dev := mustLUNDevice(t, "10.0.0.1", "0")
	if err := s.virt.DefineDomain(`<domain type='kvm'><name>ghost</name><uuid>6b1f1c2e-0000-4000-8000-000000000001</uuid>` +
		`<devices><disk type='block' device='disk'><source dev='` + dev + `'/><target dev='vda' bus='virtio'/></disk></devices></domain>`); err != nil {
		t.Fatal(err)
	}
	_, err := s.CreateVM(adminCtx(), lunVM("b", "lun0"))
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), `"ghost"`) {
		t.Fatalf("a LUN a domain uses with no row: got %v, want FailedPrecondition naming ghost", err)
	}
	requireNoVM(t, s, "b")
}

// lunPrepares counts, per LUN generation, the prepares this server's voter
// answered.
func lunPrepares(s *Server) (func() map[int64]int, func()) {
	var mu sync.Mutex
	seen := map[int64]int{}
	s.SetClaimVoteObserverForTest(func(v ClaimVote) {
		if v.Phase == "prepare" && v.Key.IsLUN() {
			mu.Lock()
			seen[v.Key.OwnerEpoch]++
			mu.Unlock()
		}
	})
	return func() map[int64]int {
			mu.Lock()
			defer mu.Unlock()
			out := map[int64]int{}
			for k, v := range seen {
				out[k] = v
			}
			return out
		}, func() {
			mu.Lock()
			seen = map[int64]int{}
			mu.Unlock()
		}
}

// N-3: a LUN created on and deleted from five times costs the sixth create a
// walk of what is still open, not of its history.
//
// Mutation: start the walk at generation 0 — this goes red.
func TestCreateVM_ISCSI_TheWalkStartsAtTheCheckpoint(t *testing.T) {
	s := lunTestServer(t)
	ctx := adminCtx()
	count, reset := lunPrepares(s)
	t.Cleanup(func() { s.SetClaimVoteObserverForTest(nil) })
	for i := 0; i < 5; i++ {
		name := "v" + string(rune('0'+i))
		if _, err := s.CreateVM(ctx, lunVM(name, "lun0")); err != nil {
			t.Fatalf("create %s: %v", name, err)
		}
		if err := corrosion.DeleteVM(ctx, s.db, name); err != nil {
			t.Fatal(err)
		}
		_ = s.virt.UndefineDomain(name, false)
	}
	reset()
	if _, err := s.CreateVM(ctx, lunVM("last", "lun0")); err != nil {
		t.Fatalf("sixth create: %v", err)
	}
	if got := count(); len(got) > 3 {
		t.Fatalf("the sixth create walked generations %v: its cost grows with the LUN's history", got)
	}
}

// N-4: a rebuild whose claim side cannot be judged — no voter majority — is
// refused BEFORE the teardown, VM intact. A main-era VM (rows, no claim) is
// judged the same way.
//
// Mutation: drop the claim from the preflight — the rebuild tears down, then
// fails, and this goes red.
func TestRebuildVM_ISCSI_ClaimRefusalComesBeforeTheTeardown(t *testing.T) {
	s := lunTestServer(t)
	ctx := adminCtx()
	if _, err := s.CreateVM(ctx, lunVM("a", "lun0")); err != nil {
		t.Fatalf("create: %v", err)
	}
	inc, err := s.db.VoterIncarnation(ctx)
	if err != nil {
		t.Fatal(err)
	}
	readoptTestGeneration(t, s, []corrosion.VoterMember{
		{Name: s.hostName, Incarnation: inc}, {Name: "voter-b", Incarnation: "b"}, {Name: "voter-c", Incarnation: "c"}})
	s.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) {
		return nil, nil, errors.New("partitioned")
	}
	_, err = s.RebuildVM(ctx, &pb.RebuildVMRequest{Name: "a"})
	if err == nil || !strings.Contains(err.Error(), "nothing was changed") {
		t.Fatalf("rebuild with no voter majority: got %v, want a refusal before the teardown", err)
	}
	vmExists(t, s, "a", "after the refused rebuild")
	if !s.virt.DomainExists("a") {
		t.Error("the refused rebuild undefined the domain")
	}
}

// Re-review 2, C-1: a rebuild MOVES the VM's claim — it decides the LUN's
// next allocation, naming the host doing the rebuild (which holds the LUN
// until the new rows are visible there) — so a racing create meets it at
// the latest allocation, whatever host first created the VM.
//
// Mutation: keep the old allocation without deciding a new one (round 2) —
// this goes red.
func TestRebuildVM_ISCSI_MovesItsClaim(t *testing.T) {
	s := lunTestServer(t)
	ctx := adminCtx()
	if _, err := s.CreateVM(ctx, lunVM("a", "lun0")); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := s.RebuildVM(ctx, &pb.RebuildVMRequest{Name: "a"}); err != nil {
		t.Fatalf("rebuild: %v", err)
	}
	k := corrosion.LUNClaimKey(mustLUNKey(t, "10.0.0.1", "0"), 1)
	st, found, err := s.db.ClaimState(ctx, k)
	if err != nil || !found || st.Value == nil || st.Value.LUN == nil {
		t.Fatalf("the rebuild decided no allocation 1 (%+v, %v): it kept the old claim instead of moving it", st, err)
	}
	if l := st.Value.LUN; l.VMName != "a" || l.Host != s.hostName {
		t.Fatalf("allocation 1 = %+v, want VM a on the rebuilding host %s", l, s.hostName)
	}
	vmExists(t, s, "a", "after the rebuild")
}

// Re-review 2, I-2: an iscsi LUN is allocated only under an adopted member
// voter generation. With none — genesis pending, or after a reset — the
// create is refused, naming the command that adopts one.
//
// Mutation: fall back to a derived voter set — the create succeeds and this
// goes red.
func TestCreateVM_ISCSI_WithoutAVoterGeneration(t *testing.T) {
	s := newLUNTestServer(t, false)
	_, err := s.CreateVM(adminCtx(), lunVM("a", "lun0"))
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "lv cluster voter init") {
		t.Fatalf("iscsi create with no voter generation: got %v, want FailedPrecondition naming lv cluster voter init", err)
	}
	requireNoVM(t, s, "a")
}

// m-2: a refused claim says why, not a guess.
//
// Mutation: restore the "may be cut off" guess — this goes red.
func TestCreateVM_ISCSI_NoMajoritySaysWhy(t *testing.T) {
	s := lunTestServer(t)
	ctx := adminCtx()
	inc, _ := s.db.VoterIncarnation(ctx)
	readoptTestGeneration(t, s, []corrosion.VoterMember{
		{Name: s.hostName, Incarnation: inc}, {Name: "voter-b", Incarnation: "b"}, {Name: "voter-c", Incarnation: "c"}})
	s.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) {
		return nil, nil, errors.New("partitioned")
	}
	_, err := s.CreateVM(ctx, lunVM("a", "lun0"))
	if err == nil || !strings.Contains(err.Error(), "voter-b") || !strings.Contains(err.Error(), "unreachable") ||
		strings.Contains(err.Error(), "cut off") {
		t.Fatalf("no-majority refusal: %v — want the voters' reasons and no guess", err)
	}
}

// m-3: a recreate that changes only the image keeps the LUN's contents, so it
// writes the new image only when overwrite says so, and otherwise refuses —
// before anything is torn down.
//
// Mutation: let the takeover skip the image change silently — this goes red.
func TestRecreate_ISCSI_AnImageChangeNeedsOverwrite(t *testing.T) {
	s := lunImageServer(t)
	d := newLUNDisks(t)
	d.lun("0", 64<<20)
	ctx := adminCtx()
	if _, err := s.CreateVM(ctx, lunImageVM("a", "lun0", false)); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := qcow2.Create(s.images.ImagePath("cirros2"), 32<<20, nil); err != nil {
		t.Fatal(err)
	}
	ops := &serverOps{s: s}
	next := lunImageVM("a", "lun0", false).Spec
	next.Image = "cirros2"
	err := ops.RecreateVM(ctx, "a", next)
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "overwrite") {
		t.Fatalf("image-only recreate without overwrite: got %v, want FailedPrecondition naming overwrite", err)
	}
	vmExists(t, s, "a", "after the refused recreate")
	next.Disks[0].Overwrite = true
	if err := ops.RecreateVM(ctx, "a", next); err != nil {
		t.Fatalf("image-only recreate with overwrite: %v", err)
	}
	if len(d.writes) != 2 || !strings.Contains(d.writes[1], "cirros2") {
		t.Errorf("writes = %v, want the new image written on the second", d.writes)
	}
}

// m-4: the store's images are qcow2. Anything else — raw bytes, a VDI, a VHDX
// — is refused, never copied onto the LUN as if it were raw.
//
// Mutation: write anything that is not qcow2 as raw — this goes red.
func TestCreateVM_ISCSI_ANonQcow2ImageIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name string
		head []byte
	}{
		{"raw bytes", []byte("\xeb\x63\x90 bootsector")},
		{"vhdx", []byte("vhdxfile")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := lunTestServer(t)
			d := newLUNDisks(t)
			d.lun("0", 64<<20)
			path := s.images.ImagePath("odd")
			if err := os.WriteFile(path, append(tc.head, make([]byte, 1<<20)...), 0o644); err != nil {
				t.Fatal(err)
			}
			req := lunImageVM("a", "lun0", false)
			req.Spec.Image = "odd"
			_, err := s.CreateVM(adminCtx(), req)
			if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "qcow2") {
				t.Fatalf("a %s image: got %v, want FailedPrecondition naming qcow2", tc.name, err)
			}
			if len(d.writes) != 0 {
				t.Errorf("wrote %v", d.writes)
			}
		})
	}
}

// N-3: the checkpoint is a replicated row any peer could write; a create
// trusts it only when the voters show an allocation was decided just below
// it. A checkpoint past a live allocation is ignored.
//
// Mutation: trust the checkpoint without asking the voters — the create
// starts past far's allocation, takes the LUN, and this goes red.
func TestCreateVM_ISCSI_ABogusCheckpointIsNotTrusted(t *testing.T) {
	s := lunTestServer(t)
	ctx := adminCtx()
	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{Name: "peer-host", Address: "10.0.0.10", State: "active"}); err != nil {
		t.Fatal(err)
	}
	key := mustLUNKey(t, "10.0.0.1", "0")
	decideForeign(t, s, key, 0, "far", "peer-host")
	if err := corrosion.AdvanceLUNResolved(ctx, s.db, lunGrant(t), key, 5, "forger"); err != nil {
		t.Fatal(err)
	}
	s.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) {
		return &lunPeer{holders: []*pb.LUNHolder{{Lun: key, VmName: "far", DiskName: "root", HostName: "peer-host", InFlight: true}}}, func() {}, nil
	}
	_, err := s.CreateVM(ctx, lunVM("b", "lun0"))
	if status.Code(err) != codes.Aborted || !strings.Contains(err.Error(), `VM "far"`) {
		t.Fatalf("create past a bogus checkpoint: got %v, want Aborted naming far", err)
	}
}

// Re-review 2, m-2: a checkpoint exactly one past the live holder is not
// trusted either: the walk starts at the allocation just below the
// checkpoint, decides it, and meets its holder.
//
// Mutation: start the walk at the checkpoint itself — this goes red.
func TestCreateVM_ISCSI_ACheckpointOnePastTheHolderIsNotTrusted(t *testing.T) {
	s := lunTestServer(t)
	ctx := adminCtx()
	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{Name: "peer-host", Address: "10.0.0.10", State: "active"}); err != nil {
		t.Fatal(err)
	}
	key := mustLUNKey(t, "10.0.0.1", "0")
	decideForeign(t, s, key, 0, "far", "peer-host")
	if err := corrosion.AdvanceLUNResolved(ctx, s.db, lunGrant(t), key, 1, "forger"); err != nil {
		t.Fatal(err)
	}
	s.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) {
		return &lunPeer{holders: []*pb.LUNHolder{{Lun: key, VmName: "far", DiskName: "root", HostName: "peer-host", InFlight: true}}}, func() {}, nil
	}
	_, err := s.CreateVM(ctx, lunVM("b", "lun0"))
	if status.Code(err) != codes.Aborted || !strings.Contains(err.Error(), `VM "far"`) {
		t.Fatalf("create with a checkpoint one past the live holder: got %v, want Aborted naming far", err)
	}
}

// Re-review 2, m-6: a host that was voted out but still has a live row here
// is not evidenced removed: with no answer from it, its allocation stays
// held.
//
// Mutation: drop the live-row guard in votedOut — this goes red.
func TestCreateVM_ISCSI_AVotedOutHostWithALiveRowHoldsItsLUN(t *testing.T) {
	s := lunTestServer(t)
	ctx := adminCtx()
	inc, _ := s.db.VoterIncarnation(ctx)
	for _, g := range []struct {
		gen     int64
		members []corrosion.VoterMember
	}{
		{2, []corrosion.VoterMember{{Name: s.hostName, Incarnation: inc}, {Name: "peer-host", Incarnation: "p"}}},
		{3, []corrosion.VoterMember{{Name: s.hostName, Incarnation: inc}}},
	} {
		val := corrosion.VoterConfigValue{Generation: g.gen, Members: corrosion.SortMembers(g.members),
			Change: corrosion.VoterChangeGenesis, CreatedBy: "test", CreatedAt: "test"}
		if err := corrosion.WriteVoterConfig(ctx, s.db, val, corrosion.ClaimCertificate{}); err != nil {
			t.Fatal(err)
		}
		if err := corrosion.RecordVoterAdoption(ctx, s.db, g.gen); err != nil {
			t.Fatal(err)
		}
	}
	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{Name: "peer-host", Address: "10.0.0.10", State: "active"}); err != nil {
		t.Fatal(err)
	}
	decideForeign(t, s, mustLUNKey(t, "10.0.0.1", "0"), 0, "far", "peer-host")
	s.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) {
		return nil, nil, errors.New("dial: no route to host")
	}
	_, err := s.CreateVM(ctx, lunVM("b", "lun0"))
	if status.Code(err) != codes.Unavailable || !strings.Contains(err.Error(), "peer-host") {
		t.Fatalf("a voted-out host with a live row: got %v, want Unavailable naming peer-host", err)
	}
}

// Re-review 2, m-4: the image's format is judged before the teardown even
// where this host cannot open the LUN: a recreate onto a non-qcow2 image is
// refused with the VM intact.
//
// Mutation: skip the format check when the device cannot be opened here —
// the VM is torn down, then refused, and this goes red.
func TestRecreate_ISCSI_ImageFormatJudgedBeforeTheTeardown(t *testing.T) {
	s := lunImageServer(t)
	d := newLUNDisks(t)
	dev := d.lun("0", 64<<20)
	ctx := adminCtx()
	if _, err := s.CreateVM(ctx, lunImageVM("a", "lun0", false)); err != nil {
		t.Fatalf("create: %v", err)
	}
	delete(d.files, dev) // this host cannot open the LUN any more
	if err := os.WriteFile(s.images.ImagePath("odd"), append([]byte("vhdxfile"), make([]byte, 1<<20)...), 0o644); err != nil {
		t.Fatal(err)
	}
	next := lunImageVM("a", "lun0", true).Spec
	next.Image = "odd"
	err := (&serverOps{s: s}).RecreateVM(ctx, "a", next)
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "qcow2") ||
		!strings.Contains(err.Error(), "nothing was deleted") {
		t.Fatalf("recreate onto a non-qcow2 image: got %v, want FailedPrecondition before the teardown", err)
	}
	vmExists(t, s, "a", "after the refused recreate")
}

var _ = json.Marshal
