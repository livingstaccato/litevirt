package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/events"
	"github.com/litevirt/litevirt/internal/image"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/pki"
	"github.com/litevirt/litevirt/internal/storage"
)

const lunTestTarget = "iqn.2020-01.com.example:store"

// lunTestServer is a server on test-host with three iscsi pools: lun0 and
// lun0b are the SAME LUN spelled two ways, lun1 is another LUN of the target.
// It is the one voter of an adopted generation (so it decides LUN claims
// alone), the iscsi_lun_claim release feature is open, and iscsiadm is a
// no-op.
func lunTestServer(t *testing.T) *Server {
	t.Helper()
	return newLUNTestServer(t, true)
}

// newLUNTestServer is lunTestServer, adopting the one-voter generation only
// when adopt is set: without it the server has adopted no voter generation,
// as before genesis or after a reset.
func newLUNTestServer(t *testing.T, adopt bool) *Server {
	t.Helper()
	t.Cleanup(storage.OverrideISCSICommandForTest(func(context.Context, string, ...string) ([]byte, error) {
		return nil, nil
	}))
	db, err := corrosion.NewSharedTestClient(fmt.Sprintf("luntest-%d", lunTestDB.Add(1)), "test-host")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := adminCtx()
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	dataDir := t.TempDir()
	store := image.NewStore(dataDir)
	store.Init()
	s := &Server{
		hostName: "test-host", dataDir: dataDir, db: db, images: store, events: events.NewBus(),
		vmLocks: make(map[string]*sync.Mutex), bridgeEnsure: func(string) error { return nil },
		virt: libvirtfake.New(),
	}
	pkiDir := t.TempDir()
	caCert, caKey := filepath.Join(pkiDir, "ca.crt"), filepath.Join(pkiDir, "ca.key")
	if err := pki.GenerateCA(caCert, caKey); err != nil {
		t.Fatal(err)
	}
	if err := pki.GenerateHostCert(caCert, caKey, filepath.Join(pkiDir, "host.crt"), filepath.Join(pkiDir, "host.key"),
		s.hostName, net.ParseIP("127.0.0.1")); err != nil {
		t.Fatal(err)
	}
	s.pkiDir = pkiDir
	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{
		Name: "test-host", Address: "10.0.0.9", State: "active", CPUTotal: 8, MemTotal: 65536,
	}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}
	inc, err := s.db.VoterIncarnation(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if adopt {
		adoptTestGeneration(t, s, []corrosion.VoterMember{{Name: s.hostName, Incarnation: inc}})
	} else {
		s.db.SetVoterConfigGate(func() bool { return true })
	}
	s.db.SetClusterPolicyGate(func() bool { return true })
	// The feature is open: the gate grants, and the use is recorded as the
	// real gate leaves it (a plain delete reads it, lunPlainDeleteRecordable).
	s.SetReleaseFeatureGate(fakeFeatureGate{t: t, grant: true})
	if err := corrosion.RecordReleaseFeatureUse(ctx, s.db, capabilities.ReleaseToken,
		string(capabilities.FeatureISCSILUNClaim), s.hostName, true); err != nil {
		t.Fatalf("record the iscsi_lun_claim use: %v", err)
	}
	for name, opts := range map[string]map[string]string{
		"lun0":  {"portal": "10.0.0.1", "lun": "0"},
		"lun0b": {"portal": "10.0.0.1:3260"},
		"lun1":  {"portal": "10.0.0.1", "lun": "1"},
	} {
		if err := corrosion.UpsertStoragePool(ctx, s.db, corrosion.StoragePoolRecord{
			HostName: "test-host", Name: name, Driver: "iscsi", Source: lunTestTarget, Options: opts, State: "active",
		}); err != nil {
			t.Fatalf("UpsertStoragePool %s: %v", name, err)
		}
	}
	return s
}

var lunTestDB atomic.Int64

// readoptTestGeneration moves s to generation 2 with members.
func readoptTestGeneration(t *testing.T, s *Server, members []corrosion.VoterMember) {
	t.Helper()
	ctx := context.Background()
	val := corrosion.VoterConfigValue{Generation: 2, Members: corrosion.SortMembers(members),
		Change: corrosion.VoterChangeGenesis, CreatedBy: "test", CreatedAt: "test"}
	if err := corrosion.WriteVoterConfig(ctx, s.db, val, corrosion.ClaimCertificate{}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.RecordVoterAdoption(ctx, s.db, 2); err != nil {
		t.Fatal(err)
	}
}

func lunVM(name string, pools ...string) *pb.CreateVMRequest {
	spec := &pb.VMSpec{Name: name, Cpu: 1, MemoryMib: 256, Placement: &pb.PlacementSpec{Host: "test-host"}}
	for i, p := range pools {
		d := "root"
		if i > 0 {
			d = "data" + string(rune('0'+i))
		}
		spec.Disks = append(spec.Disks, &pb.DiskSpec{Name: d, Size: "1G", Storage: p})
	}
	return &pb.CreateVMRequest{Spec: spec}
}

func requireNoVM(t *testing.T, s *Server, name string) {
	t.Helper()
	if rec, _ := corrosion.GetVM(context.Background(), s.db, name); rec != nil {
		t.Errorf("refused VM %q was persisted anyway", name)
	}
}

// A second VM on a LUN another VM's disk already is — whichever pool spells it
// — is refused naming that VM. Another LUN of the same target is free.
//
// Mutation: drop the replica check (lunHoldersHere's disk loop) — b is created
// on a's LUN and this goes red.
func TestCreateVM_ISCSI_SecondVMOnALUNIsRefused(t *testing.T) {
	s := lunTestServer(t)
	ctx := adminCtx()
	if _, err := s.CreateVM(ctx, lunVM("a", "lun0")); err != nil {
		t.Fatalf("first VM on lun0: %v", err)
	}
	_, err := s.CreateVM(ctx, lunVM("b", "lun0b"))
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), `VM "a"`) {
		t.Fatalf("second VM on a's LUN: got %v, want FailedPrecondition naming VM \"a\"", err)
	}
	requireNoVM(t, s, "b")
	if _, err := s.CreateVM(ctx, lunVM("c", "lun1")); err != nil {
		t.Fatalf("a VM on another LUN of the target: %v", err)
	}
}

// Two disks of ONE VM on one LUN are refused before anything is created.
//
// Mutation: drop the duplicate check in fixedDeviceUses — the VM is created
// with both disks on one LUN and this goes red.
func TestCreateVM_ISCSI_TwoDisksOfOneVMOnALUNAreRefused(t *testing.T) {
	s := lunTestServer(t)
	_, err := s.CreateVM(adminCtx(), lunVM("a", "lun0", "lun0b"))
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "are both iSCSI LUN") {
		t.Fatalf("two disks of one VM on one LUN: got %v, want FailedPrecondition", err)
	}
	requireNoVM(t, s, "a")
	if _, err := s.CreateVM(adminCtx(), lunVM("a", "lun0", "lun1")); err != nil {
		t.Fatalf("two disks on two LUNs: %v", err)
	}
}

// A deleted VM holds nothing: its LUN is free for the next VM, as on main.
func TestCreateVM_ISCSI_ADeletedVMsLUNIsFree(t *testing.T) {
	s := lunTestServer(t)
	ctx := adminCtx()
	if _, err := s.CreateVM(ctx, lunVM("a", "lun0")); err != nil {
		t.Fatalf("first VM: %v", err)
	}
	if err := corrosion.DeleteVM(ctx, s.db, "a"); err != nil {
		t.Fatalf("DeleteVM: %v", err)
	}
	// A delete removes its domain too: a destroy, then the undefine (an
	// undefine alone leaves a running domain transient, as libvirt does).
	_ = s.virt.DestroyDomain("a")
	_ = s.virt.UndefineDomain("a", false)
	if _, err := s.CreateVM(ctx, lunVM("b", "lun0")); err != nil {
		t.Fatalf("a VM on a deleted VM's LUN: %v", err)
	}
}

// A create still in flight on this host holds its LUN: a second create is
// refused (retryable), and the LUN is free once the first lets go.
//
// Mutation: make lunClaimRegistry.take ignore existing claims — the second
// create is admitted and this goes red.
func TestCreateVM_ISCSI_AnInFlightCreateHoldsItsLUN(t *testing.T) {
	s := lunTestServer(t)
	_, release, _, _ := s.lunClaims.take("racer", "racer-uuid", "", []lunUse{{key: mustLUNKey(t, "10.0.0.1", "0"), disk: "root"}})
	if release == nil {
		t.Fatal("take on an empty registry refused")
	}
	_, err := s.CreateVM(adminCtx(), lunVM("b", "lun0b"))
	if status.Code(err) != codes.Aborted || !strings.Contains(err.Error(), `VM "racer"`) {
		t.Fatalf("create on a LUN an in-flight create holds: got %v, want Aborted naming \"racer\"", err)
	}
	requireNoVM(t, s, "b")
	release()
	if _, err := s.CreateVM(adminCtx(), lunVM("b", "lun0b")); err != nil {
		t.Fatalf("create once the racer let go: %v", err)
	}
	// And the create's own registration is gone once it returned.
	if got := s.lunClaims.holding(map[string]bool{mustLUNKey(t, "10.0.0.1", "0"): true}, 0); len(got) != 0 {
		t.Errorf("a finished create still holds its LUN in flight: %v", got)
	}
}

func mustLUNKey(t *testing.T, portal, lun string) string {
	t.Helper()
	k, _, ok := storage.FixedDevice(storage.Config{Driver: "iscsi", Source: lunTestTarget,
		Options: map[string]string{"portal": portal, "lun": lun}})
	if !ok {
		t.Fatal("not a fixed device")
	}
	return k
}

// lunPeer is a peer's LiteVirtClient answering only LUNHolders.
type lunPeer struct {
	pb.LiteVirtClient
	holders    []*pb.LUNHolder
	err        error
	asked      *pb.LUNHoldersRequest
	answeredBy string // "" answers as peer-host
}

func (p *lunPeer) LUNHolders(_ context.Context, req *pb.LUNHoldersRequest, _ ...grpc.CallOption) (*pb.LUNHoldersResponse, error) {
	p.asked = req
	if p.err != nil {
		return nil, p.err
	}
	by := p.answeredBy
	if by == "" {
		by = "peer-host"
	}
	return &pb.LUNHoldersResponse{Holders: p.holders, AnsweredBy: by}, nil
}

// A LUN an earlier allocation took for a create on another host is free only
// once that host shows the create gone. Its answer decides: in flight refuses
// (Aborted, naming the VM), a holder refuses (FailedPrecondition), nothing
// lets the walk go on to the next allocation, and no answer refuses
// (Unavailable) — what a host that cannot be asked took, it holds.
//
// Mutation: treat an allocation decided for another create as gone without
// asking its host — the in-flight and holder cases go red.
func TestCreateVM_ISCSI_AnEarlierAllocationMustBeProvenGone(t *testing.T) {
	key := func(t *testing.T) string { return mustLUNKey(t, "10.0.0.1", "0") }
	for _, tc := range []struct {
		name     string
		peer     func(t *testing.T) *lunPeer
		wantCode codes.Code
		wantText string
	}{
		{"committed there", func(t *testing.T) *lunPeer {
			return &lunPeer{holders: []*pb.LUNHolder{{Lun: key(t), VmName: "far", DiskName: "root", HostName: "peer-host"}}}
		}, codes.FailedPrecondition, `VM "far"`},
		{"in flight there", func(t *testing.T) *lunPeer {
			return &lunPeer{holders: []*pb.LUNHolder{{Lun: key(t), VmName: "far", DiskName: "root", HostName: "peer-host", InFlight: true}}}
		}, codes.Aborted, `VM "far"`},
		{"gone there", func(t *testing.T) *lunPeer { return &lunPeer{} }, codes.OK, ""},
		{"an answer never adds a LUN", func(t *testing.T) *lunPeer {
			return &lunPeer{holders: []*pb.LUNHolder{{Lun: "iscsi:other", VmName: "x", DiskName: "root"}}}
		}, codes.OK, ""},
		{"that host cannot be asked", func(t *testing.T) *lunPeer {
			return &lunPeer{err: status.Error(codes.Unavailable, "connection refused")}
		}, codes.Unavailable, "peer-host"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := lunTestServer(t)
			ctx := adminCtx()
			if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{
				Name: "peer-host", Address: "10.0.0.10", State: "active", CPUTotal: 8, MemTotal: 65536,
			}); err != nil {
				t.Fatalf("InsertHost: %v", err)
			}
			// Allocation 0 of the LUN was decided for a create of VM "far" on
			// peer-host, which this host's replica has never heard of.
			if _, err := s.decideLUN(ctx, lunGrant(t), corrosion.LUNAllocation{LUN: key(t), Generation: 0, ClaimID: "far-claim",
				VMID: "far-uuid", VMName: "far", Disk: "root", Host: "peer-host"}); err != nil {
				t.Fatalf("decide allocation 0: %v", err)
			}
			peer := tc.peer(t)
			s.peerClientOverride = func(_ context.Context, host string) (pb.LiteVirtClient, func(), error) {
				if host != "peer-host" {
					t.Errorf("asked %q", host)
				}
				return peer, func() {}, nil
			}
			_, err := s.CreateVM(ctx, lunVM("b", "lun0"))
			if status.Code(err) != tc.wantCode || (tc.wantText != "" && !strings.Contains(err.Error(), tc.wantText)) {
				t.Fatalf("got %v, want %v containing %q", err, tc.wantCode, tc.wantText)
			}
			if tc.wantCode != codes.OK {
				requireNoVM(t, s, "b")
			}
			if peer.asked == nil || len(peer.asked.Luns) != 1 || peer.asked.Luns[0] != key(t) {
				t.Errorf("peer asked %+v, want the one LUN", peer.asked)
			}
		})
	}
}

// A create without an iscsi disk asks no one: nothing about it changes.
func TestCreateVM_ISCSI_NonISCSICreateAsksNoPeer(t *testing.T) {
	s := lunTestServer(t)
	ctx := adminCtx()
	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{
		Name: "peer-host", Address: "10.0.0.10", State: "active", CPUTotal: 8, MemTotal: 65536,
	}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}
	s.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) {
		t.Error("a create without an iscsi disk asked a peer")
		return nil, nil, errors.New("unreachable")
	}
	if _, err := s.CreateVM(ctx, &pb.CreateVMRequest{Spec: &pb.VMSpec{
		Name: "plain", Cpu: 1, MemoryMib: 256, Placement: &pb.PlacementSpec{Host: "test-host"},
		Disks: []*pb.DiskSpec{{Name: "root", Size: "1G"}},
	}}); err != nil {
		t.Fatalf("plain create: %v", err)
	}
}

// LUNHolders answers from this host's in-flight creates and its replica —
// except the rows of the incarnation the asker replaces, named by name AND
// created_at; a name alone exempts nothing (review I-2) — and only for peers.
//
// Mutation: drop the in-flight half of lunHoldersHere — the racer is not
// reported and this goes red.
func TestLUNHolders_AnswersInFlightAndReplica(t *testing.T) {
	s := lunTestServer(t)
	ctx := adminCtx()
	if _, err := s.CreateVM(ctx, lunVM("a", "lun0")); err != nil {
		t.Fatalf("VM a: %v", err)
	}
	k0, k1 := mustLUNKey(t, "10.0.0.1", "0"), mustLUNKey(t, "10.0.0.1", "1")
	_, release, _, _ := s.lunClaims.take("racer", "racer-uuid", "", []lunUse{{key: k1, disk: "data"}})
	defer release()

	if _, err := s.LUNHolders(ctx, &pb.LUNHoldersRequest{Luns: []string{k0}}); status.Code(err) != codes.PermissionDenied &&
		status.Code(err) != codes.Unauthenticated {
		t.Fatalf("LUNHolders from a non-peer: got %v, want a refusal", err)
	}
	pctx := peerCtxFor(t, s, "peer-host")
	resp, err := s.LUNHolders(pctx, &pb.LUNHoldersRequest{Luns: []string{k0, k1}})
	if err != nil {
		t.Fatalf("LUNHolders: %v", err)
	}
	got := map[string]*pb.LUNHolder{}
	for _, h := range resp.Holders {
		got[h.Lun] = h
	}
	if h := got[k0]; h == nil || h.VmName != "a" || h.InFlight || h.HostName != "test-host" {
		t.Errorf("LUN 0 holder = %+v, want committed VM a on test-host", h)
	}
	if h := got[k1]; h == nil || h.VmName != "racer" || !h.InFlight {
		t.Errorf("LUN 1 holder = %+v, want in-flight racer", h)
	}
	// A name alone exempts nothing: a duplicate create of "a" elsewhere must
	// still be told a holds the LUN.
	resp, err = s.LUNHolders(pctx, &pb.LUNHoldersRequest{Luns: []string{k0}, ReplacedName: "a"})
	if err != nil {
		t.Fatalf("LUNHolders: %v", err)
	}
	if len(resp.Holders) == 0 {
		t.Errorf("a name alone exempted VM a's disk: %v", resp.Holders)
	}
	// Nor does the name with another incarnation's created_at (an earlier
	// VM of the name, whose recreate this is not).
	resp, err = s.LUNHolders(pctx, &pb.LUNHoldersRequest{Luns: []string{k0}, ReplacedName: "a", ReplacedCreatedAt: "2001-01-01T00:00:00Z"})
	if err != nil {
		t.Fatalf("LUNHolders: %v", err)
	}
	if len(resp.Holders) == 0 {
		t.Errorf("another incarnation's created_at exempted VM a's disk: %v", resp.Holders)
	}
	// The incarnation a recreate replaces — name and created_at — holds
	// nothing against it.
	rec := vmRecord(t, s, "a")
	resp, err = s.LUNHolders(pctx, &pb.LUNHoldersRequest{Luns: []string{k0}, ReplacedName: "a", ReplacedCreatedAt: rec.CreatedAt})
	if err != nil {
		t.Fatalf("LUNHolders: %v", err)
	}
	if len(resp.Holders) != 0 {
		t.Errorf("the replaced incarnation's own disk reported against it: %v", resp.Holders)
	}
}
