package grpcapi

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"

	golibvirt "github.com/digitalocean/go-libvirt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/compose/planner"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// Fix round 4 of fix/iscsi-one-disk-per-lun: re-review 3's I-1, I-2 and
// m-1..m-4.

// restartedLUNServer is s after a daemon restart: a new Server on the same
// state database and data directory, with libvirt's domains as they were,
// and nothing that lived only in the old process's memory.
func restartedLUNServer(s *Server) *Server {
	return &Server{
		hostName: s.hostName, dataDir: s.dataDir, db: s.db, images: s.images, events: s.events,
		vmLocks: make(map[string]*sync.Mutex), bridgeEnsure: s.bridgeEnsure, virt: s.virt,
		pkiDir: s.pkiDir, releaseFeatureGate: s.releaseFeatureGate,
	}
}

// I-2: the hold a rebuild or recreate takes on the LUNs whose claim it moves
// is durable on this host: a daemon restart between the teardown and the
// re-created VM's rows does not drop it, and the restarted host still answers
// that the LUN is taken.
//
// Mutation: keep the hold in memory only — the restarted host answers
// nothing and this goes red.
func TestRebuildVM_ISCSI_TheMovedHoldSurvivesARestart(t *testing.T) {
	s := lunTestServer(t)
	ctx := adminCtx()
	if _, err := s.CreateVM(ctx, lunVM("a", "lun0")); err != nil {
		t.Fatalf("create: %v", err)
	}
	_, release, err := s.preflightLUNs(ctx, lunVM("a", "lun0").Spec, vmRecord(t, s, "a"), "")
	if err != nil {
		t.Fatalf("preflight: %v", err)
	}
	defer release()
	if err := corrosion.DeleteVM(ctx, s.db, "a"); err != nil {
		t.Fatal(err)
	}
	_ = s.virt.UndefineDomain("a", false)

	s2 := restartedLUNServer(s)
	resp, err := s2.LUNHolders(peerCtxFor(t, s2, "peer-host"), &pb.LUNHoldersRequest{Luns: []string{mustLUNKey(t, "10.0.0.1", "0")}})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Holders) != 1 || !resp.Holders[0].InFlight || resp.Holders[0].VmName != "a" {
		t.Fatalf("after a restart during the rebuild the LUN is held by %v, want the rebuild of a in flight", resp.Holders)
	}
	if _, err := s2.CreateVM(ctx, lunVM("b", "lun0")); status.Code(err) != codes.Aborted || !strings.Contains(err.Error(), `VM "a"`) {
		t.Fatalf("a create on the restarted host: got %v, want Aborted naming a", err)
	}
}

// m-1: the moved allocation is decided only after every refusal the
// preflight can still make — a recreate refused for its image decides no
// allocation, so the LUN's checkpoint never moves past the allocation of the
// VM that still runs.
//
// Mutation: decide before the image checks — this goes red.
func TestRecreate_ISCSI_ARefusedRecreateDecidesNoAllocation(t *testing.T) {
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
	next := lunImageVM("a", "lun0", false).Spec
	next.Image = "cirros2"
	for i := 0; i < 2; i++ {
		err := (&serverOps{s: s}).RecreateVM(ctx, "a", next)
		if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "overwrite") {
			t.Fatalf("image-only recreate without overwrite: got %v, want FailedPrecondition naming overwrite", err)
		}
	}
	key := mustLUNKey(t, "10.0.0.1", "0")
	for g := int64(1); g <= 2; g++ {
		if st, found, err := s.db.ClaimState(ctx, corrosion.LUNClaimKey(key, g)); err != nil || (found && st.Value != nil) {
			t.Fatalf("a refused recreate decided allocation %d: %+v (%v)", g, st, err)
		}
	}
	if c, err := corrosion.GetLUNResolved(ctx, s.db, key); err != nil || c > 0 {
		t.Fatalf("checkpoint after two refused recreates = %d (%v), want it still at the running VM's allocation", c, err)
	}
	vmExists(t, s, "a", "after the refused recreates")
}

// m-2: a domain is skipped only when libvirt says it does not exist
// (VIR_ERR_NO_DOMAIN). Any other error reading a listed domain — a dropped
// libvirt connection, which also makes every lookup fail — fails the answer:
// a guest running with no row must never read as nothing.
//
// (Asked through LUNHolders: a create on this host is refused earlier, by the
// runtime-inventory admission, which reads every domain too.)
//
// Mutation: skip on any error once DomainExists reports false — the dropped
// connection reads as "nothing here" and this goes red.
func TestCreateVM_ISCSI_ADomainUnreadableForAnyOtherReasonFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name     string
		err      error
		wantCode codes.Code
	}{
		{"connection dropped", errors.New("libvirt: the connection was closed"), codes.Internal},
		{"undefined since it was listed", golibvirt.Error{Code: uint32(golibvirt.ErrNoDomain), Message: "Domain not found"}, codes.OK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := lunTestServer(t)
			dev := mustLUNDevice(t, "10.0.0.1", "0")
			fake := s.virt.(*libvirtfake.Fake)
			if err := fake.DefineDomain(`<domain type='kvm'><name>ghost</name><uuid>6b1f1c2e-0000-4000-8000-000000000002</uuid>` +
				`<devices><disk type='block' device='disk'><source dev='` + dev + `'/><target dev='vda' bus='virtio'/></disk></devices></domain>`); err != nil {
				t.Fatal(err)
			}
			// Between the listing and the read the domain can no longer be
			// looked up: for the dropped connection that is every lookup
			// failing, for the other case the domain really is gone.
			fake.FailDumpXML = func(name string) error {
				if name != "ghost" {
					return nil
				}
				_ = fake.UndefineDomain("ghost", false)
				return tc.err
			}
			resp, err := s.LUNHolders(peerCtxFor(t, s, "peer-host"), &pb.LUNHoldersRequest{Luns: []string{mustLUNKey(t, "10.0.0.1", "0")}})
			if status.Code(err) != tc.wantCode {
				t.Fatalf("got %v (holders %v), want %v", err, resp.GetHolders(), tc.wantCode)
			}
		})
	}
}

// hostPeers answers LUNHolders as each named host: holders per host, or the
// host's error; every question is recorded in order.
type hostPeers struct {
	mu      sync.Mutex
	holders map[string][]*pb.LUNHolder
	errs    map[string]error
	present map[string]bool // HoldPresent per host
	asked   []string
}

func (p *hostPeers) client(_ context.Context, host string) (pb.LiteVirtClient, func(), error) {
	return &hostPeer{p: p, host: host}, func() {}, nil
}

type hostPeer struct {
	pb.LiteVirtClient
	p    *hostPeers
	host string
}

func (h *hostPeer) CleanupMigrationArtifacts(context.Context, *pb.CleanupMigrationArtifactsRequest, ...grpc.CallOption) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}

func (h *hostPeer) LUNHolders(_ context.Context, req *pb.LUNHoldersRequest, _ ...grpc.CallOption) (*pb.LUNHoldersResponse, error) {
	h.p.mu.Lock()
	defer h.p.mu.Unlock()
	h.p.asked = append(h.p.asked, h.host)
	if err := h.p.errs[h.host]; err != nil {
		return nil, err
	}
	return &pb.LUNHoldersResponse{Holders: h.p.holders[h.host], AnsweredBy: h.host,
		HoldPresent: req.HoldToken != "" && h.p.present[h.host]}, nil
}

// I-2: a moved allocation names the host that holds the claim and the host the
// re-created VM runs on. It is gone only when BOTH show nothing; either one
// holding it refuses, either one unreachable refuses Unavailable naming it,
// and the holding host is asked first.
//
// Mutation: ask only the allocation's Host — the run host's holder and its
// silence go unseen, and this goes red.
func TestCreateVM_ISCSI_AMovedAllocationIsGoneOnlyWhenBothHostsShowNothing(t *testing.T) {
	key := func(t *testing.T) string { return mustLUNKey(t, "10.0.0.1", "0") }
	for _, tc := range []struct {
		name     string
		peers    func(t *testing.T) *hostPeers
		wantCode codes.Code
		wantText string
	}{
		{"the run host holds it", func(t *testing.T) *hostPeers {
			return &hostPeers{holders: map[string][]*pb.LUNHolder{
				"run-host": {{Lun: key(t), VmName: "web", DiskName: "root", HostName: "run-host"}}}}
		}, codes.FailedPrecondition, `VM "web"`},
		{"the run host cannot be asked", func(*testing.T) *hostPeers {
			return &hostPeers{errs: map[string]error{"run-host": errors.New("dial: no route to host")}}
		}, codes.Unavailable, "run-host"},
		{"the holding host cannot be asked", func(*testing.T) *hostPeers {
			return &hostPeers{errs: map[string]error{"hold-host": errors.New("dial: no route to host")}}
		}, codes.Unavailable, "hold-host"},
		{"both show nothing", func(*testing.T) *hostPeers { return &hostPeers{} }, codes.OK, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := lunTestServer(t)
			ctx := adminCtx()
			for _, h := range []string{"hold-host", "run-host"} {
				if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{Name: h, Address: "10.0.0.20", State: "active"}); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := s.decideLUN(ctx, corrosion.LUNAllocation{LUN: key(t), Generation: 0, ClaimID: "moved",
				VMID: "web-uuid", VMName: "web", Disk: "root", Host: "hold-host", RunHost: "run-host"}); err != nil {
				t.Fatal(err)
			}
			peers := tc.peers(t)
			s.peerClientOverride = peers.client
			_, err := s.CreateVM(ctx, lunVM("b", "lun0"))
			if status.Code(err) != tc.wantCode || (tc.wantText != "" && !strings.Contains(err.Error(), tc.wantText)) {
				t.Fatalf("got %v, want %v containing %q", err, tc.wantCode, tc.wantText)
			}
			if len(peers.asked) == 0 || peers.asked[0] != "hold-host" {
				t.Fatalf("asked %v, want the holding host first", peers.asked)
			}
		})
	}
}

// I-1 and I-2: a moved hold gives way only to the re-created incarnation's
// own rows (the created_at its run host shows), or to its run host showing
// nothing, or to that host's recorded removal. Rows of the replaced
// incarnation — still here while its tombstone travels — are not evidence,
// and neither is a run host that cannot be asked.
//
// Mutation: let the hold give way to any live row of the VM's name (round 3)
// — the replaced incarnation's rows release it, and this goes red.
func TestLUNHold_GivesWayOnlyToPositiveEvidence(t *testing.T) {
	s := lunTestServer(t)
	ctx := adminCtx()
	key := mustLUNKey(t, "10.0.0.1", "0")
	if _, err := s.CreateVM(ctx, lunVM("web", "lun0")); err != nil {
		t.Fatalf("create: %v", err)
	}
	old := vmRecord(t, s, "web").CreatedAt
	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{Name: "run-host", Address: "10.0.0.20", State: "active"}); err != nil {
		t.Fatal(err)
	}
	if err := s.putLUNHold(&lunHoldRecord{Token: "tok", VM: "web", ReplacedCreatedAt: old,
		LUNs: map[string]string{key: "root"}, RunHost: "run-host"}); err != nil {
		t.Fatal(err)
	}
	s.finishLUNHold("tok")
	held := func() bool {
		ok, err := s.lunHoldPresent("tok", []string{key})
		if err != nil {
			t.Fatal(err)
		}
		return ok
	}
	peers := &hostPeers{holders: map[string][]*pb.LUNHolder{
		"run-host": {{Lun: key, VmName: "web", DiskName: "root", HostName: "run-host", VmCreatedAt: "2099-01-01T00:00:00Z"}}}}
	s.peerClientOverride = peers.client

	// This replica still has web's replaced incarnation; the run host shows
	// the new one.
	if _, err := s.resolveLUNHold(ctx, "tok"); err != nil || !held() {
		t.Fatalf("the replaced incarnation's rows released the hold (err %v)", err)
	}
	// The run host cannot be asked: kept, however often it is judged.
	peers.errs = map[string]error{"run-host": errors.New("dial: no route to host")}
	for i := 0; i < 3; i++ {
		_ = s.ResolveLUNHolds(ctx)
	}
	if !held() {
		t.Fatal("an unreachable run host released the hold")
	}
	// The run host shows nothing: released.
	peers.errs, peers.holders = nil, nil
	if released, err := s.resolveLUNHold(ctx, "tok"); err != nil || !released || held() {
		t.Fatalf("a run host showing nothing did not release the hold: released=%v err=%v", released, err)
	}

	// Again, and this time the new incarnation's rows arrive here.
	if err := s.putLUNHold(&lunHoldRecord{Token: "tok2", VM: "web", ReplacedCreatedAt: "replaced",
		LUNs: map[string]string{key: "root"}, RunHost: "run-host"}); err != nil {
		t.Fatal(err)
	}
	s.finishLUNHold("tok2")
	peers.holders = map[string][]*pb.LUNHolder{
		"run-host": {{Lun: key, VmName: "web", DiskName: "root", HostName: "run-host", VmCreatedAt: old}}}
	if released, err := s.resolveLUNHold(ctx, "tok2"); err != nil || !released {
		t.Fatalf("the new incarnation's rows here did not release the hold: released=%v err=%v", released, err)
	}

	// And a run host recorded removed releases it too.
	if err := s.putLUNHold(&lunHoldRecord{Token: "tok3", VM: "web", ReplacedCreatedAt: old,
		LUNs: map[string]string{key: "root"}, RunHost: "run-host"}); err != nil {
		t.Fatal(err)
	}
	s.finishLUNHold("tok3")
	peers.errs = map[string]error{"run-host": errors.New("dial: no such host")}
	if err := corrosion.DeleteHost(ctx, s.db, "run-host"); err != nil {
		t.Fatal(err)
	}
	if released, err := s.resolveLUNHold(ctx, "tok3"); err != nil || !released {
		t.Fatalf("a removed run host did not release the hold: released=%v err=%v", released, err)
	}
}

// I-2: a re-create in flight is never judged: its hold stays while the
// re-create runs, whatever its run host shows.
//
// Mutation: judge active holds too — the run host shows nothing before the
// create reaches it, and this goes red.
func TestLUNHold_IsNotJudgedWhileItsRecreateRuns(t *testing.T) {
	s := lunTestServer(t)
	key := mustLUNKey(t, "10.0.0.1", "0")
	if err := s.putLUNHold(&lunHoldRecord{Token: "tok", VM: "web", ReplacedCreatedAt: "x",
		LUNs: map[string]string{key: "root"}, RunHost: "run-host"}); err != nil {
		t.Fatal(err)
	}
	s.peerClientOverride = (&hostPeers{}).client
	if released, err := s.resolveLUNHold(adminCtx(), "tok"); err != nil || released {
		t.Fatalf("an active hold was released: %v %v", released, err)
	}
}

// I-2: a create that takes a LUN over from a moved claim does so only while
// the host that moved it still holds it — asked by name, or read here when
// that host is this one. A hold released meanwhile (its re-create given up,
// a racer since allowed) refuses the create before anything starts.
//
// Mutation: skip the check — the absent cases create the VM and this goes
// red.
func TestCreateVM_ISCSI_ATakeoverNeedsTheMovingHostsHold(t *testing.T) {
	for _, tc := range []struct {
		name     string
		holdHost string
		present  bool
		wantCode codes.Code
	}{
		{"held by a peer", "hold-host", true, codes.OK},
		{"released by a peer", "hold-host", false, codes.Aborted},
		{"held here", "test-host", true, codes.OK},
		{"released here", "test-host", false, codes.Aborted},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := lunTestServer(t)
			ctx := adminCtx()
			key := mustLUNKey(t, "10.0.0.1", "0")
			if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{Name: "hold-host", Address: "10.0.0.20", State: "active"}); err != nil {
				t.Fatal(err)
			}
			if tc.holdHost == "test-host" && tc.present {
				if err := s.putLUNHold(&lunHoldRecord{Token: "tok", VM: "a", ReplacedCreatedAt: "x",
					LUNs: map[string]string{key: "root"}, RunHost: "test-host"}); err != nil {
					t.Fatal(err)
				}
			}
			peers := &hostPeers{present: map[string]bool{"hold-host": tc.present}}
			s.peerClientOverride = peers.client
			cctx := context.WithValue(ctx, replacedVMKey{}, replacedVM{name: "a",
				snap: corrosion.VMDeleteSnapshot{CreatedAt: "x"}, claimed: map[string]string{key: "root"},
				holdToken: "tok", holdHost: tc.holdHost})
			if tc.holdHost == "test-host" {
				cctx = context.WithValue(cctx, lunHandoffKey{}, "tok")
			}
			_, err := s.CreateVM(cctx, lunVM("a", "lun0"))
			if status.Code(err) != tc.wantCode {
				t.Fatalf("got %v, want %v", err, tc.wantCode)
			}
			if tc.wantCode != codes.OK {
				requireNoVM(t, s, "a")
			}
		})
	}
}

// createCapture is a peer that records the replaced VM a forwarded create
// carries, and answers it.
type createCapture struct {
	pb.LiteVirtClient
	mu   sync.Mutex
	wire []string
}

func (c *createCapture) record(ctx context.Context) {
	md, _ := metadata.FromOutgoingContext(ctx)
	c.mu.Lock()
	c.wire = append(c.wire, md.Get(replacedVMMD)...)
	c.mu.Unlock()
}

// CleanupMigrationArtifacts is the delete's leftover sweep on the peer: nothing
// to sweep.
func (c *createCapture) CleanupMigrationArtifacts(context.Context, *pb.CleanupMigrationArtifactsRequest, ...grpc.CallOption) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}

func (c *createCapture) CreateVM(ctx context.Context, req *pb.CreateVMRequest, _ ...grpc.CallOption) (*pb.VM, error) {
	c.record(ctx)
	return &pb.VM{Name: req.GetSpec().GetName()}, nil
}

func (c *createCapture) ExecuteCreateVM(ctx context.Context, req *pb.ExecuteCreateVMRequest, _ ...grpc.CallOption) (*pb.VM, error) {
	c.record(ctx)
	return &pb.VM{Name: req.GetRequest().GetSpec().GetName()}, nil
}

// m-4: the inline (default) deploy update binds the VM it replaces from what
// its delete reported tombstoning — the owner's row — not from this host's
// copy, which may be behind it, exactly as a rolling recreate does.
//
// Mutation: bind this host's copy (round 3) — the create carries the older
// spec generation, and this goes red.
func TestRecreateInline_ISCSI_BindsTheRowItsDeleteReported(t *testing.T) {
	s := lunTestServer(t)
	ctx := adminCtx()
	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{
		Name: "peer-host", Address: "10.0.0.20", State: "active", CPUTotal: 8, MemTotal: 65536}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpsertStoragePool(ctx, s.db, corrosion.StoragePoolRecord{HostName: "peer-host", Name: "lun0",
		Driver: "iscsi", Source: lunTestTarget, Options: map[string]string{"portal": "10.0.0.1", "lun": "0"}, State: "active"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateVM(ctx, lunVM("web", "lun0")); err != nil {
		t.Fatalf("create: %v", err)
	}
	before := vmRecord(t, s, "web").SpecGeneration
	// Once the update has read its copy of web, the row moves on (as the
	// owner's would, ahead of this host's copy) before the delete runs.
	fake := s.virt.(*libvirtfake.Fake)
	var once sync.Once
	fake.FailListDomains = func() error {
		once.Do(func() {
			if _, _, err := corrosion.MutateDesiredSpec(context.Background(), s.db, "web", func(old string) (string, error) {
				var m map[string]any
				if err := json.Unmarshal([]byte(old), &m); err != nil {
					return "", err
				}
				m["labels"] = map[string]string{"moved-on": "yes"}
				b, err := json.Marshal(m)
				return string(b), err
			}); err != nil {
				t.Errorf("move web's spec on: %v", err)
			}
		})
		return nil
	}
	peer := &createCapture{}
	s.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) { return peer, func() {}, nil }
	spec := lunVM("web", "lun0").Spec
	spec.Placement.Host = "peer-host"
	a := planner.VMAction{Kind: planner.OpUpdate, VMName: "web", TargetHost: "peer-host", Spec: spec}
	f := &compose.File{Name: "st"}
	if err := s.recreateInline(ctx, a, f, newDependsOnGate(s, f, []planner.VMAction{a}, nil)); err != nil {
		t.Fatalf("inline recreate: %v", err)
	}
	if len(peer.wire) != 1 {
		t.Fatalf("the forwarded create carried %d replaced VMs, want 1", len(peer.wire))
	}
	var w replacedVMWire
	if err := json.Unmarshal([]byte(peer.wire[0]), &w); err != nil {
		t.Fatal(err)
	}
	if w.SpecGeneration != before+1 {
		t.Fatalf("the create carried spec generation %d, want %d — the row the delete tombstoned", w.SpecGeneration, before+1)
	}
}
