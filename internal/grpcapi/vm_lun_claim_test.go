package grpcapi

import (
	"context"
	"errors"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/storage"
)

const lunTestTarget = "iqn.2020-01.com.example:store"

// lunTestServer is a server on test-host with three iscsi pools: lun0 and
// lun0b are the SAME LUN spelled two ways, lun1 is another LUN of the target.
// iscsiadm is a no-op.
func lunTestServer(t *testing.T) *Server {
	t.Helper()
	t.Cleanup(storage.OverrideISCSICommandForTest(func(context.Context, string, ...string) ([]byte, error) {
		return nil, nil
	}))
	s := testServerR2(t)
	s.virt = libvirtfake.New()
	ctx := adminCtx()
	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{
		Name: "test-host", Address: "10.0.0.9", State: "active", CPUTotal: 8, MemTotal: 65536,
	}); err != nil {
		t.Fatalf("InsertHost: %v", err)
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
	_, release, _, _ := s.lunClaims.take("racer", []lunUse{{key: mustLUNKey(t, "10.0.0.1", "0"), disk: "root"}})
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
	holders []*pb.LUNHolder
	err     error
	asked   *pb.LUNHoldersRequest
}

func (p *lunPeer) LUNHolders(_ context.Context, req *pb.LUNHoldersRequest, _ ...grpc.CallOption) (*pb.LUNHoldersResponse, error) {
	p.asked = req
	if p.err != nil {
		return nil, p.err
	}
	return &pb.LUNHoldersResponse{Holders: p.holders}, nil
}

// What another host holds — in its replica or in a create of its own in
// flight — refuses the create; this host's replica need not know of it.
//
// Mutation: skip lunHoldersOnPeers in claimLUNs — the create is admitted
// and the holder cases go red.
func TestCreateVM_ISCSI_APeersHolderRefuses(t *testing.T) {
	key := func(t *testing.T) string { return mustLUNKey(t, "10.0.0.1", "0") }
	for _, tc := range []struct {
		name     string
		state    string
		peer     func(t *testing.T) *lunPeer
		wantCode codes.Code
		wantText string
	}{
		{"committed elsewhere", "active", func(t *testing.T) *lunPeer {
			return &lunPeer{holders: []*pb.LUNHolder{{Lun: key(t), VmName: "far", DiskName: "root", HostName: "peer-host"}}}
		}, codes.FailedPrecondition, `VM "far"`},
		{"in flight elsewhere", "active", func(t *testing.T) *lunPeer {
			return &lunPeer{holders: []*pb.LUNHolder{{Lun: key(t), VmName: "racer", DiskName: "root", HostName: "peer-host", InFlight: true}}}
		}, codes.Aborted, `VM "racer"`},
		{"an answer never adds a LUN", "active", func(t *testing.T) *lunPeer {
			return &lunPeer{holders: []*pb.LUNHolder{{Lun: "iscsi:other", VmName: "far", DiskName: "root"}}}
		}, codes.OK, ""},
		{"an active peer that cannot be asked", "active", func(t *testing.T) *lunPeer {
			return &lunPeer{err: status.Error(codes.Unavailable, "connection refused")}
		}, codes.Unavailable, "peer-host"},
		{"an older build", "active", func(t *testing.T) *lunPeer {
			return &lunPeer{err: status.Error(codes.Unimplemented, "unknown method LUNHolders")}
		}, codes.OK, ""},
		{"a peer marked offline", "offline", func(t *testing.T) *lunPeer {
			return &lunPeer{err: errors.New("dial: no route to host")}
		}, codes.OK, ""},
		{"a peer in maintenance", "maintenance", func(t *testing.T) *lunPeer {
			return &lunPeer{err: errors.New("dial: no route to host")}
		}, codes.OK, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := lunTestServer(t)
			ctx := adminCtx()
			if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{
				Name: "peer-host", Address: "10.0.0.10", State: tc.state, CPUTotal: 8, MemTotal: 65536,
			}); err != nil {
				t.Fatalf("InsertHost: %v", err)
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
			if tc.state == "active" {
				if peer.asked == nil || peer.asked.VmName != "b" || len(peer.asked.Luns) != 1 || peer.asked.Luns[0] != key(t) {
					t.Errorf("peer asked %+v, want VM b and the one LUN", peer.asked)
				}
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
// except the asking VM's own rows (the incarnation a recreate replaces) — and
// only for peers.
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
	_, release, _, _ := s.lunClaims.take("racer", []lunUse{{key: k1, disk: "data"}})
	defer release()

	if _, err := s.LUNHolders(ctx, &pb.LUNHoldersRequest{Luns: []string{k0}}); status.Code(err) != codes.PermissionDenied &&
		status.Code(err) != codes.Unauthenticated {
		t.Fatalf("LUNHolders from a non-peer: got %v, want a refusal", err)
	}
	pctx := peerCtxFor(t, s, "peer-host")
	resp, err := s.LUNHolders(pctx, &pb.LUNHoldersRequest{Luns: []string{k0, k1}, VmName: "b"})
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
	// The asking VM's own rows hold nothing against it.
	resp, err = s.LUNHolders(pctx, &pb.LUNHoldersRequest{Luns: []string{k0}, VmName: "a"})
	if err != nil {
		t.Fatalf("LUNHolders: %v", err)
	}
	if len(resp.Holders) != 0 {
		t.Errorf("VM a's own disk reported against it: %v", resp.Holders)
	}
}
