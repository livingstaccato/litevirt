package grpcapi

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// A re-create with an installer ISO is placed before the teardown, judged by
// the host placement chose, and forwarded there carrying the VM's own ISO
// grant (vm_recreate_preflight.go). The multi-host behaviour is pinned by the
// fleet scenarios (tests/fleet/iso_recreate_placement_test.go); these pin the
// pieces a single process can reach: who may hand a grant over, who may ask
// for a judgement, and what placement counts.

// grantMD is the incoming metadata a peer re-creating a VM with installer ISO
// iso hands the host it forwards to.
func grantMD(ctx context.Context, iso, scope string) context.Context {
	b, _ := json.Marshal(recreateISOGrantWire{ISO: iso, Scope: scope})
	return metadata.NewIncomingContext(ctx, metadata.Pairs(recreateISOGrantMD, string(b)))
}

// promotedOperator is what the auth interceptor hands a handler for a peer
// call relaying an Operator's bearer under forwarded identity: the Operator,
// on the peer transport.
func promotedOperator(t *testing.T, s *Server, peer string) context.Context {
	t.Helper()
	_ = peerCtxFor(t, s, peer) // the peer is a known host
	ctx := context.WithValue(userCtx("op", "operator"), ctxKeyAuthMethod, authMethodToken)
	ctx = context.WithValue(ctx, ctxKeyMTLSCommonName, peer)
	return context.WithValue(ctx, ctxKeyPrincipalKind, principalKindPeer)
}

// The grant crosses a forward only from a peer host. An Operator's own call
// naming a host path, with the grant's metadata attached by hand, is refused
// as it would be without it; the same create forwarded by a peer for the
// relayed Operator is admitted with it, and refused without it.
//
// Mutation: drop the peer check in acceptRecreateISOGrantMD — the first leg
// goes red.
func TestRecreateGrant_OnlyAPeerHostHandsOneOver(t *testing.T) {
	s, _, _ := isoServer(t)
	iso := filepath.Join(t.TempDir(), "win.iso")
	writeLibFile(t, iso, opticalImage("win"))

	if _, err := s.CreateVM(grantMD(userCtx("op", "operator"), iso, isoScopeHostPath), isoCreate("by-hand", iso, "")); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("an Operator's own create naming a host path, with a grant in its metadata: got %v, want PermissionDenied", err)
	}
	peer := promotedOperator(t, s, "host-b")
	if _, err := s.CreateVM(peer, isoCreate("no-grant", iso, "")); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("a forwarded create for an Operator, no grant: got %v, want PermissionDenied", err)
	}
	if _, err := s.CreateVM(grantMD(peer, iso, isoScopeHostPath), isoCreate("re-created", iso, "")); err != nil {
		t.Fatalf("a forwarded re-create for an Operator, with the VM's grant: %v", err)
	}
	if spec := vmSpecFor(vmRecord(t, s, "re-created")); spec.GetIso() != iso || spec.GetIsoScope() != isoScopeHostPath {
		t.Fatalf("the re-created VM's ISO = %q (%q), want %q (%s)", spec.GetIso(), spec.GetIsoScope(), iso, isoScopeHostPath)
	}
}

// A grant is for one ISO: a peer's grant for another file admits nothing.
func TestRecreateGrant_IsForItsOwnISOOnly(t *testing.T) {
	s, _, _ := isoServer(t)
	dir := t.TempDir()
	iso, other := filepath.Join(dir, "win.iso"), filepath.Join(dir, "other.iso")
	writeLibFile(t, iso, opticalImage("win"))
	writeLibFile(t, other, opticalImage("other"))
	peer := grantMD(promotedOperator(t, s, "host-b"), iso, isoScopeHostPath)
	if _, err := s.CreateVM(peer, isoCreate("other", other, "")); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("a forwarded create naming another file than the grant's: got %v, want PermissionDenied", err)
	}
}

// Only a peer host asks for a re-create's judgement — not even an Admin's
// own call, whose spec would pass.
//
// Mutation: drop the peer check in PreflightRecreateVM — red.
func TestPreflightRecreateVM_IsPeerOnly(t *testing.T) {
	s, _, _ := isoServer(t)
	if _, err := s.PreflightRecreateVM(adminCtx(), &pb.PreflightRecreateVMRequest{
		Spec: &pb.VMSpec{Name: "x", Cpu: 1, MemoryMib: 256},
	}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("PreflightRecreateVM from a user: got %v, want PermissionDenied", err)
	}
}

// The chosen host's judgement is the create's: for a relayed Operator it
// refuses a host path without the grant and admits it with one, and it
// refuses a file this host does not have.
func TestPreflightRecreateVM_JudgesAsTheCreate(t *testing.T) {
	s, _, _ := isoServer(t)
	iso := filepath.Join(t.TempDir(), "win.iso")
	writeLibFile(t, iso, opticalImage("win"))
	peer := promotedOperator(t, s, "host-b")
	spec := &pb.VMSpec{Name: "web", Cpu: 1, MemoryMib: 256, Iso: iso, IsoScope: isoScopeHostPath}
	if _, err := s.PreflightRecreateVM(peer, &pb.PreflightRecreateVMRequest{Spec: spec}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("judgement for a relayed Operator, no grant: got %v, want PermissionDenied", err)
	}
	if _, err := s.PreflightRecreateVM(grantMD(peer, iso, isoScopeHostPath), &pb.PreflightRecreateVMRequest{Spec: spec}); err != nil {
		t.Fatalf("judgement for a relayed Operator with the VM's grant: %v", err)
	}
	missing := filepath.Join(t.TempDir(), "gone.iso")
	spec.Iso = missing
	if _, err := s.PreflightRecreateVM(grantMD(peer, missing, isoScopeHostPath), &pb.PreflightRecreateVMRequest{Spec: spec}); err == nil {
		t.Fatal("judgement of an ISO this host does not have: admitted")
	}
}

// placeRecreate counts the VM it re-creates as gone: a running VM filling its
// host is placed back on it, and a spec naming itself in its anti-affinity
// is not kept off its own host by itself.
//
// Mutations: drop Replaces — the first leg goes red; keep the VM in its own
// anti-affinity — the second.
func TestPlaceRecreate_TheVMItReplacesHoldsNothing(t *testing.T) {
	s, _, _ := isoServer(t)
	ctx := context.Background()
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "web", HostName: s.hostName, State: "running", CPUActual: 3, MemActual: 512,
	}, nil, nil); err != nil {
		t.Fatal(err)
	}
	// 1 core x 4 overcommit - 1 reserved = 3 vCPU: one 3-vCPU VM fits, two do not.
	if err := s.db.Execute(ctx, `UPDATE hosts SET cpu_total = 1 WHERE name = ?`, s.hostName); err != nil {
		t.Fatal(err)
	}
	cur := vmRecord(t, s, "web")
	spec := &pb.VMSpec{Name: "web", Cpu: 3, MemoryMib: 512, Iso: "/srv/x.iso"}
	if host, err := s.placeRecreate(ctx, spec, cur); err != nil || host != s.hostName {
		t.Fatalf("placing a running VM that fills its host: %q, %v; want %s", host, err, s.hostName)
	}
	spec.Cpu = 1
	spec.Placement = &pb.PlacementSpec{AntiAffinity: []string{"web"}}
	if host, err := s.placeRecreate(ctx, spec, cur); err != nil || host != s.hostName {
		t.Fatalf("placing a VM whose anti-affinity names itself: %q, %v; want %s", host, err, s.hostName)
	}
}

// peerHost is another host as a forward reaches it: a real Server sharing the
// entry's database, whose handlers see what its auth interceptor would hand
// them for a peer call relaying an Operator's bearer under forwarded identity
// — the Operator, on the peer transport — and the metadata the entry sent.
type peerHost struct {
	pb.LiteVirtClient
	s                   *Server
	caller              context.Context
	preflights, creates int
}

func (p *peerHost) in(ctx context.Context) context.Context {
	md, _ := metadata.FromOutgoingContext(ctx)
	return metadata.NewIncomingContext(p.caller, md)
}

func (p *peerHost) PreflightRecreateVM(ctx context.Context, in *pb.PreflightRecreateVMRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	p.preflights++
	return p.s.PreflightRecreateVM(p.in(ctx), in)
}

func (p *peerHost) CreateVM(ctx context.Context, in *pb.CreateVMRequest, _ ...grpc.CallOption) (*pb.VM, error) {
	p.creates++
	return p.s.CreateVM(p.in(ctx), in)
}

// CleanupMigrationArtifacts answers a delete's leftover sweep: nothing there.
func (p *peerHost) CleanupMigrationArtifacts(context.Context, *pb.CleanupMigrationArtifactsRequest, ...grpc.CallOption) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}

func (p *peerHost) ExecuteCreateVM(ctx context.Context, in *pb.ExecuteCreateVMRequest, _ ...grpc.CallOption) (*pb.VM, error) {
	p.creates++
	return p.s.ExecuteCreateVM(p.in(ctx), in)
}

// forwardedIdentityPair is an Operator's legacy host-path ISO VM "old" (made
// on main: no iso_scope, no pin) on this host, which is in maintenance, so
// placement puts its re-create on host-b — a second host that judges the
// relayed Operator, as auth.forwarded_identity has it.
func forwardedIdentityPair(t *testing.T) (*Server, *peerHost, context.Context, string) {
	t.Helper()
	s, fake, _ := isoServer(t)
	iso := filepath.Join(t.TempDir(), "win.iso")
	writeLibFile(t, iso, opticalImage("win"))
	legacyVM(t, s, fake, "old", iso)
	ctx := context.Background()
	spec := vmSpecFor(vmRecord(t, s, "old"))
	spec.Placement = nil
	b, _ := json.Marshal(spec)
	if err := s.db.Execute(ctx, `UPDATE vms SET spec = ? WHERE name = ?`, string(b), "old"); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{
		Name: "host-b", Address: "10.0.0.2", State: "active", CPUTotal: 8, MemTotal: 16384,
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.db.Execute(ctx, `UPDATE hosts SET state = 'maintenance' WHERE name = ?`, s.hostName); err != nil {
		t.Fatal(err)
	}
	b2, _, _ := isoServer(t)
	b2.db, b2.hostName = s.db, "host-b"
	caller := context.WithValue(userCtx("op", "operator"), ctxKeyAuthMethod, authMethodToken)
	caller = context.WithValue(caller, ctxKeyMTLSCommonName, s.hostName)
	caller = context.WithValue(caller, ctxKeyPrincipalKind, principalKindPeer)
	peer := &peerHost{s: b2, caller: caller}
	s.peerClientOverride = func(_ context.Context, host string) (pb.LiteVirtClient, func(), error) {
		if host != "host-b" {
			return nil, nil, status.Errorf(codes.Unavailable, "no host %s", host)
		}
		return peer, func() {}, nil
	}
	return s, peer, userCtx("op", "operator"), iso
}

// C-C with auth.forwarded_identity on: an Operator's rebuild and rolling
// recreate of a main-era host-path ISO VM, placed on another host, are judged
// there as the Operator holding the VM's own ISO grant, and the VM is
// re-created there with that ISO — as on main, which had no ISO gate.
//
// Mutations: drop the grant from the forwarded create — the VM is torn down
// and refused there, and is gone; drop it from the judgement — the rebuild is
// refused before the teardown.
func TestRecreateGrant_CrossesTheForwardUnderForwardedIdentity(t *testing.T) {
	for _, via := range []string{"rebuild", "recreate"} {
		t.Run(via, func(t *testing.T) {
			s, peer, op, iso := forwardedIdentityPair(t)
			var err error
			if via == "rebuild" {
				_, err = s.RebuildVM(op, &pb.RebuildVMRequest{Name: "old"})
			} else {
				err = (&serverOps{s: s}).RecreateVM(op, "old", vmSpecFor(vmRecord(t, s, "old")))
			}
			rec := vmExists(t, s, "old", "after the "+via)
			if err != nil {
				t.Fatalf("an Operator's %s onto another host under forwarded identity: %v", via, err)
			}
			spec := vmSpecFor(rec)
			if rec.HostName != "host-b" || peer.preflights != 1 || peer.creates != 1 {
				t.Fatalf("after the %s: host %s, host-b judged %d and created %d time(s); want host-b, once each",
					via, rec.HostName, peer.preflights, peer.creates)
			}
			if spec.GetIso() != iso || spec.GetIsoScope() != "" {
				t.Fatalf("the re-created VM's ISO = %q (%q), want %q as it was (legacy)", spec.GetIso(), spec.GetIsoScope(), iso)
			}
		})
	}
}
