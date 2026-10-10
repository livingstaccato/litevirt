package grpcapi

import (
	"context"
	"errors"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// r4Networks seeds the networks the R3-I1 cases need: ctnet (global, the
// caller's), vnet (project victim's, rendered as br-victim) and a direct
// network, which create refuses for containers.
func r4Networks(t *testing.T, s *Server) {
	t.Helper()
	ctx := context.Background()
	for _, n := range []corrosion.NetworkRecord{
		{Name: "ctnet", Type: "bridge", Config: `{"type":"bridge","interface":"br-ctnet"}`},
		{Name: "vnet", Type: "bridge", Project: "victim", Config: `{"type":"bridge","interface":"br-victim"}`},
		{Name: "mvt", Type: "direct", Config: `{"type":"direct","interface":"eno1"}`},
	} {
		if err := corrosion.UpsertNetwork(ctx, s.db, n); err != nil {
			t.Fatal(err)
		}
	}
}

func nicNames(ns []corrosion.ContainerNetwork) []string {
	var out []string
	for _, n := range ns {
		out = append(out, n.Name+"@"+n.Bridge)
	}
	return out
}

// R3-I1. Admission runs on the AUTHORIZED NICs, after a raw bridge has been
// reclassified as the managed network it renders: (a) a managed NIC naming a
// network with no record is dropped, never rendered on a bridge of that name;
// (b) a raw NIC naming another project's rendered bridge is that project's
// NIC and is refused like one; a direct/sriov network is refused as create
// refuses it. Each is dropped and said, and the restore proceeds.
func TestAuthorizeRestoredNICs_AdmitsTheAuthorizedNICs(t *testing.T) {
	s := testServer(t)
	r4Networks(t, s)
	forged := corrosion.ContainerCreateSpec{Template: "download", Networks: []corrosion.ContainerNetwork{
		{Name: "eth0", NetworkName: "ctnet"},
		{Name: "eth1", NetworkName: "br-mgmt"}, // (a) no such network
		{Name: "eth2", Bridge: "br-victim"},    // (b) project victim's bridge
		{Name: "eth3", NetworkName: "mvt"},     // direct: never a container's
	}}
	for _, tc := range []struct {
		who string
		ctx context.Context
	}{{"scoped operator", projectBoundCtx(t, s, "carol", "acme")}, {"admin", adminCtx()}} {
		out, dropped, err := s.authorizeRestoredNICs(tc.ctx, "acme", forged, nil, false)
		if err != nil {
			t.Fatalf("%s: %v", tc.who, err)
		}
		if got := nicNames(out.Networks); len(got) != 1 || got[0] != "eth0@br-ctnet" {
			t.Errorf("%s's restore NICs = %v; want only eth0@br-ctnet", tc.who, got)
		}
		said := strings.Join(dropped, "; ")
		for _, want := range []string{"eth1", "br-mgmt", "eth2", "vnet", "eth3", "mvt"} {
			if !strings.Contains(said, want) {
				t.Errorf("%s: the drop of %q was not said: %s", tc.who, want, said)
			}
		}
	}
	// A restore INTO project victim keeps its own network's NIC.
	out, _, err := s.authorizeRestoredNICs(adminCtx(), "victim", forged, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if got := nicNames(out.Networks); len(got) != 2 || got[1] != "eth2@br-victim" {
		t.Errorf("a restore into victim NICs = %v; want eth0 and eth2@br-victim", got)
	}
}

// R3-I1 on a peer move: a raw bridge that resolves to a managed network is
// kept only when the source row records that NIC, and a NIC whose network
// has no record is dropped there too (never the flat-bridge fallback).
func TestAuthorizeRestoredNICs_PeerMoveReclassified(t *testing.T) {
	s := testServer(t)
	r4Networks(t, s)
	forged := corrosion.ContainerCreateSpec{Template: "download", Networks: []corrosion.ContainerNetwork{
		{Name: "eth0", NetworkName: "ctnet"},
		{Name: "eth1", NetworkName: "gone"},
		{Name: "eth2", Bridge: "br-victim"},
	}}
	out, dropped, err := s.authorizeRestoredNICs(adminCtx(), "acme", forged, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if got := nicNames(out.Networks); len(got) != 1 || got[0] != "eth0@br-ctnet" {
		t.Errorf("a peer move with no source row kept NICs %v; want only eth0@br-ctnet (dropped: %v)", got, dropped)
	}
	src := &corrosion.ContainerRecord{CreateSpec: corrosion.EncodeCreateSpec(corrosion.ContainerCreateSpec{Template: "download",
		Networks: []corrosion.ContainerNetwork{{Name: "eth0", NetworkName: "ctnet"}, {Name: "eth2", NetworkName: "vnet", Bridge: "br-victim"}}})}
	out, _, err = s.authorizeRestoredNICs(adminCtx(), "acme", forged, src, true)
	if err != nil {
		t.Fatal(err)
	}
	if got := nicNames(out.Networks); len(got) != 2 || got[1] != "eth2@br-victim" {
		t.Errorf("a peer move dropped the NIC its source row records: %v", got)
	}
}

// R3-m5. A source whose security cannot be read is not cloned: whether it is
// mid-conversion is unknown, so the refusal says so instead of cloning.
func TestCloneContainer_SecurityReadErrorFailsClosed(t *testing.T) {
	s, rt := secServer(t)
	seedSecCT(t, s, rt, "src", "stopped", corrosion.ContainerCreateSpec{Template: "download"})
	rt.securityErr = map[string]error{"src": errors.New("config unreadable")}
	_, err := s.CloneContainer(adminCtx(), &pb.CloneContainerRequest{Source: "src", Target: "c2", HostName: "host-a"})
	if status.Code(err) != codes.Unavailable || !strings.Contains(err.Error(), "config unreadable") {
		t.Fatalf("clone of a source whose security is unreadable = %v; want Unavailable naming the error", err)
	}
	if len(rt.cloneCalls) != 0 {
		t.Fatalf("the refused clone copied the source: %+v", rt.cloneCalls)
	}
}

// R3-I1. A network record that cannot be read fails the restore (Unavailable,
// retried) rather than reading as "no such network" and dropping the NIC.
func TestAuthorizeRestoredNICs_UnreadableNetworkFailsClosed(t *testing.T) {
	s := testServer(t)
	r4Networks(t, s)
	_ = s.db.Close()
	cs := corrosion.ContainerCreateSpec{Template: "download", Networks: []corrosion.ContainerNetwork{{Name: "eth0", NetworkName: "ctnet"}}}
	if _, dropped, err := s.authorizeRestoredNICs(adminCtx(), "acme", cs, nil, false); status.Code(err) != codes.Unavailable {
		t.Fatalf("an unreadable network record = %v (dropped %v); want Unavailable", err, dropped)
	}
}
