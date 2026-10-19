package fleet

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// The harness pieces the live firmware move scenarios stand on (spec §15,
// "Fake prerequisites"): a node that answers an RPC as an older build does,
// a migration that lands on another node's fake and store as libvirt did in
// the probes, and each node's store reaching its fake and its reconcilers.

// n.RefuseRPCs answers each named RPC exactly as a build without it: the code
// and the text grpc itself gives a method the server does not have, before
// the handler (or auth) runs. Restoring serves it again.
//
// Mutations: let the interceptor ignore the refused set — red; answer with
// another code or text — red; run the handler before refusing — red.
func TestFleet_RefuseRPCsAnswersUnimplemented(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	t.Cleanup(c.Stop)
	n := c.Nodes[1]
	ctx := context.Background()
	cl := c.SelfClient(n)

	// What a server says of a method it does not have.
	const absent = "NoSuchMethodInAnyBuild"
	err := n.selfConn.Invoke(ctx, "/"+pb.LiteVirt_ServiceDesc.ServiceName+"/"+absent, &pb.PingRequest{}, &pb.PingResponse{})
	real := status.Convert(err)
	if real.Code() != codes.Unimplemented || !strings.Contains(real.Message(), absent) {
		t.Fatalf("fixture: an absent method answered %v", err)
	}

	restore := n.RefuseRPCs("Ping", "ListVMs")
	ran := 0
	n.HookUnary("Ping", func(ctx context.Context, req any, h grpc.UnaryHandler) (any, error) {
		ran++
		return h(ctx, req)
	})
	for _, call := range []struct {
		method string
		do     func() error
	}{
		{"Ping", func() error { _, err := cl.Ping(ctx, &pb.PingRequest{}); return err }},
		{"ListVMs", func() error { _, err := cl.ListVMs(ctx, &pb.ListVMsRequest{}); return err }},
	} {
		st := status.Convert(call.do())
		want := strings.Replace(real.Message(), absent, call.method, 1)
		if st.Code() != codes.Unimplemented || st.Message() != want {
			t.Errorf("%s refused with %v %q, want %v %q", call.method, st.Code(), st.Message(), codes.Unimplemented, want)
		}
	}
	if ran != 0 {
		t.Errorf("the refused Ping reached its handler %d times", ran)
	}
	// Only the named RPCs are refused.
	if _, err := cl.ListHosts(ctx, &pb.ListHostsRequest{}); err != nil {
		t.Errorf("ListHosts, not refused, failed: %v", err)
	}

	restore()
	if _, err := cl.Ping(ctx, &pb.PingRequest{}); err != nil {
		t.Fatalf("Ping after restore: %v", err)
	}
	if ran != 1 {
		t.Errorf("Ping after restore ran its handler %d times, want once", ran)
	}
}

const (
	hlVM   = "fwharness"
	hlUUID = "5d3c2b1a-9e8f-4a7b-8c6d-1e2f3a4b5c6d"
	hlXML  = "<domain type='kvm'><name>" + hlVM + "</name><uuid>" + hlUUID + "</uuid>" +
		"<os><nvram>/var/lib/litevirt/nvram/" + hlVM + "_VARS.fd</nvram></os><devices></devices></domain>"
)

func hlPermall(fw *lv.FirmwareStore) string {
	return filepath.Join(fw.SwtpmDir(hlUUID), "tpm2", "tpm2-00.permall")
}

func hlWrite(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func hlRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return b
}

// src.LandMigrationsOn(dst) lands a FirmwareLive migrate on dst's fake and
// store as the probes saw libvirt do it: the source shut off with reason
// migrated and its state intact, the target paused with the permall in ITS
// store, and the source's NVRAM written there only when the guest resumes.
// An ordinary migrate lands running, or paused when asked.
//
// Mutations: land on the source's own store — red; land running — red; skip
// the firmware model in the hook — red.
func TestFleet_FirmwareLiveLandsOnTarget(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	t.Cleanup(c.Stop)
	src, dst := c.Nodes[0], c.Nodes[1]
	src.LandMigrationsOn(dst)

	if err := src.Virt.DefineDomain(hlXML); err != nil {
		t.Fatal(err)
	}
	if err := src.Virt.StartDomain(hlVM); err != nil {
		t.Fatal(err)
	}
	permall, nvram := []byte("the source's permall"), []byte("the source's final vars")
	hlWrite(t, hlPermall(src.FW), permall)
	hlWrite(t, src.FW.NvramPath(hlVM), nvram)

	p := lv.MigrateParams{Live: true, FirmwareLive: true, WithStorage: true, TLS: true,
		TargetAddress: dst.Address, TLSDestination: dst.Address}
	if err := src.Virt.MigrateToTarget(hlVM, "qemu+tls://"+dst.Address+"/system", p); err != nil {
		t.Fatal(err)
	}
	if st, ok := src.Virt.RawState(hlVM); !ok || st != libvirtfake.StateShutdown {
		t.Errorf("source = %q (defined %v), want defined and shut off", st, ok)
	}
	if ds, _ := src.Virt.DomainStateReason(hlVM); ds.Reason != "migrated" {
		t.Errorf("source reason = %q, want migrated", ds.Reason)
	}
	if !bytes.Equal(hlRead(t, hlPermall(src.FW)), permall) || !bytes.Equal(hlRead(t, src.FW.NvramPath(hlVM)), nvram) {
		t.Error("the source's state changed")
	}
	if st, ok := dst.Virt.RawState(hlVM); !ok || st != libvirtfake.StatePaused {
		t.Fatalf("target = %q (defined %v), want defined and paused", st, ok)
	}
	if got := hlRead(t, hlPermall(dst.FW)); !bytes.Equal(got, permall) {
		t.Errorf("target permall = %q, want the source's", got)
	}
	if got := hlRead(t, dst.FW.NvramPath(hlVM)); !bytes.Equal(got, libvirtfake.TemplateNVRAM) {
		t.Errorf("target nvram while paused = %q, want the template", got)
	}
	if err := dst.Virt.ResumeDomain(hlVM); err != nil {
		t.Fatal(err)
	}
	if got := hlRead(t, dst.FW.NvramPath(hlVM)); !bytes.Equal(got, nvram) {
		t.Errorf("target nvram after resume = %q, want the source's", got)
	}

	// An ordinary migrate of another guest.
	const plain = "plainvm"
	if err := src.Virt.DefineDomain(libvirtfake.StoppedDomainXML(plain, libvirtfake.DomainUUIDFor(plain), "52:54:00:00:00:01")); err != nil {
		t.Fatal(err)
	}
	if err := src.Virt.StartDomain(plain); err != nil {
		t.Fatal(err)
	}
	for _, paused := range []bool{false, true} {
		if paused {
			_ = dst.Virt.DestroyDomain(plain)
			_ = dst.Virt.UndefineDomain(plain, false)
		}
		if err := src.Virt.MigrateToTarget(plain, "qemu+tls://"+dst.Address+"/system", lv.MigrateParams{Live: true, Paused: paused}); err != nil {
			t.Fatal(err)
		}
		want := libvirtfake.StateRunning
		if paused {
			want = libvirtfake.StatePaused
		}
		if st, _ := dst.Virt.RawState(plain); st != want {
			t.Errorf("ordinary migrate (paused=%v) landed %q, want %q", paused, st, want)
		}
	}
}

// Each node's store reaches its fake, so probe (g) acts on that node's files,
// and the harness's reconciler helper hands a reconciler the same store.
//
// Mutations: drop n.Virt.SetFirmwareStore from buildServer — red; build the
// reconciler without n.FW — red.
func TestFleet_NodeFirmwareStoreReachesFakeAndReconciler(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	t.Cleanup(c.Stop)
	for _, n := range c.Nodes {
		if got := n.Virt.FirmwareStore(); got != n.FW {
			t.Errorf("%s's fake holds store %+v, not the node's", n.Name, got)
		}
		if got := n.Reconciler().FirmwareStore(); got != n.FW {
			t.Errorf("%s's reconciler holds store %+v, not the node's", n.Name, got)
		}
	}
	a, b := c.Nodes[0], c.Nodes[1]
	if err := a.Virt.DefineDomain(hlXML); err != nil {
		t.Fatal(err)
	}
	for _, n := range []*Node{a, b} {
		hlWrite(t, hlPermall(n.FW), []byte(n.Name+" permall"))
		hlWrite(t, n.FW.NvramPath(hlVM), []byte(n.Name+" vars"))
	}
	if err := a.Virt.UndefineDomain(hlVM, false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(a.FW.NvramPath(hlVM)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("%s's NVRAM after UndefineDomain: %v, want deleted (probe (g))", a.Name, err)
	}
	if got := hlRead(t, hlPermall(a.FW)); string(got) != a.Name+" permall" {
		t.Errorf("%s's permall = %q, want kept (probe (g))", a.Name, got)
	}
	if got := hlRead(t, b.FW.NvramPath(hlVM)); string(got) != b.Name+" vars" {
		t.Errorf("%s's undefine touched %s's NVRAM: %q", a.Name, b.Name, got)
	}
}
