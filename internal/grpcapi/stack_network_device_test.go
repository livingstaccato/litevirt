package grpcapi

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
)

func seedStackNetworkRow(t *testing.T, s *Server, stack, short string, def compose.NetworkDef) {
	t.Helper()
	cfg, err := json.Marshal(def)
	if err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpsertNetwork(context.Background(), s.db, corrosion.NetworkRecord{
		Name: compose.ScopedNetworkName(stack, short), StackName: stack, Type: "bridge", Config: string(cfg),
	}); err != nil {
		t.Fatal(err)
	}
}

func backendFile(stack string, nd compose.NetworkDef) *compose.File {
	return &compose.File{Name: stack, Networks: map[string]compose.NetworkDef{"backend": nd}}
}

// A stack network with no interface and no row gets its scoped name; two
// stacks with the same short name therefore get different devices.
//
// Mutation: default to the short name (compose.DefaultNetworkInterfaces) — red.
func TestDefaultStackNetworkDevices_NewNetworkGetsItsScopedName(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	sa, sb := backendFile("sa", compose.NetworkDef{Type: "bridge"}), backendFile("sb", compose.NetworkDef{Type: "bridge"})
	for _, f := range []*compose.File{sa, sb} {
		if w, err := s.defaultStackNetworkDevices(ctx, f); err != nil || len(w) != 0 {
			t.Fatalf("%s: warnings=%v err=%v", f.Name, w, err)
		}
	}
	if got := sa.Networks["backend"].Interface; got != "sa_backend" {
		t.Errorf("sa backend on %q, want sa_backend", got)
	}
	if got := sb.Networks["backend"].Interface; got != "sb_backend" {
		t.Errorf("sb backend on %q, want sb_backend", got)
	}
}

// A network whose row already names a device keeps it on a redeploy: the
// default never moves a deployed network. A row with no interface (a legacy
// peer write) records no device and gets the scoped default.
//
// Mutation: do not pass the recorded devices to DefaultNetworkInterfaces — red.
func TestDefaultStackNetworkDevices_RecordedDeviceKept(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	seedStackNetworkRow(t, s, "sa", "backend", compose.NetworkDef{Type: "bridge", Interface: "backend", Subnet: "10.1.0.0/24"})
	seedStackNetworkRow(t, s, "sc", "backend", compose.NetworkDef{Type: "bridge", Subnet: "10.3.0.0/24"})
	sa := backendFile("sa", compose.NetworkDef{Type: "bridge", Subnet: "10.1.0.0/24"})
	if _, err := s.defaultStackNetworkDevices(ctx, sa); err != nil {
		t.Fatal(err)
	}
	if got := sa.Networks["backend"].Interface; got != "backend" {
		t.Errorf("deployed sa backend moved to %q, want its recorded backend", got)
	}
	sc := backendFile("sc", compose.NetworkDef{Type: "bridge", Subnet: "10.3.0.0/24"})
	if _, err := s.defaultStackNetworkDevices(ctx, sc); err != nil {
		t.Fatal(err)
	}
	if got := sc.Networks["backend"].Interface; got != "sc_backend" {
		t.Errorf("sc backend (row with no interface) on %q, want sc_backend", got)
	}
}

// An explicit interface in the file is honoured, whatever the row records.
func TestDefaultStackNetworkDevices_ExplicitInterfaceHonoured(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	seedStackNetworkRow(t, s, "sa", "backend", compose.NetworkDef{Type: "bridge", Interface: "backend"})
	seedStackNetworkRow(t, s, "sb", "backend", compose.NetworkDef{Type: "bridge", Interface: "backend"})
	sa := backendFile("sa", compose.NetworkDef{Type: "bridge", Interface: "br7"})
	w, err := s.defaultStackNetworkDevices(ctx, sa)
	if err != nil {
		t.Fatal(err)
	}
	if got := sa.Networks["backend"].Interface; got != "br7" {
		t.Errorf("explicit interface became %q, want br7", got)
	}
	if len(w) != 0 {
		t.Errorf("an explicit interface warned about sharing: %v", w)
	}
}

// A deployed stack whose kept device is also another stack's device is not
// moved, but the deploy is told: both stacks, the device and the remedy (an
// explicit interface, which moves the network).
//
// Mutation: skip the cross-stack check — red.
func TestDefaultStackNetworkDevices_SharedDeviceWarns(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	seedStackNetworkRow(t, s, "sa", "backend", compose.NetworkDef{Type: "bridge", Interface: "backend", Subnet: "10.1.0.0/24"})
	seedStackNetworkRow(t, s, "sb", "backend", compose.NetworkDef{Type: "bridge", Interface: "backend", Subnet: "10.2.0.0/24"})
	seedStackNetworkRow(t, s, "sd", "front", compose.NetworkDef{Type: "bridge", Interface: "front"})
	sa := backendFile("sa", compose.NetworkDef{Type: "bridge", Subnet: "10.1.0.0/24"})
	w, err := s.defaultStackNetworkDevices(ctx, sa)
	if err != nil {
		t.Fatal(err)
	}
	if got := sa.Networks["backend"].Interface; got != "backend" {
		t.Errorf("shared sa backend moved to %q; it must be kept, not moved silently", got)
	}
	if len(w) != 1 {
		t.Fatalf("warnings %v, want exactly one", w)
	}
	for _, want := range []string{`"sa"`, `"sb"`, "sb_backend", `"backend"`, "interface: sa_backend"} {
		if !strings.Contains(w[0], want) {
			t.Errorf("warning %q does not name %s", w[0], want)
		}
	}
	// The other stack's own redeploy is told the same.
	sb := backendFile("sb", compose.NetworkDef{Type: "bridge", Subnet: "10.2.0.0/24"})
	if w, _ := s.defaultStackNetworkDevices(ctx, sb); len(w) != 1 || !strings.Contains(w[0], "sa_backend") {
		t.Errorf("sb's redeploy warnings %v, want one naming sa_backend", w)
	}
}
