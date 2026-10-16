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
	for _, want := range []string{`"sa"`, `"sb"`, "sb_backend", `"backend"`, "interface: sa_backend", "If that is not intended"} {
		if !strings.Contains(w[0].Detail, want) {
			t.Errorf("warning %q does not name %s", w[0].Detail, want)
		}
	}
	// The other stack's own redeploy is told the same.
	sb := backendFile("sb", compose.NetworkDef{Type: "bridge", Subnet: "10.2.0.0/24"})
	if w, _ := s.defaultStackNetworkDevices(ctx, sb); len(w) != 1 || !strings.Contains(w[0].Detail, "sa_backend") {
		t.Errorf("sb's redeploy warnings %v, want one naming sa_backend", w)
	}
}

// A direct network's interface is the host NIC macvtap attaches to: with none
// given it is the network's own name, as on main, never a scoped name no NIC
// carries.
//
// Mutation: give direct the scoped default — red.
func TestDefaultStackNetworkDevices_DirectNetworkKeepsItsShortName(t *testing.T) {
	s := testServer(t)
	f := &compose.File{Name: "st", Networks: map[string]compose.NetworkDef{"eth1": {Type: "direct"}}}
	if _, err := s.defaultStackNetworkDevices(context.Background(), f); err != nil {
		t.Fatal(err)
	}
	if got := f.Networks["eth1"].Interface; got != "eth1" {
		t.Errorf("direct eth1 on %q, want the host NIC eth1", got)
	}
}

// A row whose config does not parse records no device: the deploy goes on, as
// on main (which wrote the row over), and the network gets the default.
func TestDefaultStackNetworkDevices_UnparseableRowRecordsNoDevice(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	if err := corrosion.UpsertNetwork(ctx, s.db, corrosion.NetworkRecord{
		Name: "st_backend", StackName: "st", Type: "bridge", Config: "{not json",
	}); err != nil {
		t.Fatal(err)
	}
	f := backendFile("st", compose.NetworkDef{Type: "bridge"})
	if _, err := s.defaultStackNetworkDevices(ctx, f); err != nil {
		t.Fatalf("an unparseable row refused the deploy: %v", err)
	}
	if got := f.Networks["backend"].Interface; got != "st_backend" {
		t.Errorf("backend on %q, want st_backend", got)
	}
}

// A new stack network named after a bridge that already exists on the entry
// host, which no stack network is recorded on and litevirt did not make, is
// put on that bridge, as on main: naming a host bridge attaches to it.
//
// Mutation: drop the host-bridge rule — red.
func TestDefaultStackNetworkDevices_ExistingHostBridgeIsUsed(t *testing.T) {
	s := testServer(t)
	s.bridgeExists = func(dev string) bool { return dev == "br0" }
	f := &compose.File{Name: "st", Networks: map[string]compose.NetworkDef{
		"br0": {Type: "bridge"},
		"lan": {Type: "bridge"},
	}}
	w, err := s.defaultStackNetworkDevices(context.Background(), f)
	if err != nil || len(w) != 0 {
		t.Fatalf("warnings=%v err=%v", w, err)
	}
	if got := f.Networks["br0"].Interface; got != "br0" {
		t.Errorf("br0 on %q, want the host's br0", got)
	}
	if got := f.Networks["lan"].Interface; got != "st_lan" {
		t.Errorf("lan on %q, want st_lan", got)
	}
}

// A bridge another stack's network is recorded on is not a host bridge to
// attach to: the new stack gets its scoped name.
//
// Mutation: drop the recorded-by-a-stack check — red.
func TestDefaultStackNetworkDevices_BridgeRecordedByAStackIsNotTaken(t *testing.T) {
	s := testServer(t)
	s.bridgeExists = func(dev string) bool { return dev == "backend" }
	seedStackNetworkRow(t, s, "sa", "backend", compose.NetworkDef{Type: "bridge", Interface: "backend"})
	sb := backendFile("sb", compose.NetworkDef{Type: "bridge"})
	if _, err := s.defaultStackNetworkDevices(context.Background(), sb); err != nil {
		t.Fatal(err)
	}
	if got := sb.Networks["backend"].Interface; got != "sb_backend" {
		t.Errorf("sb backend on %q, want sb_backend", got)
	}
}

type createdBridgesProv struct {
	hostNetworkProvisioner
	created []string
}

func (p createdBridgesProv) CreatedBridges() ([]string, error) { return p.created, nil }

// A bridge litevirt made here (a legacy stack network's, whose row no longer
// names it) is not an operator's host bridge either.
//
// Mutation: drop the created-bridge check — red.
func TestDefaultStackNetworkDevices_LitevirtMadeBridgeIsNotAHostBridge(t *testing.T) {
	s := testServer(t)
	s.bridgeExists = func(dev string) bool { return dev == "backend" }
	s.SetNetworkProvisioner(createdBridgesProv{created: []string{"backend"}})
	f := backendFile("sc", compose.NetworkDef{Type: "bridge"})
	if _, err := s.defaultStackNetworkDevices(context.Background(), f); err != nil {
		t.Fatal(err)
	}
	if got := f.Networks["backend"].Interface; got != "sc_backend" {
		t.Errorf("sc backend on %q, want sc_backend", got)
	}
}

// The other direction: a new stack's scoped default that another stack names
// as its interface is shared too, and warned about.
//
// Mutation: check only recorded devices — red.
func TestDefaultStackNetworkDevices_ScopedDefaultOnAnotherStacksDeviceWarns(t *testing.T) {
	s := testServer(t)
	seedStackNetworkRow(t, s, "x", "lan", compose.NetworkDef{Type: "bridge", Interface: "sa_backend"})
	sa := backendFile("sa", compose.NetworkDef{Type: "bridge"})
	w, err := s.defaultStackNetworkDevices(context.Background(), sa)
	if err != nil {
		t.Fatal(err)
	}
	if len(w) != 1 || !strings.Contains(w[0].Detail, "x_lan") || !strings.Contains(w[0].Detail, `"x"`) || w[0].Event != eventBridgeShared {
		t.Errorf("warnings %v, want one naming x_lan of stack x", w)
	}
}

// A bridge network with no interface whose name is an operator's host bridge
// that another stack's network is already recorded on gets its scoped name
// (sharing across stacks must be explicit), and the deploy says so: the
// stack, the host bridge, the stacks on it and how to share it.
//
// Mutation: no host-bridge warning — red.
// Mutation: warn on a bridge litevirt made — the "made" case goes red.
func TestDefaultStackNetworkDevices_HostBridgeOfAnotherStackWarns(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	s.bridgeExists = func(dev string) bool { return dev == "br0" || dev == "backend" }
	s.SetNetworkProvisioner(createdBridgesProv{created: []string{"backend"}})
	seedStackNetworkRow(t, s, "sa", "br0", compose.NetworkDef{Type: "bridge", Interface: "br0"})
	seedStackNetworkRow(t, s, "sc", "up", compose.NetworkDef{Type: "bridge", Interface: "br0"})
	sb := &compose.File{Name: "sb", Networks: map[string]compose.NetworkDef{"br0": {Type: "bridge"}}}
	w, err := s.defaultStackNetworkDevices(ctx, sb)
	if err != nil {
		t.Fatal(err)
	}
	if got := sb.Networks["br0"].Interface; got != "sb_br0" {
		t.Errorf("sb br0 on %q, want sb_br0", got)
	}
	if len(w) != 1 || w[0].Event != eventHostBridgeNotShared {
		t.Fatalf("warnings %+v, want one %s", w, eventHostBridgeNotShared)
	}
	for _, want := range []string{`"sb"`, `"br0"`, `"sa"`, `"sc"`, "sb_br0", "to share it, set \"interface: br0\" and redeploy"} {
		if !strings.Contains(w[0].Detail, want) {
			t.Errorf("warning %q does not name %s", w[0].Detail, want)
		}
	}

	// A bridge litevirt made (a stack's own, recorded by sa) is not a host
	// bridge: no such warning.
	seedStackNetworkRow(t, s, "sa", "backend", compose.NetworkDef{Type: "bridge", Interface: "backend"})
	sd := backendFile("sd", compose.NetworkDef{Type: "bridge"})
	if w, err := s.defaultStackNetworkDevices(ctx, sd); err != nil || len(w) != 0 {
		t.Errorf("made bridge: warnings %+v err %v, want none", w, err)
	}
}
