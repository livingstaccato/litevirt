package compose

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestMemory_UnmarshalYAML_Int(t *testing.T) {
	var m Memory
	if err := yaml.Unmarshal([]byte("8192"), &m); err != nil {
		t.Fatalf("unmarshal int: %v", err)
	}
	if int(m) != 8192 {
		t.Errorf("Memory = %d, want 8192", m)
	}
}

func TestMemory_UnmarshalYAML_StringG(t *testing.T) {
	var m Memory
	if err := yaml.Unmarshal([]byte(`"8G"`), &m); err != nil {
		t.Fatalf("unmarshal string: %v", err)
	}
	if int(m) != 8192 {
		t.Errorf("Memory = %d, want 8192 (8G)", m)
	}
}

func TestMemory_UnmarshalYAML_StringM(t *testing.T) {
	var m Memory
	if err := yaml.Unmarshal([]byte(`"512M"`), &m); err != nil {
		t.Fatalf("unmarshal string: %v", err)
	}
	if int(m) != 512 {
		t.Errorf("Memory = %d, want 512", m)
	}
}

func TestDiskDef_UnmarshalYAML_Shorthand(t *testing.T) {
	var d DiskDef
	if err := yaml.Unmarshal([]byte(`"20G"`), &d); err != nil {
		t.Fatalf("unmarshal shorthand: %v", err)
	}
	if d.Size != "20G" {
		t.Errorf("Size = %q, want 20G", d.Size)
	}
}

func TestDiskDef_UnmarshalYAML_FullForm(t *testing.T) {
	yamlStr := `
size: "50G"
bus: scsi
cache: none
storage: ceph-pool
`
	var d DiskDef
	if err := yaml.Unmarshal([]byte(yamlStr), &d); err != nil {
		t.Fatalf("unmarshal full form: %v", err)
	}
	if d.Size != "50G" {
		t.Errorf("Size = %q", d.Size)
	}
	if d.Bus != "scsi" {
		t.Errorf("Bus = %q", d.Bus)
	}
	if d.Cache != "none" {
		t.Errorf("Cache = %q", d.Cache)
	}
	if d.Storage != "ceph-pool" {
		t.Errorf("Storage = %q", d.Storage)
	}
}

func TestDeviceDef_YAML(t *testing.T) {
	yamlStr := `
type: gpu
vendor: "10de"
model: A10
count: 2
sriov: false
`
	var d DeviceDef
	if err := yaml.Unmarshal([]byte(yamlStr), &d); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if d.Type != "gpu" {
		t.Errorf("Type = %q", d.Type)
	}
	if d.Vendor != "10de" {
		t.Errorf("Vendor = %q", d.Vendor)
	}
	if d.Model != "A10" {
		t.Errorf("Model = %q", d.Model)
	}
	if d.Count != 2 {
		t.Errorf("Count = %d", d.Count)
	}
}

func TestDeviceDef_Address(t *testing.T) {
	yamlStr := `
type: pci
address: "0000:41:00.0"
`
	var d DeviceDef
	if err := yaml.Unmarshal([]byte(yamlStr), &d); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if d.Address != "0000:41:00.0" {
		t.Errorf("Address = %q", d.Address)
	}
}

func TestDeviceDef_SRIOV(t *testing.T) {
	yamlStr := `
type: network
sriov: true
parent: enp65s0f0
`
	var d DeviceDef
	if err := yaml.Unmarshal([]byte(yamlStr), &d); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !d.SRIOV {
		t.Error("SRIOV should be true")
	}
	if d.Parent != "enp65s0f0" {
		t.Errorf("Parent = %q", d.Parent)
	}
}

func TestVMDef_WithDevices(t *testing.T) {
	yamlStr := `
image: ubuntu-24
cpu: 4
memory: 8192
devices:
  - type: gpu
    vendor: "10de"
    count: 1
  - type: network
    sriov: true
    parent: enp65s0f0
`
	var vm VMDef
	if err := yaml.Unmarshal([]byte(yamlStr), &vm); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(vm.Devices) != 2 {
		t.Fatalf("expected 2 devices, got %d", len(vm.Devices))
	}
	if vm.Devices[0].Type != "gpu" {
		t.Errorf("Device[0].Type = %q", vm.Devices[0].Type)
	}
	if vm.Devices[1].SRIOV != true {
		t.Error("Device[1].SRIOV should be true")
	}
}

func TestResourcesDef_YAML(t *testing.T) {
	yamlStr := `
hugepages: true
cpu-pinning: [0, 1, 2, 3]
io-threads: 4
`
	var r ResourcesDef
	if err := yaml.Unmarshal([]byte(yamlStr), &r); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !r.HugePages {
		t.Error("HugePages should be true")
	}
	if len(r.CPUPinning) != 4 {
		t.Fatalf("CPUPinning: got %d, want 4", len(r.CPUPinning))
	}
	if r.IOThreads != 4 {
		t.Errorf("IOThreads = %d", r.IOThreads)
	}
}

func TestPlacementDef_YAML(t *testing.T) {
	yamlStr := `
host: node1
anti-affinity: [db-1, db-2]
require:
  zone: us-east
prefer:
  rack: rack-a
spread: true
`
	var p PlacementDef
	if err := yaml.Unmarshal([]byte(yamlStr), &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if p.Host != "node1" {
		t.Errorf("Host = %q", p.Host)
	}
	if len(p.AntiAffinity) != 2 {
		t.Errorf("AntiAffinity length = %d", len(p.AntiAffinity))
	}
	if p.Require["zone"] != "us-east" {
		t.Errorf("Require[zone] = %q", p.Require["zone"])
	}
	if !p.Spread {
		t.Error("Spread should be true")
	}
}

func TestScopedNetworkName(t *testing.T) {
	tests := []struct {
		stack, net, want string
	}{
		{"mystack", "LAN", "mystack_LAN"},
		{"prod", "mgmt", "prod_mgmt"},
		{"", "LAN", "LAN"}, // standalone — no prefix
		{"s", "n", "s_n"},  // minimal
	}
	for _, tt := range tests {
		got := ScopedNetworkName(tt.stack, tt.net)
		if got != tt.want {
			t.Errorf("ScopedNetworkName(%q, %q) = %q, want %q", tt.stack, tt.net, got, tt.want)
		}
	}
}

func TestHealthCheckDef_YAML(t *testing.T) {
	yamlStr := `
type: http
target: ":8080/health"
interval: "30s"
timeout: "5s"
retries: 3
action: restart
`
	var h HealthCheckDef
	if err := yaml.Unmarshal([]byte(yamlStr), &h); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if h.Type != "http" {
		t.Errorf("Type = %q", h.Type)
	}
	if h.Retries != 3 {
		t.Errorf("Retries = %d", h.Retries)
	}
	if h.Action != "restart" {
		t.Errorf("Action = %q", h.Action)
	}
}

// A declared bridge network with no interface takes its stack-scoped flat
// bridge name (the same on every host, and distinct from another stack's
// network of the same short name); one with an interface keeps it, and an
// external network is not touched. Any other type keeps its short name: for
// `direct` that is the host NIC macvtap attaches to, as on main.
//
// Mutation: default to the short name — "lan" goes red.
// Mutation: give every type the scoped default — "mgmt" and "iso" go red.
func TestDefaultNetworkInterfaces(t *testing.T) {
	f := &File{Name: "st", Networks: map[string]NetworkDef{
		"lan":            {Type: "bridge"},
		"iso":            {Type: "isolated"},
		"set":            {Type: "bridge", Interface: "br7"},
		"ext":            {External: true},
		"a-long-backend": {Type: "bridge"},
		"untyped":        {},
		"mgmt":           {Type: "direct"},
		"vx":             {Type: "vxlan", VNI: 7},
	}}
	f.DefaultNetworkInterfaces(nil)
	for name, want := range map[string]string{
		"lan": "st_lan", "iso": "iso", "set": "br7", "ext": "",
		"untyped": "st_untyped", "mgmt": "mgmt", "vx": "vx",
		"a-long-backend": FlatBridgeName("st_a-long-backend"),
	} {
		if got := f.Networks[name].Interface; got != want {
			t.Errorf("network %s: interface %q, want %q", name, got, want)
		}
	}
	if got := f.Networks["a-long-backend"].Interface; len(got) > 15 || !strings.HasPrefix(got, "lvf-") {
		t.Errorf("long network: interface %q, want the hashed lvf- form within 15 bytes", got)
	}
}

// Two stacks that each name a network `backend` get different devices.
func TestDefaultNetworkInterfaces_SameShortNameTwoStacks(t *testing.T) {
	sa := &File{Name: "sa", Networks: map[string]NetworkDef{"backend": {Type: "bridge"}}}
	sb := &File{Name: "sb", Networks: map[string]NetworkDef{"backend": {Type: "bridge"}}}
	sa.DefaultNetworkInterfaces(nil)
	sb.DefaultNetworkInterfaces(nil)
	if a, b := sa.Networks["backend"].Interface, sb.Networks["backend"].Interface; a == b {
		t.Fatalf("both stacks' backend default to %q", a)
	}
}

// A network whose row already records a device keeps it (a deployed network
// is never moved by the default); an interface the file names wins over the
// record, and a network with no record gets the scoped default.
//
// Mutation: ignore recorded — "old" goes red.
func TestDefaultNetworkInterfaces_RecordedDeviceKept(t *testing.T) {
	f := &File{Name: "st", Networks: map[string]NetworkDef{
		"old": {Type: "bridge"},
		"new": {Type: "bridge"},
		"set": {Type: "bridge", Interface: "br7"},
	}}
	f.DefaultNetworkInterfaces(map[string]string{"old": "old", "set": "br9"})
	for name, want := range map[string]string{"old": "old", "new": "st_new", "set": "br7"} {
		if got := f.Networks[name].Interface; got != want {
			t.Errorf("network %s: interface %q, want %q", name, got, want)
		}
	}
}

// FlatBridgeName is the network name when it fits IFNAMSIZ and the stable
// hashed lvf- form otherwise.
func TestFlatBridgeName(t *testing.T) {
	if got := FlatBridgeName("sa_backend"); got != "sa_backend" {
		t.Errorf("short: %q", got)
	}
	got := FlatBridgeName("averylongstack_backend")
	if len(got) != 15 || got != FlatBridgeName("averylongstack_backend") || got == FlatBridgeName("averylongstack_backenc") {
		t.Errorf("long: %q", got)
	}
}
