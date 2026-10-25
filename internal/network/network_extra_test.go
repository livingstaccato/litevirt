package network

import (
	"context"
	"errors"
	"testing"

	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
)

func TestProvision_EmptyType_IsBridge(t *testing.T) {
	execCommand = func(name string, args ...string) ([]byte, error) {
		return nil, nil
	}
	defer func() { execCommand = defaultExec }()

	db := corrosion.NewTestClientT(t)
	ctx := context.Background()
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}

	def := compose.NetworkDef{
		Type:      "", // empty = bridge
		Interface: "br-lan",
	}
	bridge, err := Provision(ctx, db, "test-net", def, "10.0.0.1", "host1")
	if err != nil {
		t.Fatalf("Provision empty type: %v", err)
	}
	if bridge != "br-lan" {
		t.Errorf("expected br-lan, got %s", bridge)
	}
}

func TestProvision_UnknownType(t *testing.T) {
	execCommand = func(name string, args ...string) ([]byte, error) {
		return nil, nil
	}
	defer func() { execCommand = defaultExec }()

	db := corrosion.NewTestClientT(t)
	ctx := context.Background()
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}

	def := compose.NetworkDef{Type: "magic"}
	_, err := Provision(ctx, db, "test-net", def, "10.0.0.1", "host1")
	if err == nil {
		t.Error("expected error for unknown type")
	}
}

func TestProvision_VXLAN_MissingVNI(t *testing.T) {
	db := corrosion.NewTestClientT(t)
	ctx := context.Background()
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}

	def := compose.NetworkDef{
		Type:     "vxlan",
		VNI:      0,
		Underlay: "eth0",
	}
	_, err := Provision(ctx, db, "test-net", def, "10.0.0.1", "host1")
	if err == nil {
		t.Error("expected error for missing VNI")
	}
}

func TestProvision_VXLAN_MissingUnderlay(t *testing.T) {
	db := corrosion.NewTestClientT(t)
	ctx := context.Background()
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}

	def := compose.NetworkDef{
		Type:      "vxlan",
		VNI:       100,
		Underlay:  "",
		Interface: "",
	}
	_, err := Provision(ctx, db, "test-net", def, "10.0.0.1", "host1")
	if err == nil {
		t.Error("expected error for missing underlay")
	}
}

func TestProvision_VXLAN_FallbackToInterface(t *testing.T) {
	var calls [][]string
	execCommand = func(name string, args ...string) ([]byte, error) {
		calls = append(calls, append([]string{name}, args...))
		// Return a fake default route so defaultRouteInterface() auto-detects underlay.
		if name == "ip" && len(args) >= 2 && args[0] == "route" && args[1] == "show" {
			return []byte("default via 10.0.0.1 dev ens192 proto static"), nil
		}
		return nil, nil
	}
	defer func() { execCommand = defaultExec }()

	db := corrosion.NewTestClientT(t)
	ctx := context.Background()
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}

	def := compose.NetworkDef{
		Type:      "vxlan",
		VNI:       700,
		Underlay:  "", // empty — auto-detected from default route
		Interface: "myvxlan",
	}
	bridge, err := Provision(ctx, db, "test-net", def, "10.0.0.1", "host1")
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if bridge != "br-vni700" {
		t.Errorf("expected br-vni700, got %s", bridge)
	}
}

func TestProvision_Isolated(t *testing.T) {
	var calls [][]string
	execCommand = func(name string, args ...string) ([]byte, error) {
		calls = append(calls, append([]string{name}, args...))
		return nil, nil
	}
	defer func() { execCommand = defaultExec }()

	db := corrosion.NewTestClientT(t)
	ctx := context.Background()
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}

	def := compose.NetworkDef{
		Type:      "isolated",
		Interface: "mynet",
	}
	bridge, err := Provision(ctx, db, "test-net", def, "10.0.0.1", "host1")
	if err != nil {
		t.Fatalf("Provision isolated: %v", err)
	}
	if bridge != "br-iso-test-net" {
		t.Errorf("expected br-iso-test-net, got %s", bridge)
	}
	// Should have ip link add and ip link set up.
	if len(calls) < 2 {
		t.Fatalf("expected at least 2 calls, got %d", len(calls))
	}
}

func TestVtepName(t *testing.T) {
	tests := []struct {
		vni  int
		want string
	}{
		{100, "vxlan100"},
		{1, "vxlan1"},
		{4094, "vxlan4094"},
	}
	for _, tt := range tests {
		got := vtepName(tt.vni)
		if got != tt.want {
			t.Errorf("vtepName(%d) = %q, want %q", tt.vni, got, tt.want)
		}
	}
}

func TestIsFileExists(t *testing.T) {
	if !isFileExists([]byte("RTNETLINK answers: File exists\n")) {
		t.Error("should detect File exists")
	}
	if isFileExists([]byte("some other error")) {
		t.Error("should not detect File exists in unrelated text")
	}
	if isFileExists(nil) {
		t.Error("nil should not be File exists")
	}
}

func TestIsAlreadyExists(t *testing.T) {
	if !isAlreadyExists([]byte("File exists")) {
		t.Error("should detect File exists")
	}
	if !isAlreadyExists([]byte("already exists")) {
		t.Error("should detect already exists")
	}
	if isAlreadyExists([]byte("something else")) {
		t.Error("should not detect non-exists text")
	}
}

func TestAddFDBEntry_AlreadyExists(t *testing.T) {
	execCommand = func(name string, args ...string) ([]byte, error) {
		return []byte("already exists\n"), errors.New("exit status 2")
	}
	defer func() { execCommand = defaultExec }()

	err := AddFDBEntry(100, "aa:bb:cc:dd:ee:ff", "192.168.1.2")
	if err != nil {
		t.Errorf("AddFDBEntry should not error on already exists: %v", err)
	}
}

func TestDeleteFDBEntry_AlreadyExists(t *testing.T) {
	execCommand = func(name string, args ...string) ([]byte, error) {
		return []byte("File exists\n"), errors.New("exit status 2")
	}
	defer func() { execCommand = defaultExec }()

	err := DeleteFDBEntry(200, "11:22:33:44:55:66", "10.0.0.5")
	if err != nil {
		t.Errorf("DeleteFDBEntry should not error on File exists: %v", err)
	}
}

func TestFloodEntry_Error(t *testing.T) {
	execCommand = func(name string, args ...string) ([]byte, error) {
		return []byte("permission denied"), errors.New("exit status 1")
	}
	defer func() { execCommand = defaultExec }()

	err := FloodEntry(300, "172.16.0.1")
	if err == nil {
		t.Error("FloodEntry should return error on non-exists failure")
	}
}

func TestDeleteFloodEntry_Error(t *testing.T) {
	execCommand = func(name string, args ...string) ([]byte, error) {
		return []byte("not found"), errors.New("exit status 1")
	}
	defer func() { execCommand = defaultExec }()

	err := DeleteFloodEntry(400, "172.16.0.2")
	if err == nil {
		t.Error("DeleteFloodEntry should return error on non-exists failure")
	}
}

func TestDeprovisionVXLAN_Error(t *testing.T) {
	execCommand = func(name string, args ...string) ([]byte, error) {
		return []byte("permission denied"), errors.New("exit status 1")
	}
	defer func() { execCommand = defaultExec }()

	err := DeprovisionVXLAN(999)
	if err == nil {
		t.Error("DeprovisionVXLAN should return error on non-exists failure")
	}
}

func TestDeprovisionVXLAN_AlreadyGone(t *testing.T) {
	execCommand = func(name string, args ...string) ([]byte, error) {
		return []byte("Cannot find device \"br-vni999\""), errors.New("exit status 1")
	}
	defer func() { execCommand = defaultExec }()

	err := DeprovisionVXLAN(999)
	if err != nil {
		t.Errorf("DeprovisionVXLAN should succeed when device already gone, got: %v", err)
	}
}

func TestSubnetRange(t *testing.T) {
	gw, start, end, mask, err := SubnetRange("10.0.0.0/24")
	if err != nil {
		t.Fatalf("SubnetRange: %v", err)
	}
	if gw != "10.0.0.1/24" {
		t.Errorf("gateway = %q, want 10.0.0.1/24", gw)
	}
	if start != "10.0.0.2" {
		t.Errorf("start = %q, want 10.0.0.2", start)
	}
	if end != "10.0.0.254" {
		t.Errorf("end = %q, want 10.0.0.254", end)
	}
	if mask != "255.255.255.0" {
		t.Errorf("mask = %q, want 255.255.255.0", mask)
	}
}

func TestSubnetRange_Slash25(t *testing.T) {
	gw, start, end, mask, err := SubnetRange("10.0.1.128/25")
	if err != nil {
		t.Fatalf("SubnetRange: %v", err)
	}
	if gw != "10.0.1.129/25" {
		t.Errorf("gateway = %q, want 10.0.1.129/25", gw)
	}
	if start != "10.0.1.130" {
		t.Errorf("start = %q, want 10.0.1.130", start)
	}
	if end != "10.0.1.254" {
		t.Errorf("end = %q, want 10.0.1.254", end)
	}
	if mask != "255.255.255.128" {
		t.Errorf("mask = %q, want 255.255.255.128", mask)
	}
}

func TestSubnetRange_Small(t *testing.T) {
	_, _, _, _, err := SubnetRange("10.0.0.0/31")
	if err == nil {
		t.Error("expected error for /31 subnet")
	}
}

func TestSubnetRange_Invalid(t *testing.T) {
	_, _, _, _, err := SubnetRange("invalid")
	if err == nil {
		t.Error("expected error for invalid subnet")
	}
}

func TestNextFreeIP_InvalidSubnet(t *testing.T) {
	_, err := nextFreeIP("not-a-cidr", nil)
	if err == nil {
		t.Error("expected error for invalid subnet")
	}
}

func TestEnsureVXLAN_Error(t *testing.T) {
	execCommand = func(name string, args ...string) ([]byte, error) {
		return []byte("some error"), errors.New("exit status 1")
	}
	defer func() { execCommand = defaultExec }()

	_, err := EnsureVXLAN(999, "eth0", "10.0.0.1")
	if err == nil {
		t.Error("expected error from EnsureVXLAN")
	}
}
