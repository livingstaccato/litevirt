package cloudinit

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// hotplugSeedDB is a database with three networks and VM "hp" created with
// spec [A(stnet, ip 10.5.0.50), B(dnet)], both MACs recorded in the spec and
// both NIC rows written to both NIC tables, as CreateVM writes them.
func hotplugSeedDB(t *testing.T) (*corrosion.Client, *pb.VMSpec) {
	t.Helper()
	ctx := context.Background()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	for name, def := range map[string]compose.NetworkDef{
		"stnet":  {Type: "bridge", Subnet: "10.5.0.0/24", DHCP: true},
		"dnet":   {Type: "bridge", Subnet: "10.6.0.0/24", DHCP: true},
		"isonet": {Type: "isolated", Subnet: "10.7.0.0/24", DHCP: true},
	} {
		cfg, _ := json.Marshal(def)
		if err := corrosion.UpsertNetwork(ctx, db, corrosion.NetworkRecord{Name: name, Type: def.Type, Config: string(cfg)}); err != nil {
			t.Fatal(err)
		}
	}
	spec := &pb.VMSpec{Name: "hp", Network: []*pb.NetworkAttachment{
		{Name: "stnet", Mac: "52:54:00:00:0a:0a", Ip: "10.5.0.50"},
		{Name: "dnet", Mac: "52:54:00:00:0b:0b"},
	}}
	ifaces := []corrosion.InterfaceRecord{
		{VMName: "hp", NetworkName: "stnet", Ordinal: 0, MAC: "52:54:00:00:0a:0a", IP: "10.5.0.50"},
		{VMName: "hp", NetworkName: "dnet", Ordinal: 1, MAC: "52:54:00:00:0b:0b"},
	}
	var nics []corrosion.NICRecord
	for _, i := range ifaces {
		nics = append(nics, corrosion.NICRecord{VMName: i.VMName, ID: corrosion.DeterministicNICID(i.VMName, i.MAC),
			NetworkName: i.NetworkName, MAC: i.MAC, Ordinal: i.Ordinal, IP: i.IP})
	}
	if err := corrosion.InsertVMWithHardware(ctx, db, corrosion.VMRecord{Name: "hp", HostName: "h", Spec: "{}", State: "running"},
		ifaces, nil, nics, nil, true); err != nil {
		t.Fatal(err)
	}
	return db, spec
}

// The rows a hot attach writes: vm_nics always, vm_interfaces too before
// hardware_v2 latches (writeNICAttachRows).
func hotAttachRows(t *testing.T, db *corrosion.Client, latched bool, network, mac string, ordinal int) {
	t.Helper()
	ctx := context.Background()
	if err := corrosion.UpsertNIC(ctx, db, corrosion.NICRecord{VMName: "hp", ID: corrosion.DeterministicNICID("hp", mac),
		NetworkName: network, MAC: mac, Ordinal: ordinal}); err != nil {
		t.Fatal(err)
	}
	if !latched {
		if err := corrosion.InsertInterface(ctx, db, corrosion.InterfaceRecord{VMName: "hp", NetworkName: network, Ordinal: ordinal, MAC: mac}); err != nil {
			t.Fatal(err)
		}
	}
}

// The rows a hot detach writes: the vm_nics tombstone always, the
// vm_interfaces one too before hardware_v2 latches (executeNICDetach).
func hotDetachRows(t *testing.T, db *corrosion.Client, latched bool, mac string) {
	t.Helper()
	ctx := context.Background()
	if err := corrosion.TombstoneNIC(ctx, db, "hp", corrosion.DeterministicNICID("hp", mac)); err != nil {
		t.Fatal(err)
	}
	if !latched {
		if err := corrosion.SoftDeleteInterfaceByMAC(ctx, db, "hp", mac); err != nil {
			t.Fatal(err)
		}
	}
}

// Lab 2 (d53dc770, C3): on a hardware_v2-latched cluster a hot attach and
// detach change only vm_nics, so a seed rebuilt from the spec and
// vm_interfaces still named the detached NIC (its MAC and static address) and
// left out the attached one. The seed follows the NIC rows attach and detach
// maintain on both kinds of cluster: exactly the VM's live NICs, each
// detached NIC's address gone with it.
//
// Each NIC keeps its name with no seed to read it from: B the eth1 create
// gave it, C eth2, its ordinal (T2 concern 2).
//
// Mutation: read the NIC set from the live vm_interfaces rows again — the
// latched case names A and 10.5.0.50 and misses C; name each entry by its
// position — B eth0, C eth1.
func TestSeedNetworkConfig_FollowsHotplug(t *testing.T) {
	for _, latched := range []bool{true, false} {
		name := "unlatched"
		if latched {
			name = "latched"
		}
		t.Run(name, func(t *testing.T) {
			db, spec := hotplugSeedDB(t)
			ctx := context.Background()
			// Attach C on the isolated network, then detach A (static).
			hotAttachRows(t, db, latched, "isonet", "52:54:00:00:0c:0c", 2)
			hotDetachRows(t, db, latched, "52:54:00:00:0a:0a")

			got, err := SeedNetworkConfig(ctx, db, "hp", spec, nil)
			if err != nil {
				t.Fatal(err)
			}
			for _, gone := range []string{"52:54:00:00:0a:0a", "10.5.0.50"} {
				if strings.Contains(got, gone) {
					t.Errorf("the detached NIC's %s is in the seed:\n%s", gone, got)
				}
			}
			for _, want := range []string{
				"  eth1:\n    match:\n      macaddress: \"52:54:00:00:0b:0b\"\n    set-name: eth1\n    dhcp4: true\n",
				"  eth2:\n    match:\n      macaddress: \"52:54:00:00:0c:0c\"\n    set-name: eth2\n    dhcp4: true\n",
			} {
				if !strings.Contains(got, want) {
					t.Errorf("want\n%s\nin the seed:\n%s", want, got)
				}
			}
			if n := strings.Count(got, "macaddress:"); n != 2 {
				t.Errorf("want exactly the 2 live NICs, got %d:\n%s", n, got)
			}
		})
	}
}

// A NIC attached by an earlier build can share its ordinal with a NIC that
// stayed (attach numbered by the count of NICs left after a detach). Without a
// prior seed (a rebuild where none is readable) every live NIC still gets its
// own name: B the eth1 create gave it, and C, whose eth<ordinal> B holds, the
// lowest eth<n> free above the NICs that were there.
//
// Mutation: name an attached NIC by its ordinal whether or not it is free —
// eth1 twice.
func TestSeedNetworkConfig_SharedOrdinalGetsItsOwnName(t *testing.T) {
	db, spec := hotplugSeedDB(t)
	ctx := context.Background()
	hotDetachRows(t, db, true, "52:54:00:00:0a:0a")
	hotAttachRows(t, db, true, "dnet", "52:54:00:00:0c:0c", 1) // shares B's ordinal 1
	got, err := SeedNetworkConfig(ctx, db, "hp", spec, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"  eth1:\n    match:\n      macaddress: \"52:54:00:00:0b:0b\"\n    set-name: eth1\n",
		"  eth2:\n    match:\n      macaddress: \"52:54:00:00:0c:0c\"\n    set-name: eth2\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("want\n%s\nin:\n%s", want, got)
		}
	}
}

// A NIC still attached keeps what its spec entry says: A's static address
// stays on A after another NIC is attached.
//
// Mutation: drop the spec entry's fields for a NIC matched by MAC — A turns
// DHCP.
func TestSeedNetworkConfig_KeptNICKeepsItsSpecAddress(t *testing.T) {
	db, spec := hotplugSeedDB(t)
	hotAttachRows(t, db, true, "dnet", "52:54:00:00:0c:0c", 2)
	got, err := SeedNetworkConfig(context.Background(), db, "hp", spec, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "macaddress: \"52:54:00:00:0a:0a\"\n    set-name: eth0\n    addresses:\n      - 10.5.0.50/24\n") {
		t.Errorf("A lost its static address:\n%s", got)
	}
	if strings.Count(got, "macaddress:") != 3 {
		t.Errorf("want the 3 live NICs:\n%s", got)
	}
}

// Lab 2 (d53dc770, C2): an isolated network has no router, yet its dnsmasq
// hands out one, and a guest that takes it can move its egress off NIC 0. A
// NIC on an isolated network takes no route from DHCP (use-routes: false)
// and a static one gets no default route unless its own `gateway:` names
// one.
//
// Mutation: drop use-routes for isolated NICs — the DHCP case goes red; keep
// the derived gateway — the static case goes red; apply it to every network
// — the bridge NIC loses its route.
func TestNetworkConfig_IsolatedNetworkTakesNoDefaultRoute(t *testing.T) {
	iso := &compose.NetworkDef{Type: "isolated", Subnet: "10.7.0.0/24", DHCP: true}
	br := &compose.NetworkDef{Type: "bridge", Subnet: "10.6.0.0/24", DHCP: true}
	doc := NetworkConfig([]NIC{
		{Ordinal: 0, MAC: "52:54:00:00:00:01", Net: br},
		{Ordinal: 1, MAC: "52:54:00:00:00:02", Net: iso},
		{Ordinal: 2, MAC: "52:54:00:00:00:03", Net: iso, IP: "10.7.0.9"},
		{Ordinal: 3, MAC: "52:54:00:00:00:04", Net: iso, IP: "10.7.0.10", Gateway: "10.7.0.254"},
	})
	if !strings.Contains(doc, "set-name: eth1\n    dhcp4: true\n    dhcp4-overrides:\n      route-metric: 101\n      use-routes: false\n") {
		t.Errorf("isolated DHCP NIC takes routes:\n%s", doc)
	}
	if strings.Contains(doc, "via: 10.7.0.1\n") {
		t.Errorf("isolated static NIC got the subnet's first host as a default route:\n%s", doc)
	}
	if !strings.Contains(doc, "via: 10.7.0.254\n") {
		t.Errorf("an isolated NIC's own gateway: was dropped:\n%s", doc)
	}
	if strings.Count(doc, "use-routes: false") != 1 {
		t.Errorf("want use-routes: false on the isolated DHCP NIC only:\n%s", doc)
	}
}

// ReadSeed reads back what GenerateISO wrote; RebuildISO replaces only the
// network-config and keeps the instance-id, hostname and user-data, so a
// rebuilt seed is never a new instance to cloud-init.
//
// Mutation: rebuild with the VM name as instance-id — the instance-id check
// goes red; drop the user-data carry — the user-data check goes red.
func TestRebuildISO_KeepsIdentityAndUserData(t *testing.T) {
	if _, err := exec.LookPath("genisoimage"); err != nil {
		t.Skip("genisoimage not installed")
	}
	path := filepath.Join(t.TempDir(), "hp.iso")
	if err := GenerateISO(Config{InstanceID: "hp-first", LocalHostname: "hp-host",
		UserData: "#cloud-config\nhostname: hp\n", NetworkConfig: "version: 1\nconfig: []\n"}, path); err != nil {
		t.Fatal(err)
	}
	s, err := ReadSeed(path)
	if err != nil {
		t.Fatal(err)
	}
	if s.InstanceID() != "hp-first" || s.NetworkConfig != "version: 1\nconfig: []\n" || s.UserData != "#cloud-config\nhostname: hp\n" {
		t.Fatalf("ReadSeed: %+v", s)
	}
	changed, err := RebuildISO(path, "version: 2\nethernets: {}\n", "")
	if err != nil || !changed {
		t.Fatalf("RebuildISO = %v, %v", changed, err)
	}
	s, err = ReadSeed(path)
	if err != nil {
		t.Fatal(err)
	}
	if s.InstanceID() != "hp-first" || !strings.Contains(s.MetaData, "local-hostname: hp-host") {
		t.Errorf("identity changed: %q", s.MetaData)
	}
	if s.UserData != "#cloud-config\nhostname: hp\n" {
		t.Errorf("user-data changed: %q", s.UserData)
	}
	if s.NetworkConfig != "version: 2\nethernets: {}\n" {
		t.Errorf("network-config = %q", s.NetworkConfig)
	}
	// Unchanged network-config: nothing is rewritten.
	fi, _ := os.Stat(path)
	if changed, err := RebuildISO(path, "version: 2\nethernets: {}\n", ""); err != nil || changed {
		t.Errorf("same network-config: RebuildISO = %v, %v; want no rewrite", changed, err)
	}
	if fi2, _ := os.Stat(path); !os.SameFile(fi, fi2) {
		t.Error("an unchanged seed was replaced")
	}
	// No network-config: the file goes.
	if _, err := RebuildISO(path, "", ""); err != nil {
		t.Fatal(err)
	}
	if s, _ := ReadSeed(path); s.NetworkConfig != "" || s.InstanceID() != "hp-first" {
		t.Errorf("after dropping the network-config: %+v", s)
	}
}

// A file that is not a seed this reader understands is refused, never read
// as a seed with no instance-id.
//
// Mutation: return an empty seed for a non-ISO — red.
func TestReadSeed_RefusesANonISO(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.iso")
	if err := os.WriteFile(path, []byte("not an iso"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadSeed(path); err == nil {
		t.Error("a non-ISO read as a seed")
	}
	if _, err := RebuildISO(path, "version: 2\n", ""); err == nil {
		t.Error("a non-ISO was rebuilt")
	}
	if b, _ := os.ReadFile(path); string(b) != "not an iso" {
		t.Error("a seed that could not be read was replaced")
	}
}

// Round 1: a seed whose network-config litevirt writes carries vendor-data
// that asks cloud-init to apply the network-config again on every boot and
// on a hot-plug, so a NIC attached since the first boot is configured. The
// spec's own network-config is the operator's, and gets none. User-data,
// merged over vendor-data, can still say otherwise.
//
// Mutation: return the vendor-data for a spec network-config too — red;
// return none for a derived one — red; return it with no network-config —
// the m1 case goes red.
func TestSeedVendorData(t *testing.T) {
	const nc = "version: 2\nethernets: {}\n"
	if got := SeedVendorData(&pb.VMSpec{}, nc); got != NetworkUpdatesVendorData {
		t.Errorf("derived network-config: vendor-data = %q", got)
	}
	if got := SeedVendorData(&pb.VMSpec{CloudInit: &pb.CloudInitSpec{Userdata: "#cloud-config\n"}}, nc); got != NetworkUpdatesVendorData {
		t.Errorf("user-data only: vendor-data = %q", got)
	}
	if got := SeedVendorData(nil, nc); got != NetworkUpdatesVendorData {
		t.Errorf("no spec (a clone's own network-config): vendor-data = %q", got)
	}
	if got := SeedVendorData(&pb.VMSpec{CloudInit: &pb.CloudInitSpec{Networkconfig: "version: 2\n"}}, "version: 2\n"); got != "" {
		t.Errorf("the spec's own network-config: vendor-data = %q, want none", got)
	}
	// Review m1: litevirt writes no network-config (one DHCP NIC: cloud-init's
	// fallback) — no vendor-data either.
	if got := SeedVendorData(&pb.VMSpec{}, ""); got != "" {
		t.Errorf("no network-config: vendor-data = %q, want none", got)
	}
	for _, want := range []string{"#cloud-config\n", "updates:\n  network:\n    when: [boot-new-instance, boot, hotplug]\n"} {
		if !strings.Contains(NetworkUpdatesVendorData, want) {
			t.Errorf("vendor-data %q lacks %q", NetworkUpdatesVendorData, want)
		}
	}
}

// GenerateISO writes the vendor-data it is given; RebuildISO sets it with
// the network-config and still keeps meta-data and user-data byte for byte.
//
// Mutation: drop the vendor-data file from writeISO — red; keep the old
// vendor-data on a rebuild — red.
func TestRebuildISO_SetsVendorData(t *testing.T) {
	if _, err := exec.LookPath("genisoimage"); err != nil {
		t.Skip("genisoimage not installed")
	}
	path := filepath.Join(t.TempDir(), "vd.iso")
	if err := GenerateISO(Config{InstanceID: "vd-first", LocalHostname: "vd", UserData: "#cloud-config\nhostname: vd\n",
		NetworkConfig: "version: 1\nconfig: []\n"}, path); err != nil {
		t.Fatal(err)
	}
	if s, err := ReadSeed(path); err != nil || s.VendorData != "" {
		t.Fatalf("a seed written without vendor-data: %+v, %v", s, err)
	}
	if changed, err := RebuildISO(path, "version: 1\nconfig: []\n", NetworkUpdatesVendorData); err != nil || !changed {
		t.Fatalf("adding vendor-data: RebuildISO = %v, %v", changed, err)
	}
	s, err := ReadSeed(path)
	if err != nil {
		t.Fatal(err)
	}
	if s.VendorData != NetworkUpdatesVendorData || s.InstanceID() != "vd-first" || s.UserData != "#cloud-config\nhostname: vd\n" {
		t.Errorf("after the rebuild: %+v", s)
	}
	path2 := filepath.Join(t.TempDir(), "vd2.iso")
	if err := GenerateISO(Config{InstanceID: "vd2", LocalHostname: "vd2", VendorData: NetworkUpdatesVendorData}, path2); err != nil {
		t.Fatal(err)
	}
	if s, err := ReadSeed(path2); err != nil || s.VendorData != NetworkUpdatesVendorData {
		t.Errorf("GenerateISO dropped the vendor-data: %+v, %v", s, err)
	}
}
