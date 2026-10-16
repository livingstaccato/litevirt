package cloudinit

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// T2 concern 2: a host with no readable seed of the VM (a failover or a
// migration to a host it never ran on) named the NICs by their position, so
// after a detach and an attach the NICs the guest had were renamed at the next
// boot (detach A of [A, B] and attach C: B eth1 -> eth0, C eth2 -> eth1).
// A NIC's name is derived from what the cluster records: the name the VM's
// create gave a spec NIC, eth<ordinal> for one attached since. So the seed a
// host without one writes names every NIC as the seed rebuilt at each attach
// and detach does, and so does a host holding a copy of the seed from before
// the latest attaches (Stale).
//
// Mutation: name the NICs by position again with no prior (the round-5 code)
// — red at the first detach; name an attached NIC the lowest free eth<n>
// rather than eth<ordinal> — the chain and the derivation disagree after a
// detach and an attach; treat a NIC a stale seed does not list as unnamed —
// the stale case goes red.
func TestSeedNetworkConfig_NamesNeedNoSeed(t *testing.T) {
	nets := []string{"stnet", "dnet", "isonet"}
	for run := int64(1); run <= 12; run++ {
		t.Run(fmt.Sprint(run), func(t *testing.T) {
			rng := rand.New(rand.NewSource(run))
			db, spec := hotplugSeedDB(t) // A(stnet, 10.5.0.50) ord0, B(dnet) ord1
			ctx := context.Background()
			derive := func(prior *Prior) string {
				t.Helper()
				got, err := SeedNetworkConfig(ctx, db, "hp", spec, prior)
				if err != nil {
					t.Fatal(err)
				}
				return got
			}
			chain := derive(nil) // the seed create wrote
			history := []string{chain}
			live := []string{"52:54:00:00:0a:0a", "52:54:00:00:0b:0b"}
			next := 2
			var ops []string
			for step := 0; step < 10; step++ {
				if len(live) > 1 && rng.Intn(2) == 0 {
					i := rng.Intn(len(live))
					mac := live[i]
					live = append(live[:i:i], live[i+1:]...)
					hotDetachRows(t, db, true, mac)
					ops = append(ops, "detach "+mac)
					chain = derive(PriorFrom(chain))
				} else {
					mac := fmt.Sprintf("52:54:00:10:%02x:%02x", run, step)
					hotAttachRows(t, db, true, nets[rng.Intn(len(nets))], mac, next)
					next++
					live = append(live, mac)
					ops = append(ops, "attach "+mac)
					chain = derive(PriorFrom(chain, mac))
				}
				if got := derive(nil); got != chain {
					t.Fatalf("after %v, a host with no seed writes\n%s\nwant the seed each attach and detach rebuilt\n%s", ops, got, chain)
				}
				for j, old := range history {
					stale := PriorFrom(old)
					stale.Stale = true
					if got := derive(stale); got != chain {
						t.Fatalf("after %v, a host holding the seed of step %d writes\n%s\nwant\n%s", ops, j, got, chain)
					}
				}
				history = append(history, chain)
			}
		})
	}
}

// The case the review names, spelled out: [A, B] created, A detached, C
// attached; a host with no seed keeps B eth1 and gives C eth2.
//
// Mutation: name by position with no prior — B eth0, C eth1.
func TestSeedNetworkConfig_DetachAttachKeepsNamesWithoutASeed(t *testing.T) {
	db, spec := hotplugSeedDB(t)
	hotDetachRows(t, db, true, "52:54:00:00:0a:0a")
	hotAttachRows(t, db, true, "dnet", "52:54:00:00:0c:0c", 2)
	got, err := SeedNetworkConfig(context.Background(), db, "hp", spec, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, namedEntry("eth1", "52:54:00:00:0b:0b")) || !strings.Contains(got, namedEntry("eth2", "52:54:00:00:0c:0c")) {
		t.Errorf("want B eth1 and C eth2:\n%s", got)
	}
}

// The one NIC a detach leaves of several keeps the name its create gave it:
// a seed with no network-config would have cloud-init drop the rename at the
// next boot. A VM created with one NIC still gets none.
//
// Mutation: write no network-config for one DHCP NIC whatever its name — B's
// seed is "".
func TestSeedNetworkConfig_TheLastNICKeepsItsName(t *testing.T) {
	db, spec := hotplugSeedDB(t)
	hotDetachRows(t, db, true, "52:54:00:00:0a:0a")
	got, err := SeedNetworkConfig(context.Background(), db, "hp", spec, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, namedEntry("eth1", "52:54:00:00:0b:0b")+"    dhcp4: true\n") {
		t.Errorf("want B, the NIC left, still eth1:\n%s", got)
	}
	one := &pb.VMSpec{Name: "hp", Network: spec.Network[1:]} // created with B alone
	if got, err := SeedNetworkConfig(context.Background(), db, "hp", one, nil); err != nil || got != "" {
		t.Errorf("a VM created with one DHCP NIC: %q, %v; want no network-config", got, err)
	}
}

// A VM nothing was attached to or detached from gets the document create
// wrote, byte for byte, here a V1 one beside a NIC with nothing to configure
// (a host-isolated network with no subnet): that NIC, unnamed, does not make
// the document V2.
//
// Mutation: count a NIC the document does not write as unnamed — V2.
func TestSeedNetworkConfig_UntouchedVMIsTheCreateDocument(t *testing.T) {
	ctx := context.Background()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	for name, def := range map[string]compose.NetworkDef{
		"s1":  {Type: "bridge", Subnet: "10.8.0.0/24"},
		"hin": {Type: "bridge", HostIsolation: true},
		"s2":  {Type: "bridge", Subnet: "10.9.0.0/24"},
	} {
		cfg, _ := json.Marshal(def)
		if err := corrosion.UpsertNetwork(ctx, db, corrosion.NetworkRecord{Name: name, Type: def.Type, Config: string(cfg)}); err != nil {
			t.Fatal(err)
		}
	}
	spec := &pb.VMSpec{Name: "u", Network: []*pb.NetworkAttachment{
		{Name: "s1", Mac: "52:54:00:00:01:01", Ip: "10.8.0.5"},
		{Name: "hin", Mac: "52:54:00:00:02:02"},
		{Name: "s2", Mac: "52:54:00:00:03:03", Ip: "10.9.0.5"},
	}}
	var ifaces []corrosion.InterfaceRecord
	var create []NIC
	for i, n := range spec.Network {
		ifaces = append(ifaces, corrosion.InterfaceRecord{VMName: "u", NetworkName: n.Name, Ordinal: i, MAC: n.Mac, IP: n.Ip})
		def, _ := NetworkDef(ctx, db, n.Name)
		create = append(create, NIC{Ordinal: i, MAC: n.Mac, IP: n.Ip, Net: def})
	}
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{Name: "u", HostName: "h", Spec: "{}", State: "running"}, ifaces, nil); err != nil {
		t.Fatal(err)
	}
	want := NetworkConfig(create)
	if !strings.HasPrefix(want, "version: 1\n") {
		t.Fatalf("setup: create's document is not V1:\n%s", want)
	}
	if got, err := SeedNetworkConfig(ctx, db, "u", spec, nil); err != nil || got != want {
		t.Errorf("rebuilt with no seed:\n%s\nwant create's:\n%s (err %v)", got, want, err)
	}
}

// A NIC detached and attached again with the same MAC has a new ordinal and
// a new name (eth3, not the eth2 it had). A host holding the seed from before
// the detach names it eth3 too, not by the stale seed's entry.
//
// Mutation: keep every name a stale seed lists — C stays eth2 there.
func TestSeedNetworkConfig_ReattachedMACIsNamedAnewOverAStaleSeed(t *testing.T) {
	db, spec := hotplugSeedDB(t)
	ctx := context.Background()
	const macC = "52:54:00:00:0c:0c"
	hotAttachRows(t, db, true, "dnet", macC, 2)
	before, err := SeedNetworkConfig(ctx, db, "hp", spec, nil)
	if err != nil || !strings.Contains(before, namedEntry("eth2", macC)) {
		t.Fatalf("setup: C is not eth2: %v\n%s", err, before)
	}
	hotDetachRows(t, db, true, macC)
	hotAttachRows(t, db, true, "dnet", macC, 3)
	stale := PriorFrom(before)
	stale.Stale = true
	for name, prior := range map[string]*Prior{"no seed": nil, "the seed from before the detach": stale} {
		got, err := SeedNetworkConfig(ctx, db, "hp", spec, prior)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(got, namedEntry("eth3", macC)) {
			t.Errorf("%s: want the attached-again C eth3:\n%s", name, got)
		}
	}
}
