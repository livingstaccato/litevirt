// Fleet scenarios for console passwords, review round 1: an older peer holds
// the latch off (I2), and a host whose QEMU cannot do VNC passwords — a
// FIPS-mode host — never fails a start or an incoming live migration (C1).
package fleet

import (
	"context"
	"errors"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// TestFleet_ConsolePassword_AnOlderPeerHoldsTheLatchOff (review I2): one host
// does not advertise console_password_v1 — a previous-release build. With a
// real gate, split_brain_gate_v1 latches but console_password_v1 does not, and
// a create on an up-to-date host with the flag on gets NO password: the older
// host could be handed the guest and relays the console raw. The same holds
// with the older host parked in maintenance, which does not vote but still
// receives replication (ReplicationGated).
//
// Mutation "policy checks Latched(SplitBrainGateV1)" — red in both.
// Mutation "console_password_v1 not ReplicationGated" — red in maintenance.
func TestFleet_ConsolePassword_AnOlderPeerHoldsTheLatchOff(t *testing.T) {
	for _, maintenance := range []bool{false, true} {
		name := "active"
		if maintenance {
			name = "maintenance"
		}
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			c := New(t, Options{Nodes: 3, SharedCRDT: true})
			a, old := c.Nodes[0], c.Nodes[2]
			for _, n := range c.Nodes {
				setHostCapacity(t, c, n.Name, 64, 65536)
				n.Server.SetConsolePassword(true)
			}
			if maintenance {
				if err := corrosion.UpdateHostState(ctx, a.DB, old.Name, "maintenance"); err != nil {
					t.Fatal(err)
				}
			}
			var held atomic.Bool
			held.Store(true)
			gates := gateAll(t, c)
			for _, n := range c.Nodes {
				node := n
				peers := map[string]bool{}
				for _, o := range c.Nodes {
					if o != node {
						peers[o.Name] = true
					}
				}
				gates[node.Name].SeedPeersForTests(peers)
				gates[node.Name].SetPeerPinger(func(ctx context.Context, host string) ([]string, time.Time, error) {
					caps, wall, err := node.Server.PeerCapabilities(ctx, host)
					if held.Load() && host == old.Name {
						caps = withoutToken(caps, capabilities.ConsolePasswordV1)
					}
					return caps, wall, err
				})
			}
			if !gates[a.Name].Enforced(ctx, capabilities.SplitBrainGateV1) {
				t.Fatal("fixture: split_brain_gate_v1 did not latch")
			}
			if gates[a.Name].Enforced(ctx, capabilities.ConsolePasswordV1) {
				t.Fatalf("console_password_v1 latched across %s, which does not advertise it", old.Name)
			}
			createConsoleVM(t, c, a, "web", a.Name, true)
			for _, kind := range []string{"vnc", "spice"} {
				if pw := consolePassword(t, a, "web", kind); pw != "" {
					t.Fatalf("a %s password was set while %s (%s) cannot present one", kind, old.Name, name)
				}
			}
			// The control: once the older host advertises it, the latch forms
			// and the next create gets passwords.
			held.Store(false)
			eventually(t, 20*time.Second, "console_password_v1 latches once every host advertises it", func() bool {
				return gates[a.Name].Enforced(ctx, capabilities.ConsolePasswordV1)
			})
			createConsoleVM(t, c, a, "web2", a.Name, false)
			if consolePassword(t, a, "web2", "vnc") == "" {
				t.Fatal("no password after the latch formed: the scenario proves nothing")
			}
		})
	}
}

// desRefusal is QEMU refusing a VNC password on a FIPS-mode host.
var desRefusal = errors.New("internal error: process exited while connecting to monitor: " +
	"qemu-system-x86_64: -vnc unix:/run/libvirt/qemu/vnc.sock,password=on: Cipher backend does not support DES algorithm")

// refuseVNCPassword makes n's QEMU refuse every start whose definition has a
// VNC password, as a FIPS-mode host's does.
func refuseVNCPassword(n *Node) {
	n.Virt.FailStartDomain = func(name string) error {
		if pw, _ := lv.ConsolePasswordFromXML(n.Virt.DefinedXML(name), "vnc"); pw != "" {
			return desRefusal
		}
		return nil
	}
}

// TestFleet_ConsolePassword_AFIPSHostNeverFailsAStart (review C1): the latch
// has formed and the host's flag is on, but its QEMU cannot do VNC passwords
// and its probe has not said so. The create still runs the guest — the start
// backstop retries without the passwords — and from then on the host sets no
// VNC password (SPICE keeps its own) and reports console_password_v1 in
// not_enforcing.
//
// Mutation "no start backstop" — red.
func TestFleet_ConsolePassword_AFIPSHostNeverFailsAStart(t *testing.T) {
	c := consoleCluster(t)
	fips := c.Nodes[1]
	refuseVNCPassword(fips)

	createConsoleVM(t, c, c.Nodes[0], "first", fips.Name, true)
	if st, _ := fips.Virt.RawState("first"); st != libvirtfake.StateRunning {
		t.Fatalf("the guest is %q on the FIPS host, want running: the console password failed its start", st)
	}
	if fips.Virt.VNCPasswordUnavailable() == "" {
		t.Fatal("the host was not marked unable to do VNC passwords after QEMU refused one")
	}
	createConsoleVM(t, c, c.Nodes[0], "second", fips.Name, true)
	if pw := consolePassword(t, fips, "second", "vnc"); pw != "" {
		t.Error("the FIPS host set a VNC password again after QEMU refused one")
	}
	if pw := consolePassword(t, fips, "second", "spice"); pw == "" {
		t.Error("the FIPS host stopped setting SPICE passwords too")
	}
	if !slices.Contains(fips.Server.NotEnforcingTokensForTests(), capabilities.ConsolePasswordV1) {
		t.Error("the FIPS host does not report console_password_v1 in not_enforcing")
	}
}

// TestFleet_ConsolePassword_LiveMigrationOntoAFIPSHost (review C1): the
// target says (EnsureDisks) its QEMU cannot do VNC passwords, so the source
// hands libvirt a destination definition without the guest's VNC password
// (SPICE kept), and the move succeeds instead of failing at the target's
// QEMU launch.
//
// Mutation "source ignores the target's answer" — red.
func TestFleet_ConsolePassword_LiveMigrationOntoAFIPSHost(t *testing.T) {
	c := consoleCluster(t)
	src, dst := c.Nodes[0], c.Nodes[1]
	createConsoleVM(t, c, src, "desk", src.Name, true)
	spice := consolePassword(t, src, "desk", "spice")
	if consolePassword(t, src, "desk", "vnc") == "" || spice == "" {
		t.Fatal("fixture: the guest has no console passwords")
	}
	dst.Virt.SetVNCPasswordUnavailable("qemu-kvm refuses VNC password authentication: Cipher backend does not support DES algorithm")

	var landed string
	src.Virt.OnMigrateToTarget = func(name, _ string, p lv.MigrateParams) error {
		x := p.DestXML
		if x == "" {
			var err error
			if x, err = src.Virt.DumpXMLSecure(name); err != nil {
				return err
			}
		}
		// The target's QEMU launch, which refuses a VNC password.
		if pw, _ := lv.ConsolePasswordFromXML(x, "vnc"); pw != "" {
			return desRefusal
		}
		landed = x
		dst.Virt.LandMigrated(x)
		src.Virt.VanishDomain(name)
		return nil
	}
	if err := migrateAt(t, c, src, "desk", dst.Name); err != nil {
		t.Fatalf("live migration onto a host that cannot do VNC passwords: %v", err)
	}
	if landed == "" {
		t.Fatal("the guest did not land")
	}
	if got := consolePassword(t, dst, "desk", "spice"); got != spice {
		t.Error("the guest lost its SPICE password on the way")
	}
	if got := consolePassword(t, dst, "desk", "vnc"); got != "" {
		t.Error("the guest kept its VNC password on a host that cannot do one")
	}
}
