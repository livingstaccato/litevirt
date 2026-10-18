package fleet

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// A dedicated migration network (migration.network, migration_network.go): the
// source asks the target, in EnsureDisks, for its address inside the network,
// and the migration's DATA goes there, while libvirt's control connection and
// the name the certificate is checked against stay on the cluster address
// (every fleet node is 127.0.0.1, so the two are told apart by value).

// onMigrationNet gives n an address in 10.9.0.0/24 and turns the network on for
// the source side of every move it sends.
func onMigrationNet(n *Node, host byte, enable bool) {
	n.Server.SetLocalIPsForTest(func() ([]net.IP, error) {
		return []net.IP{net.IPv4(127, 0, 0, 1), net.IPv4(10, 9, 0, host)}, nil
	})
	if enable {
		n.Server.SetMigrationNetwork("10.9.0.0/24")
	}
}

func hasMigrationFallbackEvent(t *testing.T, n *Node, vm string) bool {
	t.Helper()
	evs, err := corrosion.ListVMEvents(context.Background(), n.DB, vm, 50, "")
	if err != nil {
		t.Fatalf("ListVMEvents: %v", err)
	}
	for _, e := range evs {
		if e.Type == "vm.migrate.network_fallback" {
			return true
		}
	}
	return false
}

// A storage copy goes to the target's migration address; the control
// connection and the certificate name stay on the cluster address.
//
// Mutation: in migrateOwnedVM use targetHost.Address instead of route.addr for
// TargetAddress — the note records addr=127.0.0.1.
func TestFleet_MigrationNetwork_StorageCopyGoesToTheMigrationAddress(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	defer c.Stop()
	src, dst := c.Nodes[0], c.Nodes[1]
	migrationTLSReady(src, true)
	migrationTLSReady(dst, true)
	onMigrationNet(src, 1, true)
	onMigrationNet(dst, 2, false)

	storageMigrationVM(t, src, filepath.Join(c.tmpRoot, dst.Name, "data", "disks", "pp1-root.qcow2"), 1<<30)
	if err := runStorageMigration(t, c, src, dst.Name); err != nil {
		t.Fatalf("migration: %v", err)
	}
	note := lastMigrateNote(src)
	for _, want := range []string{"addr=10.9.0.2", "tls=true", "tls_dest=127.0.0.1", "to=qemu+tls://127.0.0.1/system"} {
		if !strings.Contains(note, want) {
			t.Errorf("libvirt migrate = %q; want it to contain %q", note, want)
		}
	}
	if hasMigrationFallbackEvent(t, src, "pp1") {
		t.Errorf("a migration that used the network recorded a fallback warning")
	}
}

// A memory-only move leaves libvirt's tunnel for QEMU's own TLS stream, to the
// migration address, when both hosts hold migration-TLS credentials.
//
// Mutation: drop `Direct: route.direct` from the MigrateParams — direct=false.
func TestFleet_MigrationNetwork_MemoryOnlyLeavesTheTunnelWhenBothHostsHaveTLS(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	defer c.Stop()
	src, dst := c.Nodes[0], c.Nodes[1]
	migrationTLSReady(src, true)
	migrationTLSReady(dst, true)
	onMigrationNet(src, 1, true)
	onMigrationNet(dst, 2, false)
	seedRunningVM(t, c, src, "mem1", "", 1, 256)

	if err := migrateAt(t, c, src, "mem1", dst.Name); err != nil {
		t.Fatalf("migration: %v", err)
	}
	note := lastMigrateNote(src)
	for _, want := range []string{"addr=10.9.0.2", "direct=true", "tls=true", "tls_dest=127.0.0.1"} {
		if !strings.Contains(note, want) {
			t.Errorf("libvirt migrate = %q; want it to contain %q", note, want)
		}
	}
}

// Without credentials on the target the memory would cross the network in
// plaintext, so the move stays in the tunnel on the cluster address and says so.
//
// Mutation: drop the `!bothTLS` branch in chooseMigrationRoute — direct=true
// with tls=false is requested of a target that cannot decrypt it.
func TestFleet_MigrationNetwork_MemoryOnlyStaysTunnelledWithoutTLS(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	defer c.Stop()
	src, dst := c.Nodes[0], c.Nodes[1]
	migrationTLSReady(src, true)
	migrationTLSReady(dst, false)
	onMigrationNet(src, 1, true)
	onMigrationNet(dst, 2, false)
	seedRunningVM(t, c, src, "mem2", "", 1, 256)

	if err := migrateAt(t, c, src, "mem2", dst.Name); err != nil {
		t.Fatalf("a migration must not be refused for want of the network: %v", err)
	}
	note := lastMigrateNote(src)
	if !strings.Contains(note, "direct=false") || !strings.Contains(note, "addr=127.0.0.1") {
		t.Errorf("libvirt migrate = %q; want the tunnel on the cluster address", note)
	}
	if !hasMigrationFallbackEvent(t, src, "mem2") {
		t.Errorf("no fallback warning on the VM's events")
	}
}

// A target with no address in the network is moved over the cluster address,
// with the warning.
//
// Mutation: treat an empty answer as success in chooseMigrationRoute — the
// migration is sent to tcp:// with an empty authority.
func TestFleet_MigrationNetwork_TargetWithoutAnAddressFallsBack(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	defer c.Stop()
	src, dst := c.Nodes[0], c.Nodes[1]
	migrationTLSReady(src, true)
	migrationTLSReady(dst, true)
	onMigrationNet(src, 1, true)
	dst.Server.SetLocalIPsForTest(func() ([]net.IP, error) { return []net.IP{net.IPv4(127, 0, 0, 1)}, nil })
	storageMigrationVM(t, src, filepath.Join(c.tmpRoot, dst.Name, "data", "disks", "pp1-root.qcow2"), 1<<30)

	if err := runStorageMigration(t, c, src, dst.Name); err != nil {
		t.Fatalf("migration: %v", err)
	}
	if note := lastMigrateNote(src); !strings.Contains(note, "addr=127.0.0.1") {
		t.Errorf("libvirt migrate = %q; want the cluster address", note)
	}
	if !hasMigrationFallbackEvent(t, src, "pp1") {
		t.Errorf("no fallback warning on the VM's events")
	}
}

// Control: no network configured, nothing changes — and nothing is warned.
func TestFleet_MigrationNetwork_UnsetChangesNothing(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	defer c.Stop()
	src, dst := c.Nodes[0], c.Nodes[1]
	migrationTLSReady(src, true)
	migrationTLSReady(dst, true)
	onMigrationNet(dst, 2, false)
	seedRunningVM(t, c, src, "mem3", "", 1, 256)

	if err := migrateAt(t, c, src, "mem3", dst.Name); err != nil {
		t.Fatalf("migration: %v", err)
	}
	note := lastMigrateNote(src)
	if !strings.Contains(note, "direct=false") || !strings.Contains(note, "tls=false") || !strings.Contains(note, "addr=127.0.0.1") {
		t.Errorf("libvirt migrate = %q; want the tunnel, as before", note)
	}
	if hasMigrationFallbackEvent(t, src, "mem3") {
		t.Errorf("a cluster with no migration network was warned about it")
	}
}

// A source with no address in the network sends nothing to the target's
// address there: the default route would carry it. The move falls back with the
// warning.
//
// Mutation: drop the source-address check in chooseMigrationRoute - the note
// records addr=10.9.0.2.
func TestFleet_MigrationNetwork_SourceWithoutAnAddressFallsBack(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	defer c.Stop()
	src, dst := c.Nodes[0], c.Nodes[1]
	migrationTLSReady(src, true)
	migrationTLSReady(dst, true)
	onMigrationNet(dst, 2, false)
	src.Server.SetLocalIPsForTest(func() ([]net.IP, error) { return []net.IP{net.IPv4(127, 0, 0, 1)}, nil })
	src.Server.SetMigrationNetwork("10.9.0.0/24")
	storageMigrationVM(t, src, filepath.Join(c.tmpRoot, dst.Name, "data", "disks", "pp1-root.qcow2"), 1<<30)

	if err := runStorageMigration(t, c, src, dst.Name); err != nil {
		t.Fatalf("migration: %v", err)
	}
	if note := lastMigrateNote(src); !strings.Contains(note, "addr=127.0.0.1") {
		t.Errorf("libvirt migrate = %q; want the cluster address", note)
	}
	if !hasMigrationFallbackEvent(t, src, "pp1") {
		t.Errorf("no fallback warning on the VM's events")
	}
}

// An unencrypted storage copy (the operator allowed it) never goes onto the
// migration network: it stays where a main build kept it.
//
// Mutation: choose the migration address for an unencrypted storage copy - the
// note records addr=10.9.0.2 with tls=false.
func TestFleet_MigrationNetwork_UnencryptedStorageCopyStaysOnTheClusterAddress(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	defer c.Stop()
	src, dst := c.Nodes[0], c.Nodes[1]
	migrationTLSReady(src, false)
	migrationTLSReady(dst, false)
	src.Server.SetAllowUnencryptedStorageMigration(true)
	onMigrationNet(src, 1, true)
	onMigrationNet(dst, 2, false)
	storageMigrationVM(t, src, filepath.Join(c.tmpRoot, dst.Name, "data", "disks", "pp1-root.qcow2"), 1<<30)

	if err := runStorageMigration(t, c, src, dst.Name); err != nil {
		t.Fatalf("migration: %v", err)
	}
	note := lastMigrateNote(src)
	if !strings.Contains(note, "tls=false") || !strings.Contains(note, "addr=127.0.0.1") {
		t.Errorf("libvirt migrate = %q; want the cluster address, unencrypted, as on main", note)
	}
	if !hasMigrationFallbackEvent(t, src, "pp1") {
		t.Errorf("no warning that the copy stayed off the migration network")
	}
}

// A cold move's disk stream (a stopped VM's migration, a drain's cold move, the
// clone copy) is dialed at the target's migration address, and the bytes still
// arrive.
//
// Mutation: drop `abort.diskAddr = route.addr` - the dial seam is never asked.
func TestFleet_MigrationNetwork_ColdDiskStreamUsesTheMigrationAddress(t *testing.T) {
	sc := newColdStoppedScenario(t)
	onMigrationNet(sc.src, 1, true)
	onMigrationNet(sc.dst, 2, false)
	var asked []string
	sc.src.Server.SetMigrationDialForTest(func(ctx context.Context, host, addr string) (pb.LiteVirtClient, func(), error) {
		asked = append(asked, host+"@"+addr)
		return sc.c.PeerClient(sc.src, sc.dst), func() {}, nil
	})
	if err := sc.migrateCold(t); err != nil {
		t.Fatalf("cold migration: %v", err)
	}
	if len(asked) != 1 || asked[0] != sc.dst.Name+"@10.9.0.2" {
		t.Fatalf("the disk stream was dialed at %v, want %s@10.9.0.2", asked, sc.dst.Name)
	}
	if got, err := os.ReadFile(sc.file(sc.dst, sc.disk)); err != nil || string(got) != string(sc.payload) {
		t.Errorf("the disk did not arrive intact (err %v)", err)
	}
	if hasMigrationFallbackEvent(t, sc.src, "os1") {
		t.Errorf("a move that used the network recorded a fallback")
	}
}

// A migration address that does not answer is a warning, not a refusal: the
// disk stream goes to the cluster address.
//
// Mutation: return the dial error from dialColdPeer instead of falling back -
// the migration fails.
func TestFleet_MigrationNetwork_ColdDiskStreamFallsBackWhenTheNetworkIsDown(t *testing.T) {
	sc := newColdStoppedScenario(t)
	onMigrationNet(sc.src, 1, true)
	onMigrationNet(sc.dst, 2, false)
	sc.src.Server.SetMigrationDialForTest(func(ctx context.Context, host, addr string) (pb.LiteVirtClient, func(), error) {
		return nil, nil, errors.New("no route to host")
	})
	if err := sc.migrateCold(t); err != nil {
		t.Fatalf("a down migration network must not refuse the move: %v", err)
	}
	if got, err := os.ReadFile(sc.file(sc.dst, sc.disk)); err != nil || string(got) != string(sc.payload) {
		t.Errorf("the disk did not arrive intact (err %v)", err)
	}
	if !hasMigrationFallbackEvent(t, sc.src, "os1") {
		t.Errorf("no fallback warning on the VM's events")
	}
}

// Both hosts are ready for migration TLS, but their credentials come from
// different migration CAs: QEMU's own TLS stream would fail its handshake.
// A memory-only move, by `lv migrate` or by a drain, treats that as not
// ready and stays in libvirt's tunnel on the cluster address. Either side
// reporting no CA (an older build) changes nothing: the move leaves the tunnel.
//
// Mutations: drop the CA comparison from the memory route in migrateOwnedVM
// (the migrate case) or in drainOneVM (the drain case) — direct=true is
// requested, and that case goes red. Treat an unreported CA as a mismatch —
// the "target does not say" cases go red.
func TestFleet_MigrationNetwork_MemoryOnlyStaysTunnelledWhenTheMigrationCAsDiffer(t *testing.T) {
	for _, tc := range []struct {
		name       string
		dstCA      string
		drain      bool
		wantDirect bool
	}{
		{"migrate, different CAs", "bbbb2222", false, false},
		{"drain, different CAs", "bbbb2222", true, false},
		{"migrate, target does not say", "", false, true},
		{"drain, target does not say", "", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := New(t, Options{Nodes: 2, SharedCRDT: true})
			defer c.Stop()
			src, dst := c.Nodes[0], c.Nodes[1]
			for _, n := range c.Nodes {
				setHostCapacity(t, c, n.Name, 64, 65536)
			}
			migrationTLSReady(src, true)
			migrationTLSReady(dst, true)
			migrationCA(src, "aaaa1111")
			migrationCA(dst, tc.dstCA)
			onMigrationNet(src, 1, true)
			onMigrationNet(dst, 2, false)
			seedRunningVM(t, c, src, "mem3", "", 1, 256)

			var err error
			if tc.drain {
				_, err = drainAll(t, c, src)
			} else {
				err = migrateAt(t, c, src, "mem3", dst.Name)
			}
			if err != nil {
				t.Fatalf("the move was refused: %v", err)
			}
			note := lastMigrateNote(src)
			if tc.wantDirect {
				if !strings.Contains(note, "direct=true") || !strings.Contains(note, "addr=10.9.0.2") {
					t.Fatalf("libvirt migrate = %q; want QEMU's own TLS stream to the migration address", note)
				}
				return
			}
			// The tunnel: libvirt's own connection to the cluster address (a
			// drain names no data address for it; `lv migrate` names that one).
			if !strings.Contains(note, "direct=false") || strings.Contains(note, "addr=10.9.0.2") {
				t.Fatalf("libvirt migrate = %q; want the tunnel on the cluster address (the CAs differ)", note)
			}
		})
	}
}

// drainAll drains n and returns every frame, and the stream's end.
func drainAll(t *testing.T, c *Cluster, n *Node) ([]*pb.DrainProgress, error) {
	t.Helper()
	st, err := c.SelfClient(n).DrainHost(context.Background(), &pb.DrainHostRequest{Name: n.Name})
	if err != nil {
		return nil, err
	}
	var all []*pb.DrainProgress
	for {
		p, rerr := st.Recv()
		if rerr == io.EOF {
			return all, nil
		}
		if rerr != nil {
			return all, rerr
		}
		all = append(all, p)
	}
}

// A source that cannot read its own migration CA does not leave the tunnel:
// it cannot tell the target's CA is its own.
//
// Mutation: read an unreadable CA as unknown — direct=true, red.
func TestFleet_MigrationNetwork_MemoryOnlyStaysTunnelledWhenTheSourceCannotReadItsMigrationCA(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	defer c.Stop()
	src, dst := c.Nodes[0], c.Nodes[1]
	migrationTLSReady(src, true)
	migrationTLSReady(dst, true)
	src.Server.SetMigrationCAFingerprint(func() (string, error) { return "", errors.New("unreadable") })
	migrationCA(dst, "bbbb2222")
	onMigrationNet(src, 1, true)
	onMigrationNet(dst, 2, false)
	seedRunningVM(t, c, src, "mem4", "", 1, 256)
	if err := migrateAt(t, c, src, "mem4", dst.Name); err != nil {
		t.Fatalf("migration: %v", err)
	}
	if note := lastMigrateNote(src); !strings.Contains(note, "direct=false") {
		t.Fatalf("libvirt migrate = %q; want the tunnel", note)
	}
}
