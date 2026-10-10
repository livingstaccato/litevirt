package fleet

import (
	"context"
	"net"
	"path/filepath"
	"strings"
	"testing"

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
