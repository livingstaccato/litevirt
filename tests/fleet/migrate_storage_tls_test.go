package fleet

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// A storage-copying migration is encrypted when both hosts have migration-TLS
// credentials installed for QEMU (pki_dir/migration, from the migration CA).
// The source asks the target, through EnsureDisks, to install its own and say
// whether it could. Only when both are ready does libvirt get VIR_MIGRATE_TLS;
// otherwise the plaintext guard (migration.allow_unencrypted_storage) decides.

// migrationTLSReady makes n report its migration-TLS install as ready or not.
// The fleet has no QEMU, so the install itself is internal/pki's to test.
func migrationTLSReady(n *Node, ready bool) {
	n.Server.SetMigrationTLS(func() (bool, error) { return ready, nil })
}

// lastMigrateNote is the libvirt migrate call src recorded, or "".
func lastMigrateNote(n *Node) string {
	note := ""
	for _, e := range n.Virt.EventLog() {
		if e.Op == "migrate" {
			note = e.Note
		}
	}
	return note
}

func runStorageMigration(t *testing.T, c *Cluster, src *Node, target string) error {
	t.Helper()
	st, err := c.SelfClient(src).MigrateVM(context.Background(), &pb.MigrateVMRequest{
		VmName: "pp1", TargetHost: target, Strategy: pb.MigrateStrategy_MIGRATE_LIVE, WithStorage: true,
	})
	if err != nil {
		return err
	}
	for {
		if _, err := st.Recv(); err == io.EOF {
			return nil
		} else if err != nil {
			return err
		}
	}
}

// Both hosts ready: the copy is encrypted, and it needs no plaintext opt-in.
//
// Mutation: drop TLS from the MigrateParams in MigrateVM — the migration is
// refused by the guard (allow is off) or, if it ran, records tls=false.
func TestFleet_StorageMigrationIsEncryptedWhenBothHostsHaveMigrationTLS(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	defer c.Stop()
	src, dst := c.Nodes[0], c.Nodes[1]
	migrationTLSReady(src, true)
	migrationTLSReady(dst, true)

	storageMigrationVM(t, src, filepath.Join(c.tmpRoot, dst.Name, "data", "disks", "pp1-root.qcow2"), 1<<30)
	if err := runStorageMigration(t, c, src, dst.Name); err != nil {
		t.Fatalf("an encrypted storage migration was refused: %v", err)
	}
	note := lastMigrateNote(src)
	if !strings.Contains(note, "with_storage=true") || !strings.Contains(note, "tls=true") {
		t.Fatalf("libvirt migrate = %q; want a storage copy with tls=true", note)
	}
	if strings.Contains(note, "tls_dest= ") || strings.HasSuffix(note, "tls_dest=") {
		t.Errorf("libvirt migrate = %q; tls_dest is empty, so the target's certificate "+
			"is checked against the wrong name", note)
	}
}

// The target has no migration TLS and plaintext is not allowed: refused, and
// the stubs the attempt created on the target are removed.
//
// Mutation: skip the target-readiness check — the migration runs with tls=true
// against a target QEMU has no credentials on (here: records a migrate call).
func TestFleet_StorageMigrationIsRefusedWhenTheTargetHasNoMigrationTLS(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	defer c.Stop()
	src, dst := c.Nodes[0], c.Nodes[1]
	migrationTLSReady(src, true)
	migrationTLSReady(dst, false)

	path := filepath.Join(c.tmpRoot, dst.Name, "data", "disks", "pp1-root.qcow2")
	storageMigrationVM(t, src, path, 1<<30)
	err := runStorageMigration(t, c, src, dst.Name)
	if err == nil {
		t.Fatal("the migration ran although the target cannot decrypt it and plaintext is not allowed")
	}
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), dst.Name) ||
		!strings.Contains(err.Error(), "install-migration-tls") {
		t.Fatalf("refusal = %v; want FailedPrecondition naming %s and `lv host install-migration-tls`", err, dst.Name)
	}
	if n := migrateCalls(src); n != 0 {
		t.Fatalf("the refused migration reached libvirt %d time(s)", n)
	}
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Errorf("the refused migration left its disk stub %s on the target (stat err %v)", path, statErr)
	}
}

// The target has no migration TLS but the source's operator allows plaintext:
// it runs, unencrypted, as before.
func TestFleet_StorageMigrationFallsBackToPlaintextOnlyWhenAllowed(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	defer c.Stop()
	src, dst := c.Nodes[0], c.Nodes[1]
	migrationTLSReady(src, true)
	migrationTLSReady(dst, false)
	src.Server.SetAllowUnencryptedStorageMigration(true)

	storageMigrationVM(t, src, filepath.Join(c.tmpRoot, dst.Name, "data", "disks", "pp1-root.qcow2"), 1<<30)
	if err := runStorageMigration(t, c, src, dst.Name); err != nil {
		t.Fatalf("an allowed plaintext fallback was refused: %v", err)
	}
	if note := lastMigrateNote(src); !strings.Contains(note, "tls=false") {
		t.Fatalf("libvirt migrate = %q; want tls=false (the target cannot do TLS)", note)
	}
}

// migrationCA makes n report fp as the fingerprint of the migration CA its
// QEMU credentials chain to ("" for none known, as an older build reports).
func migrationCA(n *Node, fp string) {
	n.Server.SetMigrationCAFingerprint(func() (string, error) { return fp, nil })
}

// Both hosts are ready, but their credentials come from different migration
// CAs: QEMU's TLS handshake would fail mid-copy. The readiness check compares
// the CAs and refuses first, naming both hosts and the command that reissues
// their credentials from one CA; the stubs the attempt created are removed.
//
// Mutation: skip the comparison — the migration reaches libvirt (a migrate
// call is recorded) and goes red.
func TestFleet_StorageMigrationIsRefusedWhenTheHostsHaveDifferentMigrationCAs(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	defer c.Stop()
	src, dst := c.Nodes[0], c.Nodes[1]
	migrationTLSReady(src, true)
	migrationTLSReady(dst, true)
	migrationCA(src, "aaaa1111")
	migrationCA(dst, "bbbb2222")
	// An allowed plaintext fallback does not excuse it: the hosts are
	// provisioned, wrongly, and the copy is not sent unencrypted instead.
	src.Server.SetAllowUnencryptedStorageMigration(true)

	path := filepath.Join(c.tmpRoot, dst.Name, "data", "disks", "pp1-root.qcow2")
	storageMigrationVM(t, src, path, 1<<30)
	err := runStorageMigration(t, c, src, dst.Name)
	if err == nil {
		t.Fatal("the migration ran although the hosts' migration credentials come from different CAs")
	}
	msg := err.Error()
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(msg, src.Name) || !strings.Contains(msg, dst.Name) ||
		!strings.Contains(msg, "aaaa1111") || !strings.Contains(msg, "bbbb2222") ||
		!strings.Contains(msg, "lv host install-migration-tls --reissue") {
		t.Fatalf("refusal = %v; want FailedPrecondition naming %s and %s, both fingerprints, and `lv host install-migration-tls --reissue`",
			err, src.Name, dst.Name)
	}
	if n := migrateCalls(src); n != 0 {
		t.Fatalf("the refused migration reached libvirt %d time(s)", n)
	}
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Errorf("the refused migration left its disk stub %s on the target (stat err %v)", path, statErr)
	}
}

// The same migration CA on both hosts, or a target that does not say which
// (an older build): the encrypted copy runs, as before.
//
// Mutation: refuse when the target names no CA — the second case goes red.
func TestFleet_StorageMigrationRunsWhenTheMigrationCAsMatchOrTheTargetDoesNotSay(t *testing.T) {
	for _, tc := range []struct{ name, dstCA string }{{"same CA", "aaaa1111"}, {"target does not say", ""}} {
		t.Run(tc.name, func(t *testing.T) {
			c := New(t, Options{Nodes: 2, SharedCRDT: true})
			defer c.Stop()
			src, dst := c.Nodes[0], c.Nodes[1]
			migrationTLSReady(src, true)
			migrationTLSReady(dst, true)
			migrationCA(src, "aaaa1111")
			migrationCA(dst, tc.dstCA)

			storageMigrationVM(t, src, filepath.Join(c.tmpRoot, dst.Name, "data", "disks", "pp1-root.qcow2"), 1<<30)
			if err := runStorageMigration(t, c, src, dst.Name); err != nil {
				t.Fatalf("the storage migration was refused: %v", err)
			}
			if note := lastMigrateNote(src); !strings.Contains(note, "tls=true") {
				t.Fatalf("libvirt migrate = %q; want tls=true", note)
			}
		})
	}
}
