package fleet

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/pki"
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
	c.openClusterPolicyGate()
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
	c.openClusterPolicyGate()
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
	c.openClusterPolicyGate()
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
	c.openClusterPolicyGate()
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
			c.openClusterPolicyGate()
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

// The source is ready for migration TLS but cannot read its own migration CA
// (a corrupted ca.crt). It is not an older build, so it does not skip the
// comparison: it refuses the storage copy, naming the problem and the fix,
// rather than letting it fail at QEMU's handshake mid-copy.
//
// Mutation: read an unreadable CA as unknown — the copy runs, and goes red.
func TestFleet_StorageMigrationIsRefusedWhenTheSourceCannotReadItsMigrationCA(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	c.openClusterPolicyGate()
	defer c.Stop()
	src, dst := c.Nodes[0], c.Nodes[1]
	migrationTLSReady(src, true)
	migrationTLSReady(dst, true)
	src.Server.SetMigrationCAFingerprint(func() (string, error) { return "", errors.New("ca.crt holds no PEM certificate") })
	migrationCA(dst, "bbbb2222")

	path := filepath.Join(c.tmpRoot, dst.Name, "data", "disks", "pp1-root.qcow2")
	storageMigrationVM(t, src, path, 1<<30)
	err := runStorageMigration(t, c, src, dst.Name)
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), src.Name) ||
		!strings.Contains(err.Error(), "ca.crt holds no PEM certificate") ||
		!strings.Contains(err.Error(), "lv host install-migration-tls --reissue") {
		t.Fatalf("migration = %v; want FailedPrecondition naming %s, the CA error and `lv host install-migration-tls --reissue`", err, src.Name)
	}
	if n := migrateCalls(src); n != 0 {
		t.Fatalf("the refused migration reached libvirt %d time(s)", n)
	}
}

// migrationTLSInvalid makes n hold migration credentials it cannot use (a CA
// that is not a certificate, a directory where a file should be).
func migrationTLSInvalid(n *Node, why string) {
	n.Server.SetMigrationTLS(func() (bool, error) {
		return false, fmt.Errorf("%w: %s", pki.ErrInvalidMigrationCredentials, why)
	})
}

// The target holds migration credentials it cannot use (its CA is not a
// certificate). It used to report itself ready all the same, install the
// garbage for QEMU, and the copy failed mid-way with a generic error. The
// source now refuses before the copy, naming the target, why, and the fix.
//
// Mutation: read an unusable target as one with no credentials — the
// refusal is the plain "no migration-TLS credentials" one, red.
func TestFleet_StorageMigrationIsRefusedWhenTheTargetsMigrationCredentialsAreUnusable(t *testing.T) {
	for _, allow := range []bool{false, true} {
		t.Run(fmt.Sprintf("allow_unencrypted_storage=%t", allow), func(t *testing.T) {
			targetUnusableRefused(t, allow)
		})
	}
}

// targetUnusableRefused: with or without the source's plaintext opt-in, an
// unusable target is refused before the copy (M3).
func targetUnusableRefused(t *testing.T, allowPlaintext bool) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	c.openClusterPolicyGate()
	defer c.Stop()
	src, dst := c.Nodes[0], c.Nodes[1]
	migrationTLSReady(src, true)
	migrationTLSInvalid(dst, "ca.crt holds no PEM certificate")
	src.Server.SetAllowUnencryptedStorageMigration(allowPlaintext)

	path := filepath.Join(c.tmpRoot, dst.Name, "data", "disks", "pp1-root.qcow2")
	storageMigrationVM(t, src, path, 1<<30)
	err := runStorageMigration(t, c, src, dst.Name)
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), dst.Name) ||
		!strings.Contains(err.Error(), "ca.crt holds no PEM certificate") ||
		!strings.Contains(err.Error(), "lv host install-migration-tls --reissue") {
		t.Fatalf("migration = %v; want FailedPrecondition naming %s, why, and `lv host install-migration-tls --reissue`", err, dst.Name)
	}
	if n := migrateCalls(src); n != 0 {
		t.Fatalf("the refused migration reached libvirt %d time(s)", n)
	}
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Errorf("the refused migration left its disk stub %s on the target (stat err %v)", path, statErr)
	}
}

// The source's own credentials are unusable (its CA is a directory): it
// refuses with the same guidance, not "no migration-TLS credentials".
//
// Mutation: read an unusable source as one with no credentials — red.
func TestFleet_StorageMigrationIsRefusedWhenTheSourcesMigrationCredentialsAreUnusable(t *testing.T) {
	for _, allow := range []bool{false, true} {
		t.Run(fmt.Sprintf("allow_unencrypted_storage=%t", allow), func(t *testing.T) {
			sourceUnusableRefused(t, allow)
		})
	}
}

func sourceUnusableRefused(t *testing.T, allowPlaintext bool) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	c.openClusterPolicyGate()
	defer c.Stop()
	src, dst := c.Nodes[0], c.Nodes[1]
	migrationTLSInvalid(src, "read ca.crt: is a directory")
	migrationTLSReady(dst, true)
	src.Server.SetAllowUnencryptedStorageMigration(allowPlaintext)

	storageMigrationVM(t, src, filepath.Join(c.tmpRoot, dst.Name, "data", "disks", "pp1-root.qcow2"), 1<<30)
	err := runStorageMigration(t, c, src, dst.Name)
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), src.Name) ||
		!strings.Contains(err.Error(), "is a directory") ||
		!strings.Contains(err.Error(), "lv host install-migration-tls --reissue") {
		t.Fatalf("migration = %v; want FailedPrecondition naming %s, why, and `lv host install-migration-tls --reissue`", err, src.Name)
	}
	if n := migrateCalls(src); n != 0 {
		t.Fatalf("the refused migration reached libvirt %d time(s)", n)
	}
}

// An older source with the plaintext opt-in reads only migration_tls_ready:
// told "not ready", it would copy in plaintext to a target whose credentials
// are merely unusable. The target therefore refuses a storage copy (one with
// disk stubs) that asks for TLS while its own credentials are unusable,
// naming the fix, so that source fails closed. A memory-only ask (no stubs)
// is answered "not ready" as before: that move stays in libvirt's tunnel.
//
// Mutation: answer the storage ask "not ready" like the memory one — no
// error, red.
func TestFleet_TargetWithUnusableCredentialsRefusesAStorageCopyThatAsksForTLS(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	c.openClusterPolicyGate()
	defer c.Stop()
	src, dst := c.Nodes[0], c.Nodes[1]
	migrationTLSInvalid(dst, "ca.crt holds no PEM certificate")
	path := filepath.Join(c.tmpRoot, dst.Name, "data", "disks", "pp1-root.qcow2")
	storageMigrationVM(t, src, path, 1<<30)
	peer := c.PeerClient(src, dst)

	_, err := peer.EnsureDisks(context.Background(), &pb.EnsureDisksRequest{
		VmName: "pp1", WantMigrationTls: true,
		Disks: []*pb.DiskStub{{Path: path, SizeBytes: 1 << 30}},
	})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "lv host install-migration-tls --reissue") {
		t.Fatalf("EnsureDisks of a storage copy asking for TLS = %v; want FailedPrecondition with the --reissue fix", err)
	}
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Errorf("the refused copy left a disk stub %s (stat err %v)", path, statErr)
	}
	resp, err := peer.EnsureDisks(context.Background(), &pb.EnsureDisksRequest{VmName: "pp1", WantMigrationTls: true})
	if err != nil || resp.GetMigrationTlsReady() {
		t.Fatalf("EnsureDisks of a memory-only move = %+v, %v; want answered, not ready", resp, err)
	}
}

// migrationCAs makes n report a CA set: its digest, and the CA fingerprints
// that make it up, as a daemon reads them from its CA file.
func migrationCAs(n *Node, digest string, fps ...string) {
	migrationCA(n, digest)
	n.Server.SetMigrationCAList(func() ([]string, error) { return fps, nil })
}

// Mid-rotation a two-CA host's set digest appears nowhere an operator can
// look. The refusal names both hosts' real CA fingerprints, carried from the
// target in its EnsureDisks answer, which lv doctor migration-tls also lists.
//
// Mutations: print the digests (the message has neither list); do not send
// the target's list (the target is shown by its digest).
func TestFleet_StorageMigrationRefusalNamesTheRealCAFingerprints(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	c.openClusterPolicyGate()
	defer c.Stop()
	src, dst := c.Nodes[0], c.Nodes[1]
	migrationTLSReady(src, true)
	migrationTLSReady(dst, true)
	migrationCAs(src, "digest-of-two", "6cee35be", "5eda7fef")
	migrationCAs(dst, "digest-of-one", "6cee35be")

	path := filepath.Join(c.tmpRoot, dst.Name, "data", "disks", "pp1-root.qcow2")
	storageMigrationVM(t, src, path, 1<<30)
	err := runStorageMigration(t, c, src, dst.Name)
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("migration = %v; want refused", err)
	}
	msg := err.Error()
	for _, want := range []string{src.Name + ": 6cee35be, 5eda7fef", dst.Name + ": 6cee35be"} {
		if !strings.Contains(msg, want) {
			t.Errorf("refusal %q does not list %q", msg, want)
		}
	}
	if strings.Contains(msg, "digest-of") {
		t.Errorf("refusal %q quotes a set digest", msg)
	}
}
