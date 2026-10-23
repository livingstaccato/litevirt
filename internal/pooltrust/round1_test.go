package pooltrust

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// adoptFixture is a schema'd database and a store with no ledger yet.
func adoptFixture(t *testing.T) (fixture, *corrosion.Client) {
	t.Helper()
	f := newFixture(t)
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	return f, db
}

// poolWithDisk writes this host's pool row name at dir and a VM of this host
// with one disk at disk on it.
func poolWithDisk(t *testing.T, db *corrosion.Client, host, name, dir, vm, disk string) {
	t.Helper()
	ctx := context.Background()
	if err := corrosion.UpsertStoragePool(ctx, db, corrosion.StoragePoolRecord{HostName: host, Name: name, Driver: "dir", Target: dir, State: "active"}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{Name: vm, HostName: host, State: "stopped"}, nil,
		[]corrosion.DiskRecord{{VMName: vm, DiskName: "root", HostName: host, Path: disk, StorageType: "dir", StorageVolume: name}}); err != nil {
		t.Fatal(err)
	}
}

func adopted(t *testing.T, s *Store, name, dir string) bool {
	t.Helper()
	return s.Judge(name, Binding{Driver: "dir", Target: dir}).Trusted
}

// (review r0 m3) A disk path through a symlinked subdirectory of the row's
// directory, pointing at a real qcow2 elsewhere, is not evidence: its
// resolved parent is not the directory.
//
// Mutation: drop the resolved-parent comparison in qcow2DiskDirectlyIn —
// red.
func TestAdoptOnUpgrade_ADiskThroughALinkedSubdirectoryIsNotEvidence(t *testing.T) {
	f, db := adoptFixture(t)
	dir := filepath.Join(f.root, "forged")
	elsewhere := filepath.Join(f.root, "elsewhere")
	writeQcow2(t, filepath.Join(elsewhere, "real.qcow2"))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, filepath.Join(dir, "sub")); err != nil {
		t.Fatal(err)
	}
	poolWithDisk(t, db, "h1", "forged", dir, "vm1", filepath.Join(dir, "sub", "real.qcow2"))
	s := f.open(t)
	if _, err := s.AdoptOnUpgrade(context.Background(), db, "h1"); err != nil {
		t.Fatal(err)
	}
	if adopted(t, s, "forged", dir) {
		t.Fatal("a disk reached through a link to another directory got the row adopted")
	}
}

// (review r0 m3) A row whose directory CheckWriteRoot refuses (here the PKI
// directory) is not adopted, whatever qcow2 disk it holds.
//
// Mutation: drop CheckWriteRoot from upgradeEvidence — red.
func TestAdoptOnUpgrade_ARefusedDirectoryIsNotAdopted(t *testing.T) {
	f, db := adoptFixture(t)
	disk := filepath.Join(f.pki, "vm1-root.qcow2")
	writeQcow2(t, disk)
	poolWithDisk(t, db, "h1", "pkipool", f.pki, "vm1", disk)
	s := f.open(t)
	a, err := s.AdoptOnUpgrade(context.Background(), db, "h1")
	if err != nil {
		t.Fatal(err)
	}
	if adopted(t, s, "pkipool", f.pki) {
		t.Fatalf("a row naming the PKI directory was adopted: %+v", a)
	}
}

// (review r0 m3) A disk that is a symlink in the directory, to a qcow2
// elsewhere, is not evidence: it is opened without following the link.
//
// Mutation: open without O_NOFOLLOW in hasQcow2Magic — red.
func TestAdoptOnUpgrade_ALinkedDiskIsNotEvidence(t *testing.T) {
	f, db := adoptFixture(t)
	dir := filepath.Join(f.root, "forged")
	real := filepath.Join(f.root, "elsewhere", "real.qcow2")
	writeQcow2(t, real)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "vm1-root.qcow2")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	poolWithDisk(t, db, "h1", "forged", dir, "vm1", link)
	s := f.open(t)
	if _, err := s.AdoptOnUpgrade(context.Background(), db, "h1"); err != nil {
		t.Fatal(err)
	}
	if adopted(t, s, "forged", dir) {
		t.Fatal("a symlinked disk got the row adopted")
	}
}

// (review r1 I2) Only this host's own VMs count: a disk row naming this host
// whose VM row names another host is not evidence.
//
// Mutation: drop v.host_name from the adoption query — red.
func TestAdoptOnUpgrade_AnotherHostsVMIsNotEvidence(t *testing.T) {
	f, db := adoptFixture(t)
	ctx := context.Background()
	dir := filepath.Join(f.root, "p")
	disk := filepath.Join(dir, "vm1-root.qcow2")
	writeQcow2(t, disk)
	if err := corrosion.UpsertStoragePool(ctx, db, corrosion.StoragePoolRecord{HostName: "h1", Name: "p", Driver: "dir", Target: dir, State: "active"}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{Name: "vm1", HostName: "h2", State: "stopped"}, nil,
		[]corrosion.DiskRecord{{VMName: "vm1", DiskName: "root", HostName: "h1", Path: disk, StorageType: "dir", StorageVolume: "p"}}); err != nil {
		t.Fatal(err)
	}
	s := f.open(t)
	if _, err := s.AdoptOnUpgrade(ctx, db, "h1"); err != nil {
		t.Fatal(err)
	}
	if adopted(t, s, "p", dir) {
		t.Fatal("a disk of another host's VM got the row adopted")
	}
}

// (review r0 m3, m4) A ledger that is a directory (EISDIR) fails closed: the
// store is initialised (no adoption runs over it), trusts nothing, and the
// unreadable ledger is kept aside, not destroyed, before anything is
// written. CorruptNote names it until the kept copy is removed.
//
// Mutations: treat a non-ENOENT read error as no ledger — red; skip the
// set-aside — the Record fails or destroys it, red.
func TestLedger_UnreadableIsKeptAsideAndFailsClosed(t *testing.T) {
	f := newFixture(t)
	path := filepath.Join(f.data, LedgerFile)
	if err := os.MkdirAll(filepath.Join(path, "evidence"), 0o755); err != nil {
		t.Fatal(err)
	}
	s, err := Open(f.data, f.pki)
	if err == nil {
		t.Fatal("an unreadable ledger opened without an error")
	}
	if !s.Initialised() {
		t.Fatal("an unreadable ledger reads as absent: an adoption would run over it")
	}
	if s.Judge("p", Binding{Driver: "dir", Target: filepath.Join(f.root, "p")}).Trusted {
		t.Fatal("an unreadable ledger trusted a pool")
	}
	note := s.CorruptNote()
	if !strings.Contains(note, LedgerFile+CorruptSuffix) {
		t.Fatalf("CorruptNote = %q, want the kept copy named", note)
	}
	if err := s.Record("q", Binding{Driver: "dir", Target: filepath.Join(f.root, "q")}, HowTrust); err != nil {
		t.Fatalf("Record after an unreadable ledger: %v", err)
	}
	aside, _ := filepath.Glob(path + CorruptSuffix + "*")
	if len(aside) != 1 {
		t.Fatalf("kept copies = %v, want one", aside)
	}
	if _, err := os.Stat(filepath.Join(aside[0], "evidence")); err != nil {
		t.Fatalf("the kept copy lost what it held: %v", err)
	}
	// A restart before anything else: still not a first start.
	s2, _ := Open(f.data, f.pki)
	if !s2.Initialised() || s2.CorruptNote() == "" {
		t.Fatalf("reopened: initialised=%t note=%q", s2.Initialised(), s2.CorruptNote())
	}
	if err := os.RemoveAll(aside[0]); err != nil {
		t.Fatal(err)
	}
	if s2.CorruptNote() != "" {
		t.Fatal("CorruptNote still set after the kept copy was removed")
	}
}

// (review r0 m4) A ledger that does not parse is kept aside on open, and a
// crash before the next write still counts as initialised (no adoption).
//
// Mutation: drop the asides check from Open's no-ledger branch — red.
func TestLedger_CorruptKeptAsideStaysInitialised(t *testing.T) {
	f := newFixture(t)
	path := filepath.Join(f.data, LedgerFile)
	if err := os.WriteFile(path, []byte(`{"pools":{"p":`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(f.data, f.pki); err == nil {
		t.Fatal("a corrupt ledger opened without an error")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("the corrupt ledger is still in place: %v", err)
	}
	s, err := Open(f.data, f.pki)
	if err != nil {
		t.Fatal(err)
	}
	if !s.Initialised() {
		t.Fatal("with only a kept corrupt ledger, the store reads as a first start")
	}
}

// (review r0 m2) An nfs pool's mount options are bound, normalized: a
// rewrite of them is another pool; order, spacing and the hardening options
// every mount sets are not a difference. Other options are never bound.
//
// Mutation: drop MountOptions from BindingOf — the rewrite row is trusted,
// red.
func TestBinding_NFSMountOptionsAreBound(t *testing.T) {
	f := newFixture(t)
	s := f.open(t)
	tgt := filepath.Join(f.root, "nfs")
	if err := s.Record("n", BindingOf("nfs", "srv:/x", tgt, map[string]string{"options": "vers=4.2,hard"}), HowCreate); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		opts map[string]string
		want bool
	}{
		{map[string]string{"options": " vers=4.2 , hard,nosuid,NOEXEC,hard", "nfs_export": "x"}, true},
		{map[string]string{"options": "vers=4.2,soft"}, false},
		{map[string]string{"options": "vers=4.2,hard,nolock"}, false},
		{nil, false},
	} {
		if got := s.Judge("n", BindingOf("nfs", "srv:/x", tgt, tc.opts)).Trusted; got != tc.want {
			t.Errorf("options %v: trusted=%t, want %t", tc.opts, got, tc.want)
		}
	}
	if b := BindingOf("dir", "", tgt, map[string]string{"options": "x", "content": "iso"}); b.MountOptions != "" {
		t.Errorf("a dir pool binds options: %+v", b)
	}
}
