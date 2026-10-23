package pooltrust

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

type fixture struct {
	root, data, pki string
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	root := t.TempDir()
	f := fixture{root: root, data: filepath.Join(root, "data"), pki: filepath.Join(root, "pki")}
	for _, d := range []string{f.data, f.pki, filepath.Join(f.data, "disks"), filepath.Join(f.data, "pools")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

func (f fixture) open(t *testing.T) *Store {
	t.Helper()
	s, err := Open(f.data, f.pki)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return s
}

// A row is trusted through config, the ledger or the daemon's own areas, each
// bound to the row's driver, source and target; anything else is not.
//
// Mutations: drop any one of the three rules — its row goes red; compare the
// ledger entry by name only — the retargeted row goes red; drop the
// resolved-form check in InDataDirPoolArea — the symlinked pools/ dir goes red.
func TestJudge_TrustSources(t *testing.T) {
	f := newFixture(t)
	s := f.open(t)
	outside := filepath.Join(f.root, "srv-vm")
	s.SetConfig(map[string]Binding{"cfgpool": {Driver: "dir", Target: outside}})
	if err := s.Record("made", Binding{Driver: "dir", Target: filepath.Join(f.root, "made")}, HowCreate); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(f.data, "pools", "sneaky")
	if err := os.MkdirAll(filepath.Join(f.root, "elsewhere"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(f.root, "elsewhere"), link); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		b    Binding
		want bool
		why  string
	}{
		{"cfgpool", Binding{Driver: "dir", Target: outside}, true, TrustConfig},
		{"cfgpool", Binding{Driver: "dir", Target: filepath.Join(f.root, "other")}, false, "config.yaml defines"},
		{"made", Binding{Driver: "dir", Target: filepath.Join(f.root, "made") + "/"}, true, TrustLedger},
		{"made", Binding{Driver: "dir", Target: "/var/lib/cloud/seed/nocloud"}, false, "this host recorded"},
		{"forged", Binding{Driver: "dir", Target: "/var/lib/polkit-1/localauthority/50-local.d"}, false, "neither created nor confirmed"},
		{"forged-nfs", Binding{Driver: "nfs", Source: "evil:/x", Target: filepath.Join(f.data, "mounts", "x")}, false, "neither created"},
		{"inarea", Binding{Driver: "dir", Target: filepath.Join(f.data, "pools", "inarea")}, true, TrustArea},
		{"legacy", Binding{Driver: "local", Target: filepath.Join(f.data, "disks")}, true, TrustArea},
		{"implicit", Binding{Driver: "", Target: ""}, true, TrustNoHostPath},
		{"sneaky", Binding{Driver: "dir", Target: link}, false, "neither created"},
		{"areaRoot", Binding{Driver: "dir", Target: filepath.Join(f.data, "pools")}, false, "neither created"},
		{"cephpool", Binding{Driver: "ceph", Source: "rbd"}, true, TrustNoHostPath},
	} {
		v := s.Judge(tc.name, tc.b)
		if v.Trusted != tc.want || !strings.Contains(v.Why, tc.why) {
			t.Errorf("Judge(%s, %+v) = %+v, want trusted=%t why~%q", tc.name, tc.b, v, tc.want, tc.why)
		}
	}
	var nilStore *Store
	if v := nilStore.Judge("x", Binding{Driver: "dir", Target: "/srv"}); !v.Trusted {
		t.Errorf("a nil store judged %+v, want trusted (no store)", v)
	}
}

// The ledger is local, 0600, durable across an Open, and Forget drops an
// entry for good.
//
// Mutation: leave the temp file's mode at CreateTemp's — still 0600, so the
// mode check alone would not catch it; write with 0644 instead — red.
func TestLedger_PersistsPrivatelyAndForgets(t *testing.T) {
	f := newFixture(t)
	s := f.open(t)
	if s.Initialised() {
		t.Fatal("a fresh data dir reads as initialised")
	}
	b := Binding{Driver: "dir", Target: filepath.Join(f.root, "p")}
	if err := s.Record("p", b, HowTrust); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(f.data, LedgerFile))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("ledger mode %v, want 0600", fi.Mode().Perm())
	}
	s2 := f.open(t)
	if !s2.Initialised() || !s2.Judge("p", b).Trusted {
		t.Fatalf("reopened ledger lost the entry: initialised=%t judge=%+v", s2.Initialised(), s2.Judge("p", b))
	}
	if e, _ := s2.Entry("p"); e.How != HowTrust {
		t.Errorf("entry how = %q, want %q", e.How, HowTrust)
	}
	if err := s2.Forget("p"); err != nil {
		t.Fatal(err)
	}
	if f.open(t).Judge("p", b).Trusted {
		t.Error("a forgotten pool is still trusted after a reopen")
	}
}

// A ledger that cannot be parsed trusts nothing, and counts as initialised:
// no upgrade adoption runs over it.
//
// Mutation: treat a parse error as "no ledger" (initialised false) — red.
func TestLedger_CorruptFailsClosed(t *testing.T) {
	f := newFixture(t)
	if err := os.WriteFile(filepath.Join(f.data, LedgerFile), []byte(`{"pools":{"p":`), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := Open(f.data, f.pki)
	if err == nil {
		t.Fatal("a corrupt ledger opened without an error")
	}
	if !s.Initialised() {
		t.Error("a corrupt ledger reads as absent, so an adoption would run over it")
	}
	if s.Judge("p", Binding{Driver: "dir", Target: filepath.Join(f.root, "p")}).Trusted {
		t.Error("a corrupt ledger trusted a pool")
	}
}

func writeQcow2(t *testing.T, p string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, append([]byte{'Q', 'F', 'I', 0xfb, 0, 0, 0, 3}, make([]byte, 504)...), 0o600); err != nil {
		t.Fatal(err)
	}
}

// Upgrade adoption keeps an existing pool working — its directory holds a
// qcow2 disk of this host recorded on it — and does not adopt a forged row
// made before the upgrade: not one naming an existing directory, not one
// whose forged disk row names a real (non-qcow2) file there, not one whose
// disk row is another host's. It runs once: a forged row arriving after the
// first start is not adopted at the next.
//
// Mutations: adopt on the directory existing — the polkit row goes red; skip
// the qcow2 magic — the dpkg row goes red; drop host_name from the disk
// query — the other-host row goes red; run the adoption on every start
// (ignore Initialised) — the late row goes red.
func TestAdoptOnUpgrade_KeepsLegitimatePoolsNotForgedOnes(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	const host = "h1"

	legit := filepath.Join(f.root, "srv-vm")
	writeQcow2(t, filepath.Join(legit, "vm1-root.qcow2"))
	polkit := filepath.Join(f.root, "polkit-50-local.d") // exists, empty
	dpkg := filepath.Join(f.root, "dpkg-info")
	other := filepath.Join(f.root, "other-host-pool")
	writeQcow2(t, filepath.Join(other, "vm3-root.qcow2"))
	for _, d := range []string{polkit, dpkg} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dpkg, "bash.list"), []byte("/bin/bash\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, p := range []corrosion.StoragePoolRecord{
		{HostName: host, Name: "vmpool", Driver: "dir", Target: legit, State: "active"},
		{HostName: host, Name: "polkit", Driver: "dir", Target: polkit, State: "active"},
		{HostName: host, Name: "dpkg", Driver: "dir", Target: dpkg, State: "active"},
		{HostName: host, Name: "otherpool", Driver: "dir", Target: other, State: "active"},
		{HostName: host, Name: "inarea", Driver: "dir", Target: filepath.Join(f.data, "pools", "inarea"), State: "active"},
	} {
		if err := corrosion.UpsertStoragePool(ctx, db, p); err != nil {
			t.Fatal(err)
		}
	}
	for _, v := range []struct{ vm, host, path, pool string }{
		{"vm1", host, filepath.Join(legit, "vm1-root.qcow2"), "vmpool"},
		{"vm2", host, filepath.Join(dpkg, "bash.list"), "dpkg"},
		{"vm3", "h2", filepath.Join(other, "vm3-root.qcow2"), "otherpool"},
	} {
		if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{Name: v.vm, HostName: v.host, State: "stopped"}, nil,
			[]corrosion.DiskRecord{{VMName: v.vm, DiskName: "root", HostName: v.host, Path: v.path, StorageType: "dir", StorageVolume: v.pool}}); err != nil {
			t.Fatal(err)
		}
	}

	s := f.open(t)
	a, err := s.AdoptOnUpgrade(ctx, db, host)
	if err != nil {
		t.Fatalf("AdoptOnUpgrade: %v", err)
	}
	if !a.Ran {
		t.Fatal("adoption did not run on the first start")
	}
	judge := func(s *Store, name, target string) bool {
		return s.Judge(name, Binding{Driver: "dir", Target: target}).Trusted
	}
	if !judge(s, "vmpool", legit) {
		t.Errorf("the legitimate pool was not adopted: %+v", a)
	}
	for name, dir := range map[string]string{"polkit": polkit, "dpkg": dpkg, "otherpool": other} {
		if judge(s, name, dir) {
			t.Errorf("forged row %s (%s) was adopted: %+v", name, dir, a)
		}
	}
	if _, ok := s.Entry("inarea"); ok {
		t.Error("a pool in the daemon's own area was written to the ledger; it is trusted by the area rule")
	}
	if len(a.Held) != 3 {
		t.Errorf("held = %v, want the three forged rows", a.Held)
	}

	// After the first start: a forged row with a qcow2 disk is not adopted.
	late := filepath.Join(f.root, "late")
	writeQcow2(t, filepath.Join(late, "vm4-root.qcow2"))
	if err := corrosion.UpsertStoragePool(ctx, db, corrosion.StoragePoolRecord{HostName: host, Name: "late", Driver: "dir", Target: late, State: "active"}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{Name: "vm4", HostName: host, State: "stopped"}, nil,
		[]corrosion.DiskRecord{{VMName: "vm4", DiskName: "root", HostName: host, Path: filepath.Join(late, "vm4-root.qcow2"), StorageType: "dir", StorageVolume: "late"}}); err != nil {
		t.Fatal(err)
	}
	s2 := f.open(t)
	a2, err := s2.AdoptOnUpgrade(ctx, db, host)
	if err != nil || a2.Ran {
		t.Fatalf("second start: adoption ran=%t err=%v, want not run", a2.Ran, err)
	}
	if judge(s2, "late", late) {
		t.Error("a row arriving after the first start was adopted")
	}
	if !judge(s2, "vmpool", legit) {
		t.Error("the adopted pool is not trusted after a restart")
	}
}
