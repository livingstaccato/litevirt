package pooltrust

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// upsertNFS writes this host's nfs pool row with a target, and a VM of this
// host with a disk recorded directly in it (whose file is not there: the
// export is not mounted).
func upsertNFS(ctx context.Context, db *corrosion.Client, host, name, source, target string) error {
	if err := corrosion.UpsertStoragePool(ctx, db, corrosion.StoragePoolRecord{HostName: host, Name: name, Driver: "nfs", Source: source, Target: target, State: "active"}); err != nil {
		return err
	}
	return corrosion.InsertVM(ctx, db, corrosion.VMRecord{Name: "vm-" + name, HostName: host, State: "stopped"}, nil,
		[]corrosion.DiskRecord{{VMName: "vm-" + name, DiskName: "root", HostName: host, Path: filepath.Join(target, "vm-"+name+"-root.qcow2"), StorageType: "nfs", StorageVolume: name}})
}

// (re-review rr2 6) A kept copy of an unreadable ledger beside a readable
// ledger that does not record the adoption (an operator restored an older
// ledger, or a crash between the set-aside and the first write of a build
// without the flag) still counts as adopted, and is named: the branch is
// reachable only by hand, and kept so that putting a ledger back never
// re-opens the adoption over what the kept copy may have held.
//
// Mutation: drop the kept-copy check after a readable ledger — red.
func TestLedger_AKeptCopyBesideAReadableLedgerCountsAsAdopted(t *testing.T) {
	f := newFixture(t)
	path := filepath.Join(f.data, LedgerFile)
	if err := os.WriteFile(path, []byte(`{"version":1,"pools":{},"adopted":false}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+CorruptSuffix+"1", []byte("{garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := f.open(t)
	if !s.Initialised() {
		t.Fatal("a kept unreadable ledger beside a readable one let the adoption run again")
	}
	if !strings.Contains(s.CorruptNote(), CorruptSuffix) {
		t.Fatalf("CorruptNote = %q, want the kept copy named", s.CorruptNote())
	}
}

// (re-review rr2 1) A target-less nfs pool needs trust like one with a
// target; a config one is a config pool by its place (IsConfigPool), whatever
// its row's options.
//
// Mutations: NeedsTrust on write roots only — the forged row is trusted,
// red; IsConfigPool comparing mount options — the config pool with forged
// options is not one, red.
func TestJudge_TargetlessNFS(t *testing.T) {
	f := newFixture(t)
	s := f.open(t)
	s.SetConfig(map[string]Binding{"nas": BindingOf("nfs", "srv:/x", "", nil)})
	forged := BindingOf("nfs", "attacker:/x", "", map[string]string{"options": "soft"})
	if v := s.Judge("evil", forged); v.Trusted {
		t.Fatalf("a forged target-less nfs row is trusted: %+v", v)
	}
	row := BindingOf("nfs", "srv:/x", "", map[string]string{"options": "vers=3,soft,nolock"})
	if v := s.Judge("nas", row); !v.Trusted || v.Why != TrustConfig {
		t.Fatalf("a target-less config nfs pool is judged %+v, want trusted by config", v)
	}
	if !s.IsConfigPool("nas", row) {
		t.Fatal("a target-less config nfs pool with forged row options is not recognised as the config pool")
	}
	if s.IsConfigPool("nas", BindingOf("nfs", "other:/y", "", nil)) {
		t.Fatal("a row of another export is taken for the config pool")
	}
}

// (re-review rr3 3) At the upgrade an nfs pool is adopted only when its
// mount point is in <data_dir>/mounts — a target-less one, or one whose
// target is there. One whose target is outside is held for `lv pool trust`,
// even with this host's VM rows naming a qcow2 disk "in" it and that disk
// present (as if the export were mounted): for nfs the header is served by
// the export being judged and the rows are replicated, so neither is
// evidence. Nothing is mounted to judge either.
//
// Mutations: accept the qcow2 evidence for an nfs pool outside mounts/ —
// red; drop the mounts/ adoption — the target-less pool is held, red.
func TestAdoptOnUpgrade_NFSIsAdoptedOnlyInTheMountsArea(t *testing.T) {
	f, db := adoptFixture(t)
	ctx := context.Background()
	ext := filepath.Join(f.root, "etc-like", "50-local.d")
	if err := os.MkdirAll(ext, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := upsertNFS(ctx, db, "h1", "nfsext", "attacker:/ext", ext); err != nil {
		t.Fatal(err)
	}
	writeQcow2(t, filepath.Join(ext, "vm-nfsext-root.qcow2"))
	inArea := filepath.Join(f.data, "mounts", "nas_vols")
	if err := upsertNFS(ctx, db, "h1", "nfsin", "nas:/vols", inArea); err != nil {
		t.Fatal(err)
	}
	if err := upsertNFS(ctx, db, "h1", "nfsbare", "nas:/bare", ""); err != nil {
		t.Fatal(err)
	}
	s := f.open(t)
	a, err := s.AdoptOnUpgrade(ctx, db, "h1")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("adopted=%v held=%v", a.Adopted, a.Held)
	if s.Judge("nfsext", BindingOf("nfs", "attacker:/ext", ext, nil)).Trusted {
		t.Error("an nfs pool mounted outside mounts/ was adopted on a qcow2 header and replicated rows")
	}
	for name, b := range map[string]Binding{
		"nfsin":   BindingOf("nfs", "nas:/vols", inArea, nil),
		"nfsbare": BindingOf("nfs", "nas:/bare", "", nil),
	} {
		if e, ok := s.Entry(name); !ok || e.How != HowUpgrade || !s.Judge(name, b).Trusted {
			t.Errorf("an nfs pool mounted in mounts/ (%s) was not adopted: %+v %t", name, e, ok)
		}
	}
}

// (re-review rr3 1) A ledger written by the round-3 build may hold
// "pending_nfs": it is not read, nothing acts on it, and the next write
// drops it.
//
// Mutation: carry unknown ledger fields through a write — red.
func TestLedger_ARound3PendingEntryIsDropped(t *testing.T) {
	f := newFixture(t)
	path := filepath.Join(f.data, LedgerFile)
	old := `{"version":1,"pools":{},"adopted":true,"pending_nfs":{"x/../../../etc/polkit-1/rules.d":{"driver":"nfs","source":"attacker:/x"}}}`
	if err := os.WriteFile(path, []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	s := f.open(t)
	if !s.Initialised() {
		t.Fatal("a round-3 ledger lost its adopted flag")
	}
	if err := s.Record("p", Binding{Driver: "dir", Target: filepath.Join(f.root, "p")}, HowTrust); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "pending_nfs") || strings.Contains(string(b), "polkit") {
		t.Fatalf("the round-3 pending entry survived a write: %s", b)
	}
}
