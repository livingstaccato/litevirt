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

// (re-review rr2 2) An nfs pool whose export is not mounted at the adoption
// is held and recorded as pending (judged again on its first mount), and the
// pending entry survives a restart; a dir pool held for lack of evidence is
// not pending.
//
// Mutation: do not record the pending nfs pools — red.
func TestAdoptOnUpgrade_AnUnmountedNFSPoolIsPending(t *testing.T) {
	f, db := adoptFixture(t)
	ctx := context.Background()
	tgt := filepath.Join(f.root, "nfsext")
	if err := os.MkdirAll(tgt, 0o755); err != nil {
		t.Fatal(err)
	}
	poolWithDisk(t, db, "h1", "empty", filepath.Join(f.root, "empty"), "vm0", filepath.Join(f.root, "empty", "vm0.qcow2"))
	if err := upsertNFS(ctx, db, "h1", "nfsext", "nas:/ext", tgt); err != nil {
		t.Fatal(err)
	}
	s := f.open(t)
	if _, err := s.AdoptOnUpgrade(ctx, db, "h1"); err != nil {
		t.Fatal(err)
	}
	p := f.open(t).PendingNFS()
	if _, ok := p["nfsext"]; !ok || len(p) != 1 {
		t.Fatalf("pending = %v, want only nfsext", p)
	}
	if err := s.ResolvePending("nfsext", p["nfsext"], false); err != nil {
		t.Fatal(err)
	}
	if len(f.open(t).PendingNFS()) != 0 {
		t.Fatal("a resolved pending entry came back after a restart")
	}
}
