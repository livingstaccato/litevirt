package pooltrust

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// (review r0 I2) A forged row naming an ANCESTOR of a legitimate pool's
// directory (/srv above /srv/vmpool), with a forged disk row naming the
// legitimate pool's real qcow2 disk, is not adopted on upgrade: the disk's
// directory is the legitimate pool's, not the ancestor.
//
// Mutation: accept a disk anywhere under the directory (the resolved parent
// compared with "within" instead of equality) — red.
func TestAdoptOnUpgrade_AnAncestorOfALegitimatePoolIsNotAdopted(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	const host = "h1"
	srv := filepath.Join(f.root, "srv")
	legit := filepath.Join(srv, "vmpool")
	disk := filepath.Join(legit, "vm1-root.qcow2")
	writeQcow2(t, disk)
	if err := os.WriteFile(filepath.Join(srv, "unrelated-data"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, p := range []corrosion.StoragePoolRecord{
		{HostName: host, Name: "vmpool", Driver: "dir", Target: legit, State: "active"},
		{HostName: host, Name: "evil", Driver: "dir", Target: srv, State: "active"},
	} {
		if err := corrosion.UpsertStoragePool(ctx, db, p); err != nil {
			t.Fatal(err)
		}
	}
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{Name: "vm1", HostName: host, State: "stopped"}, nil,
		[]corrosion.DiskRecord{{VMName: "vm1", DiskName: "root", HostName: host, Path: disk, StorageType: "dir", StorageVolume: "vmpool"}}); err != nil {
		t.Fatal(err)
	}
	// The forger's disk row: names the legitimate disk, on pool evil.
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{Name: "forged", HostName: host, State: "stopped"}, nil,
		[]corrosion.DiskRecord{{VMName: "forged", DiskName: "root", HostName: host, Path: disk, StorageType: "dir", StorageVolume: "evil"}}); err != nil {
		t.Fatal(err)
	}
	s := f.open(t)
	a, err := s.AdoptOnUpgrade(ctx, db, host)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("adopted=%v held=%v", a.Adopted, a.Held)
	if s.Judge("evil", Binding{Driver: "dir", Target: srv}).Trusted {
		t.Errorf("R-1: forged row naming the ancestor %s of a legitimate pool was adopted", srv)
	}
}

// (review r0 I3) On a host whose <data_dir>/pools is a symlink to another
// disk (a common layout: the data dir's pools on a big volume), the daemon's
// own rows — the default pool at pools/default and the global ISO library at
// pools/isos — are in its pool area: the area roots are judged as this host
// resolves them, so the store alone trusts them, with no ledger entry and no
// qcow2 evidence. (The daemon also records them in the ledger as it writes
// them: TestOpenPoolTrust_DaemonsOwnPoolsAreRecorded.)
//
// Mutation: judge the area roots as written only (InDataDirPoolArea without
// the resolved root forms) — red.
func TestJudge_DaemonsOwnRowsTrustedWhenPoolsAreaIsSymlinked(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	data := filepath.Join(root, "data")
	big := filepath.Join(root, "bigdisk", "pools")
	for _, d := range []string{filepath.Join(data, "disks"), filepath.Join(big, "default"), filepath.Join(big, "isos")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(big, filepath.Join(data, "pools")); err != nil {
		t.Fatal(err)
	}
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	const host = "h1"
	def := filepath.Join(data, "pools", "default")
	isos := filepath.Join(data, "pools", "isos")
	for _, p := range []corrosion.StoragePoolRecord{
		{HostName: host, Name: "default", Driver: "local", Target: def, State: "active"},
		{HostName: host, Name: "isos", Driver: "dir", Target: isos, State: "active"},
	} {
		if err := corrosion.UpsertStoragePool(ctx, db, p); err != nil {
			t.Fatal(err)
		}
	}
	s, err := Open(data, filepath.Join(root, "pki"))
	if err != nil {
		t.Fatal(err)
	}
	// What daemon.openPoolTrust gives it with no storage_pools in config.
	s.SetConfig(map[string]Binding{"litevirt": {Driver: "local", Target: filepath.Join(data, "disks")}})
	a, err := s.AdoptOnUpgrade(ctx, db, host)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("adopted=%v held=%v", a.Adopted, a.Held)
	if v := s.Judge("default", Binding{Driver: "local", Target: def}); !v.Trusted {
		t.Errorf("R-2: the daemon's own default pool is untrusted: %s", v.Why)
	}
	if v := s.Judge("isos", Binding{Driver: "dir", Target: isos}); !v.Trusted {
		t.Errorf("R-2: the daemon's own global ISO library is untrusted: %s", v.Why)
	}
}

// (review r0 I3) The legacy default pool ("default", local, <data_dir>/disks)
// on a host whose <data_dir>/disks is a symlink to a bigger volume, with no
// disk on it yet, is trusted.
func TestJudge_LegacyDefaultTrustedWhenDisksIsSymlinked(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	data := filepath.Join(root, "data")
	big := filepath.Join(root, "bigdisk", "disks")
	for _, d := range []string{filepath.Join(data, "pools"), big} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(big, filepath.Join(data, "disks")); err != nil {
		t.Fatal(err)
	}
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	disks := filepath.Join(data, "disks")
	if err := corrosion.UpsertStoragePool(ctx, db, corrosion.StoragePoolRecord{HostName: "h1", Name: "default", Driver: "local", Target: disks, State: "active"}); err != nil {
		t.Fatal(err)
	}
	s, err := Open(data, filepath.Join(root, "pki"))
	if err != nil {
		t.Fatal(err)
	}
	s.SetConfig(map[string]Binding{"litevirt": {Driver: "local", Target: disks}})
	if _, err := s.AdoptOnUpgrade(ctx, db, "h1"); err != nil {
		t.Fatal(err)
	}
	if v := s.Judge("default", Binding{Driver: "local", Target: disks}); !v.Trusted {
		t.Errorf("R-2b: the legacy default pool on a symlinked disks/ is untrusted: %s", v.Why)
	}
}
