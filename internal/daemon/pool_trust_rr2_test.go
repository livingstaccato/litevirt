package daemon

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/grpcapi"
	"github.com/litevirt/litevirt/internal/pooltrust"
	"github.com/litevirt/litevirt/internal/storage"
)

// (re-review rr2) An rc6-shaped host, as faithfully as a unit test can make it.
type rr2Host struct {
	d                 *Daemon
	root, data        string
	nfsDir, nfsExtDir string
}

func rr2Qcow(t *testing.T, p string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, append([]byte{'Q', 'F', 'I', 0xfb}, make([]byte, 508)...), 0o600); err != nil {
		t.Fatal(err)
	}
}

// nfsMounted: the export is still mounted at the upgrade (a daemon restart
// with KillMode=process leaves mounts), so its files are visible; false is
// the upgrade-with-reboot case: the mount point is an empty local directory.
func newRR2Host(t *testing.T, nfsMounted bool) rr2Host {
	ctx := context.Background()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	data := filepath.Join(root, "data")
	const host = "h1"
	h := rr2Host{root: root, data: data}
	defDir := filepath.Join(data, "pools", "default")
	isoDir := filepath.Join(data, "pools", "isos")
	vmpool := filepath.Join(root, "srv", "vmpool")
	empty := filepath.Join(root, "srv", "empty")
	emptyArea := filepath.Join(data, "pools", "scratch")
	h.nfsDir = filepath.Join(data, "mounts", storage.NFSMountName("nas:/export/vms"))
	h.nfsExtDir = filepath.Join(root, "mnt", "nfsext")
	for _, d := range []string{filepath.Join(data, "disks"), defDir, isoDir, vmpool, empty, emptyArea, h.nfsDir, h.nfsExtDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	rows := []corrosion.StoragePoolRecord{
		// rc6 registerStoragePools: implicit default, local, at pools/default.
		{HostName: host, Name: "default", Driver: "local", Target: defDir, State: "active"},
		// rc6 ensureGlobalISOLibrary.
		{HostName: host, Name: "isos", Driver: "dir", Target: isoDir, Options: grpcapi.GlobalISOLibraryOptions(), State: "active"},
		// API-created dir pool with VM disks.
		{HostName: host, Name: "vmpool", Driver: "dir", Target: vmpool, State: "active"},
		// API-created nfs pool, mount point under <data_dir>/mounts, a qcow2 disk.
		{HostName: host, Name: "nfspool", Driver: "nfs", Source: "nas:/export/vms", Options: map[string]string{"options": "vers=4.2,hard"}, State: "active"},
		// API-created nfs pool with an operator target outside the data dir.
		{HostName: host, Name: "nfsext", Driver: "nfs", Source: "nas:/export/ext", Target: h.nfsExtDir, State: "active"},
		// API-created empty dir pool outside the areas.
		{HostName: host, Name: "empty", Driver: "dir", Target: empty, State: "active"},
		// API-created empty dir pool inside <data_dir>/pools.
		{HostName: host, Name: "scratch", Driver: "dir", Target: emptyArea, State: "active"},
	}
	for _, r := range rows {
		if err := corrosion.UpsertStoragePool(ctx, db, r); err != nil {
			t.Fatal(err)
		}
	}
	disk := func(vm, pool, dir, typ string, present bool) {
		p := filepath.Join(dir, vm+"-root.qcow2")
		if present {
			rr2Qcow(t, p)
		}
		if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{Name: vm, HostName: host, State: "running"}, nil,
			[]corrosion.DiskRecord{{VMName: vm, DiskName: "root", HostName: host, Path: p, StorageType: typ, StorageVolume: pool}}); err != nil {
			t.Fatal(err)
		}
	}
	disk("vm0", "default", defDir, "local", true)
	disk("vm1", "vmpool", vmpool, "dir", true)
	disk("vm2", "nfspool", h.nfsDir, "nfs", nfsMounted)
	disk("vm3", "nfsext", h.nfsExtDir, "nfs", nfsMounted)
	h.d = &Daemon{db: db, cfg: &Config{HostName: host, DataDir: data, PKIDir: filepath.Join(root, "pki")}}
	return h
}

func (h rr2Host) report(t *testing.T, label string) map[string]bool {
	ctx := context.Background()
	rows, err := corrosion.ListStoragePoolsForHost(ctx, h.d.db, "h1")
	if err != nil {
		t.Fatal(err)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Name < rows[j].Name })
	out := map[string]bool{}
	for _, r := range rows {
		v := h.d.poolTrust.Judge(r.Name, pooltrust.BindingOf(r.Driver, r.Source, r.Target, r.Options))
		e, inLedger := h.d.poolTrust.Entry(r.Name)
		how := ""
		if inLedger {
			how = e.How
		}
		t.Logf("%s: %-8s driver=%-5s target=%-40s trusted=%-5t why=%q ledger=%q", label, r.Name, r.Driver, r.Target, v.Trusted, v.Why, how)
		out[r.Name] = v.Trusted
	}
	b, _ := os.ReadFile(h.d.poolTrust.Path())
	var lf struct {
		Adopted bool `json:"adopted"`
	}
	_ = json.Unmarshal(b, &lf)
	t.Logf("%s: ledger adopted=%t initialised=%t", label, lf.Adopted, h.d.poolTrust.Initialised())
	return out
}

func TestRR2Probe_RC6HostUpgrade(t *testing.T) {
	for _, mounted := range []bool{true, false} {
		name := "inPlaceRestart"
		if !mounted {
			name = "withReboot"
		}
		t.Run(name, func(t *testing.T) {
			h := newRR2Host(t, mounted)
			ctx := context.Background()
			h.d.openPoolTrust(ctx)
			h.d.registerStoragePools(ctx)
			got := h.report(t, "start1")
			// A second start: nothing re-judged.
			h.d.poolTrust = nil
			h.d.openPoolTrust(ctx)
			h.d.registerStoragePools(ctx)
			got2 := h.report(t, "start2")
			for k, v := range got {
				if got2[k] != v {
					t.Errorf("%s changed trust across starts: %t -> %t", k, v, got2[k])
				}
			}
			want := map[string]bool{"default": true, "isos": true, "vmpool": true, "scratch": true, "empty": false,
				"nfspool": true, "nfsext": false} // round 4: nfs adopted only in mounts/, nothing mounted to judge
			for k, w := range want {
				if got[k] != w {
					t.Errorf("%s trusted=%t, expected %t", k, got[k], w)
				}
			}
		})
	}
}

// After an adoption that could not write the ledger, the next start adopts.
func TestRR2Probe_FailedAdoptionWriteRetries(t *testing.T) {
	h := newRR2Host(t, true)
	ctx := context.Background()
	// The ledger path is a directory the write cannot replace.
	if err := os.MkdirAll(filepath.Join(h.data, "pool-trust.json"), 0o755); err != nil {
		t.Fatal(err)
	}
	h.d.openPoolTrust(ctx)
	t.Logf("initialised after an EISDIR ledger: %t", h.d.poolTrust.Initialised())
	if !h.d.poolTrust.Initialised() {
		t.Error("an unreadable ledger reads as a first start: an adoption would run over it")
	}
}

// A ledger written by a crash between the daemon's own Record and the
// adoption's write (adopted absent) adopts on the next start.
func TestRR2Probe_LedgerWithoutAdoptedAdopts(t *testing.T) {
	h := newRR2Host(t, true)
	ctx := context.Background()
	if err := os.WriteFile(filepath.Join(h.data, "pool-trust.json"), []byte(`{"version":1,"pools":{"isos":{"driver":"dir","target":"`+filepath.Join(h.data, "pools", "isos")+`","how":"daemon","at":"x"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	h.d.openPoolTrust(ctx)
	if e, ok := h.d.poolTrust.Entry("vmpool"); !ok || e.How != "upgrade" {
		t.Fatalf("not adopted: %+v %t", e, ok)
	}
}

// A read-only data dir: adoption's write fails; Initialised must stay false
// so the next start retries, and the ledger, once writable, records it.
func TestRR2Probe_AdoptionWriteFailureIsRetried(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores modes")
	}
	h := newRR2Host(t, true)
	ctx := context.Background()
	if err := os.Chmod(h.data, 0o555); err != nil {
		t.Fatal(err)
	}
	h.d.openPoolTrust(ctx)
	if h.d.poolTrust.Initialised() {
		t.Fatal("a failed adoption write left the store initialised")
	}
	if _, err := os.Stat(h.d.poolTrust.Path()); err == nil {
		t.Fatal("a ledger file was written")
	}
	_ = os.Chmod(h.data, 0o755)
	h.d.poolTrust = nil
	h.d.openPoolTrust(ctx)
	if e, ok := h.d.poolTrust.Entry("vmpool"); !ok || e.How != "upgrade" {
		t.Fatalf("not adopted on the retry: %+v %t", e, ok)
	}
}
