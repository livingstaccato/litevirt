package health

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// A deleted VM's shut-off domain on the host a failover moved it off, as on
// lab 2 (pakg@node-4, 2026-10-17): node-4 lost power with pakg running at
// owner epoch 1, pakg failed over to node-1 (epoch 2), and `lv rm pakg` ran
// before node-4's first reconciler pass after it came back. The domain stayed
// defined, reported as vm_orphan_runtime and never reaped.
//
// leftoverFixture is node-4: the domain pakg, shut off with the given
// reason, carrying owner epoch domainEpoch, the host-local marker at
// fileEpoch (0: none), a disk file, and the record tombstoned on rowHost at
// rowEpoch.
type leftoverFixture struct {
	db      *corrosion.Client
	fake    *libvirtfake.Fake
	r       *Reconciler
	dataDir string
	disk    string
	marker  string
}

type supersededCase struct {
	rowHost      string
	rowEpoch     int64
	domainEpoch  int64 // 0: no owner-epoch element
	managed      bool  // the managed stamp
	fileEpoch    int64 // 0: no host-local marker
	fileGarbage  bool  // an unreadable host-local marker
	state        libvirtfake.State
	reason       string
	managedSave  bool
	staleReplica bool
}

func lab2Case() supersededCase {
	return supersededCase{rowHost: "node-1", rowEpoch: 2, domainEpoch: 1, fileEpoch: 1,
		state: libvirtfake.StateShutdown, reason: "unknown"}
}

func newLeftoverFixture(t *testing.T, c supersededCase) *leftoverFixture {
	t.Helper()
	ctx := context.Background()
	f := &leftoverFixture{db: corrosion.NewTestClientT(t), fake: libvirtfake.New(), dataDir: t.TempDir()}
	if err := corrosion.InitSchema(ctx, f.db); err != nil {
		t.Fatal(err)
	}
	for _, h := range []string{"node-1", "node-4"} {
		if err := corrosion.InsertHost(ctx, f.db, corrosion.HostRecord{Name: h, Address: "127.0.0.1", GRPCPort: 7443, State: "active"}); err != nil {
			t.Fatal(err)
		}
	}
	f.disk = filepath.Join(f.dataDir, "disks", "pakg-root.qcow2")
	if err := os.MkdirAll(filepath.Dir(f.disk), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.disk, []byte("pakg's real data"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertVM(ctx, f.db, corrosion.VMRecord{Name: "pakg", HostName: c.rowHost, State: "running", Spec: `{}`},
		nil, []corrosion.DiskRecord{{VMName: "pakg", DiskName: "root", HostName: "node-4", Path: f.disk, StorageType: "local", TargetDev: "vda"}}); err != nil {
		t.Fatal(err)
	}
	if err := f.db.Execute(ctx, `UPDATE vms SET vm_owner_epoch = ? WHERE name = 'pakg'`, c.rowEpoch); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.DeleteVM(ctx, f.db, "pakg"); err != nil {
		t.Fatal(err)
	}

	f.fake.SetState("pakg", c.state)
	if c.reason != "" {
		f.fake.SetStateReason("pakg", c.reason)
	}
	f.fake.SetManagedSaveImage("pakg", c.managedSave)
	if c.domainEpoch > 0 {
		if err := f.fake.SetDomainOwnerEpoch("pakg", c.domainEpoch, c.state == libvirtfake.StateRunning); err != nil {
			t.Fatal(err)
		}
	}
	if c.managed {
		if err := f.fake.SetDomainManaged("pakg", c.state == libvirtfake.StateRunning); err != nil {
			t.Fatal(err)
		}
	}
	f.marker = filepath.Join(f.dataDir, "vms", "pakg", "owner_epoch")
	switch {
	case c.fileGarbage:
		if err := os.MkdirAll(filepath.Dir(f.marker), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(f.marker, []byte("garbage\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	case c.fileEpoch > 0:
		if err := WriteVMOwnerEpochMarker(f.dataDir, "pakg", c.fileEpoch); err != nil {
			t.Fatal(err)
		}
	}

	f.r = NewReconciler("node-4", f.dataDir, f.db, f.fake)
	if c.staleReplica {
		f.r.SetReplicaFreshness(func() (bool, string) { return false, "process restarted (test)" })
	}
	return f
}

func (f *leftoverFixture) undefines() []libvirtfake.Event {
	var out []libvirtfake.Event
	for _, e := range f.fake.EventLog() {
		if e.Op == "undefine" && e.Domain == "pakg" {
			out = append(out, e)
		}
	}
	return out
}

func (f *leftoverFixture) orphanOpen(t *testing.T) bool {
	t.Helper()
	all, err := corrosion.ListHealthConditions(context.Background(), f.db, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range all {
		if c.Evaluator == OrphanRuntimeEvaluator && c.SubjectID == "pakg@node-4" {
			return true
		}
	}
	return false
}

func supersededPresent(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// The lab 2 shape: on its second sighting the reconciler undefines the
// shut-off domain, keeping its firmware state, removes the owner-epoch marker
// and its directory, leaves the disk, records a VM event, and raises nothing.
// One pass alone undefines nothing.
//
// Red on b4ef9fe9: the domain stays defined and vm_orphan_runtime is raised.
func TestReconciler_UndefinesADeletedVMsSupersededStoppedDomain(t *testing.T) {
	for _, reason := range []string{"unknown", "destroyed", "guest-shutdown"} {
		t.Run(reason, func(t *testing.T) {
			c := lab2Case()
			c.reason = reason
			f := newLeftoverFixture(t, c)
			ctx := context.Background()

			f.r.ReconcileOnce(ctx)
			if !f.fake.DomainExists("pakg") {
				t.Fatal("one sighting undefined the domain; the orphan report's two are required")
			}
			f.r.ReconcileOnce(ctx)
			if f.fake.DomainExists("pakg") {
				t.Fatal("the superseded shut-off domain is still defined after two passes")
			}
			u := f.undefines()
			if len(u) != 1 || u[0].Note != "keep_state=true" {
				t.Fatalf("undefines = %+v, want one keeping the UEFI vars and TPM state", u)
			}
			if supersededPresent(f.marker) || supersededPresent(filepath.Dir(f.marker)) {
				t.Fatal("the owner-epoch marker (or its directory) is still there")
			}
			if b, err := os.ReadFile(f.disk); err != nil || string(b) != "pakg's real data" {
				t.Fatalf("the disk was touched: %q, %v", b, err)
			}
			if f.orphanOpen(t) {
				t.Fatal("vm_orphan_runtime is open for an undefined domain")
			}
			evs, err := corrosion.ListVMEvents(ctx, f.db, "pakg", 10, "")
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, e := range evs {
				if e.Type == "vm.leftover.undefined" && e.HostName == "node-4" {
					found = true
				}
			}
			if !found {
				t.Fatalf("no vm.leftover.undefined event: %+v", evs)
			}
		})
	}
}

// Every case that must stay report-only: the domain stays defined, the marker
// stays, and (for a recognised runtime on a trusted replica) the orphan
// condition is raised as before.
//
// Mutations: `>` to `>=` on the epochs — "row epoch equal" goes red; drop the
// shut-off check — "running" and "paused" go red; drop the managed-save check
// — "managed-save image" goes red; drop the host-local marker read — "marker
// unreadable" and "marker not older" go red; drop the other-host check —
// "tombstone names this host" goes red.
func TestReconciler_KeepsEveryDomainNotProvablySuperseded(t *testing.T) {
	for _, tc := range []struct {
		name     string
		mutate   func(*supersededCase)
		reported bool
	}{
		{"running", func(c *supersededCase) { c.state, c.reason = libvirtfake.StateRunning, "" }, true},
		{"paused", func(c *supersededCase) { c.state, c.reason = libvirtfake.StatePaused, "" }, true},
		{"crashed", func(c *supersededCase) { c.reason = "crashed" }, true},
		// No host-local marker, so the domain's own epoch alone decides.
		{"row epoch equal", func(c *supersededCase) { c.rowEpoch, c.fileEpoch = 1, 0 }, true},
		{"row epoch older (the claimvm shape)", func(c *supersededCase) { c.rowEpoch, c.domainEpoch, c.fileEpoch = 0, 2, 2 }, true},
		{"managed stamp only", func(c *supersededCase) { c.domainEpoch, c.managed = 0, true }, true},
		{"managed-save image", func(c *supersededCase) { c.managedSave = true }, true},
		{"marker unreadable", func(c *supersededCase) { c.fileGarbage = true }, true},
		{"marker not older", func(c *supersededCase) { c.fileEpoch = 2 }, true},
		{"tombstone names this host", func(c *supersededCase) { c.rowHost = "node-4" }, true},
		{"replica not caught up", func(c *supersededCase) { c.staleReplica = true }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := lab2Case()
			tc.mutate(&c)
			f := newLeftoverFixture(t, c)
			markerBefore := supersededPresent(f.marker)
			ctx := context.Background()
			for i := 0; i < 3; i++ {
				f.r.ReconcileOnce(ctx)
			}
			if !f.fake.DomainExists("pakg") {
				t.Fatal("a domain that is not provably superseded was undefined")
			}
			if u := f.undefines(); len(u) != 0 {
				t.Fatalf("undefines = %+v, want none", u)
			}
			if supersededPresent(f.marker) != markerBefore {
				t.Fatal("the owner-epoch marker was removed")
			}
			if got := f.orphanOpen(t); got != tc.reported {
				t.Fatalf("vm_orphan_runtime open = %v, want %v", got, tc.reported)
			}
		})
	}
}
