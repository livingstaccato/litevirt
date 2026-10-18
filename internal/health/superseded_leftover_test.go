package health

import (
	"context"
	"os"
	"path/filepath"
	"strings"
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
	vars    []string // UEFI vars files the domain has
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

	// UEFI vars: the definition's own (libvirt's directory, a plain UEFI
	// VM's) and the name-keyed one a Secure Boot or vTPM VM uses.
	old := LibvirtNvramDir
	LibvirtNvramDir = t.TempDir()
	t.Cleanup(func() { LibvirtNvramDir = old })
	f.vars = []string{filepath.Join(LibvirtNvramDir, "pakg_VARS.fd"), filepath.Join(f.dataDir, "nvram", "pakg_VARS.fd")}
	for _, v := range f.vars {
		if err := os.MkdirAll(filepath.Dir(v), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(v, []byte("vars of "+v), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	f.fake.SetInactiveXML("pakg", `<domain type="kvm"><name>pakg</name><uuid>11111111-2222-4333-8444-555555555555</uuid>`+
		`<os><nvram>`+f.vars[0]+`</nvram></os></domain>`)

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
			// Each vars file is set aside whole, and listed with the VM's name.
			listed, err := ListSupersededVars(f.dataDir)
			if err != nil {
				t.Fatal(err)
			}
			for _, v := range f.vars {
				if supersededPresent(v) {
					t.Errorf("%s is still at its path", v)
				}
				set, _ := filepath.Glob(v + ".superseded-*")
				if len(set) != 1 {
					t.Fatalf("%s set aside as %v, want one file", v, set)
				}
				if b, err := os.ReadFile(set[0]); err != nil || string(b) != "vars of "+v {
					t.Errorf("%s holds %q (%v)", set[0], b, err)
				}
				found := false
				for _, l := range listed {
					found = found || (l.Path == set[0] && l.VarsPath == v && l.VM == "pakg")
				}
				if !found {
					t.Errorf("%s not listed: %+v", set[0], listed)
				}
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
			for _, v := range f.vars {
				if !supersededPresent(v) {
					t.Errorf("%s was moved", v)
				}
			}
			if got := f.orphanOpen(t); got != tc.reported {
				t.Fatalf("vm_orphan_runtime open = %v, want %v", got, tc.reported)
			}
		})
	}
}

// A domain that starts between the rule's check and the undefine survives the
// undefine as a transient, running one: it is left to the orphan report, with
// its marker and UEFI vars, and no event says it was undefined.
//
// Mutation: drop the post-undefine DomainExists check — the marker and the
// vars go and the event is written.
func TestReconciler_DomainStartedAtTheUndefineIsLeftAlone(t *testing.T) {
	f := newLeftoverFixture(t, lab2Case())
	f.fake.FailUndefinePreserv = func(name string) error {
		f.fake.SetState(name, libvirtfake.StateRunning)
		return nil
	}
	ctx := context.Background()
	f.r.ReconcileOnce(ctx)
	f.r.ReconcileOnce(ctx)
	if !f.fake.DomainExists("pakg") {
		t.Fatal("the started domain is gone")
	}
	if !supersededPresent(f.marker) {
		t.Fatal("the marker of a running domain was removed")
	}
	for _, v := range f.vars {
		if !supersededPresent(v) {
			t.Errorf("%s of a running domain was moved", v)
		}
	}
	evs, err := corrosion.ListVMEvents(ctx, f.db, "pakg", 10, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range evs {
		if e.Type == "vm.leftover.undefined" {
			t.Fatalf("an undefine was recorded for a domain that kept running: %+v", e)
		}
	}
}

// A create of the name on this host replaces the definition between the
// rule's check and the undefine: the new definition (no owner epoch, another
// uuid) is never undefined.
//
// Mutation: drop the identity re-check before the undefine — the new
// definition is undefined.
func TestReconciler_ADefinitionReplacedMeanwhileIsNotUndefined(t *testing.T) {
	f := newLeftoverFixture(t, lab2Case())
	ctx := context.Background()
	f.r.ReconcileOnce(ctx) // the first sighting
	replaced := false
	f.fake.FailHasManagedSaveImage = func(name string) error {
		if !replaced {
			replaced = true
			// What a create does: undefine the stopped leftover, define its own.
			if err := f.fake.UndefineDomain(name, true); err != nil {
				t.Error(err)
			}
			f.fake.SetState(name, libvirtfake.StateShutdown)
			f.fake.SetInactiveXML(name, `<domain type="kvm"><name>pakg</name><uuid>99999999-2222-4333-8444-555555555555</uuid></domain>`)
		}
		return nil
	}
	f.r.ReconcileOnce(ctx)
	if !replaced {
		t.Fatal("the rule never reached the managed-save check")
	}
	if !f.fake.DomainExists("pakg") {
		t.Fatal("the create's new definition was undefined")
	}
	if u := f.undefines(); len(u) != 1 || u[0].Note != "remove_storage=true" {
		t.Fatalf("undefines = %+v, want only the create's", u)
	}
}

// redefineAfterCheck is the fake with a same-name create's define landing
// right after the reap's post-undefine DomainExists check.
type redefineAfterCheck struct {
	*libvirtfake.Fake
	undefined, redefined bool
}

func (v *redefineAfterCheck) UndefineDomainPreservingState(name string) error {
	err := v.Fake.UndefineDomainPreservingState(name)
	v.undefined = err == nil
	return err
}

func (v *redefineAfterCheck) DomainExists(name string) bool {
	exists := v.Fake.DomainExists(name)
	if v.undefined && !v.redefined {
		v.redefined = true
		v.Fake.SetState(name, libvirtfake.StateShutdown)
		v.Fake.SetInactiveXML(name, `<domain type="kvm"><name>pakg</name><uuid>99999999-2222-4333-8444-555555555555</uuid></domain>`)
	}
	return exists
}

// A same-name create that defines its domain, or whose record arrives, after
// the reap's undefine keeps the UEFI vars where they are: the name may be
// theirs now.
//
// Mutation: drop the re-check before each vars rename — both subtests red.
func TestReap_VarsStayWhenTheNameIsRetakenAfterTheUndefine(t *testing.T) {
	ctx := context.Background()
	check := func(t *testing.T, f *leftoverFixture, virt SupersededLeftoverVirt, why string) {
		t.Helper()
		ok, reason := ReapSupersededStoppedLeftover(ctx, f.db, virt, f.dataDir, "node-4", "pakg", "test")
		if !ok {
			t.Fatalf("not undefined: %s", reason)
		}
		for _, v := range f.vars {
			if !supersededPresent(v) {
				t.Errorf("%s was moved", v)
			}
		}
		set, err := ListSupersededVars(f.dataDir)
		if err != nil {
			t.Fatal(err)
		}
		if len(set) != 0 {
			t.Errorf("set-aside vars = %+v, want none", set)
		}
		evs, err := corrosion.ListVMEvents(ctx, f.db, "pakg", 10, "")
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, e := range evs {
			if e.Type == "vm.leftover.undefined" && strings.Contains(e.Detail, "left in place ("+why) {
				found = true
			}
		}
		if !found {
			t.Errorf("no event says the vars were left in place because %s: %+v", why, evs)
		}
	}
	t.Run("live record", func(t *testing.T) {
		f := newLeftoverFixture(t, lab2Case())
		f.fake.OnUndefined = func(name string) {
			if err := corrosion.InsertVM(ctx, f.db, corrosion.VMRecord{Name: name, HostName: "node-4", State: "pending", Spec: `{}`}, nil, nil); err != nil {
				t.Error(err)
			}
		}
		check(t, f, f.fake, "the name has a live record again")
	})
	t.Run("domain defined again", func(t *testing.T) {
		f := newLeftoverFixture(t, lab2Case())
		v := &redefineAfterCheck{Fake: f.fake}
		check(t, f, v, "a domain of the name is defined again")
		if !v.redefined {
			t.Fatal("the create's define never landed")
		}
	})
}
