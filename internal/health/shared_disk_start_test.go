package health

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// sharedRowVM puts vm1 on node-a with a root disk here and a shared (nfs)
// data1 whose row names dataHost, as a partial promotion leaves it. It
// returns data1's path.
func sharedRowVM(t *testing.T, db *corrosion.Client, state, spec, dataHost string) string {
	t.Helper()
	dir := t.TempDir()
	root, data1 := filepath.Join(dir, "vm1-root.qcow2"), filepath.Join(dir, "vm1-data1.qcow2")
	for _, p := range []string{root, data1} {
		if err := os.WriteFile(p, []byte("disk"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := corrosion.InsertVM(context.Background(), db, corrosion.VMRecord{
		Name: "vm1", HostName: "node-a", Spec: spec, State: state,
	}, nil, []corrosion.DiskRecord{
		{VMName: "vm1", DiskName: "root", HostName: "node-a", Path: root, StorageType: "local", TargetDev: "vda"},
		{VMName: "vm1", DiskName: "data1", HostName: dataHost, Path: data1, StorageType: "nfs", StorageVolume: "nfs1", TargetDev: "vdb"},
	}); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	return data1
}

func fenceRow(t *testing.T, db *corrosion.Client, host, method, result string, age time.Duration) {
	t.Helper()
	ts := time.Now().Add(-age).UTC().Format(time.RFC3339)
	if err := db.Execute(context.Background(), `INSERT INTO fencing_log (id, host_name, method, result, timestamp, detail)
		VALUES (?, ?, ?, ?, ?, '')`, method+"-"+result+"-"+host, host, method, result, ts); err != nil {
		t.Fatal(err)
	}
}

// Review R4-I2: a start the reconciler builds from the disk rows — onboot, or
// the restart of a VM recorded running whose domain is gone — attaches a
// shared disk whose row names another host only when that host is proven
// powered off, the rule a promotion's reattach applies. A partial promotion
// leaves exactly such a row (naming the VM's old owner) and used to see the
// disk attached at the promoted VM's next start without that host judged:
// two writers. The VM still starts — main started it — without the disk, and
// the start is reported with the disk, why, and the remedy; a start that
// withholds nothing clears the report.
//
// Mutation "attach every row" (JudgeSharedDiskRows withholds nothing) — red
// on every withheld row. Mutation "proof ignored" (SharedDiskOwnerVerdict
// never passes) — red on the proven-off rows.
func TestReconcilerStart_ASharedDiskWhoseOwnerIsNotProvenOffIsLeftOut(t *testing.T) {
	for _, c := range []struct {
		name     string
		state    string // old-owner's hosts row state; "" = no row
		fence    []string
		dataHost string
		attached bool
		why      string
	}{
		{"fenced by ssh", "fenced", []string{"ssh", "fenced"}, "old-owner", false, "old-owner is fenced, but not proven powered off"},
		{"no hosts row, no proof", "", nil, "old-owner", false, "old-owner is no longer a member of the cluster"},
		{"active", "active", nil, "old-owner", false, "its owner old-owner is active, not fenced"},
		{"offline", "offline", nil, "old-owner", false, "its owner old-owner is offline, not fenced"},
		{"fenced by ipmi", "fenced", []string{"ipmi", "fenced"}, "old-owner", true, ""},
		{"no hosts row, confirmed", "", []string{"manual", "manual-confirmed"}, "old-owner", true, ""},
		{"row names this host", "", nil, "node-a", true, ""},
		{"row names no host", "", nil, "", true, ""},
	} {
		for _, path := range []string{"onboot", "domain gone"} {
			t.Run(c.name+"/"+path, func(t *testing.T) {
				db := testReconcilerDB(t)
				ctx := context.Background()
				state, spec := "stopped", `{"onboot":true}`
				if path == "domain gone" {
					state, spec = "running", `{}`
				}
				data1 := sharedRowVM(t, db, state, spec, c.dataHost)
				if c.state != "" {
					if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{Name: "old-owner", Address: "10.0.0.9", State: c.state}); err != nil {
						t.Fatal(err)
					}
				}
				if c.fence != nil {
					fenceRow(t, db, "old-owner", c.fence[0], c.fence[1], time.Minute)
				}
				fake := libvirtfake.New()
				r := NewReconciler("node-a", t.TempDir(), db, fake)
				var reported, cleared []string
				r.SetSharedDiskWithheldReporter(
					func(_ context.Context, vm, detail string) { reported = append(reported, vm+": "+detail) },
					func(_ context.Context, vm string) { cleared = append(cleared, vm) })

				if path == "onboot" {
					r.StartOnbootVMs(ctx)
				} else {
					vm, _ := corrosion.GetVM(ctx, db, "vm1")
					r.startPendingVM(ctx, *vm)
				}
				if st, _ := fake.DomainState("vm1"); st != "running" {
					t.Fatalf("vm1 was not started (state %q): a withheld shared disk must never refuse the start", st)
				}
				xml := fake.DefinedXML("vm1")
				if got := strings.Contains(xml, data1); got != c.attached {
					t.Fatalf("data1 attached = %v, want %v:\n%s", got, c.attached, xml)
				}
				if c.attached {
					if len(reported) != 0 || len(cleared) != 1 {
						t.Errorf("reported %v, cleared %v; want only a clear", reported, cleared)
					}
					return
				}
				if len(reported) != 1 || len(cleared) != 0 {
					t.Fatalf("reported %v, cleared %v; want one report", reported, cleared)
				}
				for _, want := range []string{"data1", data1, c.why,
					"once old-owner is powered off, `lv host fence-confirm old-owner`", "then `lv restart vm1`",
					"no move of vm1 re-homes the disk's row"} {
					if !strings.Contains(reported[0], want) {
						t.Errorf("report = %q, want %q", reported[0], want)
					}
				}
			})
		}
	}
}

// Review m1: a withheld BOOT disk does not start a VM with no root: the start
// waits for the proof. A local start leaves the VM in error with the remedy.
//
// Mutation "boot disk like any other" (WithheldBootDisk never finds one) — red.
func TestReconcilerStart_AWithheldBootDiskDoesNotStartTheVM(t *testing.T) {
	db := testReconcilerDB(t)
	ctx := context.Background()
	data1 := sharedRowVM(t, db, "stopped", `{"onboot":true}`, "node-a")
	_ = data1
	if err := db.Execute(ctx, `UPDATE vm_disks SET host_name = 'old-owner', storage_type = 'nfs' WHERE vm_name = 'vm1' AND disk_name = 'root'`); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{Name: "old-owner", Address: "10.0.0.9", State: "offline"}); err != nil {
		t.Fatal(err)
	}
	fake := libvirtfake.New()
	r := NewReconciler("node-a", t.TempDir(), db, fake)
	var reported []string
	r.SetSharedDiskWithheldReporter(func(_ context.Context, _, d string) { reported = append(reported, d) }, func(context.Context, string) {})
	r.StartOnbootVMs(ctx)
	if st, _ := fake.DomainState("vm1"); st == "running" {
		t.Fatal("vm1 was started without its boot disk")
	}
	vm, _ := corrosion.GetVM(ctx, db, "vm1")
	if vm == nil || vm.State != "error" || !strings.Contains(vm.StateDetail, "boot disk root is withheld") {
		t.Fatalf("vm1 = %+v, want error naming the withheld boot disk", vm)
	}
	if len(reported) != 1 || !strings.Contains(reported[0], "`lv host fence-confirm old-owner`") {
		t.Errorf("reported %v, want the remedy", reported)
	}
}
