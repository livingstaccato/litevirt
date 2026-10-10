// Fleet scenario: a RUNNING VM with a host-local disk fails over, and its
// real disk — the only copy of its data from before the failover — is kept
// and can be put back.
//
// The VM is restarted elsewhere under its failure policy, as before, on a
// disk rebuilt from its image: that host cannot reach the real one. What this
// pins is everything around that restart, across hosts:
//
//  1. the coordinator records the disk it left on the failed host
//     (vm_disk_stranded), and `lv inspect` shows it from any node;
//  2. when the failed host is back it sets the real disk aside under a name
//     nothing else takes, and the retention sweep keeps it while the VM
//     exists, whatever its state — before, it was deleted seven days after
//     the VM was running again;
//  3. a later failover back onto that host rebuilds the disk without
//     touching the copy, and an operator puts the copy back with
//     `lv host superseded-disks <host> --restore <copy>`, asked on another
//     node: the disk the VM ran on since is set aside in turn, not deleted.

package fleet

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/grpcapi"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/image"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// Mutations, each turning the test red at the step named:
//   - drop noteDiskStranded after the reschedule (step 1: no record, no
//     stranded disk in inspect);
//   - drop the set-aside in tendStrandedDisk (step 2: the real disk is still
//     at its path);
//   - drop the retention of a copy whose VM exists in PurgeSupersededDisks
//     (the last step: the sweep removes a copy of the running VM; in step 2
//     the VM is still pending, which holds its copies on its own);
//   - drop the set-aside of the current disk in RestoreSupersededDisk
//     (step 3: the restore refuses on the occupied path);
//   - record a pending VM's reschedule too (step 3: other, which never ran
//     hl, is named as holding its disk);
//   - leave StrandedDisks out of InspectVM (step 1).
func TestFleet_FailoverKeepsTheRealHostLocalDiskAndCanPutItBack(t *testing.T) {
	c := New(t, Options{Nodes: 3, SharedCRDT: true})
	defer c.Stop()
	ctx := context.Background()
	other, home, coord := c.Nodes[0], c.Nodes[1], c.Nodes[2]

	// home runs hl on a host-local overlay holding real data.
	homeData := filepath.Join(c.tmpRoot, home.Name, "data")
	store := image.NewStore(homeData)
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	if err := qcow2.Create(store.ImagePath("base"), 64<<20, nil); err != nil {
		t.Fatal(err)
	}
	path := store.DiskPath("hl", "root")
	if err := qcow2.CreateWithBacking(path, store.ImagePath("base"), 1<<30, nil); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("the VM's real data")); err != nil {
		t.Fatal(err)
	}
	f.Close()
	realBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	spec := func(pin string) string {
		return `{"name":"hl","cpu":1,"memory_mib":256,"on_host_failure":"restart-any","placement":{"host":"` + pin + `"}}`
	}
	if err := corrosion.InsertVM(ctx, coord.DB, corrosion.VMRecord{
		Name: "hl", HostName: home.Name, State: "running", CPUActual: 1, MemActual: 256, Spec: spec(other.Name),
	}, nil, []corrosion.DiskRecord{{
		VMName: "hl", DiskName: "root", HostName: home.Name, Path: path,
		BackingImage: "base", SizeBytes: 1 << 30, StorageType: "local", TargetDev: "vda",
	}}); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	// Step 1: home fails; hl is restarted on other, as before — and the disk
	// it left on home is recorded and shown.
	if got := fenceVictim(t, c, coord, home, other, coord); got != 1 {
		t.Fatalf("fencer fired %d times, want 1", got)
	}
	if vm, _ := corrosion.GetVM(ctx, coord.DB, "hl"); vm == nil || vm.HostName != other.Name || vm.State != "pending" {
		t.Fatalf("hl after the failover = %+v, want it pending on %s", vm, other.Name)
	}
	inspected, err := c.SelfClient(coord).InspectVM(ctx, &pb.InspectVMRequest{Name: "hl"})
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	if len(inspected.StrandedDisks) != 1 || inspected.StrandedDisks[0].Host != home.Name ||
		inspected.StrandedDisks[0].Path != path || inspected.StrandedDisks[0].Copy != "" {
		t.Fatalf("inspect shows stranded disks %+v, want root at %s on %s", inspected.StrandedDisks, path, home.Name)
	}
	evs, err := corrosion.ListVMEvents(ctx, coord.DB, "hl", 20, "")
	if err != nil {
		t.Fatal(err)
	}
	if !hasEvent(evs, "vm.failover.disk_stranded", home.Name) {
		t.Fatalf("no vm.failover.disk_stranded event naming %s: %+v", home.Name, evs)
	}

	// Step 2: home is back. Its reconciler sets the real disk aside, and the
	// sweep keeps it a month later: the VM still exists.
	if err := coord.DB.Execute(ctx, `UPDATE hosts SET state = 'active', updated_at = ? WHERE name = ?`, coord.DB.NowTS(), home.Name); err != nil {
		t.Fatal(err)
	}
	if err := coord.DB.Execute(ctx, `DELETE FROM host_health WHERE target = ?`, home.Name); err != nil {
		t.Fatal(err)
	}
	homeRec := health.NewReconciler(home.Name, homeData, home.DB, home.Virt)
	homeRec.SetAutoPullImage(func(context.Context, string) error { return nil })
	homeRec.ReconcileOnce(ctx)
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("the real disk is still at %s on %s after it came back (stat err %v)", path, home.Name, err)
	}
	inspected, err = c.SelfClient(other).InspectVM(ctx, &pb.InspectVMRequest{Name: "hl"})
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	if len(inspected.StrandedDisks) != 1 || inspected.StrandedDisks[0].Copy == "" {
		t.Fatalf("inspect shows %+v, want the set-aside copy", inspected.StrandedDisks)
	}
	copyPath := inspected.StrandedDisks[0].Copy
	if b, err := os.ReadFile(copyPath); err != nil || !bytes.Equal(b, realBytes) {
		t.Fatalf("the copy at %s does not hold the real disk (err %v)", copyPath, err)
	}
	if _, err := health.PurgeSupersededDisks(ctx, home.DB, homeData, 7*24*time.Hour, time.Now().Add(30*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(copyPath); err != nil {
		t.Fatalf("the sweep removed the only copy of hl's data from before the failover: %v", err)
	}

	// Step 3: other fails before it ever started hl; hl comes back to home,
	// on a disk rebuilt from its image, the copy untouched beside it.
	if err := coord.DB.Execute(ctx, `UPDATE vms SET spec = ?, updated_at = ? WHERE name = 'hl'`, spec(home.Name), coord.DB.NowTS()); err != nil {
		t.Fatal(err)
	}
	if got := fenceVictim(t, c, coord, other, home, coord); got != 1 {
		t.Fatalf("second fencer fired %d times, want 1", got)
	}
	if vm, _ := corrosion.GetVM(ctx, coord.DB, "hl"); vm == nil || vm.HostName != home.Name || vm.State != "pending" {
		t.Fatalf("hl after the second failover = %+v, want it pending on %s", vm, home.Name)
	}
	// other never ran hl, so nothing of hl's is on it: no record names it.
	if got, _ := health.StrandedDisksOf(ctx, coord.DB, "hl"); len(got) != 1 || got[0].Host != home.Name {
		t.Fatalf("stranded records after the second failover = %+v, want only %s's", got, home.Name)
	}
	homeRec.ReconcileOnce(ctx)
	if vm, _ := corrosion.GetVM(ctx, coord.DB, "hl"); vm == nil || vm.State != "running" {
		t.Fatalf("hl = %+v, want it running on %s", vm, home.Name)
	}
	if b, _ := os.ReadFile(path); bytes.Equal(b, realBytes) {
		t.Fatal("the rebuilt disk is the copy; the start took the set-aside file")
	}
	if b, err := os.ReadFile(copyPath); err != nil || !bytes.Equal(b, realBytes) {
		t.Fatalf("the restart onto %s touched the copy (err %v)", home.Name, err)
	}

	// The operator puts the real disk back, asking on another node.
	if _, err := c.SelfClient(coord).StopVM(ctx, &pb.StopVMRequest{Name: "hl"}); err != nil {
		t.Fatalf("stop: %v", err)
	}
	blankBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.SelfClient(coord).SupersededDisks(ctx, &pb.SupersededDisksRequest{
		Host: home.Name, Purge: true, OlderThanSec: grpcapi.SupersededNamedOnlySec, RestorePath: copyPath,
	})
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if resp.Restored != copyPath || resp.RestoredTo != path || resp.SetAside == "" {
		t.Fatalf("restore answered %+v", resp)
	}
	if b, err := os.ReadFile(path); err != nil || !bytes.Equal(b, realBytes) {
		t.Fatalf("after the restore the disk at %s is not the real one (err %v)", path, err)
	}
	if b, err := os.ReadFile(resp.SetAside); err != nil || !bytes.Equal(b, blankBytes) {
		t.Fatalf("the disk hl ran on since the failover was not kept at %s (err %v)", resp.SetAside, err)
	}
	retained := false
	for _, d := range resp.Disks {
		if d.Path == resp.SetAside && d.Retained != "" && !d.Removed {
			retained = true
		}
	}
	if !retained {
		t.Fatalf("the swapped-out disk is not listed as retained: %+v", resp.Disks)
	}
	if _, err := c.SelfClient(coord).StartVM(ctx, &pb.StartVMRequest{Name: "hl"}); err != nil {
		t.Fatalf("start on the restored disk: %v", err)
	}
	if !strings.Contains(home.Virt.DefinedXML("hl"), path) {
		t.Fatalf("hl is not defined on %s with its disk at %s", home.Name, path)
	}
	// hl runs again; a month on, the sweep still keeps the disk it ran on
	// while home was away: hl exists.
	if vm, _ := corrosion.GetVM(ctx, coord.DB, "hl"); vm == nil || vm.State != "running" {
		t.Fatalf("hl = %+v, want running", vm)
	}
	if _, err := health.PurgeSupersededDisks(ctx, home.DB, homeData, 7*24*time.Hour, time.Now().Add(30*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(resp.SetAside); err != nil {
		t.Fatalf("the sweep removed a copy of running hl's data: %v", err)
	}
}

func hasEvent(evs []corrosion.VMEventRecord, typ, mention string) bool {
	for _, e := range evs {
		if e.Type == typ && strings.Contains(e.Detail, mention) {
			return true
		}
	}
	return false
}
