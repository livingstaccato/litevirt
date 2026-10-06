// Fleet scenarios for a Secure Boot VM with a host-local disk: `lv host drain`
// and `lv migrate --cold` move it stopped, with its disk and its UEFI vars
// (NVRAM), the way they move any stopped VM with its disk.
//
// On the lab both were refused, with "has a host-local disk ... move it to
// shared storage first", and the drain's message for a RUNNING one sent the
// operator to exactly those two routes. The cold path has streamed host-local
// disks since it learned to move a stopped VM (Task 8); the refusal predates
// that and was all that stood between a firmware VM and it.
//
// The vTPM half of the firmware travels in the same bundle; the fleet's nodes
// share one swtpm root (a process-wide path), so it is pinned in
// internal/grpcapi (TestColdMigrateStoppedVM_CarriesFirmwareWithAHostLocalDisk)
// with a root per host.

package fleet

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
)

// fwUUID is the scenario domain's uuid (newColdStoppedScenario).
const fwUUID = "11111111-2222-4333-8444-555555555555"

// makeSecureBoot turns the scenario's os1 into a UEFI Secure Boot VM with its
// vars file on the source, labels the target Secure-Boot-capable, and gives
// both nodes one firmware layout, as every host of a real cluster has. It
// returns the vars file's content.
func (sc *coldStoppedScenario) makeSecureBoot(t *testing.T) []byte {
	t.Helper()
	ctx := context.Background()
	spec, err := json.Marshal(&pb.VMSpec{Name: "os1", Cpu: 1, MemoryMib: 256, SecureBoot: true, Firmware: "uefi", Uuid: fwUUID})
	if err != nil {
		t.Fatal(err)
	}
	if err := sc.src.DB.Execute(ctx, `UPDATE vms SET spec = ?, updated_at = ? WHERE name = 'os1'`, string(spec), sc.src.DB.NowTS()); err != nil {
		t.Fatalf("mark os1 Secure Boot: %v", err)
	}
	if err := corrosion.SetHostLabel(ctx, sc.src.DB, sc.dst.Name, corrosion.LabelSecureBootCapable, "true"); err != nil {
		t.Fatalf("label %s Secure-Boot-capable: %v", sc.dst.Name, err)
	}
	layout := filepath.Join(sc.c.tmpRoot, "layout")
	for _, n := range []*Node{sc.src, sc.dst} {
		n.Server.SetFirmwareLayoutDirForTest(layout)
	}
	vars := []byte("os1's UEFI vars: enrolled Secure Boot keys")
	p := sc.nvram(sc.src)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, vars, 0o600); err != nil {
		t.Fatal(err)
	}
	return vars
}

// nvram is where node n keeps os1's UEFI vars file.
func (sc *coldStoppedScenario) nvram(n *Node) string {
	return lv.NvramPath(filepath.Join(sc.c.tmpRoot, n.Name, "data"), "os1")
}

// assertFirmwareVMMoved: os1 is on the target, stopped, with its disk and its
// vars file, and nothing of it is left on the source.
func (sc *coldStoppedScenario) assertFirmwareVMMoved(t *testing.T, vars []byte) {
	t.Helper()
	if vm := sc.vm(t); vm.HostName != sc.dst.Name || vm.State != "stopped" {
		t.Errorf("os1 row = host %s state %s, want host %s state stopped", vm.HostName, vm.State, sc.dst.Name)
	}
	for name, host := range sc.diskHosts(t) {
		if host != sc.dst.Name {
			t.Errorf("disk %s row names %s, want %s", name, host, sc.dst.Name)
		}
	}
	if got, err := os.ReadFile(sc.file(sc.dst, sc.disk)); err != nil || string(got) != string(sc.payload) {
		t.Errorf("os1's disk did not arrive intact on %s (err %v)", sc.dst.Name, err)
	}
	if got, err := os.ReadFile(sc.nvram(sc.dst)); err != nil || string(got) != string(vars) {
		t.Errorf("os1's UEFI vars did not arrive intact on %s: %q (err %v)", sc.dst.Name, got, err)
	}
	if !sc.dst.Virt.DomainExists("os1") {
		t.Errorf("os1's domain is not defined on %s", sc.dst.Name)
	}
	if active, _ := sc.dst.Virt.DomainIsActive("os1"); active {
		t.Errorf("os1 was started on %s; it moved stopped", sc.dst.Name)
	}
	if sc.src.Virt.DomainExists("os1") {
		t.Errorf("os1's domain is still defined on %s", sc.src.Name)
	}
	if _, err := os.Stat(sc.file(sc.src, sc.disk)); !os.IsNotExist(err) {
		t.Errorf("os1's disk is still on %s (stat: %v)", sc.src.Name, err)
	}
	if _, err := os.Stat(sc.nvram(sc.src)); !os.IsNotExist(err) {
		t.Errorf("os1's UEFI vars are still on %s (stat: %v)", sc.src.Name, err)
	}
}

// A stopped Secure Boot VM with a host-local disk drains: it moves cold with
// its disk and its vars file, and the drain completes.
//
// Mutation: restore the cold path's host-local refusal for a firmware VM —
// os1's frame is "failed ... has a host-local disk" and the drain ends
// incomplete.
func TestFleet_DrainMovesAStoppedFirmwareVMWithItsLocalDisk(t *testing.T) {
	sc := newColdStoppedScenario(t)
	vars := sc.makeSecureBoot(t)

	progress, err := sc.drain(t)
	if err != nil {
		t.Fatalf("drain of a stopped Secure Boot VM with a host-local disk: %v (os1: %+v)", err, progress["os1"])
	}
	if p := progress["os1"]; p == nil || p.Status != "done" || p.Error != "" || p.Strategy != pb.MigrateStrategy_MIGRATE_COLD {
		t.Fatalf("drain progress for os1 = %+v, want done cold", p)
	}
	sc.assertFirmwareVMMoved(t, vars)
}

// `lv migrate os1 <target> --cold` moves the same VM the same way.
//
// Mutation: as above — the migration is refused "has a host-local disk".
func TestFleet_ColdMigrationMovesAStoppedFirmwareVMWithItsLocalDisk(t *testing.T) {
	sc := newColdStoppedScenario(t)
	vars := sc.makeSecureBoot(t)

	if err := sc.migrateCold(t); err != nil {
		t.Fatalf("lv migrate --cold of a stopped Secure Boot VM with a host-local disk: %v", err)
	}
	sc.assertFirmwareVMMoved(t, vars)
}

// A RUNNING Secure Boot VM is still not drained, and the drain says what to
// do instead — and what it says works: stop it, drain again, and it moves.
// On the lab both routes the message named were refused for a VM with a
// host-local disk.
//
// Mutations: restore the host-local refusal — the second drain fails with it;
// let the running refusal name `lv migrate --cold` without the stop — the
// message check goes red.
func TestFleet_DrainOfARunningFirmwareVMNamesARouteThatWorks(t *testing.T) {
	sc := newColdStoppedScenario(t)
	vars := sc.makeSecureBoot(t)
	sc.makeRunning(t)
	ctx := context.Background()

	progress, err := sc.drain(t)
	assertIncomplete(t, err)
	p := progress["os1"]
	if p == nil || p.Status != "skipped" {
		t.Fatalf("drain progress for running os1 = %+v, want skipped", p)
	}
	for _, w := range []string{"`lv stop os1`", "drain again", "`lv migrate os1 <target-host> --cold`"} {
		if !strings.Contains(p.Error, w) {
			t.Errorf("running firmware VM's drain message %q does not contain %q", p.Error, w)
		}
	}

	if _, err := sc.c.SelfClient(sc.src).StopVM(ctx, &pb.StopVMRequest{Name: "os1"}); err != nil {
		t.Fatalf("lv stop os1 on the draining host: %v", err)
	}
	progress, err = sc.drain(t)
	if err != nil {
		t.Fatalf("drain again after stopping os1: %v (os1: %+v)", err, progress["os1"])
	}
	if p := progress["os1"]; p == nil || p.Status != "done" || p.Strategy != pb.MigrateStrategy_MIGRATE_COLD {
		t.Fatalf("second drain progress for os1 = %+v, want done cold", p)
	}
	sc.assertFirmwareVMMoved(t, vars)
}
