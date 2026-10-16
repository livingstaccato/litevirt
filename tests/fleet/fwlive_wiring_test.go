package fleet

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fwmig"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// The fleet carries what a live firmware move needs from the daemon: each
// node's live firmware host check (SetLiveFirmwareHost) and its hold sweep
// (RunFirmwareHoldSweep). The scenarios themselves are tests/fleet/fwlive*.

const (
	fwwVM   = "fwlive1"
	fwwUUID = "7a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d"
)

var (
	fwwPermall = []byte("fwlive1's TPM state")
	fwwNvram   = []byte("fwlive1's UEFI vars")
)

// fwwCluster is two nodes, src running fwlive1 (Secure Boot + vTPM, no disk)
// with its firmware state, dst labelled for a live firmware move, one firmware
// layout, and src's migrations landing on dst.
func fwwCluster(t *testing.T) (*Cluster, *Node, *Node) {
	t.Helper()
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	t.Cleanup(c.Stop)
	src, dst := c.Nodes[0], c.Nodes[1]
	ctx := context.Background()
	setHostCapacity(t, c, src.Name, 64, 65536)
	setHostCapacity(t, c, dst.Name, 64, 65536)
	layout := filepath.Join(c.tmpRoot, "layout")
	for _, n := range c.Nodes {
		n.Server.SetFirmwareLayoutDirForTest(layout)
	}
	for _, l := range []string{corrosion.LabelTPMCapable, corrosion.LabelSecureBootCapable, corrosion.LabelFwLiveMigrate} {
		if err := corrosion.SetHostLabel(ctx, src.DB, dst.Name, l, "true"); err != nil {
			t.Fatal(err)
		}
	}
	spec, err := json.Marshal(&pb.VMSpec{Name: fwwVM, Cpu: 1, MemoryMib: 256, SecureBoot: true, Tpm: true, Firmware: "uefi", Uuid: fwwUUID})
	if err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertVM(ctx, src.DB, corrosion.VMRecord{Name: fwwVM, HostName: src.Name, State: "running",
		Spec: string(spec), CPUActual: 1, MemActual: 256}, nil, nil); err != nil {
		t.Fatal(err)
	}
	x := "<domain type='kvm'><name>" + fwwVM + "</name><uuid>" + fwwUUID + "</uuid><os><type>hvm</type>" +
		"<loader readonly='yes' secure='yes' type='pflash'>/usr/share/OVMF/OVMF_CODE.secboot.fd</loader>" +
		"<nvram>" + src.FW.NvramPath(fwwVM) + "</nvram></os><devices>" +
		"<tpm model='tpm-crb'><backend type='emulator' version='2.0' persistent_state='yes'/></tpm></devices></domain>"
	src.Virt.SetInactiveXML(fwwVM, x)
	src.Virt.SetActiveXML(fwwVM, x)
	src.Virt.SetState(fwwVM, libvirtfake.StateRunning)
	hlWrite(t, filepath.Join(src.FW.SwtpmDir(fwwUUID), "tpm2", "tpm2-00.permall"), fwwPermall)
	hlWrite(t, src.FW.NvramPath(fwwVM), fwwNvram)
	src.LandMigrationsOn(dst)
	return c, src, dst
}

// A live firmware move runs end to end over real gRPC: the guest lands paused,
// verifies, commits and is released running on dst with the source's final
// NVRAM, and the source keeps its state for the source cleanup.
//
// Mutations: drop SetLiveFirmwareHost from buildServer — refused at stage A,
// red.
func TestFleet_LiveFirmwareMoveWired(t *testing.T) {
	c, src, dst := fwwCluster(t)
	if err := migrateAt(t, c, src, fwwVM, dst.Name); err != nil {
		t.Fatalf("live firmware move: %v", err)
	}
	if st, _ := dst.Virt.RawState(fwwVM); st != libvirtfake.StateRunning {
		t.Fatalf("target domain %q, want running", st)
	}
	vm, err := corrosion.GetVM(context.Background(), src.DB, fwwVM)
	if err != nil || vm == nil || vm.HostName != dst.Name || vm.State != "running" {
		t.Fatalf("row %+v (%v), want running on %s", vm, err, dst.Name)
	}
	if got := hlRead(t, dst.FW.NvramPath(fwwVM)); !bytes.Equal(got, fwwNvram) {
		t.Errorf("target NVRAM %q, want the source's final", got)
	}
	if _, ok, err := fwmig.New(dst.FW.DataDir).GetHold(fwwVM); ok || err != nil {
		t.Errorf("the target still holds the move (%v)", err)
	}
	m, ok, err := fwmig.New(src.FW.DataDir).GetMarker(fwwVM)
	if err != nil || !ok || m.Phase != fwmig.PhaseReleased {
		t.Errorf("source marker %+v (present %v, %v), want released, awaiting the source cleanup", m.Phase, ok, err)
	}
	if got := hlRead(t, filepath.Join(src.FW.SwtpmDir(fwwUUID), "tpm2", "tpm2-00.permall")); !bytes.Equal(got, fwwPermall) {
		t.Errorf("source permall %q, want it kept", got)
	}
}

// Each node runs the hold sweep: a hold whose guest has been held paused for
// longer than the sweep's condition delay is reported as
// firmware_migration_held.
//
// Mutation: drop RunFirmwareHoldSweep from buildServer — red.
func TestFleet_FirmwareHoldSweepRuns(t *testing.T) {
	c, src, dst := fwwCluster(t)
	_ = c
	vm, err := corrosion.GetVM(context.Background(), src.DB, fwwVM)
	if err != nil || vm == nil {
		t.Fatal(err)
	}
	h := fwmig.Hold{VM: fwwVM, Binding: fwmig.Binding{UUID: fwwUUID, CreatedAt: vm.CreatedAt, Attempt: "a1a1a1a1-0000-4000-8000-0000000000aa"},
		Source: src.Name, Since: time.Now().Add(-time.Hour).UTC(), State: fwmig.HoldPrepared, TPM: true, UEFI: true,
		NvramMaterialised: fwmig.NvramDone, SwtpmAbsentAtPrepare: true}
	if err := fwmig.New(dst.FW.DataDir).PutHold(h); err != nil {
		t.Fatal(err)
	}
	dst.Virt.SetInactiveXML(fwwVM, "<domain type='kvm'><name>"+fwwVM+"</name><uuid>"+fwwUUID+"</uuid></domain>")
	dst.Virt.SetState(fwwVM, libvirtfake.StatePaused)
	deadline := time.Now().Add(30 * time.Second)
	for {
		row, found, err := corrosion.GetHealthCondition(context.Background(), dst.DB, "firmware_migration", "firmware_migration_held", "vm", fwwVM)
		if err == nil && found && row.Lifecycle != corrosion.ConditionResolved {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("no firmware_migration_held from %s's hold sweep after 30 s (%v)", dst.Name, err)
		}
		time.Sleep(200 * time.Millisecond)
	}
}
