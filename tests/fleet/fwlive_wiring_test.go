package fleet

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fwmig"
	lv "github.com/litevirt/litevirt/internal/libvirt"
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

// fwwCluster is the live firmware move scene without a disk (fwliveSetup,
// fwlive_scene_test.go): two nodes, src running fwlive1 (Secure Boot + vTPM)
// with its firmware state, dst labelled for a live firmware move, one
// firmware layout, and src's migrations landing on dst.
func fwwCluster(t *testing.T) (*Cluster, *Node, *Node) {
	t.Helper()
	sc := fwliveSetup(t, false)
	return sc.c, sc.src, sc.dst
}

// A live firmware move runs end to end over real gRPC: the guest lands paused,
// verifies, commits and is released running on dst with the source's final
// NVRAM; the source cleanup then keeps the source's state in its retained
// bundle, undefines the leftover and wipes the state (spec §6.7).
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
	if m, ok, err := fwmig.New(src.FW.DataDir).GetMarker(fwwVM); ok || err != nil {
		t.Errorf("source marker %+v left (%v), want it removed by the source cleanup", m.Phase, err)
	}
	if st, ok := src.Virt.RawState(fwwVM); ok {
		t.Errorf("the source domain is still defined (%s)", st)
	}
	for _, p := range []string{filepath.Join(src.FW.SwtpmDir(fwwUUID), "tpm2", "tpm2-00.permall"), src.FW.NvramPath(fwwVM)} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("source state %s not wiped (%v)", p, err)
		}
	}
	// The retained bundle holds the source's state (24 h, DECISION 4-E).
	tars, _ := filepath.Glob(filepath.Join(src.FW.DataDir, fwmig.RetainedDir, fwwVM+"-*.tar"))
	if len(tars) != 1 {
		t.Fatalf("retained bundles %v, want one", tars)
	}
	f, err := os.Open(tars[0])
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	fresh := &lv.FirmwareStore{DataDir: t.TempDir(), SwtpmBase: t.TempDir()}
	if err := fresh.ReadFirmwareBundle(f, fwwVM, fwwUUID); err != nil {
		t.Fatalf("the retained bundle does not restore: %v", err)
	}
	if got := hlRead(t, filepath.Join(fresh.SwtpmDir(fwwUUID), "tpm2", "tpm2-00.permall")); !bytes.Equal(got, fwwPermall) {
		t.Errorf("retained permall %q, want the source's", got)
	}
	if got := hlRead(t, fresh.NvramPath(fwwVM)); !bytes.Equal(got, fwwNvram) {
		t.Errorf("retained NVRAM %q, want the source's", got)
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
