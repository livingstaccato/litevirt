package grpcapi

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// Review I-3: the start refusal for a too-deep chain names what holds the
// layers, so the operator knows which clone to deal with.
func TestStartChain_TooDeepNamesTheVMThatHoldsTheLayers(t *testing.T) {
	needQemuImg(t)
	s, _ := newDiskPathTestServer(t)
	s.dataDir = t.TempDir()
	dir := t.TempDir()
	prev := filepath.Join(dir, "deep-root.qcow2")
	runQemuImg(t, "create", "-q", "-f", "qcow2", prev, "1M")
	held := prev
	for i := 0; i <= maxBackingDepth+1; i++ {
		next := filepath.Join(dir, fmt.Sprintf("deep-root.c%d", i))
		runQemuImg(t, "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", prev, next)
		if i == 3 {
			held = next
		}
		prev = next
	}
	if err := corrosion.InsertVM(adminCtx(), s.db, corrosion.VMRecord{Name: "deep", HostName: "host-a", State: "stopped"}, nil,
		[]corrosion.DiskRecord{{VMName: "deep", DiskName: "root", HostName: "host-a", Path: prev, StorageType: "local"}}); err != nil {
		t.Fatal(err)
	}
	holderFile := filepath.Join(dir, "holder-root.qcow2")
	runQemuImg(t, "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", held, holderFile)
	if err := corrosion.InsertVM(adminCtx(), s.db, corrosion.VMRecord{Name: "holder", HostName: "host-a", State: "stopped"}, nil,
		[]corrosion.DiskRecord{{VMName: "holder", DiskName: "root", HostName: "host-a", Path: holderFile, StorageType: "local", BackingDisk: held}}); err != nil {
		t.Fatal(err)
	}
	vm := &corrosion.VMRecord{Name: "deep", HostName: "host-a"}
	d := corrosion.DiskRecord{VMName: "deep", DiskName: "root", HostName: "host-a", Path: prev, StorageType: "local"}
	err := s.verifyDiskChainForStart(adminCtx(), vm, d, prev)
	if err == nil {
		t.Fatal("a chain deeper than the cap was accepted")
	}
	if !strings.Contains(err.Error(), "holder") {
		t.Errorf("refusal %q does not name the VM (holder) whose clone holds the layers", err)
	}
}
