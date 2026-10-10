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

// The re-keyed stopped VM's define re-checks the domain once it holds the
// start lease: a start that finished between the first look and the lease
// is a running domain, and the define leaves it alone rather than undefining
// and redefining it under the running guest.
//
// Mutation: drop the re-check after acquireVMLock — the define replaces the
// running domain's definition and the test goes red.
func TestRekeyedStoppedVM_DefineLeavesADomainStartedMeanwhile(t *testing.T) {
	db := testReconcilerDB(t)
	ctx := context.Background()
	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
		Name: "node-a", Address: "10.0.0.1", SSHUser: "root", CertSerial: "s-a", State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	disk := filepath.Join(t.TempDir(), "sv-root.qcow2")
	if err := os.WriteFile(disk, []byte("shared"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "sv", HostName: "node-a", State: "stopped", StateDetail: corrosion.StoppedRekeyDetail("node-f"),
		CPUActual: 1, MemActual: 256, Spec: `{"name":"sv","cpu":1,"memory_mib":256}`,
	}, nil, []corrosion.DiskRecord{{VMName: "sv", DiskName: "root", HostName: "node-a", Path: disk, StorageType: "nfs"}}); err != nil {
		t.Fatal(err)
	}
	fake := libvirtfake.New()
	r := NewReconciler("node-a", t.TempDir(), db, fake)
	r.rekeyDefineHook = func(context.Context, string) {
		// An `lv start` that completed just before the lease was taken.
		if err := fake.DefineDomain(`<domain><name>sv</name><devices><!-- started --></devices></domain>`); err != nil {
			t.Error(err)
		}
		fake.SetState("sv", libvirtfake.StateRunning)
	}
	r.ReconcileOnce(ctx)
	if st, _ := fake.DomainState("sv"); st != "running" {
		t.Fatalf("sv after the define pass: %q, want the domain started meanwhile left running", st)
	}
	if xml := fake.DefinedXML("sv"); !strings.Contains(xml, "started") {
		t.Fatalf("the define replaced a running domain's definition:\n%s", xml)
	}
}
