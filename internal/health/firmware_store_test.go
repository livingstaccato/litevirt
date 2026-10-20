package health

import (
	"testing"

	lv "github.com/litevirt/litevirt/internal/libvirt"
)

// A reconciler's firmware store is the production layout under its data dir
// until the daemon injects the one it shares with the server.
//
// Mutations: NewReconciler without fwStore — red; SetFirmwareStore a no-op —
// red; SetFirmwareStore storing nil — red.
func TestReconciler_FirmwareStore(t *testing.T) {
	r := NewReconciler("h1", "/var/lib/litevirt", nil, nil)
	fw := r.FirmwareStore()
	if fw == nil || fw.DataDir != "/var/lib/litevirt" || fw.SwtpmBase != "/var/lib/libvirt/swtpm" {
		t.Fatalf("store = %+v, want NVRAM under /var/lib/litevirt and swtpm under /var/lib/libvirt/swtpm", fw)
	}
	own := &lv.FirmwareStore{DataDir: "/var/lib/litevirt", SwtpmBase: t.TempDir()}
	r.SetFirmwareStore(own)
	if r.FirmwareStore() != own {
		t.Fatalf("reconciler uses %+v, not the injected store %+v", r.FirmwareStore(), own)
	}
	// The same directory spelled differently is the same directory (review
	// m-3): no panic.
	slash := &lv.FirmwareStore{DataDir: "/var/lib/litevirt/", SwtpmBase: own.SwtpmBase}
	r.SetFirmwareStore(slash)
	if r.FirmwareStore() != slash {
		t.Fatalf("a store under %q was not taken", slash.DataDir)
	}
	r.SetFirmwareStore(own)
	// nil is ignored, as the server does (D2-1 review m-4): the reconciler
	// keeps its store rather than nil-panicking at its next firmware read.
	r.SetFirmwareStore(nil)
	if r.FirmwareStore() != own {
		t.Fatalf("SetFirmwareStore(nil) replaced the store: %+v", r.FirmwareStore())
	}
	_ = r.FirmwareStore().HasNvram("vm1")
}

// A store whose data dir is not the reconciler's is refused (D2-1 review
// m-2): the domain the reconciler renders names the NVRAM under its own data
// dir.
//
// Mutation: drop the DataDir check from SetFirmwareStore — red.
func TestReconciler_SetFirmwareStoreRefusesAnotherDataDir(t *testing.T) {
	r := NewReconciler("h1", "/var/lib/litevirt", nil, nil)
	before := r.FirmwareStore()
	defer func() {
		if recover() == nil {
			t.Fatal("SetFirmwareStore took a store under another data dir")
		}
		if r.FirmwareStore() != before {
			t.Fatalf("the refused store was installed: %+v", r.FirmwareStore())
		}
	}()
	r.SetFirmwareStore(&lv.FirmwareStore{DataDir: t.TempDir(), SwtpmBase: t.TempDir()})
}
