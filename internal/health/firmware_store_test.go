package health

import (
	"testing"

	lv "github.com/litevirt/litevirt/internal/libvirt"
)

// A reconciler's firmware store is the production layout under its data dir
// until the daemon injects the one it shares with the server.
//
// Mutations: NewReconciler without fwStore — red; SetFirmwareStore a no-op —
// red.
func TestReconciler_FirmwareStore(t *testing.T) {
	r := NewReconciler("h1", "/var/lib/litevirt", nil, nil)
	fw := r.FirmwareStore()
	if fw == nil || fw.DataDir != "/var/lib/litevirt" || fw.SwtpmBase != "/var/lib/libvirt/swtpm" {
		t.Fatalf("store = %+v, want NVRAM under /var/lib/litevirt and swtpm under /var/lib/libvirt/swtpm", fw)
	}
	own := &lv.FirmwareStore{DataDir: t.TempDir(), SwtpmBase: t.TempDir()}
	r.SetFirmwareStore(own)
	if r.FirmwareStore() != own {
		t.Fatalf("reconciler uses %+v, not the injected store %+v", r.FirmwareStore(), own)
	}
}
