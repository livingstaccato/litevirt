package grpcapi

import (
	"testing"

	lv "github.com/litevirt/litevirt/internal/libvirt"
)

// A server's firmware store is the production layout under its data dir until
// the daemon (or the fleet harness) injects one, and the injected one is the
// one it uses. A server built as a struct literal gets the production layout
// under its data dir too, as every server had before the store existed.
//
// Mutations: fw() without the fallback — the literal case panics; fw()
// ignoring the injected store — the injected case goes red.
func TestServer_FirmwareStore(t *testing.T) {
	const uuid = "aad2e0bb-3311-42a9-92f9-4062205a4dc1"
	for name, s := range map[string]*Server{
		"NewServer": NewServer("h1", "/var/lib/litevirt", t.TempDir(), nil, nil, nil),
		"literal":   {dataDir: "/var/lib/litevirt"},
	} {
		fw := s.FirmwareStore()
		if fw.DataDir != "/var/lib/litevirt" || fw.SwtpmBase != "/var/lib/libvirt/swtpm" {
			t.Errorf("%s: store = %+v, want NVRAM under /var/lib/litevirt and swtpm under /var/lib/libvirt/swtpm", name, fw)
		}
		if got, want := fw.SwtpmDir(uuid), "/var/lib/libvirt/swtpm/"+uuid; got != want {
			t.Errorf("%s: SwtpmDir = %q, want %q", name, got, want)
		}
	}

	s := NewServer("h1", t.TempDir(), t.TempDir(), nil, nil, nil)
	own := &lv.FirmwareStore{DataDir: t.TempDir(), SwtpmBase: t.TempDir()}
	s.SetFirmwareStore(own)
	if s.fw() != own {
		t.Fatalf("server uses %+v, not the injected store %+v", s.fw(), own)
	}
}
