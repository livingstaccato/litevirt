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
	own := &lv.FirmwareStore{DataDir: s.dataDir, SwtpmBase: t.TempDir()}
	s.SetFirmwareStore(own)
	if s.fw() != own {
		t.Fatalf("server uses %+v, not the injected store %+v", s.fw(), own)
	}
	// The same directory spelled differently is the same directory (review
	// m-3): no panic.
	slash := &lv.FirmwareStore{DataDir: s.dataDir + "/", SwtpmBase: own.SwtpmBase}
	s.SetFirmwareStore(slash)
	if s.fw() != slash {
		t.Fatalf("a store under %q was not taken", slash.DataDir)
	}
	s.SetFirmwareStore(own)
	// nil is ignored: the server keeps the store it has (the reconciler
	// does the same, TestReconciler_FirmwareStore).
	s.SetFirmwareStore(nil)
	if s.fw() != own {
		t.Fatalf("SetFirmwareStore(nil) replaced the store: %+v", s.fw())
	}
}

// The test server the fleet builds holds a store of its own from the start
// (not fw()'s per-call fallback), with the production layout under its data
// dir, so a guard installed on it stays installed.
//
// Mutation: drop fwStore from NewServerForTests — red.
func TestNewServerForTests_HoldsAFirmwareStore(t *testing.T) {
	dir := t.TempDir()
	s := NewServerForTests(TestServerOpts{HostName: "h1", DataDir: dir})
	if s.fwStore == nil {
		t.Fatal("NewServerForTests left fwStore nil; fw() would build a fresh store on each call")
	}
	if s.fw() != s.fw() || s.fw().DataDir != dir || s.fw().SwtpmBase != lv.DefaultSwtpmBase {
		t.Fatalf("store = %+v, want one store with NVRAM under %s and swtpm under %s", s.fw(), dir, lv.DefaultSwtpmBase)
	}
}

// A store whose data dir is not the server's is refused: the domain XML
// names the NVRAM under the server's data dir (ApplyTo), so the store must be
// the one holding it (D2-1 review m-2).
//
// Mutation: drop the DataDir check from SetFirmwareStore — red.
func TestServer_SetFirmwareStoreRefusesAnotherDataDir(t *testing.T) {
	s := NewServer("h1", t.TempDir(), t.TempDir(), nil, nil, nil)
	before := s.fw()
	defer func() {
		if recover() == nil {
			t.Fatal("SetFirmwareStore took a store under another data dir")
		}
		if s.fw() != before {
			t.Fatalf("the refused store was installed: %+v", s.fw())
		}
	}()
	s.SetFirmwareStore(&lv.FirmwareStore{DataDir: t.TempDir(), SwtpmBase: t.TempDir()})
}
