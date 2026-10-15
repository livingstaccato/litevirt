package libvirt

import (
	"os"
	"path/filepath"
	"testing"
)

// The production layout is what it was before the store existed: NVRAM and the
// retained marker under the daemon's dataDir, swtpm state under libvirt's own
// root. A domain defined by an older build names these paths, so a change here
// strands every firmware VM on an upgraded host.
//
// Mutation: DefaultSwtpmBase, or NewFirmwareStore's SwtpmBase, set to any other
// path — this goes red.
func TestNewFirmwareStore_ProductionLayout(t *testing.T) {
	const uuid = "aad2e0bb-3311-42a9-92f9-4062205a4dc1"
	s := NewFirmwareStore("/var/lib/litevirt")
	for _, c := range []struct{ what, got, want string }{
		{"DataDir", s.DataDir, "/var/lib/litevirt"},
		{"SwtpmBase", s.SwtpmBase, "/var/lib/libvirt/swtpm"},
		{"SwtpmDir", s.SwtpmDir(uuid), "/var/lib/libvirt/swtpm/" + uuid},
		{"NvramPath", s.NvramPath("win"), "/var/lib/litevirt/nvram/win_VARS.fd"},
		{"retained marker", s.retainedMarkerPath("win"), "/var/lib/litevirt/nvram/win.kept-uuid"},
	} {
		if c.got != c.want {
			t.Errorf("%s = %q, want %q", c.what, c.got, c.want)
		}
	}
	// The NVRAM path the store reads and writes is the one the rendered domain
	// names (ApplyTo → NvramPath), or libvirt and the store disagree on the file.
	if got, want := s.NvramPath("win"), NvramPath("/var/lib/litevirt", "win"); got != want {
		t.Errorf("store NvramPath %q differs from the rendered NvramPath %q", got, want)
	}
}

// T-1. Two stores with their own roots never see each other's state: what one
// writes, wipes or restores lives under its own roots only. The fleet runs every
// node in one process, so this is what gives each node a firmware store of its
// own.
//
// Mutation: SwtpmDir reads the package default instead of the store's base —
// this goes red.
func TestFirmwareStore_RootsAreIndependent(t *testing.T) {
	const uuid = "aad2e0bb-3311-42a9-92f9-4062205a4dc1"
	a := &FirmwareStore{DataDir: t.TempDir(), SwtpmBase: filepath.Join(t.TempDir(), "swtpm")}
	b := &FirmwareStore{DataDir: t.TempDir(), SwtpmBase: filepath.Join(t.TempDir(), "swtpm")}

	if got := a.SwtpmDir(uuid); got != filepath.Join(a.SwtpmBase, uuid) {
		t.Fatalf("a.SwtpmDir = %q, not under a's base %q", got, a.SwtpmBase)
	}
	if a.SwtpmDir(uuid) == b.SwtpmDir(uuid) {
		t.Fatalf("both stores keep %s's swtpm state at %s", uuid, a.SwtpmDir(uuid))
	}
	if a.NvramPath("vm") == b.NvramPath("vm") {
		t.Fatalf("both stores keep vm's NVRAM at %s", a.NvramPath("vm"))
	}

	seedStore(t, a, "vm", uuid)
	if !a.HasTPMState(uuid) || !a.HasNvram("vm") {
		t.Fatal("a does not see the state seeded into it")
	}
	if b.HasTPMState(uuid) || b.HasNvram("vm") {
		t.Fatal("b sees state seeded into a")
	}
	if _, ok := b.ReadRetainedFirmwareMarker("vm"); ok {
		t.Fatal("b sees a's retained marker")
	}

	// A wipe on b leaves a's state alone.
	seedStore(t, b, "vm", uuid)
	b.WipeFirmwareState("vm", uuid)
	if b.HasTPMState(uuid) || b.HasNvram("vm") {
		t.Fatal("b's wipe left b's state")
	}
	if !a.HasTPMState(uuid) || !a.HasNvram("vm") {
		t.Fatal("b's wipe removed a's state")
	}
}

// RemoveNvram and RenameNvram act on the store's own NVRAM files only.
func TestFirmwareStore_RemoveAndRenameNvram(t *testing.T) {
	const uuid = "aad2e0bb-3311-42a9-92f9-4062205a4dc1"
	a := &FirmwareStore{DataDir: t.TempDir(), SwtpmBase: filepath.Join(t.TempDir(), "swtpm")}
	b := &FirmwareStore{DataDir: t.TempDir(), SwtpmBase: filepath.Join(t.TempDir(), "swtpm")}
	seedStore(t, a, "tmp", uuid)
	seedStore(t, b, "tmp", uuid)

	if err := a.RenameNvram("tmp", "vm"); err != nil {
		t.Fatal(err)
	}
	if a.HasNvram("tmp") || !a.HasNvram("vm") {
		t.Fatal("RenameNvram did not move a's vars file from tmp to vm")
	}
	if got, _ := os.ReadFile(a.NvramPath("vm")); string(got) != "NVRAM-tmp" {
		t.Fatalf("renamed vars = %q, want the content of tmp's", got)
	}
	if !b.HasNvram("tmp") || b.HasNvram("vm") {
		t.Fatal("a's RenameNvram touched b")
	}

	if err := a.RemoveNvram("vm"); err != nil {
		t.Fatal(err)
	}
	if a.HasNvram("vm") {
		t.Fatal("RemoveNvram left the vars file")
	}
	if !a.HasTPMState(uuid) {
		t.Fatal("RemoveNvram removed the swtpm state")
	}
	if err := a.RemoveNvram("vm"); !os.IsNotExist(err) {
		t.Fatalf("RemoveNvram of an absent file = %v, want a not-exist error", err)
	}
}

// A store with no swtpm base confines nothing, so it refuses every swtpm key
// rather than resolving one against the working directory.
func TestFirmwareStore_EmptySwtpmBaseRefusesKeys(t *testing.T) {
	s := &FirmwareStore{DataDir: t.TempDir()}
	if _, ok := s.swtpmDir("aad2e0bb-3311-42a9-92f9-4062205a4dc1"); ok {
		t.Fatal("a store with an empty swtpm base accepted a key")
	}
}

func seedStore(t *testing.T, s *FirmwareStore, vm, uuid string) {
	t.Helper()
	p := s.NvramPath(vm)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("NVRAM-"+vm), 0o600); err != nil {
		t.Fatal(err)
	}
	d := filepath.Join(s.SwtpmDir(uuid), "tpm2")
	if err := os.MkdirAll(d, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d, "tpm2-00.permall"), []byte("TPM-"+uuid), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.WriteRetainedFirmwareMarker(vm, uuid); err != nil {
		t.Fatal(err)
	}
}
