package daemon

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/litevirt/litevirt/internal/endpointfile"
)

// The daemon publishes its endpoint for a non-root lv: the gRPC port and PKI
// directory and nothing else, 0644, replacing what was there (here a stale
// 0600 file) by a rename.
//
// Mutations: publish nothing: red. Leave the temp file's 0600: red. Write
// the whole config: red.
func TestPublishEndpoint_WritesOnlyThePortAndPKIDirWorldReadable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("a root daemon writes /run/litevirt/endpoint")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "endpoint")
	if err := os.WriteFile(path, []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	before, _ := os.Stat(path)
	cfg := &Config{GRPCPort: 9443, PKIDir: "/etc/litevirt/pki", DataDir: dir, HostName: "node-1"}
	(&Daemon{cfg: cfg}).publishEndpoint()

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if want := "grpc_port: 9443\npki_dir: /etc/litevirt/pki\n"; string(got) != want {
		t.Fatalf("endpoint file = %q, want %q", got, want)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o644 {
		t.Errorf("endpoint file mode = %o, want 0644", fi.Mode().Perm())
	}
	if os.SameFile(before, fi) {
		t.Error("the file was rewritten in place, not replaced by a rename")
	}
	if e, err := endpointfile.Read(path); err != nil || e.GRPCPort != 9443 {
		t.Errorf("lv's reader rejects what the daemon wrote: %+v, %v", e, err)
	}
	if leftovers, _ := filepath.Glob(filepath.Join(dir, ".endpoint-*")); len(leftovers) != 0 {
		t.Errorf("temp files left behind: %v", leftovers)
	}
}
