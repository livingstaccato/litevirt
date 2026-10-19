package fleet

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Every node has a firmware store of its own, as every real host has: the
// server uses the node's store, its NVRAM is under the node's data dir, its
// swtpm root is the node's alone, and state seeded on one node is invisible
// on the other. Before the store, every node in the process read and wrote
// one swtpm root.
//
// Mutation: give every node the same swtpm root in buildServer — this goes red.
func TestFleet_EachNodeHasItsOwnFirmwareStore(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	t.Cleanup(c.Stop)
	a, b := c.Nodes[0], c.Nodes[1]
	const uuid = "aad2e0bb-3311-42a9-92f9-4062205a4dc1"

	for _, n := range []*Node{a, b} {
		if n.FW == nil {
			t.Fatalf("%s has no firmware store", n.Name)
		}
		if got := n.Server.FirmwareStore(); got != n.FW {
			t.Fatalf("%s's server uses store %+v, not the node's %+v", n.Name, got, n.FW)
		}
		if n.FW.DataDir != n.Server.DataDir() {
			t.Errorf("%s's store keeps NVRAM under %s, its server's data dir is %s", n.Name, n.FW.DataDir, n.Server.DataDir())
		}
		if !strings.HasPrefix(n.FW.SwtpmBase, filepath.Join(c.tmpRoot, n.Name)+string(filepath.Separator)) {
			t.Errorf("%s's swtpm root %s is not under the node's own directory", n.Name, n.FW.SwtpmBase)
		}
	}
	if a.FW.SwtpmDir(uuid) == b.FW.SwtpmDir(uuid) {
		t.Fatalf("%s and %s keep %s's swtpm state at the same path %s", a.Name, b.Name, uuid, a.FW.SwtpmDir(uuid))
	}

	p := filepath.Join(a.FW.SwtpmDir(uuid), "tpm2", "tpm2-00.permall")
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("a's TPM"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !a.FW.HasTPMState(uuid) {
		t.Fatalf("%s does not see the swtpm state seeded into its store", a.Name)
	}
	if b.FW.HasTPMState(uuid) {
		t.Fatalf("%s sees the swtpm state seeded into %s's store", b.Name, a.Name)
	}
	b.FW.WipeFirmwareStateByUUID(uuid)
	if !a.FW.HasTPMState(uuid) {
		t.Fatalf("a wipe on %s removed %s's swtpm state", b.Name, a.Name)
	}
}
