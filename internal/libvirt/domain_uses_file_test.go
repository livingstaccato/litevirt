package libvirt

import (
	"os"
	"path/filepath"
	"testing"
)

// R3 m-1. DomainUsesFile is asked before a set-aside overlay is removed: a
// domain must count as naming a file anywhere in a disk's chain, through a
// symlinked path, and a definition that cannot be read must not read as
// "not named".
//
// Mutations, each red: "top source only" (the <backingStore> chain not
// walked); "exact string" (no symlink resolution); "parse error is not
// named" (an unmarshal error returns false, nil).
func TestDomainUsesFile_TheWholeChainResolvedAndFailsClosed(t *testing.T) {
	t.Run("a backing file of a disk", func(t *testing.T) {
		m := newPITModel()
		m.inactive["vda"] = "/pool/inspect.qcow2"
		m.backing["vda"] = "/pool/.web-root.qcow2.lv-pit.orphan-20261018-120000"
		if used, err := domainUsesFile(m, "web", "/pool/.web-root.qcow2.lv-pit.orphan-20261018-120000"); err != nil || !used {
			t.Fatalf("an orphan under the inspection overlay = %v, %v; want named", used, err)
		}
	})
	t.Run("deep in the chain", func(t *testing.T) {
		m := newPITModel()
		m.rawXML = "<domain><name>web</name><devices><disk type='file' device='disk'><source file='/pool/top'/>" +
			"<backingStore type='file'><source file='/pool/mid'/><backingStore type='file'><source file='/pool/orphan'/><backingStore/></backingStore></backingStore>" +
			"<target dev='vda'/></disk></devices></domain>"
		if used, err := domainUsesFile(m, "web", "/pool/orphan"); err != nil || !used {
			t.Fatalf("a file two levels down the chain = %v, %v; want named", used, err)
		}
		if used, err := domainUsesFile(m, "web", "/pool/other"); err != nil || used {
			t.Fatalf("a file nowhere in the chain = %v, %v; want not named", used, err)
		}
	})
	t.Run("through a symlink", func(t *testing.T) {
		dir := t.TempDir()
		real := filepath.Join(dir, "orphan")
		if err := os.WriteFile(real, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(dir, "pool-link")
		if err := os.Symlink(dir, link); err != nil {
			t.Fatal(err)
		}
		m := newPITModel()
		m.live["vda"] = filepath.Join(link, "orphan")
		if used, err := domainUsesFile(m, "web", real); err != nil || !used {
			t.Fatalf("a disk naming the file through a symlinked directory = %v, %v; want named", used, err)
		}
	})
	t.Run("a definition that cannot be read", func(t *testing.T) {
		m := newPITModel()
		m.rawXML = "<domain><devices><disk><source file='/pool/orphan'"
		if used, err := domainUsesFile(m, "web", "/pool/orphan"); err == nil {
			t.Fatalf("unparsable XML = %v, nil; want an error", used)
		}
	})
}
