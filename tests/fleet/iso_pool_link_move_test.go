// I-2: a pool ISO whose pool directory is a link that names another
// directory on each host (/var/lib/libvirt/images on a data disk) moves to a
// target older than this build. That target opens the path it is handed, as
// main did, so it is handed the pool's file as the path is written there — the
// link, which its qemu follows there — not the file this host resolved it to.
package fleet

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// Mutation: make olderTargetISORemap return nil for a pool scope (as before)
// — the migrate call carries no cdroms and the test goes red.
func TestFleet_ALiveMoveToAnOlderTargetCarriesThePoolsLink(t *testing.T) {
	c, src, dst, files := isoLiveMoveCluster(t)
	defer c.Stop()
	dst.Server.AnswerEnsureDisksAsAnOlderTargetForTest(true)
	if err := migrateAt(t, c, src, "inst", dst.Name); err != nil {
		t.Fatalf("live move of a pool ISO to an older target: %v", err)
	}
	there := filepath.Join(c.tmpRoot, dst.Name, "isos", "install.iso")
	want := "cdroms=" + files[src.Name] + "->" + there
	if note := lastMigrateNote(src); !strings.Contains(note, want) {
		t.Fatalf("libvirt migrate = %q; want the older target handed the pool's link path (%s)", note, want)
	}
}

// The same for a stopped VM's cold move: the definition the target is handed
// names the pool's file through the target's link.
//
// Mutation: as above — the definition carries the source's file and the test
// goes red.
func TestFleet_AColdMoveShipsThePoolsLink(t *testing.T) {
	sc := newColdStoppedScenario(t)
	ctx := context.Background()
	links := map[string]string{}
	for _, n := range []*Node{sc.src, sc.dst} {
		real := filepath.Join(sc.c.tmpRoot, n.Name, "isos-"+n.Name)
		if err := os.MkdirAll(real, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(real, "install.iso"), []byte("CD001 installer"), 0o644); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(sc.c.tmpRoot, n.Name, "isos")
		if err := os.Symlink(real, link); err != nil {
			t.Fatal(err)
		}
		links[n.Name] = link
		if err := corrosion.UpsertStoragePool(ctx, n.DB, corrosion.StoragePoolRecord{
			HostName: n.Name, Name: "shared-isos", Driver: "dir", Target: link, State: "active",
		}); err != nil {
			t.Fatal(err)
		}
	}
	resolved, err := filepath.EvalSymlinks(filepath.Join(links[sc.src.Name], "install.iso"))
	if err != nil {
		t.Fatal(err)
	}
	spec, _ := json.Marshal(&pb.VMSpec{Name: "os1", Cpu: 1, MemoryMib: 256, Iso: "shared-isos/install.iso", IsoScope: "pool"})
	if err := sc.src.DB.Execute(ctx, `UPDATE vms SET spec = ? WHERE name = 'os1'`, string(spec)); err != nil {
		t.Fatal(err)
	}
	x := sc.src.Virt.DefinedXML("os1")
	x = strings.Replace(x, "</devices>", `<disk type='file' device='cdrom'><driver name='qemu' type='raw'/><source file='`+resolved+
		`'/><target dev='sda' bus='sata'/><readonly/></disk></devices>`, 1)
	if err := sc.src.Virt.DefineDomain(x); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var defined []string
	sc.dst.Virt.FailDefineDomain = func(x string) error {
		mu.Lock()
		defined = append(defined, x)
		mu.Unlock()
		return nil
	}
	sc.dst.Server.AnswerEnsureDisksAsAnOlderTargetForTest(true)
	if err := sc.migrateCold(t); err != nil {
		t.Fatalf("cold move of a stopped VM with a pool ISO to an older target: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	there := filepath.Join(links[sc.dst.Name], "install.iso")
	requireShippedLink(t, defined, there, resolved)
}
