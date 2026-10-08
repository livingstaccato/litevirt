package libvirt

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"testing"
	"time"

	golibvirt "github.com/digitalocean/go-libvirt"
)

// Re-review 2, I-B. libvirt rewrites the persistent definition on a pivot
// only when the persistent and live sources match. When it did not, the
// running guest writes into the base while a cold start would boot the old
// top over it — every cluster the top holds shadowing newer data. The
// merge must repoint the persistent definition itself before anything is
// given up, so the next stop/start boots the base.
func TestFlattenSnapshot_RunningRepointsAPersistentDefinitionThePivotLeftOnTheTop(t *testing.T) {
	needQemuTools(t)
	chains := chainFixture(t, t.TempDir(), "vda")
	v := newScripted(golibvirt.DomainRunning, chains)
	v.pivotKeepsConfig = true
	if _, err := flattenSnapshot(v, "vm", "s1", basesOf(chains)); err != nil {
		t.Fatal(err)
	}
	// Stop, then start: a cold start boots the persistent definition.
	if got := parseDomainDiskSources(v.inac)["vda"]; got != chains["vda"][1] {
		t.Fatalf("after the merge a cold start boots %s, not the merged base %s: stale data", got, chains["vda"][1])
	}
}

// A merge whose cycles repoint the domain keeps the domain's chain exactly
// as deep as it was. Each cycle is what a stopped VM's snapshot create/rm
// does: the overlay is made over whatever the domain's persistent definition
// names now, the definition cut over to it, and the merge run. The disk sits
// on an image, so the depth is a measurement: a merge that left the domain
// on its overlay would make the next one a layer deeper.
func TestFlattenSnapshot_TwentyOfflineCyclesKeepTheDomainsChainAtItsDepth(t *testing.T) {
	needQemuTools(t)
	dir := t.TempDir()
	img := filepath.Join(dir, "image.qcow2")
	base := filepath.Join(dir, "vm-root.qcow2")
	run(t, "qemu-img", "create", "-q", "-f", "qcow2", img, "1M")
	run(t, "qemu-img", "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", img, base)
	v := newScripted(golibvirt.DomainShutoff, map[string][2]string{"vda": {base, img}})
	for i := 0; i < 20; i++ {
		cur := parseDomainDiskSources(v.inac)["vda"]
		snap := fmt.Sprintf("c%d", i)
		top := filepath.Join(dir, "vm-root."+snap)
		run(t, "qemu-img", "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", cur, top)
		run(t, "qemu-io", "-f", "qcow2", "-c", fmt.Sprintf("write -P %d %d 4k", i+1, i*4096), top)
		x, _, err := RewriteDiskSourceFile(v.inac, "vda", cur, top)
		if err != nil {
			t.Fatal(err)
		}
		v.inac, v.live = x, x
		v.snaps[snap] = "<domainsnapshot/>"
		removable, err := flattenSnapshot(v, "vm", snap, map[string]string{"vda": base})
		if err != nil {
			t.Fatalf("cycle %d: %v", i, err)
		}
		for _, l := range flattenLayers(removable) {
			os.Remove(l)
		}
		on := parseDomainDiskSources(v.inac)["vda"]
		if d := depthOf(t, on); d != 2 {
			t.Fatalf("cycle %d: the domain is on %s, %d deep; want exactly 2 (its disk over the image)", i, on, d)
		}
	}
	for i := 0; i < 20; i++ {
		run(t, "qemu-io", "-f", "qcow2", "-c", fmt.Sprintf("read -P %d %d 4k", i+1, i*4096), base)
	}
}

// Offline, two disks, the second's commit failing after the first's
// succeeded: nothing is redefined, nothing is given up, and every disk the
// definition names still reads its data — so the record, synced to the
// definition, matches the files.
func TestFlattenSnapshot_OfflineMultiDiskPartialFailureLeavesEveryDiskConsistent(t *testing.T) {
	needQemuTools(t)
	chains := chainFixture(t, t.TempDir(), "vda", "vdb")
	// Hold vdb's base open for writing, as a stray qemu would: its commit
	// cannot take the write lock.
	holder := exec.Command("qemu-io", "-f", "qcow2", chains["vdb"][1])
	stdin, err := holder.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	holder.Stdout, holder.Stderr = io.Discard, io.Discard
	if err := holder.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stdin.Close(); holder.Process.Kill(); holder.Wait() })
	for i := 0; ; i++ {
		if exec.Command("qemu-img", "info", chains["vdb"][1]).Run() != nil {
			break // locked
		}
		if i > 600 {
			out, _ := exec.Command("qemu-img", "info", chains["vdb"][1]).CombinedOutput()
			t.Fatalf("qemu-io never took the lock in 60s (holder exited: %v): %s", holder.ProcessState, out)
		}
		time.Sleep(100 * time.Millisecond)
	}
	v := newScripted(golibvirt.DomainShutoff, chains)
	removable, err := flattenSnapshot(v, "vm", "s1", basesOf(chains))
	if err == nil || len(flattenLayers(removable)) != 0 {
		t.Fatalf("flatten = %v, %v; want an error and nothing given up", removable, err)
	}
	if indexOfCall(v.calls, "define") >= 0 {
		t.Fatalf("redefined after a failed commit: %v", v.calls)
	}
	got := parseDomainDiskSources(v.inac)
	for i, dev := range []string{"vda", "vdb"} {
		if got[dev] != chains[dev][0] {
			t.Fatalf("%s: the definition names %s, want its top %s", dev, got[dev], chains[dev][0])
		}
		if !exists(chains[dev][0]) || !exists(chains[dev][1]) {
			t.Fatalf("%s: a layer was removed", dev)
		}
		run(t, "qemu-io", "-r", "-U", "-f", "qcow2", "-c", fmt.Sprintf("read -P %d 0 4k", i+7), chains[dev][0])
	}
}

// flattenLayers is every layer a flatten gave up, sorted.
func flattenLayers(r map[string][]string) []string {
	var out []string
	for _, ls := range r {
		out = append(out, ls...)
	}
	sort.Strings(out)
	return out
}
