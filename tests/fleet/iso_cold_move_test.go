// N5-1: a stopped, firmware or drain-cold move ships the domain's definition
// for the target to define. An Admin's host-path ISO goes as the path the VM
// was given (its link), not as the file it resolved to on the source: a target
// on main has its qemu follow the link there, as main to main did; a target on
// this build judges the path at its start and points the domain at its own
// file.
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
)

// withHostPathISO gives the cold scenario's os1 an Admin's host-path ISO — a
// link — and a domain that carries the file it resolved to on the source (as
// after a start on this build). It returns the link, the resolved file and a
// reader of every definition the target is handed.
func (sc *coldStoppedScenario) withHostPathISO(t *testing.T) (link, resolved string, defined func() []string) {
	t.Helper()
	dir := filepath.Join(sc.c.tmpRoot, "virtio")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	real := filepath.Join(dir, "virtio-win-0.1.240.iso")
	if err := os.WriteFile(real, []byte("CD001 virtio"), 0o644); err != nil {
		t.Fatal(err)
	}
	link = filepath.Join(dir, "virtio-win.iso")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	resolved, err := filepath.EvalSymlinks(real)
	if err != nil {
		t.Fatal(err)
	}
	spec, _ := json.Marshal(&pb.VMSpec{Name: "os1", Cpu: 1, MemoryMib: 256, Iso: link, IsoScope: "hostpath"})
	if err := sc.src.DB.Execute(context.Background(), `UPDATE vms SET spec = ? WHERE name = 'os1'`, string(spec)); err != nil {
		t.Fatal(err)
	}
	x := sc.src.Virt.DefinedXML("os1")
	x = strings.Replace(x, "</devices>", `<disk type='file' device='cdrom'><driver name='qemu' type='raw'/><source file='`+resolved+
		`'/><target dev='sda' bus='sata'/><readonly/></disk></devices>`, 1)
	if err := sc.src.Virt.DefineDomain(x); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var got []string
	sc.dst.Virt.FailDefineDomain = func(x string) error {
		mu.Lock()
		got = append(got, x)
		mu.Unlock()
		return nil
	}
	sc.dst.Server.AnswerEnsureDisksAsAnOlderTargetForTest(true)
	return link, resolved, func() []string { mu.Lock(); defer mu.Unlock(); return append([]string(nil), got...) }
}

func requireShippedLink(t *testing.T, defined []string, link, resolved string) {
	t.Helper()
	if len(defined) == 0 {
		t.Fatal("the target was handed no definition")
	}
	first := defined[0]
	if !strings.Contains(first, "file='"+link+"'") || strings.Contains(first, resolved) {
		t.Fatalf("the definition the target was handed carries\n%s\nwant the link %s, not the source's file %s", first, link, resolved)
	}
}

// Mutation: drop the rewrite in coldMigrateStoppedVM — red.
func TestFleet_AColdMoveShipsTheISOLink(t *testing.T) {
	sc := newColdStoppedScenario(t)
	link, resolved, defined := sc.withHostPathISO(t)
	if err := sc.migrateCold(t); err != nil {
		t.Fatalf("cold move of a stopped VM to an older target: %v", err)
	}
	requireShippedLink(t, defined(), link, resolved)
}

// The drain of a running VM with a host-local disk moves it cold.
func TestFleet_ADrainColdMoveShipsTheISOLink(t *testing.T) {
	sc := newColdStoppedScenario(t)
	link, resolved, defined := sc.withHostPathISO(t)
	sc.makeRunning(t)
	progress, err := sc.drain(t)
	if err != nil {
		t.Fatalf("drain: %v", err)
	}
	if p := progress["os1"]; p == nil || p.Status != "done" {
		t.Fatalf("drain progress for os1 = %+v, want done", p)
	}
	requireShippedLink(t, defined(), link, resolved)
}
