// A dual-run scan that lands on a migration's final step — the source's
// domain being undefined — must not record vm_dual_run.
//
// Observed on the kvm003-f3 lab (lab1-reltok, 2026-10-10, both hosts on
// labrelay-2c2cd6a5): rt-vm live-migrated node-3 -> node-4 with the dual-run
// detector running on node-3, the source. The source qemu exited at
// 21:11:41.84, libvirt undefined the source domain (MigrateUndefineSource), the
// migration logged complete at 21:11:42.120, and the detector logged
// `condition observed kind=ha.dualrun.vm target=rt-vm` at 21:11:42.138 naming
// node-3 and node-4. `lv start rt-vm` was then refused ("active warning
// ownership condition (vm_dual_run ...)") until two clean passes resolved it at
// 21:13:54. systemd-machined on node-3 shows no rt-vm qemu after 21:11:41.84:
// there was never a second copy. It was a false positive.
//
// The scan's gather read rt-vm running on the source just before the cutover
// and running on the target just after — the straddle reprobeMultiHolders
// exists to settle. The re-probe did not settle it: it reached the source while
// libvirt was undefining the domain, so the domain was in the list and gone by
// the time it was asked about. That per-domain VIR_ERR_NO_DOMAIN marked the
// source's whole inventory partial, a partial re-probe proves nothing, and the
// first sighting stood.
//
// A domain libvirt says does not exist holds no disk. It is absent — proven by
// the runtime itself — not a probe failure.

package fleet

import (
	"context"
	"sync/atomic"
	"testing"

	golibvirt "github.com/digitalocean/go-libvirt"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

func noDomainErr(name string) error {
	return golibvirt.Error{Code: uint32(golibvirt.ErrNoDomain), Message: "Domain not found: no domain with matching name '" + name + "'"}
}

func TestFleet_MigrateScanAtSourceUndefine_DoesNotRecordDualRun(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	src, dst := c.Nodes[0], c.Nodes[1]
	for _, n := range c.Nodes {
		setHostCapacity(t, c, n.Name, 64, 65536)
	}
	seedRunningVM(t, c, src, "mover", "", 1, 512)
	emulateLibvirtMove(src, dst)
	emulateLibvirtMove(dst, src)

	if err := migrateAt(t, c, src, "mover", dst.Name); err != nil {
		t.Fatalf("migration %s -> %s: %v", src.Name, dst.Name, err)
	}

	// The scan the lab took, on the source:
	//   gather    — mover is still running on src (DomainState), and the
	//               cutover lands right after: src's copy pauses, dst's runs.
	//   re-probe  — src's domain list still has mover, and libvirt undefines it
	//               before the per-domain calls reach it: VIR_ERR_NO_DOMAIN.
	src.Virt.SetState("mover", libvirtfake.StateRunning)
	var dumps atomic.Int32
	src.Virt.FailDumpXML = func(name string) error {
		if name != "mover" {
			return nil
		}
		switch dumps.Add(1) {
		case 1: // gather: DomainState already counted mover as a holder
			src.Virt.SetState("mover", libvirtfake.StatePaused)
			return nil
		case 2: // re-probe: listed, then undefined under the probe
			src.Virt.VanishDomain("mover")
			return noDomainErr(name)
		}
		return noDomainErr(name)
	}
	runOneDualRunPass(t, src)
	src.Virt.FailDumpXML = nil
	if got := dumps.Load(); got < 2 {
		t.Fatalf("the scan probed mover on the source %d time(s); the scenario needs the gather and the re-probe", got)
	}
	if src.Virt.DomainExists("mover") {
		t.Fatal("setup: the source domain must be gone after the scan")
	}

	if got := vmDualRunLifecycle(t, src, "mover"); got != "" {
		t.Fatalf("a scan whose re-probe met the source's undefine recorded vm_dual_run %q for mover; "+
			"the source holds nothing, so this is a false positive that blocks the next start/migrate", got)
	}
	if err := migrateAt(t, c, dst, "mover", src.Name); err != nil {
		t.Fatalf("migration back %s -> %s refused after a scan at the source's undefine: %v",
			dst.Name, src.Name, err)
	}
	rec, err := corrosion.GetVM(context.Background(), src.DB, "mover")
	if err != nil || rec == nil || rec.HostName != src.Name {
		t.Fatalf("after the migration back: rec=%+v err=%v, want mover owned by %s", rec, err, src.Name)
	}
}

// The control: a re-probe that fails for any OTHER reason is still blind, and
// a blind re-probe proves nothing — the first sighting stands. Only libvirt's
// own "no such domain" is evidence of absence.
func TestFleet_MigrateScan_ReprobeOtherErrorStillBlind(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	src, dst := c.Nodes[0], c.Nodes[1]
	for _, n := range c.Nodes {
		setHostCapacity(t, c, n.Name, 64, 65536)
	}
	seedRunningVM(t, c, src, "mover", "", 1, 512)
	emulateLibvirtMove(src, dst)
	if err := migrateAt(t, c, src, "mover", dst.Name); err != nil {
		t.Fatalf("migration %s -> %s: %v", src.Name, dst.Name, err)
	}

	src.Virt.SetState("mover", libvirtfake.StateRunning)
	var dumps atomic.Int32
	src.Virt.FailDumpXML = func(name string) error {
		if name != "mover" {
			return nil
		}
		if dumps.Add(1) == 1 {
			src.Virt.SetState("mover", libvirtfake.StatePaused)
			return nil
		}
		return golibvirt.Error{Code: uint32(golibvirt.ErrOperationTimeout), Message: "cannot acquire state change lock"}
	}
	runOneDualRunPass(t, src)
	src.Virt.FailDumpXML = nil
	if got := vmDualRunLifecycle(t, src, "mover"); got != corrosion.ConditionObserved {
		t.Fatalf("a re-probe blinded by a non-NO_DOMAIN libvirt error: vm_dual_run %q, want observed (absence unproven)", got)
	}
}
