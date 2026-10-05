// Fleet scenarios for the CREDITED CPU requirement of a host-model guest.
//
// libvirt expands a running host-model guest's <cpu> with features its own
// hypervisor compare does not credit the host with. On the lab (EPYC-Milan,
// libvirt 10.0.0, QEMU 8.2.2) that is exactly topoext: the live CPU requires it,
// the host's domcapabilities host-model does not list it, and
// `virsh hypervisor-cpu-compare` rejects the guest on its own host. A requirement
// built verbatim from the live XML can therefore never tell a good target from a
// bad one there. The source strips every required feature its own host-model
// does not list, and the target judges the rest.
//
// The fakes model the lab hypervisor: each node's compare credits exactly its
// HostModelFeatures list.

package fleet

import (
	"context"
	"os"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
)

// labHostModelFeatures is the lab node's `virsh domcapabilities` host-model
// feature list (internal/libvirt/testdata/domcaps_epyc_milan.xml). No topoext.
var labHostModelFeatures = []string{
	"x2apic", "tsc-deadline", "hypervisor", "tsc_adjust", "vaes", "vpclmulqdq",
	"spec-ctrl", "stibp", "arch-capabilities", "ssbd", "cmp_legacy",
	"stibp-always-on", "virt-ssbd", "amd-psfd", "lbrv", "tsc-scale",
	"vmcb-clean", "flushbyasid", "pause-filter", "pfthreshold",
	"v-vmsave-vmload", "vgif", "no-nested-data-bp", "lfence-always-serializing",
	"null-sel-clr-base", "rdctl-no", "skip-l1dfl-vmentry", "mds-no",
	"pschange-mc-no", "gds-no",
}

const labMachine = "pc-q35-8.2"

func without(list []string, drop ...string) []string {
	var out []string
	for _, f := range list {
		keep := true
		for _, d := range drop {
			if f == d {
				keep = false
			}
		}
		if keep {
			out = append(out, f)
		}
	}
	return out
}

// labLiveCPU is the live <cpu> of a running host-model guest on the lab,
// optionally with some required features removed (a guest booted on an older
// host carries a narrower expansion).
func labLiveCPU(t *testing.T, drop ...string) string {
	t.Helper()
	b, err := os.ReadFile("../../internal/libvirt/testdata/cpu_live_host_model_epyc_milan.xml")
	if err != nil {
		t.Fatalf("read lab fixture: %v", err)
	}
	cpu := string(b)
	for _, d := range drop {
		line := "<feature policy='require' name='" + d + "'/>"
		if !strings.Contains(cpu, line) {
			t.Fatalf("fixture has no %s", line)
		}
		cpu = strings.Replace(cpu, line, "", 1)
	}
	return cpu
}

func labDomain(name, cpu string) string {
	return "<domain type='kvm'><name>" + name + "</name>" +
		"<os><type arch='x86_64' machine='" + labMachine + "'>hvm</type></os>" +
		cpu + "</domain>"
}

// Two identical lab hosts: the topoext the compare does not credit must not be
// the reason the migration is waved through or refused. The target must judge
// the CREDITED requirement and say yes on its own — the source is never asked
// to second-guess it.
func TestFleet_MigrateVM_LabHostModelGuestMigratesBetweenIdenticalHosts(t *testing.T) {
	c := New(t, Options{Nodes: 2})
	defer c.Stop()

	source, target := c.Nodes[0], c.Nodes[1]
	source.Virt.HostModelFeatures = labHostModelFeatures
	target.Virt.HostModelFeatures = labHostModelFeatures
	seedRunningCPUVM(t, c, source, "vm-lab", lv.CPUModeHostModel, labDomain("vm-lab", labLiveCPU(t)))

	if err := migrateAt(t, c, source, "vm-lab", target.Name); err != nil {
		t.Fatalf("migrate between identical lab hosts: %v", err)
	}
	asked := target.Virt.ComparedCPUXML()
	if len(asked) == 0 {
		t.Fatal("target was never asked")
	}
	if strings.Contains(asked[0], "topoext") {
		t.Errorf("target was asked about topoext, which the source's own host-model does not credit: %q", asked[0])
	}
	if !strings.Contains(asked[0], "EPYC-Milan") || !strings.Contains(asked[0], "'vaes'") {
		t.Errorf("credited requirement lost the model or a credited feature: %q", asked[0])
	}
	if got := source.Virt.ComparedCPUXML(); len(got) != 0 {
		t.Errorf("source was asked to second-guess a target that said yes: %q", got)
	}
	// The guest keeps its machine type across a migration, so the target is
	// asked about that machine, not its own default.
	if m := target.Virt.ComparedMachines(); len(m) == 0 || m[0] != labMachine {
		t.Errorf("target compare machine = %q, want the guest's %q", m, labMachine)
	}
}

// The point of crediting: a target that lacks a feature the source DOES credit
// (here vaes) is refused, on the very hardware where the verbatim requirement
// could only ever say "cannot decide".
func TestFleet_MigrateVM_LabHostModelRefusedWhenTargetLacksACreditedFeature(t *testing.T) {
	c := New(t, Options{Nodes: 2})
	defer c.Stop()

	source, target := c.Nodes[0], c.Nodes[1]
	source.Virt.HostModelFeatures = labHostModelFeatures
	target.Virt.HostModelFeatures = without(labHostModelFeatures, "vaes")
	seedRunningCPUVM(t, c, source, "vm-vaes", lv.CPUModeHostModel, labDomain("vm-vaes", labLiveCPU(t)))

	err := migrateAt(t, c, source, "vm-vaes", target.Name)
	if got := status.Code(err); got != codes.FailedPrecondition {
		t.Fatalf("migrate status = %v, want FailedPrecondition (err = %v)", got, err)
	}
	// The source's own verdict is in the refusal, so a refusal by an older-build
	// target can be told from a real one.
	if !strings.Contains(err.Error(), "source_verdict=identical") {
		t.Errorf("refusal does not carry the source's verdict: %v", err)
	}
	vm, gerr := corrosion.GetVM(context.Background(), source.DB, "vm-vaes")
	if gerr != nil || vm == nil {
		t.Fatalf("GetVM: %v", gerr)
	}
	if vm.HostName != source.Name {
		t.Errorf("VM host = %q, want it left on the source %q", vm.HostName, source.Name)
	}
}

// A guest booted on an older host and migrated here carries a NARROWER live
// expansion than this host's host-model. Moving it back to a host like the one
// it booted on must not be refused: the requirement is what the guest runs
// with, never this host's whole host-model.
func TestFleet_MigrateVM_GuestNarrowerThanSourceHostModelNotRefused(t *testing.T) {
	c := New(t, Options{Nodes: 2})
	defer c.Stop()

	source, target := c.Nodes[0], c.Nodes[1]
	source.Virt.HostModelFeatures = labHostModelFeatures
	target.Virt.HostModelFeatures = without(labHostModelFeatures, "vaes", "vpclmulqdq")
	seedRunningCPUVM(t, c, source, "vm-old", lv.CPUModeHostModel,
		labDomain("vm-old", labLiveCPU(t, "vaes", "vpclmulqdq")))

	if err := migrateAt(t, c, source, "vm-old", target.Name); err != nil {
		t.Fatalf("migrate of a guest narrower than the source host-model was refused: %v", err)
	}
	if len(target.Virt.ComparedCPUXML()) == 0 {
		t.Fatal("target was never asked")
	}
	if got := source.Virt.ComparedCPUXML(); len(got) != 0 {
		t.Errorf("the target's yes was not its own — the source was asked to second-guess it: %q", got)
	}
}
