package grpcapi

import (
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/vfio"
)

// migHostdev is a managed PCI hostdev of the GPU at 0000:41:00.0.
const migHostdev = "<hostdev mode='subsystem' type='pci' managed='yes'><source>" +
	"<address domain='0x0000' bus='0x41' slot='0x00' function='0x0'/></source></hostdev>"

const migGPUEnabled = "0, 00000000:41:00.0, Enabled, Enabled, NVIDIA A100\n"
const migGPUDisabled = "0, 00000000:41:00.0, Disabled, Disabled, NVIDIA A100\n"

// A start of a domain whose definition already passes through a GPU MIG
// holds is refused before libvirt (managed='yes') would bind the GPU itself,
// before the hardware_v2 latch (passthroughForStart leaves such a
// definition alone, and the PCI start-preflight is post-latch only) and
// after it (the device has no intent the preflight would acquire). With MIG
// off, the same start goes ahead.
func TestStartVM_RefusesADefinitionPassingThroughAMIGGPU(t *testing.T) {
	for _, latched := range []bool{false, true} {
		name := map[bool]string{false: "pre-latch", true: "post-latch"}[latched]
		t.Run(name, func(t *testing.T) {
			s, fake := provableCreateServer(t)
			if latched {
				enableHardwareV2(t, s)
			}
			fs := newNvidiaDriverFS()
			defer vfio.SetFS(fs)()
			ctx := adminCtx()
			insertTestVMWithSpec(t, ctx, s.db, "vm1", s.hostName, "stopped", `{"name":"vm1","cpu":1,"memory_mib":512}`)
			seedPCIGPU(t, s, "0000:41:00.0", -1)
			if err := fake.DefineDomain("<domain type='kvm'><name>vm1</name><uuid>uuid-vm1</uuid><memory unit='MiB'>512</memory><vcpu>1</vcpu><devices>" +
				migHostdev + "</devices></domain>"); err != nil {
				t.Fatal(err)
			}
			migFakeSMI(t, migGPUEnabled, noGIs, 6)

			_, err := s.StartVM(ctx, &pb.StartVMRequest{Name: "vm1"})
			if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "MIG mode is on") ||
				!strings.Contains(err.Error(), "lv host mig disable 0") {
				t.Fatalf("StartVM = %v; want the MIG refusal", err)
			}
			if st, _ := fake.RawState("vm1"); st == libvirtfake.StateRunning {
				t.Fatal("vm1's domain was started")
			}
			if fs.binds != 0 {
				t.Fatalf("%d vfio binds", fs.binds)
			}

			migFakeSMI(t, migGPUDisabled, noGIs, 6)
			if _, err := s.StartVM(ctx, &pb.StartVMRequest{Name: "vm1"}); err != nil {
				t.Fatalf("StartVM with MIG off: %v", err)
			}
			if st, _ := fake.RawState("vm1"); st != libvirtfake.StateRunning {
				t.Fatalf("vm1's domain is %q with MIG off, want running", st)
			}
		})
	}
}

// A cutover's runtime handoff starts the replaced VM outside the start hook.
// A definition passing through a GPU MIG holds is refused there too, and
// the refusal is a failed handoff step like any failed start: the row keeps
// its running intent and the handoff, retried once MIG is off, starts it.
func TestFinishVMReplaceRuntime_RefusesAMIGGPUAndStaysRetryable(t *testing.T) {
	s, fake := provableCreateServer(t)
	fs := newNvidiaDriverFS()
	defer vfio.SetFS(fs)()
	ctx := adminCtx()
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "x", HostName: s.hostName, State: "running",
		CPUActual: 1, MemActual: 512, Spec: `{"name":"x","cpu":1,"memory_mib":512}`,
	}, nil, nil); err != nil {
		t.Fatal(err)
	}
	seedPCIGPU(t, s, "0000:41:00.0", -1)
	vm, err := corrosion.GetVM(ctx, s.db, "x")
	if err != nil || vm == nil {
		t.Fatal(err)
	}
	dom := "<domain type='kvm'><name>x-next</name><uuid>uuid-x</uuid><memory unit='MiB'>512</memory><vcpu>1</vcpu><devices>" +
		migHostdev + "</devices></domain>"
	cl := corrosion.VMReplaceCleanup{OperationID: "op-x", AcceptedState: "running",
		Handoff: corrosion.VMReplaceHandoff{XML: dom, UUID: "uuid-x"},
		Manifest: corrosion.VMReplaceManifest{
			HostName: s.hostName, ReplacedVM: "x", Replacement: "x-next",
			ReplacementIncarnation: vm.CreatedAt, ReplacementUUID: "uuid-x",
		}}
	migFakeSMI(t, migGPUEnabled, noGIs, 6)

	err = s.finishVMReplaceRuntime(ctx, cl)
	if err == nil || !strings.Contains(err.Error(), "MIG mode is on") {
		t.Fatalf("handoff = %v; want the MIG refusal", err)
	}
	if st, _ := fake.RawState("x"); st == libvirtfake.StateRunning {
		t.Fatal("x was started")
	}
	if fs.binds != 0 {
		t.Fatalf("%d vfio binds", fs.binds)
	}
	if row, _ := corrosion.GetVM(ctx, s.db, "x"); row == nil || row.State != "running" {
		t.Fatalf("x's row after the refused handoff = %+v; its running intent must stay for the retry", row)
	}

	migFakeSMI(t, migGPUDisabled, noGIs, 6)
	if err := s.finishVMReplaceRuntime(ctx, cl); err != nil {
		t.Fatalf("handoff retried with MIG off: %v", err)
	}
	if st, _ := fake.RawState("x"); st != libvirtfake.StateRunning {
		t.Fatalf("x is %q after the retried handoff, want running", st)
	}
}
