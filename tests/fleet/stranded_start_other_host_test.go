package fleet

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/grpcapi"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// rc9 lab F1, review m2, on two real daemons: node a's start of an
// access-VLAN VM is cut off in its paused window (the daemon "dies" while
// putting the VLAN on), and failover moves the VM to b, which runs it. When
// a's sweep runs, its paused domain is a second qemu of a VM b runs. One copy
// at every moment: a's domain is neither resumed nor killed, and it is named
// by vm_start_stranded_paused, a condition every node sees, naming both hosts
// and how to stop a's copy. Once a's copy is gone, the condition resolves
// everywhere.
//
// Mutation: drop the record when the row names another host (the old rule) —
// red (nothing names a's paused qemu).
func TestFleet_StrandedStartWhoseVMAnotherHostRunsIsNamed(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 2, IndependentReplicas: true})
	a, b := c.Nodes[0], c.Nodes[1]
	const vm = "stranded"
	for _, n := range []*Node{a, b} {
		(&accVLANBridge{on: true}).wire(n)
	}
	if err := corrosion.InsertVM(ctx, a.DB, corrosion.VMRecord{Name: vm, HostName: a.Name, State: "stopped",
		CPUActual: 1, MemActual: 256,
		Spec: vmSpecJSON(t, &pb.VMSpec{Name: vm, Cpu: 1, MemoryMib: 256,
			Network: []*pb.NetworkAttachment{{Name: "accnet", Mac: "52:54:00:ac:00:09", Trunk: []int32{30}}}})},
		nil, nil); err != nil {
		t.Fatal(err)
	}
	const domXML = `<domain type='kvm'><name>stranded</name><uuid>5a5a5a5a-0000-4000-8000-00000000f1f1</uuid></domain>`
	if err := a.Virt.DefineDomain(domXML); err != nil {
		t.Fatal(err)
	}
	c.WaitConverged(t, convergeTimeout)

	// a's start stops between the paused create and the resume.
	entered, release := make(chan struct{}), make(chan struct{})
	var once, released sync.Once
	// A failed assertion must not leave the start blocked under the
	// cluster's shutdown.
	t.Cleanup(func() { released.Do(func() { close(release) }) })
	a.Virt.FailConfigureVLANTap = func(domain, mac string, vlan int) error {
		if domain != vm {
			return nil
		}
		once.Do(func() { close(entered) })
		<-release
		return errors.New("the daemon died here")
	}
	startDone := make(chan error, 1)
	go func() {
		_, err := c.SelfClient(a).StartVM(ctx, &pb.StartVMRequest{Name: vm})
		startDone <- err
	}()
	select {
	case <-entered:
	case <-time.After(convergeTimeout):
		t.Fatal("a's start never reached its paused window")
	}
	if st, _ := a.Virt.RawState(vm); st != libvirtfake.StatePaused {
		t.Fatalf("a's domain in the paused window is %v, want paused", st)
	}

	// Failover moved the VM to b, which runs it.
	if err := corrosion.UpdateVMHost(ctx, b.DB, vm, b.Name, "running"); err != nil {
		t.Fatal(err)
	}
	if err := b.Virt.DefineDomain(domXML); err != nil {
		t.Fatal(err)
	}
	b.Virt.SetState(vm, libvirtfake.StateRunning)
	c.WaitConverged(t, convergeTimeout)

	a.Server.ResumeStrandedStarts(ctx)
	if st, _ := a.Virt.RawState(vm); st != libvirtfake.StatePaused {
		t.Fatalf("a's paused copy is %v after the sweep, want left paused", st)
	}
	if st, _ := b.Virt.RawState(vm); st != libvirtfake.StateRunning {
		t.Fatalf("b's copy is %v, want running", st)
	}
	c.WaitConverged(t, convergeTimeout)
	subject := vm + "@" + a.Name
	cond, ok, err := corrosion.GetHealthCondition(ctx, b.DB, grpcapi.StrandedStartEvaluator, grpcapi.CondStrandedStartPaused, "vm", subject)
	if err != nil || !ok || cond.Lifecycle == corrosion.ConditionResolved {
		t.Fatalf("b does not see a's paused copy named: %+v (found %v, %v)", cond, ok, err)
	}
	for _, want := range []string{a.Name, b.Name, "`virsh destroy " + vm + "`", "neither resumed nor killed"} {
		if !strings.Contains(cond.Evidence, want) {
			t.Fatalf("the condition %q does not say %q", cond.Evidence, want)
		}
	}

	// The cut-off start ends (its error destroys a's copy); the condition
	// resolves on a's next check, everywhere.
	released.Do(func() { close(release) })
	select {
	case err := <-startDone:
		if err == nil {
			t.Fatal("a's cut-off start succeeded")
		}
	case <-time.After(convergeTimeout):
		t.Fatal("a's start never returned")
	}
	if st, _ := a.Virt.RawState(vm); st == libvirtfake.StatePaused || st == libvirtfake.StateRunning {
		t.Fatalf("a's copy is %v after its start failed, want stopped", st)
	}
	a.Server.JudgeStrandedStarts(ctx)
	c.WaitConverged(t, convergeTimeout)
	if cond, ok, _ := corrosion.GetHealthCondition(ctx, b.DB, grpcapi.StrandedStartEvaluator, grpcapi.CondStrandedStartPaused, "vm", subject); !ok || cond.Lifecycle != corrosion.ConditionResolved {
		t.Fatalf("the condition after a's copy went: %+v, want resolved", cond)
	}
	if st, _ := b.Virt.RawState(vm); st != libvirtfake.StateRunning {
		t.Fatalf("b's copy is %v at the end, want running", st)
	}
}
