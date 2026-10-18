// A reschedule or an ownership transfer carries the disk row the coordinator
// read, so every replica converges on the file the new owner boots, whatever
// order the replicas received the move and an earlier commit of the row in.
//
// The sequence needs no operator action: a commits a move of the VM's disk
// onto a copy, the commit reaches c, and a dies before it reaches b. The VM
// fails over to b, whose row still names the source; b starts it there and
// writes it. b is lost, and the VM fails over to c. With a host-only move,
// c's row was a's (the copy) with b's host on it, and c booted the copy: every
// write b acknowledged was gone, silently.
//
// Multi-node by construction: three replicas, each with its own database, and
// the order each receives the writes in is steered.
package fleet

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestFleet_RescheduleCarriesTheDiskRowItRead (I7-2).
//
//  1. a's VM rsd runs on a with its disk on the shared source; every replica
//     has it.
//  2. a commits a move of the disk onto a copy (UpdateDiskPlacement); only c
//     receives it.
//  3. a dies; rsd fails over to b, whose row names the source.
//  4. c receives the failover, before or after a's commit (both orders).
//  5. b dies; rsd fails over to c, by the same kind of move.
//  6. c's row names the source, and c's reconciler boots the source. a, back, converges on
//     the source too.
//
// Mutation: emit the host-only move (UPDATE vm_disks SET host_name) again in
// any of the movers — the subtests using it go red: c's row names the copy
// and c boots it.
func TestFleet_RescheduleCarriesTheDiskRowItRead(t *testing.T) {
	type mover func(ctx context.Context, n *Node, vm, to, state string) error
	reschedule := func(ctx context.Context, n *Node, vm, to, state string) error {
		return corrosion.RescheduleVMHost(ctx, n.DB, vm, to, state)
	}
	transfer := func(ctx context.Context, n *Node, vm, to, state string) error {
		cur, err := corrosion.GetVM(ctx, n.DB, vm)
		if err != nil || cur == nil {
			t.Fatalf("read %s on %s: %+v %v", vm, n.Name, cur, err)
		}
		return corrosion.TransferVMOwnerWithDisks(ctx, n.DB, vm, to, state, cur.OwnerEpoch)
	}
	for _, tc := range []struct {
		name          string
		move          mover
		failoverFirst bool // c receives the failover to b before a's commit
	}{
		{name: "reschedule, a's commit first", move: reschedule},
		{name: "reschedule, failover first", move: reschedule, failoverFirst: true},
		{name: "transfer, a's commit first", move: transfer},
		{name: "transfer, failover first", move: transfer, failoverFirst: true},
	} {
		t.Run(tc.name, func(t *testing.T) { rescheduleCarriesRow(t, tc.move, tc.failoverFirst) })
	}
}

func rescheduleCarriesRow(t *testing.T, move func(context.Context, *Node, string, string, string) error, failoverFirst bool) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 3})
	a, b, cn := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	const vm = "rsd"

	// 1. rsd on a, its disk on the shared source; everyone has it.
	src := sharedDiskVM(t, c, a, vm, a.Name, "running", "")
	dst := filepath.Join(filepath.Dir(src), "copy", vm+"-root.qcow2")
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, []byte("a's copy"), 0o644); err != nil {
		t.Fatal(err)
	}
	pumpMutations(t, c, a, b)
	pumpMutations(t, c, a, cn)

	// 2. a commits the move onto the copy; only c receives it.
	if err := corrosion.UpdateDiskPlacement(ctx, a.DB, vm, "root", a.Name, dst, "nfs", "copy"); err != nil {
		t.Fatal(err)
	}
	// The failover is decided later on another clock: its timestamp must be
	// the later one, as it is in any real failover.
	time.Sleep(5 * time.Millisecond)

	// 3. a dies; rsd fails over to b, which reads the source.
	if err := move(ctx, b, vm, b.Name, "pending"); err != nil {
		t.Fatalf("fail %s over to %s: %v", vm, b.Name, err)
	}
	if disks, _ := corrosion.GetVMDisks(ctx, b.DB, vm); len(disks) != 1 || disks[0].Path != src || disks[0].HostName != b.Name {
		t.Fatalf("%s's disk row on %s = %+v, want the source on %s", vm, b.Name, disks, b.Name)
	}
	const bWrites = "b's writes since the failover"
	if err := os.WriteFile(src, []byte(bWrites), 0o644); err != nil {
		t.Fatal(err)
	}

	// 4. c receives both, in the order the case names.
	if failoverFirst {
		pumpMutations(t, c, b, cn)
		pumpMutations(t, c, a, cn)
	} else {
		pumpMutations(t, c, a, cn)
		pumpMutations(t, c, b, cn)
	}
	disks, _ := corrosion.GetVMDisks(ctx, cn.DB, vm)
	if len(disks) != 1 || disks[0].Path != src || disks[0].HostName != b.Name || disks[0].StorageVolume != "" {
		t.Fatalf("%s's disk row on %s after the failover to %s = %+v, want the source on %s", vm, cn.Name, b.Name, disks, b.Name)
	}

	// 5. b dies; rsd fails over to c, to be started there.
	time.Sleep(5 * time.Millisecond)
	if err := move(ctx, cn, vm, cn.Name, "pending"); err != nil {
		t.Fatalf("fail %s over to %s: %v", vm, cn.Name, err)
	}

	// 6. c's row names the source, and c boots it.
	if disks, _ := corrosion.GetVMDisks(ctx, cn.DB, vm); len(disks) != 1 || disks[0].Path != src || disks[0].HostName != cn.Name {
		t.Fatalf("%s's disk row on %s = %+v, want the source on %s", vm, cn.Name, disks, cn.Name)
	}
	reconcileAll(t, c, cn)
	if st, _ := cn.Virt.DomainState(vm); st != "running" {
		t.Fatalf("%s on %s after its reconciler ran: %q, want running", vm, cn.Name, st)
	}
	if xml := cn.Virt.DefinedXML(vm); !strings.Contains(xml, src) || strings.Contains(xml, dst) {
		t.Fatalf("%s booted %s from the wrong file, want %s:\n%s", cn.Name, vm, src, xml)
	}
	if got, err := os.ReadFile(src); err != nil || string(got) != bWrites {
		t.Fatalf("%s = %q %v, want b's writes", src, got, err)
	}

	// a comes back: its own commit loses to the moves everywhere.
	pumpMutations(t, c, b, a)
	pumpMutations(t, c, cn, a)
	if disks, _ := corrosion.GetVMDisks(ctx, a.DB, vm); len(disks) != 1 || disks[0].Path != src || disks[0].HostName != cn.Name {
		t.Fatalf("%s's disk row on %s once it returns = %+v, want the source on %s", vm, a.Name, disks, cn.Name)
	}
}
