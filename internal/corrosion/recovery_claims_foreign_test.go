package corrosion

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

// AbandonForeignProof is the legacy-key bridge's exclusion
// (docs/design/recovery-claims.md §10 item 37): the destination of a legacy
// decision signs that the proof is not the decision of the incarnation a
// scoped key names, and will never execute, only when its own database shows
// it. Anything it cannot show is refused, and the bridge then adopts the
// legacy value rather than deciding beside it.

func foreignFixture(t *testing.T) (*Client, context.Context) {
	t.Helper()
	c := newTestDB(t)
	return c, context.Background()
}

// mintVMProof writes a reschedule proof of vm to this node (host "") at epoch,
// pointing the VM at it, as the coordinator's WriteVMRescheduleProof does.
func mintVMProof(t *testing.T, c *Client, id, vm string, epoch string) {
	t.Helper()
	p := ActionProof{ID: id, Action: ActionReschedule, TargetKind: ClaimKindVM, TargetName: vm,
		DestHost: c.hostName, Coordinator: "coord", OwnerEpoch: epoch}
	if err := WriteVMRescheduleProof(context.Background(), c, p, vm, c.hostName); err != nil {
		t.Fatalf("mint %s: %v", id, err)
	}
}

func insertBareVM(t *testing.T, c *Client, name, host string) {
	t.Helper()
	if err := InsertVM(context.Background(), c, VMRecord{Name: name, HostName: host, Spec: `{}`, State: "running"}, nil, nil); err != nil {
		t.Fatal(err)
	}
}

func liveVM(t *testing.T, c *Client, name string) *VMRecord {
	t.Helper()
	vm, err := GetVM(context.Background(), c, name)
	if err != nil || vm == nil {
		t.Fatalf("read %s: %v %+v", name, err, vm)
	}
	return vm
}

func scoped(kind, name, inc string, epoch int64) ClaimKey {
	return ClaimKey{TargetKind: kind, TargetName: name, OwnerEpoch: epoch, Incarnation: inc}
}

// TestAbandonForeignProof_VM.
//
// Mutations: skip the epoch comparison — the completed decision of THIS
// incarnation is abandoned; skip the pending-link check — this incarnation's
// pending decision is abandoned; accept a proof this replica does not hold —
// the absent case is abandoned.
func TestAbandonForeignProof_VM(t *testing.T) {
	c, ctx := foreignFixture(t)
	host := c.hostName

	// Incarnation A: recovered here under V, which completed (epoch 0 -> 1).
	insertBareVM(t, c, "vm-a", host)
	mintVMProof(t, c, "v-ran-for-a", "vm-a", "0")
	if err := ClaimActionProof(ctx, c, "v-ran-for-a", host); err != nil {
		t.Fatal(err)
	}
	if err := CompleteVMStartProof(ctx, c, "v-ran-for-a", "vm-a", host); err != nil {
		t.Fatal(err)
	}
	// A deleted; B re-created under the name at epoch 0.
	if err := DeleteVM(ctx, c, "vm-a"); err != nil {
		t.Fatal(err)
	}
	insertBareVM(t, c, "vm-a", host)
	b := liveVM(t, c, "vm-a")
	keyB := scoped(ClaimKindVM, "vm-a", IncarnationOf(b.CreatedAt), 0)
	if err := c.AbandonForeignProof(ctx, "v-ran-for-a", keyB, "t"); err != nil {
		t.Fatalf("a completed proof that did not move B was not abandoned: %v", err)
	}
	if ok, _ := c.ProofAbandoned(ctx, "v-ran-for-a"); !ok {
		t.Fatal("the abandonment was not recorded")
	}

	// B's own decision, completed: B is past the epoch, so it is B's.
	mintVMProof(t, c, "v-ran-for-b", "vm-a", "0")
	if err := ClaimActionProof(ctx, c, "v-ran-for-b", host); err != nil {
		t.Fatal(err)
	}
	if err := CompleteVMStartProof(ctx, c, "v-ran-for-b", "vm-a", host); err != nil {
		t.Fatal(err)
	}
	if err := c.AbandonForeignProof(ctx, "v-ran-for-b", keyB, "t"); !errors.Is(err, ErrProofNotForeign) {
		t.Fatalf("this incarnation's completed decision: %v, want ErrProofNotForeign", err)
	}

	// B's own pending decision at epoch 1: B is pending on it.
	mintVMProof(t, c, "v-pending-b", "vm-a", "1")
	keyB1 := scoped(ClaimKindVM, "vm-a", IncarnationOf(b.CreatedAt), 1)
	if err := c.AbandonForeignProof(ctx, "v-pending-b", keyB1, "t"); !errors.Is(err, ErrProofNotForeign) {
		t.Fatalf("this incarnation's pending decision: %v, want ErrProofNotForeign", err)
	}

	// A proof this replica does not hold.
	if err := c.AbandonForeignProof(ctx, "never-seen", keyB, "t"); !errors.Is(err, ErrProofNotForeign) {
		t.Fatalf("an absent proof: %v, want ErrProofNotForeign", err)
	}
	// A legacy key names no incarnation to be foreign to.
	if err := c.AbandonForeignProof(ctx, "v-ran-for-a", keyB.Legacy(), "t"); !errors.Is(err, ErrProofNotForeign) {
		t.Fatalf("a legacy key: %v, want ErrProofNotForeign", err)
	}
}

// TestAbandonForeignProof_PendingOfAPreviousIncarnation: incarnation A's
// decision never ran (A was deleted while it was pending); B, re-created,
// is not pending on it. It is abandoned, and never runs here.
func TestAbandonForeignProof_PendingOfAPreviousIncarnation(t *testing.T) {
	c, ctx := foreignFixture(t)
	host := c.hostName
	insertBareVM(t, c, "vm-p", host)
	mintVMProof(t, c, "v-a-pending", "vm-p", "0")
	if err := DeleteVM(ctx, c, "vm-p"); err != nil {
		t.Fatal(err)
	}
	insertBareVM(t, c, "vm-p", host)
	b := liveVM(t, c, "vm-p")
	if err := c.AbandonForeignProof(ctx, "v-a-pending", scoped(ClaimKindVM, "vm-p", IncarnationOf(b.CreatedAt), 0), "t"); err != nil {
		t.Fatalf("a previous incarnation's pending decision was not abandoned: %v", err)
	}
	if err := ClaimActionProofFenced(ctx, c, "v-a-pending", host, nil); err == nil {
		t.Fatal("an abandoned proof was claimed")
	}
}

// TestAbandonForeignProof_Container: a container relocation is this
// incarnation's while a live row of the name carries its token.
//
// Mutation: skip the token check — this incarnation's completed relocation is
// abandoned.
func TestAbandonForeignProof_Container(t *testing.T) {
	c, ctx := foreignFixture(t)
	host := c.hostName
	if err := UpsertContainer(ctx, c, ContainerRecord{HostName: host, Name: "ct", State: "running", Image: "alpine",
		RelocateToken: "tok-b"}); err != nil {
		t.Fatal(err)
	}
	ct, _ := GetContainer(ctx, c, host, "ct")
	key := scoped(ClaimKindContainer, "ct", IncarnationOf(ct.CreatedAt), 0)
	for _, p := range []ActionProof{
		{ID: "reloc-b", Action: ActionRelocate, TargetKind: ClaimKindContainer, TargetName: "ct", DestHost: host,
			Coordinator: "coord", RelocationToken: "tok-b", OwnerEpoch: "0"},
		{ID: "reloc-a", Action: ActionRelocate, TargetKind: ClaimKindContainer, TargetName: "ct", DestHost: host,
			Coordinator: "coord", RelocationToken: "tok-a", OwnerEpoch: "0"},
	} {
		if err := WriteActionProof(ctx, c, p); err != nil {
			t.Fatal(err)
		}
		if err := ClaimActionProof(ctx, c, p.ID, host); err != nil {
			t.Fatal(err)
		}
		if err := CompleteActionProof(ctx, c, p.ID, host); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.AbandonForeignProof(ctx, "reloc-b", key, "t"); !errors.Is(err, ErrProofNotForeign) {
		t.Fatalf("the relocation the live row carries: %v, want ErrProofNotForeign", err)
	}
	if err := c.AbandonForeignProof(ctx, "reloc-a", key, "t"); err != nil {
		t.Fatalf("a completed relocation no live row carries was not abandoned: %v", err)
	}
}

// TestAbandonForeignProof_IgnoresClocks is the skew edge: the incarnation's
// created_at comes from its creator's wall clock and a proof's mint time from
// its minter's, and nothing bounds the difference (hlc.Clock refuses to adopt
// a remote clock more than MaxSkewMS ahead, it does not correct one). A
// creator ten minutes ahead makes this incarnation's own pending decision look
// minted "before" it existed; one a day behind makes it look minted long
// after. Neither moves the answer: the destination reads its own rows, not the
// clocks, and refuses to exclude this incarnation's decision either way.
//
// Mutation: attribute by mint time (the pre-review rule: minted earlier than
// created_at less MaxSkewMS is a previous incarnation's) — the decision of a
// creator ahead of the minter is abandoned as foreign.
func TestAbandonForeignProof_IgnoresClocks(t *testing.T) {
	c, ctx := foreignFixture(t)
	host := c.hostName
	for i, tc := range []struct{ name, createdAt string }{
		{"creator ten minutes ahead", "2099-01-01T00:10:00Z"},
		{"creator a day behind", "2000-01-01T00:00:00Z"},
	} {
		vm := fmt.Sprintf("vm-skew-%d", i)
		insertBareVM(t, c, vm, host)
		if err := c.Execute(ctx, `UPDATE vms SET created_at = ? WHERE name = ?`, tc.createdAt, vm); err != nil {
			t.Fatal(err)
		}
		mintVMProof(t, c, "v-"+vm, vm, "0")
		key := scoped(ClaimKindVM, vm, tc.createdAt, 0)
		if err := c.AbandonForeignProof(ctx, "v-"+vm, key, "t"); !errors.Is(err, ErrProofNotForeign) {
			t.Errorf("%s: this incarnation's pending decision was excluded: %v", tc.name, err)
		}
	}
}
