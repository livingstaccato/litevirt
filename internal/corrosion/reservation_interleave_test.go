package corrosion

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// Reserve-then-verify must admit at most capacity under ANY arrival order.
//
// Operation ids are random, so the order they sort in says nothing about the
// order claimants arrive in. The earlier-only rule let a claim that had already
// WON be ignored by every claimant with a smaller id that arrived after it; these
// tests pin that a decided claim counts whatever its id, while a claim still
// deciding keeps the tie-break (an earlier id does not yield to it).

const (
	interleaveClaimMiB = 1536
	// 4096 MiB host − the default 1024 MiB reserve = 3072 allocatable: room for
	// exactly two 1536 MiB claims.
	interleaveHostMiB = 4096
	interleaveRoom    = 2
)

// interleaveDim is one admission dimension reserve-then-verify decides.
type interleaveDim struct {
	name string
	// fits reports whether claim opID, already reserved, fits in scope.
	fits func(t *testing.T, c *Client, scope, opID string) bool
	// vector is claim's reservation in scope.
	vector func(scope string) ReservationVector
	// setup creates scope.
	setup func(t *testing.T, c *Client, scope string)
}

func interleaveDims() []interleaveDim {
	ctx := context.Background()
	projectFits := func(reserved QuotaAmount) bool {
		return reserved.MemMiB+interleaveClaimMiB <= interleaveRoom*interleaveClaimMiB
	}
	return []interleaveDim{
		{
			name: "host",
			setup: func(t *testing.T, c *Client, scope string) {
				t.Helper()
				if err := InsertHost(ctx, c, HostRecord{Name: scope, Address: "127.0.0.1", GRPCPort: 1,
					State: "active", CPUTotal: 64, MemTotal: interleaveHostMiB}); err != nil {
					t.Fatal(err)
				}
			},
			vector: func(scope string) ReservationVector {
				return ReservationVector{TargetHost: scope, TargetCPU: 1, TargetMemMiB: interleaveClaimMiB, Provisional: true}
			},
			fits: func(t *testing.T, c *Client, scope, opID string) bool {
				t.Helper()
				_, free, ok, err := HostFreeCapacityBefore(ctx, c, scope, DefaultCapacityPolicy(), opID)
				if err != nil || !ok {
					t.Fatalf("HostFreeCapacityBefore(%s): ok=%v err=%v", opID, ok, err)
				}
				return free >= interleaveClaimMiB
			},
		},
		{
			name:  "project",
			setup: func(*testing.T, *Client, string) {},
			vector: func(scope string) ReservationVector {
				return ReservationVector{Project: scope, ProjectMemMiB: interleaveClaimMiB, Provisional: true}
			},
			fits: func(t *testing.T, c *Client, scope, opID string) bool {
				t.Helper()
				r, err := ProjectReservedBefore(ctx, c, scope, opID)
				if err != nil {
					t.Fatalf("ProjectReservedBefore(%s): %v", opID, err)
				}
				return projectFits(r)
			},
		},
		{
			// The authority holder's check. grace 0: a refused claim is released
			// here, and the settle term is about winners, not refusals.
			name:  "project-settling",
			setup: func(*testing.T, *Client, string) {},
			vector: func(scope string) ReservationVector {
				return ReservationVector{Project: scope, ProjectMemMiB: interleaveClaimMiB, Provisional: true}
			},
			fits: func(t *testing.T, c *Client, scope, opID string) bool {
				t.Helper()
				r, err := ProjectReservedSettlingAmount(ctx, c, scope, opID, 0, time.Now())
				if err != nil {
					t.Fatalf("ProjectReservedSettlingAmount(%s): %v", opID, err)
				}
				return projectFits(r)
			},
		},
	}
}

// interleaveClaimant runs one admission's two events against c: reserve
// (publish the provisional claim) and decide (verify; mark it admitted when it
// fits, release it when it does not). decide is atomic, as the decider's
// admission lock makes it within one node.
type interleaveClaimant struct {
	t     *testing.T
	c     *Client
	dim   interleaveDim
	scope string
	id    string
}

func (cl interleaveClaimant) reserve() {
	cl.t.Helper()
	ctx := context.Background()
	rv := cl.dim.vector(cl.scope)
	js, err := rv.Encode()
	if err != nil {
		cl.t.Fatal(err)
	}
	if err := InsertOperation(ctx, cl.c, OperationRecord{ID: cl.id, Method: "CreateVM", Project: rv.Project,
		ResourceKind: CapacityResourceKind, OperationKind: string(OpResourceUpdateRunning), ReservationJSON: js}); err != nil {
		cl.t.Fatal(err)
	}
}

func (cl interleaveClaimant) decide() bool {
	cl.t.Helper()
	ctx := context.Background()
	if cl.dim.fits(cl.t, cl.c, cl.scope, cl.id) {
		if err := MarkReservationAdmitted(ctx, cl.c, cl.id); err != nil {
			cl.t.Fatal(err)
		}
		return true
	}
	if err := AppendOperationStep(ctx, cl.c, OperationStepRecord{OperationID: cl.id, StepName: OpStepCompleted}); err != nil {
		cl.t.Fatal(err)
	}
	return false
}

// TestReserveThenVerify_AdmittedHigherIDCounts is the interleaving that
// over-admitted: c (the highest id) reserves and is admitted before the others
// exist; a then ignored c as "later"; b counted only a. Three of three onto room
// for two.
func TestReserveThenVerify_AdmittedHigherIDCounts(t *testing.T) {
	for _, dim := range interleaveDims() {
		t.Run(dim.name, func(t *testing.T) {
			c := NewTestClientT(t)
			if err := InitSchema(context.Background(), c); err != nil {
				t.Fatal(err)
			}
			dim.setup(t, c, "s")
			admitted := 0
			for _, id := range []string{"c", "a", "b"} {
				cl := interleaveClaimant{t: t, c: c, dim: dim, scope: "s", id: id}
				cl.reserve()
				if cl.decide() {
					admitted++
				}
			}
			if admitted != interleaveRoom {
				t.Fatalf("admitted %d of 3 arriving c, a, b onto room for %d: an admitted claim must "+
					"count against every later arrival whatever its id", admitted, interleaveRoom)
			}
		})
	}
}

// TestReserveThenVerify_NoInterleavingOverAdmits checks EVERY interleaving of
// three claimants' reserve and decide events (90 of them), in each dimension:
// never more than capacity, and never nobody (the tie-break still elects a
// winner when claimants see each other).
func TestReserveThenVerify_NoInterleavingOverAdmits(t *testing.T) {
	ids := []string{"a", "b", "c"}
	var orders [][]int // each entry: claimant index; its first occurrence reserves, its second decides
	var gen func(prefix []int, left [3]int)
	gen = func(prefix []int, left [3]int) {
		if left == [3]int{} {
			orders = append(orders, append([]int(nil), prefix...))
			return
		}
		for i := range left {
			if left[i] > 0 {
				next := left
				next[i]--
				gen(append(prefix, i), next)
			}
		}
	}
	gen(nil, [3]int{2, 2, 2})
	if len(orders) != 90 {
		t.Fatalf("generated %d interleavings, want 90", len(orders))
	}

	for _, dim := range interleaveDims() {
		t.Run(dim.name, func(t *testing.T) {
			c := NewTestClientT(t)
			if err := InitSchema(context.Background(), c); err != nil {
				t.Fatal(err)
			}
			for n, order := range orders {
				// A scope per interleaving keeps them independent in one database;
				// the id prefix keeps a, b, c in that order within it.
				scope := fmt.Sprintf("s%02d", n)
				dim.setup(t, c, scope)
				seen := [3]bool{}
				admitted := 0
				var trace []string
				for _, i := range order {
					cl := interleaveClaimant{t: t, c: c, dim: dim, scope: scope, id: scope + "-" + ids[i]}
					if !seen[i] {
						seen[i] = true
						cl.reserve()
						trace = append(trace, "R"+ids[i])
						continue
					}
					ok := cl.decide()
					if ok {
						admitted++
					}
					trace = append(trace, fmt.Sprintf("V%s=%v", ids[i], ok))
				}
				if admitted > interleaveRoom {
					t.Errorf("interleaving %v admitted %d onto room for %d", trace, admitted, interleaveRoom)
				}
				if admitted == 0 {
					t.Errorf("interleaving %v admitted nobody: the tie-break must elect a winner", trace)
				}
			}
		})
	}
}

// TestReservedBefore_LaterClaimCountsOnceDecided pins the three cases of the
// rule for a claim sorting AFTER ours.
func TestReservedBefore_LaterClaimCountsOnceDecided(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name        string
		provisional bool
		admitted    bool
		wantCounted bool
	}{
		{"provisional and still deciding yields to us", true, false, false},
		{"provisional and admitted counts", true, true, true},
		{"never provisional (overcommit, an older build) counts", false, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := NewTestClientT(t)
			if err := InitSchema(ctx, c); err != nil {
				t.Fatal(err)
			}
			rv := ReservationVector{Project: "p", ProjectMemMiB: 512, TargetHost: "h", TargetMemMiB: 512, Provisional: tc.provisional}
			js, err := rv.Encode()
			if err != nil {
				t.Fatal(err)
			}
			if err := InsertOperation(ctx, c, OperationRecord{ID: "zzz-later", Method: "CreateVM", Project: "p",
				ResourceKind: CapacityResourceKind, OperationKind: string(OpResourceUpdateRunning), ReservationJSON: js}); err != nil {
				t.Fatal(err)
			}
			if tc.admitted {
				if err := MarkReservationAdmitted(ctx, c, "zzz-later"); err != nil {
					t.Fatal(err)
				}
			}
			_, hostMem, _, projMem, err := ReservedBefore(ctx, c, "h", "p", "aaa-ours")
			if err != nil {
				t.Fatal(err)
			}
			settling, err := ProjectReservedSettlingAmount(ctx, c, "p", "aaa-ours", 0, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			want := 0
			if tc.wantCounted {
				want = 512
			}
			if hostMem != want || projMem != want || settling.MemMiB != want {
				t.Fatalf("later claim counted host=%d project=%d settling=%d MiB, want %d each",
					hostMem, projMem, settling.MemMiB, want)
			}
		})
	}
}
