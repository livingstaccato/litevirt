package corrosion

import (
	"context"
	"strings"
	"testing"
)

func withStackRowInterleave(t *testing.T, fn func()) {
	t.Helper()
	stackRowInterleaveHook = fn
	t.Cleanup(func() { stackRowInterleaveHook = nil })
}

// A stack's state is written with its whole row, read first. Another writer
// that changes the row between that read and the write must not be
// overwritten with what was read: the guard refuses the write, and the retry
// reads the other writer's row and writes the state over it.
//
// Mutations: a guard that always passes writes v1's compose back over the
// redeploy (red); no retry leaves the stack "active" (red).
func TestStackRowWrite_AWriteBetweenTheReadAndTheWriteIsKept(t *testing.T) {
	for _, tc := range []struct {
		name  string
		other func(ctx context.Context, db *Client) error
		want  StackRecord // ComposeHash and State
	}{
		{"a redeploy", func(ctx context.Context, db *Client) error {
			return UpsertStack(ctx, db, StackRecord{Name: "edge", ComposeHash: "v2", ComposeYAML: "name: edge\n# v2\n", State: "active"})
		}, StackRecord{ComposeHash: "v2", State: "deleting"}},
		{"another state write through the same pattern", func(ctx context.Context, db *Client) error {
			return SetStackState(ctx, db, "edge", "deleting")
		}, StackRecord{ComposeHash: "v1", State: "deleting"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			db := newTestDB(t)
			if err := UpsertStack(ctx, db, StackRecord{Name: "edge", ComposeHash: "v1", ComposeYAML: "name: edge\n", State: "active"}); err != nil {
				t.Fatal(err)
			}
			reads, otherAt := 0, ""
			withStackRowInterleave(t, func() {
				reads++
				if reads != 1 {
					return
				}
				if err := tc.other(ctx, db); err != nil {
					t.Errorf("the other writer: %v", err)
				}
				st, _ := GetStack(ctx, db, "edge")
				otherAt = st.UpdatedAt
			})
			if err := MarkStackDeleting(ctx, db, "edge", false, "node-0"); err != nil {
				t.Fatal(err)
			}
			st, err := GetStack(ctx, db, "edge")
			if err != nil || st == nil {
				t.Fatalf("GetStack: %+v, %v", st, err)
			}
			if st.ComposeHash != tc.want.ComposeHash || st.State != tc.want.State {
				t.Errorf("stack = %s/%s, want %s/%s: the other writer's row was written over, or the state was not written",
					st.ComposeHash, st.State, tc.want.ComposeHash, tc.want.State)
			}
			if !(st.UpdatedAt > otherAt) {
				t.Errorf("updated_at %s is not after the other writer's %s", st.UpdatedAt, otherAt)
			}
			if reads < 2 {
				t.Errorf("the write was not retried after the row changed (%d reads)", reads)
			}
		})
	}
}

// A row that changes under every attempt is not written at all, and the
// caller is told.
func TestStackRowWrite_ARowThatKeepsChangingIsNotWritten(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	if err := UpsertStack(ctx, db, StackRecord{Name: "edge", ComposeHash: "v1", ComposeYAML: "name: edge\n", State: "active"}); err != nil {
		t.Fatal(err)
	}
	n := 0
	withStackRowInterleave(t, func() {
		n++
		if err := UpsertStack(ctx, db, StackRecord{Name: "edge", ComposeHash: "v" + strings.Repeat("x", n), ComposeYAML: "name: edge\n", State: "active"}); err != nil {
			t.Errorf("the other writer: %v", err)
		}
	})
	err := DeleteStackRecord(ctx, db, "edge")
	if err == nil || !strings.Contains(err.Error(), "kept changing") {
		t.Fatalf("DeleteStackRecord = %v, want the row-kept-changing error", err)
	}
	stackRowInterleaveHook = nil
	st, _ := GetStack(ctx, db, "edge")
	if st == nil || st.State != "active" || st.ComposeHash != "v"+strings.Repeat("x", n) {
		t.Errorf("stack = %+v, want the other writer's last row, live", st)
	}
}

// A row that was absent when read and arrives before the write: the write
// read for an absent row (the bare state update) is refused, and the retry
// writes the arrived row whole.
func TestStackRowWrite_ARowThatArrivesBetweenTheReadAndTheWriteIsWrittenWhole(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	reads := 0
	withStackRowInterleave(t, func() {
		reads++
		if reads != 1 {
			return
		}
		if err := UpsertStack(ctx, db, StackRecord{Name: "edge", ComposeHash: "v1", ComposeYAML: "name: edge\n", State: "active"}); err != nil {
			t.Errorf("the other writer: %v", err)
		}
	})
	if err := MarkStackDeleting(ctx, db, "edge", false, "node-0"); err != nil {
		t.Fatal(err)
	}
	st, _ := GetStack(ctx, db, "edge")
	if st == nil || st.State != "deleting" || st.ComposeHash != "v1" {
		t.Errorf("stack = %+v, want the arrived row marked deleting", st)
	}
	if reads < 2 {
		t.Errorf("the write was not retried after the row arrived (%d reads)", reads)
	}
}

// SetStackState writes only "deleting": its whole-row write brings back a row
// a lagging node has not seen tombstoned, harmless only in that state.
func TestSetStackState_RefusesAnyStateButDeleting(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	if err := UpsertStack(ctx, db, StackRecord{Name: "edge", ComposeHash: "v1", ComposeYAML: "name: edge\n", State: "deleting"}); err != nil {
		t.Fatal(err)
	}
	if err := SetStackState(ctx, db, "edge", "active"); err == nil {
		t.Fatal("SetStackState wrote \"active\"")
	}
	if st, _ := GetStack(ctx, db, "edge"); st == nil || st.State != "deleting" {
		t.Errorf("stack = %+v, want it left deleting", st)
	}
}
