package corrosion

import (
	"context"
	"encoding/json"
	"testing"
)

// The actual mutation callbacks run outside the transaction. Recreate at the
// same generation there, so a generation-only CAS necessarily sees the ABA.
func TestMutateDesiredSpec_RecreateCannotInheritOldIdentity(t *testing.T) {
	for _, path := range []string{"metadata", "mint-helper", "noop"} {
		t.Run(path, func(t *testing.T) {
			ctx := context.Background()
			c := testClient(t)
			g := mintGrant(t)
			seedVM(t, c, "aba", `{"cpu":2}`)
			oldID, _, err := MintFirewallID(ctx, c, g, TagMemberVM, "", "aba")
			if err != nil {
				t.Fatal(err)
			}
			oldVM, err := GetVM(ctx, c, "aba")
			if err != nil {
				t.Fatal(err)
			}
			var fresh *VMRecord
			calls := 0
			recreate := func() {
				calls++
				if calls != 1 {
					return
				}
				if err := DeleteVM(ctx, c, "aba"); err != nil {
					t.Fatal(err)
				}
				seedVM(t, c, "aba", `{"cpu":8,"fresh":true}`)
				newID, _, err := MintFirewallID(ctx, c, g, TagMemberVM, "", "aba")
				if err != nil {
					t.Fatal(err)
				}
				fresh, err = GetVM(ctx, c, "aba")
				if err != nil {
					t.Fatal(err)
				}
				if oldID == newID || fresh.CreatedAt == oldVM.CreatedAt || fresh.SpecGeneration != oldVM.SpecGeneration {
					t.Fatalf("fixture lacks exact generation ABA: old=%+v fresh=%+v", oldVM, fresh)
				}
			}
			var applied bool
			switch path {
			case "mint-helper":
				// The same keepFor callback position MintFirewallID uses: choosing a
				// new identity from the sampled old spec must not write a new row.
				applied, _, err = mutateDesiredSpec(ctx, c, "aba", func(old string) (string, error) { return old, nil }, func(old string) (string, error) { id := newFirewallID(); recreate(); return id, nil })
			default:
				applied, _, err = MutateDesiredSpec(ctx, c, "aba", func(old string) (string, error) {
					recreate()
					if path == "noop" {
						return old, nil
					}
					var m map[string]json.RawMessage
					if err := json.Unmarshal([]byte(old), &m); err != nil {
						return "", err
					}
					m["cpu"] = json.RawMessage("4")
					b, err := json.Marshal(m)
					return string(b), err
				})
			}
			if err != nil {
				t.Fatal(err)
			}
			if applied {
				t.Error("mutation of previous incarnation reported success after recreate")
			}
			got, err := GetVM(ctx, c, "aba")
			if err != nil {
				t.Fatal(err)
			}
			if fresh == nil || got.Spec != fresh.Spec || got.SpecGeneration != fresh.SpecGeneration || got.CreatedAt != fresh.CreatedAt {
				t.Fatalf("old writer transplanted identity/spec into fresh incarnation: fresh=%+v got=%+v", fresh, got)
			}
		})
	}
}

func TestMutateDesiredSpec_RetriesWithinSameIncarnation(t *testing.T) {
	for _, noop := range []bool{false, true} {
		t.Run(map[bool]string{false: "write", true: "noop"}[noop], func(t *testing.T) {
			ctx := context.Background()
			c := testClient(t)
			seedVM(t, c, "retry", `{"cpu":2}`)
			calls := 0
			applied, gen, err := MutateDesiredSpec(ctx, c, "retry", func(old string) (string, error) {
				calls++
				if calls == 1 {
					ok, _, err := MutateDesiredSpec(ctx, c, "retry", func(string) (string, error) { return `{"cpu":8,"concurrent":true}`, nil })
					if err != nil || !ok {
						t.Fatalf("concurrent metadata writer: %v %v", ok, err)
					}
				}
				if noop {
					return old, nil
				}
				var m map[string]json.RawMessage
				if err := json.Unmarshal([]byte(old), &m); err != nil {
					return "", err
				}
				m["labels"] = json.RawMessage(`{"team":"db"}`)
				b, err := json.Marshal(m)
				return string(b), err
			})
			wantGen := int64(2)
			if noop {
				wantGen = 1
			}
			if err != nil || !applied || calls != 2 || gen != wantGen {
				t.Fatalf("same-incarnation retry: applied=%v calls=%d gen=%d err=%v", applied, calls, gen, err)
			}
			vm, err := GetVM(ctx, c, "retry")
			if err != nil {
				t.Fatal(err)
			}
			var got map[string]json.RawMessage
			if err := json.Unmarshal([]byte(vm.Spec), &got); err != nil {
				t.Fatal(err)
			}
			if string(got["cpu"]) != "8" || string(got["concurrent"]) != "true" {
				t.Fatalf("retry lost concurrent metadata: %s", vm.Spec)
			}
		})
	}
}
