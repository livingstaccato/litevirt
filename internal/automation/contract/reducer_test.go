package contract

import (
	"bytes"
	"strings"
	"testing"
)

// Replacing a winning receipt with a later proposal's assignment changes the
// admitted identity. A conflict must retain the original permanent index too.
func TestReducerPreservesOriginalReceipt(t *testing.T) {
	c := Command{Kind: "read_barrier", ClusterUID: "cluster-one", PrincipalID: "node-one", RequestID: "request-one", Body: []byte(`{"version":1}`)}
	identity, err := CanonicalCommand(c)
	if err != nil {
		t.Fatal(err)
	}
	original := Receipt{RequestID: "request-one", OperationID: "original-operation", ResourceUID: "cluster-one", Sequence: 2, State: "succeeded"}
	p := Projection{Head: Prefix{ClusterUID: "cluster-one", Sequence: 7, Digest: "previous"}, Existing: &Request{Identity: identity, Receipt: original}}
	d := Decision{Sequence: 8, ParentDigest: strings.Repeat("a", 64), Command: c, Assignment: []byte(`{"version":1,"cluster_uid":"cluster-one","operation_id":"losing-assignment","recorded_at":"2026-10-15T00:00:00Z"}`)}
	result, err := Reduce(p, d)
	if err != nil {
		t.Fatal(err)
	}
	if result.Receipt != original || result.SaveRequest || result.ClusterUID != "cluster-one" {
		t.Fatalf("duplicate replaced winning authority: %+v", result)
	}
	d.Command.PrincipalID = "different-principal"
	conflict, err := Reduce(p, d)
	if err != nil {
		t.Fatal(err)
	}
	if conflict.Receipt.Code != CodeIdempotencyConflict || conflict.Receipt.State != "rejected" || conflict.SaveRequest || conflict.ClusterUID != "cluster-one" || !bytes.Equal(p.Existing.Identity, identity) || p.Existing.Receipt != original {
		t.Fatalf("conflict changed authority: %+v", conflict)
	}
}

// Unsupported or incompatible stored commands must stop replay; no generic
// success handler can turn them into a no-op with an admitted receipt.
func TestReducerRejectsIncompatibleHistory(t *testing.T) {
	for _, kind := range []string{"admit_create", "admit_delete", "complete_operation", "unknown"} {
		_, err := Reduce(Projection{}, Decision{Command: Command{Kind: kind, RequestID: "request"}})
		if Code(err) != CodeUnsupported {
			t.Fatalf("%s reducer=%v", kind, err)
		}
	}
}

// An assigned operation cannot alias another admitted request's permanent
// lookup key, even when a peer supplies the colliding Assignment.
func TestReducerRejectsAssignedOperationCollision(t *testing.T) {
	c := Command{Kind: "read_barrier", ClusterUID: "cluster-one", PrincipalID: "node-one", RequestID: "request-two", Body: []byte(`{"version":1}`)}
	d := Decision{Sequence: 8, ParentDigest: strings.Repeat("a", 64), Command: c, Assignment: []byte(`{"version":1,"cluster_uid":"cluster-one","operation_id":"original-operation","recorded_at":"2026-10-15T00:00:00Z"}`)}
	p := Projection{Head: Prefix{ClusterUID: "cluster-one", Sequence: 7}, Operation: &Receipt{RequestID: "request-one", OperationID: "original-operation", Sequence: 2, State: "succeeded"}}
	r, err := Reduce(p, d)
	if err != nil {
		t.Fatal(err)
	}
	if r.Receipt.Code != CodeValidation || r.Receipt.State != "rejected" || r.Receipt.OperationID != "" || !r.SaveRequest || r.ClusterUID != "cluster-one" {
		t.Fatalf("operation collision got authority: %+v", r.Receipt)
	}
}

func TestReduceOriginalReplayAndValidationOrder(t *testing.T) {
	c := Command{Kind: "read_barrier", ClusterUID: "cluster-one", PrincipalID: "node-one", RequestID: "request-one", Body: []byte(`{"version":1}`)}
	d := Decision{Sequence: 2, ParentDigest: strings.Repeat("a", 64), Command: c, Assignment: []byte(`{"version":1,"cluster_uid":"cluster-one","operation_id":"operation-one","recorded_at":"2026-10-15T00:00:00Z"}`)}
	p := Projection{Head: Prefix{ClusterUID: "cluster-one", Sequence: 1}}
	original, err := Reduce(p, d)
	if err != nil {
		t.Fatal(err)
	}
	p.Existing = &Request{Identity: original.Identity, Receipt: original.Receipt}
	p.Operation = &original.Receipt
	p.ReplayOriginal = true
	got, err := Reduce(p, d)
	if err != nil || got.Receipt != original.Receipt || got.SaveRequest {
		t.Fatal("original replay lost receipt", got, err)
	}
	t.Run("recompute", func(t *testing.T) {
		wrong := d
		wrong.Assignment = []byte(`{"version":1,"cluster_uid":"cluster-one","operation_id":"changed-operation","recorded_at":"2026-10-15T00:00:00Z"}`)
		if _, err := Reduce(p, wrong); Code(err) != CodeUnavailable {
			t.Fatal("original replay trusted retained receipt instead of recomputing", err)
		}
	})
	t.Run("identity", func(t *testing.T) {
		wrong := d
		wrong.Command.PrincipalID = "different"
		if _, err := Reduce(p, wrong); Code(err) != CodeUnavailable {
			t.Fatal(err)
		}
	})
	t.Run("future", func(t *testing.T) {
		future := p
		request := *p.Existing
		request.Receipt.Sequence = 3
		future.Existing = &request
		future.ReplayOriginal = false
		if _, err := Reduce(future, d); Code(err) != CodeUnavailable {
			t.Fatal(err)
		}
	})
	for _, mode := range []string{"kind", "schema", "assignment"} {
		t.Run(mode, func(t *testing.T) {
			wrong := d
			want := CodeUnsupported
			switch mode {
			case "kind":
				wrong.Command.Kind = "unknown"
			case "schema":
				wrong.Command.Body = []byte(`{"version":2}`)
				want = CodeValidation
			case "assignment":
				wrong.Assignment = []byte(`{}`)
				want = CodeValidation
			}
			if _, err := Reduce(p, wrong); Code(err) != want {
				t.Fatalf("validation must precede retained identity: %v", err)
			}
		})
	}
}
