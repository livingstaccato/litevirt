package automation

import (
	"bytes"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
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
	p := corrosion.AutomationProjection{Head: corrosion.AutomationPrefix{ClusterUID: "cluster-one", Sequence: 7, Digest: "previous"}, Existing: &corrosion.AutomationRequest{Identity: identity, Receipt: original}}
	d := Decision{Sequence: 8, ParentDigest: strings.Repeat("a", 64), Command: c, Assignment: []byte(`{"version":1,"cluster_uid":"cluster-one","operation_id":"losing-assignment","recorded_at":"2026-10-15T00:00:00Z"}`)}
	result, err := reduce(p, d)
	if err != nil {
		t.Fatal(err)
	}
	if result.Receipt != original || result.SaveRequest || result.ClusterUID != "cluster-one" {
		t.Fatalf("duplicate replaced winning authority: %+v", result)
	}
	d.Command.PrincipalID = "different-principal"
	conflict, err := reduce(p, d)
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
		_, err := reduce(corrosion.AutomationProjection{}, Decision{Command: Command{Kind: kind, RequestID: "request"}})
		want := CodeUnsupported
		if kind == "admit_create" || kind == "adopt_resource" || kind == "transfer_owner" {
			want = CodeValidation
		}
		if Code(err) != want {
			t.Fatalf("%s reducer=%v", kind, err)
		}
	}
}

// An assigned operation cannot alias another admitted request's permanent
// lookup key, even when a peer supplies the colliding Assignment.
func TestReducerRejectsAssignedOperationCollision(t *testing.T) {
	c := Command{Kind: "read_barrier", ClusterUID: "cluster-one", PrincipalID: "node-one", RequestID: "request-two", Body: []byte(`{"version":1}`)}
	d := Decision{Sequence: 8, ParentDigest: strings.Repeat("a", 64), Command: c, Assignment: []byte(`{"version":1,"cluster_uid":"cluster-one","operation_id":"original-operation","recorded_at":"2026-10-15T00:00:00Z"}`)}
	p := corrosion.AutomationProjection{Head: corrosion.AutomationPrefix{ClusterUID: "cluster-one", Sequence: 7}, Operation: &Receipt{RequestID: "request-one", OperationID: "original-operation", Sequence: 2, State: "succeeded"}}
	r, err := reduce(p, d)
	if err != nil {
		t.Fatal(err)
	}
	if r.Receipt.Code != CodeValidation || r.Receipt.State != "rejected" || r.Receipt.OperationID != "" || !r.SaveRequest || r.ClusterUID != "cluster-one" {
		t.Fatalf("operation collision got authority: %+v", r.Receipt)
	}
}
