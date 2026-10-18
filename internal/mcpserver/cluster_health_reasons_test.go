package mcpserver

import (
	"encoding/json"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// TestClusterHealthDTO_Reasons: reasons ride the DTO, and a HEALTHY cluster
// serialises them as [] like the sibling lists, never null.
//
// Mutation: drop the nil guard in clusterHealthDTO and the HEALTHY case
// serialises "reasons":null.
func TestClusterHealthDTO_Reasons(t *testing.T) {
	got := clusterHealthDTO(&pb.ClusterHealth{Overall: "DEGRADED", Reasons: []string{"evaluator shared_lun is stale"}})
	if r, _ := got["reasons"].([]string); len(r) != 1 || r[0] != "evaluator shared_lun is stale" {
		t.Fatalf("reasons = %#v", got["reasons"])
	}
	b, err := json.Marshal(clusterHealthDTO(&pb.ClusterHealth{Overall: "HEALTHY"}))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if string(m["reasons"]) != "[]" {
		t.Fatalf("HEALTHY reasons = %s, want []", m["reasons"])
	}
}
