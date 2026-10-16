package main

import (
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// TestPrintClusterHealth_ShowsReasons: a DEGRADED with no condition must still
// say why, right under the overall line.
//
// Mutation: drop the reasons loop from printClusterHealth and this fails.
func TestPrintClusterHealth_ShowsReasons(t *testing.T) {
	out := captureStdout(t, func() {
		printClusterHealth(&pb.ClusterHealth{Overall: "DEGRADED",
			Reasons: []string{"evaluator shared_lun is stale: last scan \"2026-10-15T18:40:04Z\" by node-1"}})
	})
	if !strings.HasPrefix(out, "overall: DEGRADED\n  - evaluator shared_lun is stale") {
		t.Fatalf("output:\n%s\nwant the reason listed under the overall line", out)
	}
}
