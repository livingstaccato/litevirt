package grpcapi

import (
	"slices"
	"testing"

	"github.com/litevirt/litevirt/internal/capabilities"
)

// TestAdvertise_PartitionPauseWithheldWhileOff pins
// docs/design/partition-pause.md §5 beside the other two answers to CLAUDE.md's
// question "where is the guarantee enforced?".
//
// partition_pause_v1's guarantee is enforced on the MINORITY, which pauses, and
// RELIED ON by the majority, which waits out the pause and then recovers. A
// flag-off peer would not pause, and the majority would start a second copy of
// a workload that is still running there. So the latch must mean config
// uniformity, and the token is withheld while the flag is off — the
// recovery_claim_v1 shape, not the shared_storage_fence_v1 one.
//
// Mutation: drop the advertisement filter — the flag-off node advertises and
// the first subtest goes red.
func TestAdvertise_PartitionPauseWithheldWhileOff(t *testing.T) {
	t.Run("flag off", func(t *testing.T) {
		s := testServer(t)
		s.SetPartitionPause(false)
		if slices.Contains(s.advertisedCapabilities(), capabilities.PartitionPauseV1) {
			t.Fatalf("%s is advertised with enforcement.partition_pause off; the cluster could latch "+
				"across a node that will not pause, and the majority would wait for nothing", capabilities.PartitionPauseV1)
		}
		if s.tokenEnabled(capabilities.PartitionPauseV1) {
			t.Fatalf("tokenEnabled(%s) is true with the flag off", capabilities.PartitionPauseV1)
		}
	})
	t.Run("flag on", func(t *testing.T) {
		s := testServer(t)
		s.SetPartitionPause(true)
		if !slices.Contains(s.advertisedCapabilities(), capabilities.PartitionPauseV1) {
			t.Fatalf("a flag-on node does not advertise %s", capabilities.PartitionPauseV1)
		}
		if !s.tokenEnabled(capabilities.PartitionPauseV1) {
			t.Fatalf("tokenEnabled(%s) is false with the flag on", capabilities.PartitionPauseV1)
		}
	})
}

// TestPartitionPauseToken_Shape: a policy (so it has a flag and is not
// mandatory), and a claim about what peers DO rather than what they can decode
// (so it is latched over voting members, not replication recipients — it
// emits no new statement shape: the pause record is a host-local file, the
// conditions and the fence row use existing shapes).
//
// Mutations: add it to capabilities.mandatory or replicationGated — this goes
// red; drop it from Supported() or All() — this goes red.
func TestPartitionPauseToken_Shape(t *testing.T) {
	tok := capabilities.PartitionPauseV1
	if capabilities.Mandatory(tok) {
		t.Errorf("%s is mandatory; it states a policy and needs its kill switch", tok)
	}
	if capabilities.ReplicationGated(tok) {
		t.Errorf("%s is replication-gated; it emits no new statement shape", tok)
	}
	if !slices.Contains(capabilities.Supported(), tok) {
		t.Errorf("%s is not in Supported()", tok)
	}
	if !slices.Contains(capabilities.All(), tok) {
		t.Errorf("%s is not in All(); its durable latch would not be pre-loaded at startup", tok)
	}
}
