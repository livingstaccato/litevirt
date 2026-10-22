package corrosion

import "github.com/litevirt/litevirt/internal/capabilities"

// latchGatedShapes lists, per release token, every replicated statement this
// build writes only once that token has DURABLY latched: a shape a host on an
// earlier build does not know, whose unknown fingerprint would back-pressure
// the sender's whole replication stream to that host. The latch is
// replication-gated, so it proves every recipient advertises the token — and
// that proves the shape known only if EVERY build advertising the token has
// it. So a token's list is frozen once its release ships, exactly as its
// feature set is (capabilities releaseFeatures): latch_gated_shapes_test.go
// pins each list by fingerprint, and a shape added under a shipped token fails
// CI. A later shape is gated on the NEXT release token's latch.
var latchGatedShapes = map[string][]string{
	capabilities.Release202611V1: {
		replicationRepointSQL,     // RepointReplicationTarget (backup and container replication switch)
		containerPlacementMintSQL, // MintContainerPlacement
		imageHostReviveSQL,        // ReviveImageHost
		deleteNetworkVTEPsSQL,     // DeleteNetworkAndVTEPs
		readmitHostV2SQL,          // AdmitHostV2 (host_incarnation)
		hostOwnEndpointSQL,        // WriteOwnEndpoint (host_incarnation)
		deleteHostAdmissionSQL,    // DeleteHostAdmissionIf (RemoveHost, ReleaseTokenLatched)
	},
	capabilities.Release202612V1: {
		HostFenceSSHUpsertSQL, // PutHostFenceSSH (fence_ssh)
	},
}

// LatchGatedShapes returns token's latch-gated statements (latchGatedShapes).
func LatchGatedShapes(token string) []string {
	return append([]string(nil), latchGatedShapes[token]...)
}
