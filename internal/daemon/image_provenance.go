package daemon

import "context"

// legacyProvenanceRecorder is the part of the gRPC server the startup
// provenance pass needs.
type legacyProvenanceRecorder interface {
	RecordLegacyImageProvenance(ctx context.Context)
}

// startLegacyImageProvenance runs the first start's provenance pass in the
// background. It hashes every image file an earlier build left in full, which
// can take minutes, and the gRPC port must listen long before that: a peer
// probing a port that does not listen counts the host unreachable, then
// suspect, then fence-eligible. Nothing waits on the pass: every reader of a
// file's provenance (pull, import, build, the compose pull, a restore)
// records it itself first, and a record written twice is the same record.
func startLegacyImageProvenance(ctx context.Context, r legacyProvenanceRecorder) {
	go r.RecordLegacyImageProvenance(ctx)
}
