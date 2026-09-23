package daemon

import (
	"context"
	"time"

	"github.com/litevirt/litevirt/internal/health"
)

// peerProber is the daemon's view of the gRPC server as a source of live facts
// about peers. Both probes are FRESH RPCs by design — never replicated rows,
// which freeze-but-look-current exactly when a peer is in trouble.
type peerProber interface {
	// PeerCapabilities answers "what does that BUILD support", for capability
	// activation.
	PeerCapabilities(ctx context.Context, host string) ([]string, time.Time, error)
	// PeerReady answers "can that DAEMON serve", for the health probe.
	PeerReady(ctx context.Context, host string) (bool, string, error)
}

// peerProbeSink is the health checker's injection surface. An interface so the
// wiring itself is testable: these two lines are the difference between a
// checker that asks peers real questions and one that fails open on both.
type peerProbeSink interface {
	SetPeerPinger(health.PeerPinger)
	SetPeerReadiness(health.PeerReadiness)
}

// wirePeerProbes injects both peer probes into the health checker.
//
// They are wired together because they are two halves of one question. The
// capability pinger asks what a peer's binary supports; the readiness prober
// asks whether that binary can currently do anything. A checker with only the
// first reports a daemon with a wedged database as perfectly healthy — it
// completes a TLS handshake, which is all the old probe ever measured.
func wirePeerProbes(sink peerProbeSink, svc peerProber) {
	sink.SetPeerPinger(svc.PeerCapabilities)
	sink.SetPeerReadiness(svc.PeerReady)
}
