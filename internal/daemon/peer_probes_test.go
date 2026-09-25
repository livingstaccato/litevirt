package daemon

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/health"
)

type probeSinkRecorder struct {
	pinger health.PeerPinger
	ready  health.PeerReadiness
}

func (r *probeSinkRecorder) SetPeerPinger(fn health.PeerPinger)       { r.pinger = fn }
func (r *probeSinkRecorder) SetPeerReadiness(fn health.PeerReadiness) { r.ready = fn }

type fakeProber struct{}

func (fakeProber) PeerCapabilities(_ context.Context, host string) ([]string, time.Time, error) {
	return []string{"cap_for_" + host}, time.Time{}, nil
}

func (fakeProber) PeerReady(_ context.Context, host string) (bool, string, error) {
	if host == "wedged" {
		return false, "database read timed out", nil
	}
	return true, "", nil
}

// The health checker gets the readiness prober, not just the capability pinger.
// Without it the checker falls back to its TLS-only probe and a daemon with a
// wedged database is reported healthy — the whole defect, restored by one
// missing line of wiring.
func TestWirePeerProbes_InjectsReadiness(t *testing.T) {
	var sink probeSinkRecorder

	wirePeerProbes(&sink, fakeProber{})

	if sink.ready == nil {
		t.Fatal("no readiness prober was injected")
	}
	ready, reason, err := sink.ready(context.Background(), "wedged")
	if err != nil {
		t.Fatalf("readiness prober: %v", err)
	}
	if ready {
		t.Error("the injected prober is not the server's PeerReady — it called a wedged peer ready")
	}
	if reason != "database read timed out" {
		t.Errorf("reason = %q, want the peer's own reason", reason)
	}
}

// The capability pinger is still wired. Without this, replacing the pinger
// injection with the readiness one would pass the test above.
func TestWirePeerProbes_StillInjectsTheCapabilityPinger(t *testing.T) {
	var sink probeSinkRecorder

	wirePeerProbes(&sink, fakeProber{})

	if sink.pinger == nil {
		t.Fatal("no capability pinger was injected")
	}
	caps, _, err := sink.pinger(context.Background(), "host-b")
	if err != nil {
		t.Fatalf("capability pinger: %v", err)
	}
	if len(caps) != 1 || caps[0] != "cap_for_host-b" {
		t.Errorf("capabilities = %v, want the server's PeerCapabilities answer", caps)
	}
}

// The real health.Checker must satisfy the sink interface, or the daemon cannot
// pass it and the wiring above is a fiction that only the recorder satisfies.
var _ peerProbeSink = (*health.Checker)(nil)
