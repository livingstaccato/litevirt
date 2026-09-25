package grpcapi

import (
	"context"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// A daemon whose database will not answer is NOT ready, however healthy its
// listener looks. This is the whole defect: the peer probe completed a TLS
// handshake, which lives entirely in the TLS stack, and reported a wedged node
// healthy because nothing ever asked it to read anything.
func TestReady_UnreadyWhenTheLocalReadFails(t *testing.T) {
	s := testServer(t)
	insertReadyHost(t, s, "test-host")
	s.db.Close() // every query from here on returns an error

	resp, err := s.Ready(context.Background(), &pb.ReadyRequest{})
	if err != nil {
		t.Fatalf("Ready returned an error: %v — an unready node must ANSWER, not hang up", err)
	}
	if resp.GetReady() {
		t.Error("ready = true with a database that cannot be read")
	}
}

// The trivial read has to be a real one. A node whose own host row is not in its
// own copy of the cluster state cannot authorize, own or schedule anything, and
// reporting it ready is the same lie in a quieter form.
func TestReady_UnreadyWhenThisNodeIsNotInItsOwnHostsTable(t *testing.T) {
	s := testServer(t)

	resp, err := s.Ready(context.Background(), &pb.ReadyRequest{})
	if err != nil {
		t.Fatalf("Ready: %v", err)
	}
	if resp.GetReady() {
		t.Error("ready = true with no hosts row for this node")
	}
}

// A working node answers ready. Without this, "always report unready" passes
// both tests above.
func TestReady_ReadyWhenTheLocalReadSucceeds(t *testing.T) {
	s := testServer(t)
	insertReadyHost(t, s, "test-host")

	resp, err := s.Ready(context.Background(), &pb.ReadyRequest{})
	if err != nil {
		t.Fatalf("Ready: %v", err)
	}
	if !resp.GetReady() {
		t.Errorf("ready = false on a working node: %q", resp.GetNotReadyReason())
	}
	if got := resp.GetHostName(); got != "test-host" {
		t.Errorf("host_name = %q, want test-host", got)
	}
}

// not_ready_reason carries local error text, so it follows the same rule Ping's
// posture disclosure does: host certificates only. The distributable lv-cli
// certificate gets the verdict without the internals.
func TestReady_ReasonIsWithheldFromANonHostCaller(t *testing.T) {
	s := testServer(t)

	resp, err := s.Ready(context.Background(), &pb.ReadyRequest{})
	if err != nil {
		t.Fatalf("Ready: %v", err)
	}
	if resp.GetReady() {
		t.Fatal("precondition: expected an unready node")
	}
	if got := resp.GetNotReadyReason(); got != "" {
		t.Errorf("not_ready_reason = %q for a caller with no host certificate, want empty", got)
	}
}

func insertReadyHost(t *testing.T, s *Server, name string) {
	t.Helper()
	ctx := context.Background()
	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{
		Name: name, Address: "10.0.0.1", SSHUser: "root", State: "active",
	}); err != nil {
		t.Fatalf("insert host: %v", err)
	}
	if h, err := corrosion.GetHost(ctx, s.db, name); err != nil || h == nil {
		t.Fatalf("read back host %q: %v", name, err)
	}
}

// Ready answers "not ready" within its own budget even when the read cannot
// start. corrosion.Client.Query takes the client lock before anything honours
// the context, so on a node whose writer is stuck inside a commit — a stalled
// WAL checkpoint, a slow fsync — the read blocks past any timeout handed to
// it. Ready then hung for the caller's whole budget, the observer saw an RPC
// that never came back, and classified the peer UNREACHABLE: the silence path,
// the one fence quorum counts. The wedged-store case this RPC exists to report
// as "here, and cannot serve" became a fencing verdict.
func TestReady_AnswersWithinItsBudgetWhenTheReadBlocks(t *testing.T) {
	s := testServer(t)
	insertReadyHost(t, s, "test-host") // so a read that completed would say ready
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	s.readyRead = func(context.Context) ([]corrosion.Row, error) {
		<-release // ignores ctx, as a read waiting on the client lock does
		return nil, nil
	}

	start := time.Now()
	resp, err := s.Ready(context.Background(), &pb.ReadyRequest{})
	if elapsed := time.Since(start); elapsed > readyReadTimeout+time.Second {
		t.Fatalf("Ready took %v with the read blocked; it must answer within readyReadTimeout (%v)", elapsed, readyReadTimeout)
	}
	if err != nil {
		t.Fatalf("Ready returned an error (%v); a blocked read is a not-ready ANSWER", err)
	}
	if resp.GetReady() {
		t.Fatal("Ready reported ready while its read could not complete")
	}

	// A second probe while the first read is still stuck answers at once,
	// rather than stacking another blocked goroutine behind the lock.
	start = time.Now()
	if resp, _ := s.Ready(context.Background(), &pb.ReadyRequest{}); resp.GetReady() {
		t.Fatal("second Ready reported ready while the first read was still blocked")
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Errorf("second Ready took %v; with a read already outstanding it should answer immediately", elapsed)
	}
}

// Concurrent probes of a HEALTHY node are all answered ready.
//
// Every peer probes every node each interval, so overlapping Ready calls are
// the normal case. A single-flight that refused any probe arriving while
// another read was merely in progress answered "not ready" for a node whose
// store was fine — and an unready observation is recorded on the first one,
// so healthy nodes flapped out of quorum as the cluster grew. Only a read that
// has actually outlived its budget makes later probes answer at once.
func TestReady_ConcurrentProbesOfAHealthyNodeAreAllReady(t *testing.T) {
	s := testServer(t)
	insertReadyHost(t, s, "test-host")
	gate := make(chan struct{})
	s.readyRead = func(context.Context) ([]corrosion.Row, error) {
		<-gate // both reads are in flight at once, then both complete
		return []corrosion.Row{{Columns: []string{"name"}, Values: []interface{}{"test-host"}}}, nil
	}

	const probes = 2
	answers := make(chan bool, probes)
	for range probes {
		go func() {
			resp, _ := s.Ready(context.Background(), &pb.ReadyRequest{})
			answers <- resp.GetReady()
		}()
	}
	time.Sleep(100 * time.Millisecond) // let both reach the read
	close(gate)
	for range probes {
		if !<-answers {
			t.Fatal("a probe of a healthy node was answered not-ready because another probe's read was in flight")
		}
	}
}

// An unready edge degrades the cluster rollup, as a suspect one does.
//
// host_health gained "unready" beside healthy and suspect, but the rollup only
// counted failing and suspect as degraded, so a cluster whose every observer
// recorded a peer's store as wedged still reported HEALTHY in `lv health` —
// the operator-surface blind spot the readiness probe exists to remove.
func TestConnectivityDegrades_UnreadyIsDegraded(t *testing.T) {
	if !connectivityDegrades(health.StatusUnready) {
		t.Errorf("connectivityDegrades(%q) = false; a peer that cannot serve degrades the cluster", health.StatusUnready)
	}
	if connectivityDegrades("healthy") {
		t.Error(`connectivityDegrades("healthy") = true`)
	}
}
