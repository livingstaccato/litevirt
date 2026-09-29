package grpcapi

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pki"
)

// voterTestServer is testServer with a real host identity, so the claim
// signer loads.
func voterTestServer(t *testing.T) *Server {
	t.Helper()
	s := testServer(t)
	dir := t.TempDir()
	caCert, caKey := filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key")
	if err := pki.GenerateCA(caCert, caKey); err != nil {
		t.Fatal(err)
	}
	if err := pki.GenerateHostCert(caCert, caKey, filepath.Join(dir, "host.crt"), filepath.Join(dir, "host.key"),
		s.hostName, net.ParseIP("127.0.0.1")); err != nil {
		t.Fatal(err)
	}
	s.pkiDir = dir
	return s
}

// TestAdvertise_VoterConfigWithheldUntilReady: voter_config_v1 is mandatory
// but advertised only by a node that can vote durably — synchronous=FULL and a
// loadable signing key — so the fleet never latches across a voter whose
// promises would not survive a crash.
//
// Mutation: drop the readiness filter in advertisedCapabilities — the
// keyless and the NORMAL-synchronous nodes both advertise.
func TestAdvertise_VoterConfigWithheldUntilReady(t *testing.T) {
	keyless := testServer(t) // pkiDir has no host key
	if slices.Contains(keyless.advertisedCapabilities(), capabilities.VoterConfigV1) {
		t.Error("a node that cannot load its signing key advertises voter_config_v1")
	}

	ready := voterTestServer(t)
	if !slices.Contains(ready.advertisedCapabilities(), capabilities.VoterConfigV1) {
		ok, reason := ready.VoterConfigReadiness(context.Background())
		t.Fatalf("a ready node does not advertise voter_config_v1 (ready=%v: %s)", ok, reason)
	}

	orig := synchronousLevel
	t.Cleanup(func() { synchronousLevel = orig })
	synchronousLevel = func(context.Context, *corrosion.Client) (int, error) { return 1, nil }
	normal := voterTestServer(t)
	if slices.Contains(normal.advertisedCapabilities(), capabilities.VoterConfigV1) {
		t.Error("a node at synchronous=NORMAL advertises voter_config_v1")
	}
	if _, err := normal.localPrepare(context.Background(), corrosion.ClaimKey{TargetKind: corrosion.ClaimKindVoterConfig},
		corrosion.Ballot{Round: 1, Coordinator: normal.hostName}, 0, nil); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("a voter below FULL answered Prepare: %v", err)
	}
}

// TestProbeOwner_Verdicts: a CN that is not the source is not reached, a
// fresh result is reused and a stale one is not (§3.5.1).
//
// Mutations: accept any CN — the impostor reads as reached; drop the max-age
// comparison — the stale result is reused and the dial count stays at one.
func TestProbeOwner_Verdicts(t *testing.T) {
	s := testServer(t)
	now := time.Unix(1000, 0)
	var dials atomic.Int32
	answer := "victim"
	s.claims.probe.now = func() time.Time { return now }
	s.claims.probe.dial = func(_ context.Context, host string) (string, error) {
		dials.Add(1)
		if answer == "" {
			return "", errors.New("connection refused")
		}
		return answer, nil
	}
	ctx := context.Background()

	answer = "impostor"
	if reached, detail := s.probeOwner(ctx, "victim"); reached || !strings.Contains(detail, "impostor") {
		t.Fatalf("a different host answering at the source's address read as reached: %v %q", reached, detail)
	}
	now = now.Add(claimProbeMaxAge + time.Second)
	answer = "victim"
	if reached, _ := s.probeOwner(ctx, "victim"); !reached {
		t.Fatal("the source answering as itself did not read as reached")
	}
	before := dials.Load()
	now = now.Add(claimProbeMaxAge / 2)
	answer = ""
	if reached, _ := s.probeOwner(ctx, "victim"); !reached || dials.Load() != before {
		t.Fatal("a fresh result was not reused")
	}
	now = now.Add(claimProbeMaxAge)
	if reached, _ := s.probeOwner(ctx, "victim"); reached || dials.Load() != before+1 {
		t.Fatalf("a result older than claimProbeMaxAge was reused (dials %d -> %d)", before, dials.Load())
	}
}

// TestProbeOwner_InterruptedProbeIsReachedAndNotCached: a probe whose
// caller's context ends mid-dial fails the dial, but that failure says nothing
// about the source. It reads as reached, like a waiter interrupted on the
// same probe (§10 item 9), and it is not cached: the next Accept naming the
// source within claimProbeMaxAge probes again rather than certifying the
// eviction on a cancelled dial.
//
// Mutation: cache the interrupted result — the next probe reuses "not
// reached" and the dial count stays at one.
func TestProbeOwner_InterruptedProbeIsReachedAndNotCached(t *testing.T) {
	s := testServer(t)
	now := time.Unix(1000, 0)
	s.claims.probe.now = func() time.Time { return now }
	var dials atomic.Int32
	s.claims.probe.dial = func(ctx context.Context, host string) (string, error) {
		dials.Add(1)
		<-ctx.Done()
		return "", ctx.Err()
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(20 * time.Millisecond); cancel() }()
	if reached, detail := s.probeOwner(ctx, "victim"); !reached || !strings.Contains(detail, "interrupted") {
		t.Fatalf("an interrupted probe read as %v %q, want reached and interrupted", reached, detail)
	}
	s.claims.probe.dial = func(context.Context, string) (string, error) {
		dials.Add(1)
		return "", errors.New("connection refused")
	}
	if reached, _ := s.probeOwner(context.Background(), "victim"); reached || dials.Load() != 2 {
		t.Fatalf("the interrupted result was cached: reached=%v dials=%d, want a fresh probe", reached, dials.Load())
	}
}

// TestRemoveHost_RefusesACurrentVoter: deleting a hosts row must no longer
// change the voting population implicitly (§4.3). The refusal names the one
// command that does.
//
// Mutation: drop the voterRemovalRefusal call in RemoveHost — the voter's row
// is deleted.
func TestRemoveHost_RefusesACurrentVoter(t *testing.T) {
	ctx := context.Background()
	s := testServer(t)
	s.db.SetVoterConfigGate(func() bool { return true })
	for _, h := range []string{"a", "b"} {
		if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{Name: h, Address: "10.0.0.1", State: "active"}); err != nil {
			t.Fatal(err)
		}
	}
	val := corrosion.VoterConfigValue{Generation: 1, Members: []corrosion.VoterMember{{Name: "a", Incarnation: "x"}},
		Change: corrosion.VoterChangeGenesis, CreatedBy: "t", CreatedAt: "t"}
	if err := corrosion.WriteVoterConfig(ctx, s.db, val, corrosion.ClaimCertificate{}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.RecordVoterAdoption(ctx, s.db, 1); err != nil {
		t.Fatal(err)
	}
	_, err := s.RemoveHost(adminCtx(), &pb.RemoveHostRequest{Name: "a"})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "lv cluster voter rm a") {
		t.Fatalf("removing a current voter was not refused with the way forward: %v", err)
	}
	if h, _ := corrosion.GetHost(ctx, s.db, "a"); h == nil {
		t.Fatal("the voter's host row was deleted")
	}
	if _, err := s.RemoveHost(adminCtx(), &pb.RemoveHostRequest{Name: "b"}); err != nil {
		t.Fatalf("a non-voter was refused: %v", err)
	}
}

// TestChangeVoterConfig_RefusedBeforeTheLatch: no voter generation can be
// written before voter_config_v1 has durably latched (§4.2).
func TestChangeVoterConfig_RefusedBeforeTheLatch(t *testing.T) {
	s := voterTestServer(t)
	_, err := s.ChangeVoterConfig(adminCtx(), &pb.ChangeVoterConfigRequest{Op: "init"})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "voter_config_v1") {
		t.Fatalf("a voter change before the latch: %v", err)
	}
}
