package corrosion_test

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"testing"
	"weak"

	"github.com/litevirt/litevirt/internal/automation"
	"github.com/litevirt/litevirt/internal/corrosion"
)

type keyEngineTransport struct {
	fixture          corrosion.KeyEngineFixture
	mu               sync.Mutex
	current          []weak.Pointer[byte]
	forwarded        []corrosion.ClaimCertificate
	forwardedDigests []string
	lastAccepted     corrosion.Ballot
	freshRefusals    int
}

func (p *keyEngineTransport) watch(v corrosion.ClaimValue) {
	if v.Automation == nil || len(v.Automation.Envelope) < 1<<20 {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.current = append(p.current, weak.Make(&v.Automation.Envelope[0]))
}
func (p *keyEngineTransport) Prepare(ctx context.Context, host string, key corrosion.ClaimKey, ballot corrosion.Ballot, generation int64, _ *corrosion.SupersedeEvidence) (corrosion.PrepareResult, error) {
	result, err := p.fixture.Clients[host].ClaimPrepare(ctx, key, ballot, generation)
	if result.State.Value != nil {
		p.watch(*result.State.Value)
	}
	return result, err
}
func (p *keyEngineTransport) Accept(ctx context.Context, host string, key corrosion.ClaimKey, ballot corrosion.Ballot, value corrosion.ClaimValue, generation int64) (corrosion.AcceptResult, error) {
	p.watch(value)
	result, err := p.fixture.Clients[host].ClaimAccept(ctx, key, ballot, value, generation, p.fixture.Signers[host], nil)
	p.mu.Lock()
	defer p.mu.Unlock()
	if result.Accepted {
		p.lastAccepted = ballot
	}
	if host == "a" && result.Refusal == corrosion.RefusalAutomationUnavailable {
		p.freshRefusals++
	}
	return result, err
}
func (p *keyEngineTransport) Fetch(ctx context.Context, host string, sequence uint64) (corrosion.AutomationRecord, bool, error) {
	return p.fixture.Clients[host].AutomationRecord(ctx, sequence)
}
func (p *keyEngineTransport) Install(_ context.Context, _ string, record corrosion.AutomationRecord) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.forwarded = append(p.forwarded, record.Certificate)
	p.forwardedDigests = append(p.forwardedDigests, record.Value.MustDigest())
	// Delivery is deliberately unavailable. No successful remote installation or
	// provider is fabricated, and no same-process nested receiver owns this body.
	return errors.New("test transport: delivery unavailable")
}

// Mutation: retain Engine.recover's full renewed record across resumeRecovery.
// Observe the actual raw envelope returned by real Prepare, not merely the
// separately decoded ciphertext; a callee-local nil cannot satisfy this test.
func TestAutomationKeyTransitionEngineRecoveryWholeStack(t *testing.T) {
	fixture := corrosion.NewKeyEngineFixture(t)
	transport := &keyEngineTransport{fixture: fixture}
	engine := automation.NewEngine("a", fixture.Clients["a"], fixture.Verifier, transport)
	checks := 0
	ctx := corrosion.WithKeyEngineBodyObserver(context.Background(), func(sequence uint64, body []byte) {
		if sequence != 8 || body != nil {
			return
		}
		transport.mu.Lock()
		defer transport.mu.Unlock()
		if len(transport.current) == 0 {
			return
		}
		runtime.GC()
		checks++
		for _, allocation := range transport.current {
			if allocation.Value() != nil {
				t.Error("Engine.recover retains near-native raw CURRENT envelope while REFERENCED original 8 opens")
			}
		}
	})
	if err := engine.Recover(ctx); err != nil {
		t.Fatal("actual Engine.Recover", err)
	}
	if checks == 0 {
		t.Fatal("actual Engine referenced-original lifetime assertion did not run")
	}
	transport.mu.Lock()
	freshRefusals := transport.freshRefusals
	transport.mu.Unlock()
	if freshRefusals == 0 {
		t.Fatal("fresh local transition accept was not refused")
	}
	assertKeyEngineForwarding(t, transport)
	// The second recovery has the value already stored locally. A lagging peer
	// makes Engine renew its certificate; forwarding must attach that NEW real
	// quorum certificate rather than the certificate reloaded from local history.
	old, found, err := fixture.Clients["a"].AutomationRecord(context.Background(), 14)
	if err != nil || !found {
		t.Fatal(err)
	}
	oldCertificate := old.Certificate
	old = corrosion.AutomationRecord{}
	corrosion.TruncateKeyEnginePrefix(t, fixture.Clients["c"], 13)
	transport.mu.Lock()
	transport.forwarded = nil
	transport.forwardedDigests = nil
	transport.current = nil
	transport.mu.Unlock()
	if err = engine.Recover(context.Background()); err != nil {
		t.Fatal("already retained renewal", err)
	}
	assertKeyEngineForwarding(t, transport)
	transport.mu.Lock()
	renewed := transport.forwarded[0]
	transport.mu.Unlock()
	if renewed.Ballot.Equal(oldCertificate.Ballot) {
		t.Fatal("forwarded old historical certificate instead of renewed certificate")
	}
	stored, found, err := fixture.Clients["a"].AutomationRecord(context.Background(), 14)
	if err != nil || !found || !stored.Certificate.Ballot.Equal(oldCertificate.Ballot) {
		t.Fatal("renewal changed original historical certificate", err)
	}
}
func assertKeyEngineForwarding(t *testing.T, transport *keyEngineTransport) {
	t.Helper()
	transport.mu.Lock()
	defer transport.mu.Unlock()
	if len(transport.forwarded) != 2 {
		t.Fatal("renewed record not forwarded to both peers", len(transport.forwarded))
	}
	cfg, err := transport.fixture.Clients["a"].AutomationMembership(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	stored, found, err := transport.fixture.Clients["a"].AutomationRecord(context.Background(), 14)
	if err != nil || !found {
		t.Fatal(err)
	}
	key, _ := corrosion.AutomationClaimKey(14)
	for i, cert := range transport.forwarded {
		if transport.forwardedDigests[i] != stored.Value.MustDigest() {
			t.Fatal("forwarded value differs from exact durable value")
		}
		if !cert.Ballot.Equal(transport.lastAccepted) {
			t.Fatal("forwarded certificate is not intended renewed ballot")
		}
		if err := transport.fixture.Verifier.Verify(cert, corrosion.CertExpectation{Key: key, ValueDigest: stored.Value.MustDigest(), ConfigGeneration: cfg.Generation, Electorate: cfg.Members, Quorum: corrosion.MajorityOf(len(cfg.Members))}); err != nil {
			t.Fatal("forwarded certificate does not verify", err)
		}
	}
}
