package automation

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/automation/contract"
	"github.com/litevirt/litevirt/internal/claims"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// These are round-selection tests, not native custody/certificate authority.
// The actual existing proposer selects and binds bytes; the transport records
// class dispatch. The grpcapi tests separately require real native TLS votes.
type freshSelectionTransport struct {
	mu                     sync.Mutex
	accepted               *corrosion.ClaimValue
	acceptedFromRound      uint64
	refuseAccept           bool
	prepareBallot          corrosion.Ballot
	owner, continuity, key int
}

func (t *freshSelectionTransport) Prepare(ctx context.Context, voter string, key corrosion.ClaimKey, b corrosion.Ballot, g int64, _ *corrosion.SupersedeEvidence) (corrosion.PrepareResult, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.prepareBallot = b
	state := corrosion.ClaimVoterState{Key: key, Promised: b, ConfigGeneration: g}
	if t.accepted != nil && b.Round >= t.acceptedFromRound {
		state.Value = t.accepted
		state.ValueDigest = t.accepted.MustDigest()
		state.Accepted = corrosion.Ballot{Round: 1, Coordinator: "0", Nonce: []byte{9}}
	}
	return corrosion.PrepareResult{Promised: true, PromisedBallot: b, State: state, Voter: voter, Incarnation: voter + "-inc"}, nil
}
func (t *freshSelectionTransport) Accept(ctx context.Context, voter string, key corrosion.ClaimKey, b corrosion.Ballot, v corrosion.ClaimValue, g int64) (corrosion.AcceptResult, error) {
	if t.refuseAccept {
		return corrosion.AcceptResult{Voter: voter, Refusal: corrosion.RefusalAutomationUnavailable}, nil
	}
	return corrosion.AcceptResult{Accepted: true, Voter: voter, Accept: &corrosion.ClaimAccept{Key: key, Ballot: b, Voter: voter, VoterIncarnation: voter + "-inc", ConfigGeneration: g, ValueDigest: v.MustDigest()}}, nil
}
func (t *freshSelectionTransport) Fetch(context.Context, string, uint64) (corrosion.AutomationRecord, bool, error) {
	return corrosion.AutomationRecord{}, false, nil
}
func (t *freshSelectionTransport) Install(context.Context, string, corrosion.AutomationRecord) error {
	return nil
}
func (t *freshSelectionTransport) PrepareOwnerPhase2(_ context.Context, _ corrosion.ClaimKey, _ corrosion.Ballot, _ corrosion.ClaimValue, _ *corrosion.VoterConfig, native *corrosion.AutomationOwnerSubmission) (corrosion.Ballot, error) {
	if native != nil {
		panic("native owner invented")
	}
	t.owner++
	return corrosion.Ballot{}, nil
}
func (t *freshSelectionTransport) PrepareContinuityPhase2(_ context.Context, _ corrosion.ClaimKey, _ corrosion.Ballot, _ corrosion.ClaimValue, _ *corrosion.VoterConfig, native *corrosion.AutomationIdentityContinuity) (corrosion.Ballot, error) {
	if native != nil {
		panic("native continuity invented")
	}
	t.continuity++
	return corrosion.Ballot{}, nil
}
func (t *freshSelectionTransport) PrepareKeyPhase2(_ context.Context, _ corrosion.ClaimKey, _ corrosion.Ballot, _ corrosion.ClaimValue, _ *corrosion.VoterConfig, native *corrosion.AutomationKeyAdmission) (corrosion.Ballot, error) {
	if native != nil {
		panic("native key invented")
	}
	t.key++
	return corrosion.Ballot{}, nil
}
func freshSelectionValue(t *testing.T, kind, request string) corrosion.ClaimValue {
	t.Helper()
	assignment, _ := json.Marshal(contract.Assignment{Version: 1, ClusterUID: "cluster", OperationID: "operation", RecordedAt: "2026-10-24T00:00:00Z"})
	raw, err := contract.EncodeDecision(contract.Decision{Sequence: 2, ParentDigest: strings.Repeat("a", 64), Command: contract.Command{Kind: kind, ClusterUID: "cluster", PrincipalID: "principal", RequestID: request, Body: []byte(`{"version":1}`)}, Assignment: assignment})
	if err != nil {
		t.Fatal(err)
	}
	return corrosion.ClaimValue{Automation: &corrosion.AutomationClaimValue{Envelope: raw}}
}
func freshSelectionConfig() *corrosion.VoterConfig {
	members := []corrosion.VoterMember{{Name: "a", Incarnation: "a-inc"}, {Name: "b", Incarnation: "b-inc"}, {Name: "c", Incarnation: "c-inc"}}
	return &corrosion.VoterConfig{VoterConfigValue: corrosion.VoterConfigValue{Generation: 1, Members: members}, MembersHash: corrosion.MembersHash(members)}
}
func TestAutomationFreshProposalUsesActualRoundOnce(t *testing.T) {
	transport := &freshSelectionTransport{}
	engine := NewEngine("a", nil, nil, transport)
	cfg := freshSelectionConfig()
	value := freshSelectionValue(t, "read_barrier", "fresh")
	builds, native, released := 0, 0, 0
	outcome, err := engine.decideFreshAutomationUsing(context.Background(), cfg, 2, claims.NewProposer("a", transport), func(context.Context) (*automationFreshValue, error) {
		builds++
		return &automationFreshValue{value: value, accept: func(_ context.Context, key corrosion.ClaimKey, b corrosion.Ballot, selected corrosion.ClaimValue, actual *corrosion.VoterConfig) (corrosion.Ballot, error) {
			native++
			transport.mu.Lock()
			promise := transport.prepareBallot
			transport.mu.Unlock()
			if !b.Equal(promise) || key.OwnerEpoch != 2 || actual.Generation != 1 || selected.MustDigest() != value.MustDigest() {
				t.Error("native callback lost actual round/value/config")
			}
			return corrosion.Ballot{}, nil
		}, release: func() { released++ }}, nil
	})
	if err != nil || outcome.Digest != value.MustDigest() || builds != 1 || native != 1 || released != 1 {
		t.Fatalf("fresh selection unavailable: builds=%d native=%d release=%d err=%v", builds, native, released, err)
	}
}
func TestAutomationFreshProposalDoesNotIssueForAcceptedValue(t *testing.T) {
	for _, kind := range []string{"read_barrier", "ensure_owner", contract.IdentityContinuityCommand, "activate_key_epoch"} {
		t.Run(kind, func(t *testing.T) {
			value := freshSelectionValue(t, kind, "accepted")
			transport := &freshSelectionTransport{accepted: &value}
			engine := NewEngine("a", nil, nil, transport)
			builds := 0
			out, err := engine.decideFreshAutomationUsing(context.Background(), freshSelectionConfig(), 2, claims.NewProposer("a", transport), func(context.Context) (*automationFreshValue, error) {
				builds++
				return &automationFreshValue{value: value}, nil
			})
			if err != nil || out.Digest != value.MustDigest() || builds != 0 {
				t.Fatalf("accepted selection used fresh issuer: builds=%d err=%v", builds, err)
			}
			if kind == "ensure_owner" && transport.owner != 1 || kind == contract.IdentityContinuityCommand && transport.continuity != 1 || kind == "activate_key_epoch" && transport.key != 1 {
				t.Fatal("selected class lost nil-native recovery dispatch")
			}
		})
	}
}

func TestAutomationFreshProposalBindingSkip(t *testing.T) {
	for _, mode := range []string{"same-digest-accepted", "other-owner-accepted", "fresh-again"} {
		t.Run(mode, func(t *testing.T) {
			transport := &freshSelectionTransport{}
			engine := NewEngine("a", nil, nil, transport)
			cfg := freshSelectionConfig()
			ctx := context.Background()
			key, _ := corrosion.AutomationClaimKey(2)
			p := claims.NewProposer("a", transport)
			p.Backoff = func(int) time.Duration { return 0 }
			seed := freshSelectionValue(t, "read_barrier", "bound-only")
			// Use the real proposer to bind round1 without sending a single acceptance.
			stopped := errors.New("stop after real ballot binding")
			if _, err := p.Decide(ctx, claims.Spec{Key: key, Generation: 1, Voters: cfg.Names(), PrepareQuorum: 2, StartRound: 1, Propose: func(map[string]corrosion.PrepareResult) (corrosion.ClaimValue, error) { return seed, nil }, BeforeAccept: func(context.Context, corrosion.Ballot, corrosion.ClaimValue) (corrosion.Ballot, error) {
				return corrosion.Ballot{}, stopped
			}}); !errors.Is(err, stopped) {
				t.Fatal("seed did not stop at binding", err)
			}
			fresh := freshSelectionValue(t, "read_barrier", "fresh")
			selected := fresh
			if mode == "other-owner-accepted" {
				selected = freshSelectionValue(t, "ensure_owner", "other")
			}
			if mode != "fresh-again" {
				transport.accepted = &selected
				transport.acceptedFromRound = 2
			}
			builds, native, releases, beforeCalls := 0, 0, 0, 0
			cell, err := engine.newAutomationFreshCell(ctx, cfg, 2, func(context.Context) (*automationFreshValue, error) {
				builds++
				return &automationFreshValue{value: fresh, accept: func(context.Context, corrosion.ClaimKey, corrosion.Ballot, corrosion.ClaimValue, *corrosion.VoterConfig) (corrosion.Ballot, error) {
					native++
					return corrosion.Ballot{}, nil
				}, release: func() { releases++ }}, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			defer cell.retire()
			outcome, err := p.Decide(ctx, claims.Spec{Key: key, Generation: 1, Voters: cfg.Names(), PrepareQuorum: 2, StartRound: 1, ReuseRound: true, MaxRounds: 3, Propose: cell.propose, BeforeAccept: func(ctx context.Context, b corrosion.Ballot, v corrosion.ClaimValue) (corrosion.Ballot, error) {
				beforeCalls++
				if b.Round < 2 {
					t.Error("proposer failed to skip already-bound round")
				}
				return cell.beforeAccept(ctx, b, v)
			}})
			wantNative := 0
			if mode == "fresh-again" {
				wantNative = 1
			}
			if err != nil || outcome.Digest != selected.MustDigest() || builds != 1 || native != wantNative || releases != 1 || beforeCalls != 1 {
				t.Fatalf("binding skip leaked fresh eligibility: builds=%d native=%d release=%d before=%d err=%v", builds, native, releases, beforeCalls, err)
			}
			if mode == "other-owner-accepted" && transport.owner != 1 {
				t.Fatal("other selected class lost recovery dispatch")
			}
		})
	}
}
func TestAutomationFreshProposalConsumesBeforeStaleAndLostOutcomes(t *testing.T) {
	for _, mode := range []string{"stale", "lost-first-reply", "no-majority", "canceled-after-build"} {
		t.Run(mode, func(t *testing.T) {
			transport := &freshSelectionTransport{refuseAccept: mode == "no-majority"}
			engine := NewEngine("a", nil, nil, transport)
			cfg := freshSelectionConfig()
			value := freshSelectionValue(t, "activate_key_epoch", "fresh")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			p := claims.NewProposer("a", transport)
			p.Backoff = func(int) time.Duration { return 0 }
			builds, native, releases := 0, 0, 0
			outcome, err := engine.decideFreshAutomationUsing(ctx, cfg, 2, p, func(context.Context) (*automationFreshValue, error) {
				builds++
				if mode == "canceled-after-build" {
					cancel()
				}
				return &automationFreshValue{value: value, release: func() { releases++ }, accept: func(_ context.Context, _ corrosion.ClaimKey, b corrosion.Ballot, _ corrosion.ClaimValue, _ *corrosion.VoterConfig) (corrosion.Ballot, error) {
					native++
					if mode == "stale" {
						return corrosion.Ballot{Round: 5, Coordinator: "z", Nonce: []byte{1}}, errors.New("stale first attempt")
					}
					if mode == "lost-first-reply" {
						transport.mu.Lock()
						transport.accepted = &value
						transport.mu.Unlock()
						return corrosion.Ballot{}, errors.New("first reply lost")
					}
					return corrosion.Ballot{}, nil
				}}, nil
			})
			wantNative := 1
			if mode == "canceled-after-build" {
				wantNative = 0
			}
			if builds != 1 || native != wantNative || releases != 1 {
				t.Fatalf("outcome reissued or leaked native handle: %d %d %d", builds, native, releases)
			}
			if mode == "stale" {
				if err != nil || outcome.Digest != value.MustDigest() || transport.key != 1 {
					t.Fatalf("stale retry did not use stored dispatch: %v", err)
				}
			} else if err == nil {
				t.Fatal("failed/canceled outcome unexpectedly succeeded")
			}
			if mode == "lost-first-reply" {
				again, err := engine.decideFreshAutomationUsing(context.Background(), cfg, 2, p, func(context.Context) (*automationFreshValue, error) {
					t.Error("accepted lost-reply bytes recollected authority")
					return nil, errors.New("unexpected builder")
				})
				if err != nil || again.Digest != value.MustDigest() || transport.key != 1 {
					t.Fatalf("accepted first vote did not recover without issuer: %v", err)
				}
			}
		})
	}
}

func TestAutomationFreshProposalCallbackCannotMutateSelectedBytes(t *testing.T) {
	transport := &freshSelectionTransport{}
	engine := NewEngine("a", nil, nil, transport)
	value := freshSelectionValue(t, "read_barrier", "fresh")
	wanted := value.MustDigest()
	out, err := engine.decideFreshAutomationUsing(context.Background(), freshSelectionConfig(), 2, nil, func(context.Context) (*automationFreshValue, error) {
		return &automationFreshValue{value: value, release: func() {}, accept: func(_ context.Context, _ corrosion.ClaimKey, _ corrosion.Ballot, v corrosion.ClaimValue, cfg *corrosion.VoterConfig) (corrosion.Ballot, error) {
			v.Automation.Envelope[0] = '!'
			cfg.Members[0].Name = "mutated"
			return corrosion.Ballot{}, nil
		}}, nil
	})
	if err != nil || out.Digest != wanted || out.Value.MustDigest() != wanted {
		t.Fatal("native callback changed bound selected bytes", err)
	}
}
