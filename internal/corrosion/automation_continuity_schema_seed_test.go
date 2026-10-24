package corrosion

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/automation/contract"
	"github.com/litevirt/litevirt/internal/capabilities"
	"golang.org/x/crypto/bcrypt"
)

// Established, historically certified unit prerequisites only. No founding,
// first-use/native enrollment, disk durability, daemon or network qualification.
type privateSeedNativeFixture struct {
	primary             *privateSeedClient
	a, b, c             *claimTestVoter
	verifier            *ClaimVerifier
	owner               PrivateSchemaSeedOwner
	bcNS                int64
	blockPeer, blockAck atomic.Bool
	applied             atomic.Int64
}

func privateSeedFresh() (p *privateSeedClient, err error) {
	start := time.Now()
	c, err := NewTestClient()
	if err != nil {
		return nil, err
	}
	p = &privateSeedClient{c: c, timing: privateSeedTimings{ConstructorNS: time.Since(start).Nanoseconds()}}
	privateSeedActive.Add(1)
	defer func() {
		if err != nil {
			err = errors.Join(err, p.close())
			p = nil
		}
	}()
	p.owner, err = privateSeedCapture(c)
	if err != nil {
		return p, err
	}
	start = time.Now()
	err = InitSchema(context.Background(), c)
	p.timing.InitNS = time.Since(start).Nanoseconds()
	if err != nil {
		return p, err
	}
	start = time.Now()
	if err = privateSeedValidate(c, true, true, ""); err != nil {
		return p, err
	}
	if err = privateSeedCheckOwner(c, p.owner); err != nil {
		return p, err
	}
	p.timing.ValidationNS = time.Since(start).Nanoseconds()
	return p, nil
}
func privateSeedNativeOwners(t *testing.T, mode string) (*privateSeedNativeFixture, privateSeedRecord) {
	t.Helper()
	ctx := context.Background()
	var primary *privateSeedClient
	var record privateSeedRecord
	var err error
	switch mode {
	case "fresh":
		primary, err = privateSeedFresh()
	case "seeded":
		primary, record, err = privateSeedNew()
	default:
		t.Fatal("unknown explicit primary factory")
	}
	privateSeedCheck(t, err)
	t.Cleanup(func() { privateSeedCheck(t, primary.close()) })
	// All keys, names, memberships, origins, and owners are produced AFTER the
	// actual empty primary initialization; none was part of the image.
	ca := newClaimTestCA(t)
	start := time.Now()
	b, c := newClaimTestVoter(t, ca, "b"), newClaimTestVoter(t, ca, "c")
	bcNS := time.Since(start).Nanoseconds()
	dir := ca.pkiDir(t, "test-node")
	signer, err := LoadClaimSigner(dir, "test-node")
	privateSeedCheck(t, err)
	inc, err := primary.c.VoterIncarnation(ctx)
	privateSeedCheck(t, err)
	a := &claimTestVoter{name: "test-node", c: primary.c, signer: signer, pki: dir, inc: inc}
	privateSeedMust(t, a.inc != b.inc && a.inc != c.inc && b.inc != c.inc, "real voter incarnations reused")
	a.c.SetVoterConfigGate(func() bool { return true })
	adoptHandBuilt(t, 1, membersOf(a, b, c), a, b, c)
	for i, v := range []*claimTestVoter{a, b, c} {
		v.c.SetClusterPolicyGate(func() bool { return true })
		privateSeedCheck(t, InsertHost(ctx, a.c, HostRecord{Name: v.name, Address: fmt.Sprintf("127.0.0.%d", i+2), State: "active", Role: "worker"}))
	}
	a.c.SetUserIncarnationGate(func() bool { return true })
	verifier, err := LoadClaimVerifier(ca.pkiDir(t, "private-seed-verifier"))
	privateSeedCheck(t, err)
	f := &privateSeedNativeFixture{primary: primary, a: a, b: b, c: c, verifier: verifier, bcNS: bcNS}
	clients := map[string]*Client{a.name: a.c, b.name: b.c, c.name: c.c}
	ping := func(ctx context.Context, host string) ([]string, time.Time, error) {
		peer := clients[host]
		if peer == nil || peer.HostName() != host || (host == "b" && f.blockPeer.Load()) {
			return nil, time.Time{}, fmt.Errorf("actual fixture peer unavailable: %s", host)
		}
		if _, err := peer.Query(ctx, `SELECT 1 AS alive`); err != nil {
			return nil, time.Time{}, err
		}
		return capabilities.Supported(), time.Now(), nil
	}
	type recipient struct {
		mu    sync.Mutex
		after int64
		r     *Replicator
	}
	recipients := map[string]*recipient{"b": {r: NewReplicator(b.c, "", RelayConfig{})}, "c": {r: NewReplicator(c.c, "", RelayConfig{})}}
	sender := NewReplicator(a.c, "", RelayConfig{})
	confirm := func(ctx context.Context, host, token, feature string) (bool, error) {
		target, ok := recipients[host]
		if !ok {
			return false, fmt.Errorf("unknown actual ACK recipient %s", host)
		}
		target.mu.Lock()
		defer target.mu.Unlock()
		if !(host == "b" && f.blockAck.Load()) {
			for batch := 0; batch < 16; batch++ {
				entries, maxSeq, err := sender.readMutationLog(ctx, target.after, 256, host)
				if err != nil {
					return false, err
				}
				if len(entries) == 0 {
					if maxSeq > target.after {
						target.after = maxSeq
					}
					break
				}
				wire := make([]*pb.MutationEntry, len(entries))
				for i, e := range entries {
					wire[i] = &pb.MutationEntry{Seq: e.Seq, Hlc: e.HLC, Origin: e.Origin, Stmts: e.Stmts}
				}
				if _, err = target.r.ApplyRemoteMutations(ctx, wire); err != nil {
					return false, err
				}
				target.after = maxSeq
				f.applied.Add(int64(len(entries)))
				if len(entries) < 256 {
					break
				}
				if batch == 15 {
					return false, fmt.Errorf("bounded actual ACK replication exhausted")
				}
			}
		}
		// Presence is the ACK prerequisite. The owner cannot mark ACKED until this
		// returns; requiring acked here would create an artificial dependency cycle.
		present, _, err := ReleaseFeatureState(ctx, clients[host], token, feature)
		return present, err
	}
	privateSeedMust(t, privateSchemaSeedOwnerFactory != nil, "real health owner missing")
	f.owner = privateSchemaSeedOwnerFactory(t, a.c, a.pki, verifier, ping, confirm)
	voters, err := VoterSet(ctx, a.c)
	privateSeedCheck(t, err)
	privateSeedMust(t, len(voters) == 3 && voters["test-node"] && voters["b"] && voters["c"], "actual release electorate differs")
	return f, record
}
func privateSeedOwnRelease(t *testing.T, f *privateSeedNativeFixture, feature capabilities.Feature) {
	t.Helper()
	info, ok := capabilities.LookupFeature(feature)
	privateSeedMust(t, ok, "feature catalog absent")
	marker, err := os.ReadFile(f.owner.MarkerPath(info.Token))
	privateSeedCheck(t, err)
	privateSeedMust(t, bytes.Equal(marker, capabilities.MarkerContent(info.Token)) && f.owner.Latched(info.Token) && f.owner.CallbackCount(feature) > 0, "real marker/callback not observed")
	uses, err := ListReleaseFeatureUses(context.Background(), f.a.c)
	privateSeedCheck(t, err)
	found := false
	for _, use := range uses {
		if use.Token == info.Token && use.Feature == string(feature) {
			found = true
			privateSeedMust(t, use.Acked && !use.Tombstoned && use.RecordedBy == "test-node", "real own release use not acknowledged")
		}
	}
	privateSeedMust(t, found && f.applied.Load() > 0, "real use/replicated mutations absent")
	for _, v := range []*claimTestVoter{f.b, f.c} {
		present, _, err := ReleaseFeatureState(context.Background(), v.c, info.Token, string(feature))
		privateSeedCheck(t, err)
		privateSeedMust(t, present, "actual recipient has no use row")
	}
}
func privateSeedResign(t *testing.T, r AutomationRecord, voters ...*claimTestVoter) AutomationRecord {
	t.Helper()
	r.Certificate.Ballot = testBallot(2, "test-node")
	r.Certificate.Accepts = nil
	for _, v := range voters {
		vote, err := v.signer.Sign(r.Certificate.Key, 1, r.Certificate.Ballot, r.Value.MustDigest(), v.inc)
		privateSeedCheck(t, err)
		r.Certificate.Accepts = append(r.Certificate.Accepts, vote)
	}
	return r
}
func privateSeedNativeSession(t *testing.T, f *privateSeedNativeFixture) *AutomationOwnerSession {
	t.Helper()
	ctx := context.Background()
	a, b, c := f.a, f.b, f.c
	key, _ := AutomationClaimKey(1)
	installAutomationEvidence(t, a.c, key, "", 1)
	// Exactly the accepted historical storage premise, not a production cutover.
	privateSeedCheck(t, a.c.execLocal(ctx, `UPDATE local_automation_authority SET bootstrap_request='initialize' WHERE id=1`))
	initial := privateSeedResign(t, sharedAutomationRecord(t, 1, "", "initialize", "initialize-op", a, b), a, b)
	receipt, err := a.c.AutomationApplyOwned(ctx, &initial, f.verifier, contract.Reduce)
	privateSeedCheck(t, err)
	privateSeedMust(t, receipt.Code == "", "historical initialize prerequisite refused: %+v", receipt)
	hash, err := bcrypt.GenerateFromPassword([]byte("correct-password"), bcrypt.MinCost)
	privateSeedCheck(t, err)
	privateSeedCheck(t, InsertUser(ctx, a.c, "alice", "operator", string(hash)))
	origin, err := AutomationLifetime(ctx, a.c, "principal", "alice")
	privateSeedCheck(t, err)
	body, _ := json.Marshal(contract.IdentityEnrollment{Version: 1, Kind: "principal", Alias: "alice", Witness: origin.Witness, EvidenceID: "closed-cutover"})
	assignment, _ := json.Marshal(contract.Assignment{Version: 1, ClusterUID: "established-cluster", OperationID: "principal-op", RecordedAt: time.Now().UTC().Format(time.RFC3339Nano), Identity: &contract.IdentityAssignment{UID: "principal-uid", Generation: 1, Enrollment: &contract.IdentityEnrollmentFacts{Version: 1, EvidenceID: "closed-cutover", ClusterUID: "established-cluster", Kind: "principal", Alias: "alice", Witness: origin.Witness, CoverageDigest: strings.Repeat("b", 64), FenceSequence: 1}}})
	decision := contract.Decision{Sequence: 2, ParentDigest: initial.Value.MustDigest(), Command: contract.Command{Kind: "assign_identity", ClusterUID: "established-cluster", PrincipalID: "host", RequestID: "principal-request", Body: body}, Assignment: assignment}
	encoded, err := contract.EncodeDecision(decision)
	privateSeedCheck(t, err)
	value := ClaimValue{Automation: &AutomationClaimValue{Envelope: encoded}}
	key, _ = AutomationClaimKey(2)
	record := privateSeedResign(t, AutomationRecord{Value: value, Certificate: ClaimCertificate{Key: key, ConfigGeneration: 1, ValueDigest: value.MustDigest()}}, a, b)
	privateSeedCheck(t, f.verifier.Verify(record.Certificate, CertExpectation{Key: key, ValueDigest: value.MustDigest(), ConfigGeneration: 1, Electorate: membersOf(a, b, c), Quorum: 2}))
	receipt, err = a.c.AutomationApplyOwned(ctx, &record, f.verifier, contract.Reduce)
	privateSeedCheck(t, err)
	privateSeedMust(t, receipt.Code == "", "historical certified identity prerequisite refused")
	cfg, err := a.c.AutomationMembership(ctx)
	privateSeedCheck(t, err)
	privateSeedMust(t, cfg.Generation == 1, "actual membership missing")
	auth, disposition, err := PrepareAutomationLocalSession(ctx, a.c, "alice", "correct-password")
	privateSeedCheck(t, err)
	privateSeedMust(t, disposition == AutomationCredentialEligible && auth != nil, "genuine password proof unavailable")
	privateSeedCheck(t, a.c.WithReleaseFeature(ctx, capabilities.FeatureLoginPolicy, func(ctx context.Context, g capabilities.FeatureGrant) error {
		return InsertAutomationSessionWithLoginData(ctx, a.c, g, auth, automationTestSession("private-continuity-session"), "", nil)
	}))
	privateSeedOwnRelease(t, f, capabilities.FeatureLoginPolicy)
	identity, session, err := AuthenticateAutomationOwnerSession(ctx, a.c, "private-continuity-session", time.Hour)
	privateSeedCheck(t, err)
	privateSeedMust(t, identity.UID == "principal-uid" && session != nil, "actual native owner session unavailable")
	return session
}
func privateSeedVerifyAccept(t *testing.T, f *privateSeedNativeFixture, key ClaimKey, value ClaimValue, result AcceptResult, err error) {
	t.Helper()
	privateSeedCheck(t, err)
	privateSeedMust(t, result.Accepted && result.Accept != nil && result.Accept.Voter == "test-node" && result.Accept.VoterIncarnation == f.a.inc, "real native accept absent: %+v", result)
	vote := *result.Accept
	cert := ClaimCertificate{Key: key, Ballot: vote.Ballot, ConfigGeneration: 1, ValueDigest: value.MustDigest(), Accepts: []ClaimAccept{vote}}
	privateSeedCheck(t, f.verifier.Verify(cert, CertExpectation{Key: key, ValueDigest: value.MustDigest(), ConfigGeneration: 1, Electorate: membersOf(f.a, f.b, f.c), Quorum: 1}))
	state, found, err := f.a.c.ClaimState(context.Background(), key)
	privateSeedCheck(t, err)
	privateSeedMust(t, found && state.Accept != nil && state.Value != nil && state.ValueDigest == value.MustDigest() && reflect.DeepEqual(*state.Value, value), "native accept was not exact durable bytes")
	expectedBallot := testBallot(4, "test-node")
	privateSeedMust(t, vote.Ballot.Equal(expectedBallot) && state.Accepted.Equal(expectedBallot) && state.Promised.Equal(expectedBallot) && reflect.DeepEqual(*state.Accept, vote), "durable acceptance/promise differs from the verified returned vote")
	storedCertificate := ClaimCertificate{Key: key, Ballot: expectedBallot, ConfigGeneration: 1, ValueDigest: value.MustDigest(), Accepts: []ClaimAccept{*state.Accept}}
	privateSeedCheck(t, f.verifier.Verify(storedCertificate, CertExpectation{Key: key, ValueDigest: value.MustDigest(), ConfigGeneration: 1, Electorate: membersOf(f.a, f.b, f.c), Quorum: 1}))
	acceptJSON, err := json.Marshal(vote)
	privateSeedCheck(t, err)
	valueJSON, err := json.Marshal(value)
	privateSeedCheck(t, err)
	rows, err := privateSeedRows(f.a.c, `SELECT accept_json,value_json,value_digest,config_generation,promised_round,promised_coord,promised_nonce,accepted_round,accepted_coord,accepted_nonce FROM local_recovery_claims WHERE target_kind=? AND target_name=? AND owner_epoch=? AND attempt=?`, key.TargetKind, key.TargetName, key.OwnerEpoch, key.Attempt)
	privateSeedCheck(t, err)
	privateSeedMust(t, len(rows) == 1, "exact durable native claim row missing")
	row := rows[0]
	privateSeedMust(t, row.String("accept_json") == string(acceptJSON) && row.String("value_json") == string(valueJSON) && row.String("value_digest") == value.MustDigest() && row.Int64("config_generation") == 1, "encoded durable accept/value differs from verified selected bytes")
	privateSeedMust(t, row.Int64("accepted_round") == 4 && row.String("accepted_coord") == "test-node" && bytes.Equal(row.Bytes("accepted_nonce"), expectedBallot.Nonce) && row.Int64("promised_round") == 4 && row.String("promised_coord") == "test-node" && bytes.Equal(row.Bytes("promised_nonce"), expectedBallot.Nonce), "encoded durable accepted/promised ballot differs")
}

type privateSeedOutcome struct {
	Accepted  bool
	Refusal   string
	ErrorKind AutomationCredentialFailure
	Recovered bool
}

func privateSeedNativeCase(t *testing.T, f *privateSeedNativeFixture, mode string) privateSeedOutcome {
	t.Helper()
	ctx := context.Background()
	session := privateSeedNativeSession(t, f)
	c := f.a.c
	p, err := PrepareAutomationIdentityContinuity(ctx, c, session, "principal", "principal-uid", "private-retained-request")
	privateSeedCheck(t, err)
	key, value := continuityTestValue(t, f.a, p)
	var original []Row
	switch mode {
	case "missing-origin":
		original, err = privateSeedRows(c, `SELECT * FROM local_automation_lifetimes`)
		privateSeedCheck(t, err)
		privateSeedCheck(t, c.execLocal(ctx, `DELETE FROM local_automation_lifetimes`))
	case "parent-recreated":
		privateSeedCheck(t, DeleteUser(ctx, c, "alice"))
		privateSeedCheck(t, InsertUser(ctx, c, "alice", "operator", "new-hash"))
	case "factor-policy":
		privateSeedCheck(t, c.execLocal(ctx, `INSERT INTO cluster_policies(key,value,set_by,updated_at) VALUES(?,'local','test','test')`, LoginTwoFactorPolicyKey))
	case "positive":
	default:
		t.Fatal("unknown native semantic case")
	}
	before := continuityStorageEffectRows(t, c)
	calls := f.owner.CallbackCount(capabilities.FeatureAutomationIdentityContinuity)
	result, err := c.ClaimAcceptContinuityNative(ctx, key, testBallot(4, "test-node"), value, 1, f.a.signer, p)
	privateSeedMust(t, f.owner.CallbackCount(capabilities.FeatureAutomationIdentityContinuity) == calls+1, "native owner callback not observed")
	privateSeedOwnRelease(t, f, capabilities.FeatureAutomationIdentityContinuity)
	outcome := privateSeedOutcome{Accepted: result.Accepted, Refusal: string(result.Refusal)}
	if mode == "positive" {
		privateSeedVerifyAccept(t, f, key, value, result, err)
		return outcome
	}
	var proof *AutomationCredentialError
	privateSeedMust(t, err != nil && errors.As(err, &proof) && proof.Kind == AutomationCredentialProofInvalid && !result.Accepted && result.Accept == nil, "native negative classification changed: %+v %T %v", result, err, err)
	outcome.ErrorKind = proof.Kind
	state, found, e := c.ClaimState(ctx, key)
	privateSeedCheck(t, e)
	privateSeedMust(t, !found || state.Accept == nil && state.Value == nil, "negative left accepted/value state")
	privateSeedMust(t, reflect.DeepEqual(before, continuityStorageEffectRows(t, c)), "negative mutated request/history/continuity/claim effects")
	switch mode {
	case "missing-origin":
		for _, r := range original {
			privateSeedCheck(t, c.execLocal(ctx, `INSERT INTO local_automation_lifetimes(kind,name,witness,origin,retired,valid) VALUES(?,?,?,?,?,?)`, r.String("kind"), r.String("name"), r.String("witness"), r.String("origin"), r.Int64("retired"), r.Int64("valid")))
		}
	case "factor-policy":
		privateSeedCheck(t, c.execLocal(ctx, `DELETE FROM cluster_policies WHERE key=?`, LoginTwoFactorPolicyKey))
	case "parent-recreated":
		result, err = c.ClaimAcceptContinuityNative(ctx, key, testBallot(4, "test-node"), value, 1, f.a.signer, p)
		privateSeedMust(t, err != nil && !result.Accepted && result.Accept == nil, "actual recreated parent incorrectly recovered original intent")
		return outcome
	}
	result, err = c.ClaimAcceptContinuityNative(ctx, key, testBallot(4, "test-node"), value, 1, f.a.signer, p)
	privateSeedVerifyAccept(t, f, key, value, result, err)
	outcome.Recovered = true
	return outcome
}
func TestAutomationContinuityPrivateMemorySchemaSeedPair(t *testing.T) {
	// Each interval surrounds t.Run, so cleanup of clients, PKI and TempDirs is
	// included. The first seeded case includes cold donor publication.
	var expected = map[string]privateSeedOutcome{}
	for pair := 0; pair < 3; pair++ {
		for _, factory := range []string{"fresh", "seeded"} {
			for _, mode := range []string{"positive", "missing-origin", "parent-recreated", "factor-policy"} {
				name := fmt.Sprintf("pair%d/%s/%s", pair, factory, mode)
				start := time.Now()
				var timing privateSeedTimings
				var bcNS int64
				var outcome privateSeedOutcome
				var donor privateSeedRecord
				ok := t.Run(name, func(t *testing.T) {
					f, r := privateSeedNativeOwners(t, factory)
					donor = r
					bcNS = f.bcNS
					defer func() { privateSeedCheck(t, f.primary.close()); timing = f.primary.timing }()
					outcome = privateSeedNativeCase(t, f, mode)
				})
				elapsed := time.Since(start).Nanoseconds()
				privateSeedMust(t, ok, "native fixture failed; preserving first actual owner/transport outcome")
				if factory == "fresh" {
					expected[mode] = outcome
				} else {
					privateSeedMust(t, reflect.DeepEqual(expected[mode], outcome), "fresh/seeded semantic outcomes differ %s: %+v %+v", mode, expected[mode], outcome)
				}
				if factory == "seeded" && pair == 0 && mode == "positive" {
					privateSeedLog(t, "DONOR", map[string]any{"constructor_ns": donor.constructorNS, "init_ns": donor.initNS, "initial_validation_ns": donor.initialValidationNS, "sanitize_validate_ns": donor.sanitizeNS, "export_ns": donor.exportNS, "total_including_cleanup_ns": donor.totalNS, "image_sha256": donor.digest})
				}
				privateSeedLog(t, "NATIVE_CASE", map[string]any{"pair": pair, "factory": factory, "case": mode, "whole_fixture_including_cleanup_ns": elapsed, "primary": timing, "unseeded_bc_setup_ns": bcNS, "cold_donor_included": factory == "seeded" && pair == 0 && mode == "positive", "outcome": outcome})
			}
		}
	}
	privateSeedMust(t, privateSeedActive.Load() == 0, "native fixture leaked primary clones")
}

func TestPrivateSchemaSeedOwnerRefusals(t *testing.T) {
	for _, mode := range []string{"missing-peer", "missing-ack"} {
		t.Run(mode, func(t *testing.T) {
			f, _ := privateSeedNativeOwners(t, "fresh")
			if mode == "missing-peer" {
				f.blockPeer.Store(true)
			} else {
				f.blockAck.Store(true)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			called := false
			err := f.a.c.WithReleaseFeature(ctx, capabilities.FeatureLoginPolicy, func(context.Context, capabilities.FeatureGrant) error { called = true; return nil })
			privateSeedMust(t, err != nil && !called && f.owner.CallbackCount(capabilities.FeatureLoginPolicy) == 0, "missing actual peer/receipt minted callback grant: %v", err)
			info, _ := capabilities.LookupFeature(capabilities.FeatureLoginPolicy)
			present, acked, e := ReleaseFeatureState(context.Background(), f.a.c, info.Token, string(capabilities.FeatureLoginPolicy))
			privateSeedCheck(t, e)
			if mode == "missing-peer" {
				privateSeedMust(t, !present && !f.owner.Latched(info.Token), "peer absence left successful first-use state")
			} else {
				privateSeedMust(t, present && !acked, "unacknowledged actual first use became acked")
				peerPresent, _, e := ReleaseFeatureState(context.Background(), f.b.c, info.Token, string(capabilities.FeatureLoginPolicy))
				privateSeedCheck(t, e)
				privateSeedMust(t, !peerPresent, "missing ACK peer actually held use")
			}
			privateSeedLog(t, "OWNER_REFUSAL", map[string]any{"kind": mode, "callback_not_reached": true, "present": present, "acked": acked})
		})
	}
}
