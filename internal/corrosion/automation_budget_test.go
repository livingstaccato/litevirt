package corrosion

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/automation/contract"
)

// Mutation: remove the electorate check in the transaction authority gate.
func TestAutomationBudgetElectorateBeforePromise(t *testing.T) {
	ctx := context.Background()
	_, a, _, _ := threeVoters(t)
	key, value := automationFixture(t, 1, "")
	members := []VoterMember{{Name: a.name, Incarnation: a.inc}}
	for i := 1; i < 8; i++ {
		members = append(members, VoterMember{Name: fmt.Sprintf("peer-%d", i), Incarnation: fmt.Sprintf("inc-%d", i)})
	}
	adoptHandBuilt(t, 2, members, a)
	installAutomationEvidence(t, a.c, key, "", 2)
	p, err := a.c.ClaimPrepare(ctx, key, testBallot(1, "a"), 2)
	if err != nil || p.Promised || p.Refusal != RefusalAutomationUnavailable {
		t.Fatalf("unsupported electorate promised: %+v, %v", p, err)
	}
	r, err := a.c.ClaimAccept(ctx, key, testBallot(1, "a"), value, 2, a.signer, nil)
	if err != nil || r.Accepted || r.Refusal != RefusalAutomationUnavailable {
		t.Fatalf("unsupported electorate accepted: %+v, %v", r, err)
	}
	if _, found, err := a.c.ClaimState(ctx, key); err != nil || found {
		t.Fatal("budget refusal wrote claim state", err)
	}
}

// Mutation: permit a signer certificate larger than the pre-admission budget.
func TestAutomationBudgetSignerBeforeAccept(t *testing.T) {
	ctx := context.Background()
	_, a, _, _ := threeVoters(t)
	key, value := automationFixture(t, 1, "")
	installAutomationEvidence(t, a.c, key, "", 1)
	// A valid leaf with trailing whitespace is accepted by the existing PEM
	// parser, but its complete emitted representation must fit the bound.
	a.signer.certPEM += strings.Repeat("\n", 8193-len(a.signer.certPEM))
	r, err := a.c.ClaimAccept(ctx, key, testBallot(1, "a"), value, 1, a.signer, nil)
	if err == nil && (r.Accepted || r.Refusal != RefusalAutomationUnavailable) {
		t.Fatalf("oversized signer accepted: %+v", r)
	}
	if _, found, err := a.c.ClaimState(ctx, key); err != nil || found {
		t.Fatal("signer refusal wrote claim state", err)
	}
}

// Every byte of a string can expand to six JSON bytes. This deliberately
// overestimates real PEM text and names, and includes ALL responding accepts,
// rather than assuming the proposer discards responses beyond a quorum.
func TestAutomationBudgetCompleteCertificate(t *testing.T) {
	key, _ := AutomationClaimKey(math.MaxInt64)
	worst := strings.Repeat("\x00", contract.MaxStringBytes)
	ballot := Ballot{Round: math.MaxInt64, Coordinator: worst, Nonce: make([]byte, 256)}
	cert := ClaimCertificate{Key: key, ConfigGeneration: math.MaxInt64, Ballot: ballot, ValueDigest: strings.Repeat("f", 64)}
	for i := 0; i < MaxAutomationVoters; i++ {
		cert.Accepts = append(cert.Accepts, ClaimAccept{Voter: worst, VoterIncarnation: worst, ConfigGeneration: cert.ConfigGeneration, Key: key, Ballot: ballot, ValueDigest: cert.ValueDigest, CertPEM: strings.Repeat("\x00", MaxAutomationSignerBytes), Signature: make([]byte, 256)})
	}
	encoded, err := json.Marshal(cert)
	if err != nil {
		t.Fatal(err)
	}
	// AutomationRecord marshals the value as an object, not as an escaped JSON
	// string. Its complete encoded limit already includes envelope base64.
	const wrapper = len(`{"Value":,"Certificate":}`)
	total := MaxAutomationClaimBytes + len(encoded) + wrapper
	if total > MaxAutomationRecordBytes {
		t.Fatalf("all %d accepts plus maximum value need %d bytes, cap %d", len(cert.Accepts), total, MaxAutomationRecordBytes)
	}
	t.Logf("maximum complete value %d + worst all-%d certificate %d + wrapper %d = %d; record cap %d", MaxAutomationClaimBytes, len(cert.Accepts), len(encoded), wrapper, total, MaxAutomationRecordBytes)
}

// Mutation: return a retained signed acceptance without applying the current
// emitted-certificate bound. Imports keep old bytes, but replies may re-sign
// the same accepted value/ballot with the current bounded signer.
func TestAutomationBudgetRetainedAcceptance(t *testing.T) {
	ctx := context.Background()
	_, a, _, _ := threeVoters(t)
	key, value := automationFixture(t, 1, "")
	installAutomationEvidence(t, a.c, key, "", 1)
	ballot := testBallot(1, "a")
	oldSigner := *a.signer
	oldSigner.certPEM += strings.Repeat("\n", MaxAutomationSignerBytes+1-len(oldSigner.certPEM))
	oldAccept, err := oldSigner.Sign(key, 1, ballot, value.MustDigest(), a.inc)
	if err != nil {
		t.Fatal(err)
	}
	state := ClaimVoterState{Key: key, Promised: ballot, Accepted: ballot, Value: &value, ValueDigest: value.MustDigest(), Accept: &oldAccept, ConfigGeneration: 1}
	if err = ValidateAutomationState(state); err != nil {
		t.Fatal(err)
	}
	if err = a.c.ExecuteLocal(ctx, func(tx *LocalTx) error { return saveClaimRowTx(ctx, tx, state) }); err != nil {
		t.Fatal(err)
	}
	result, err := a.c.ClaimAccept(ctx, key, ballot, value, 1, a.signer, nil)
	if err != nil || !result.Accepted || result.Accept == nil {
		t.Fatal("retained value could not be reaccepted", err)
	}
	if len(result.Accept.CertPEM) > MaxAutomationSignerBytes {
		t.Fatal("returned oversized retained acceptance")
	}
	got, found, err := a.c.ClaimState(ctx, key)
	if err != nil || !found || !got.Accepted.Equal(ballot) || got.ValueDigest != state.ValueDigest || !reflect.DeepEqual(got.Value, state.Value) {
		t.Fatal("resigning changed retained value or ballot", err)
	}
}

func TestAutomationBudgetSupportedBoundary(t *testing.T) {
	ctx := context.Background()
	_, a, _, _ := threeVoters(t)
	key, value := automationFixture(t, 1, "")
	members := []VoterMember{{Name: a.name, Incarnation: a.inc}}
	for i := 1; i < MaxAutomationVoters; i++ {
		members = append(members, VoterMember{Name: fmt.Sprintf("peer-%d", i), Incarnation: fmt.Sprintf("inc-%d", i)})
	}
	adoptHandBuilt(t, 2, members, a)
	installAutomationEvidence(t, a.c, key, "", 2)
	a.signer.certPEM += strings.Repeat("\n", MaxAutomationSignerBytes-len(a.signer.certPEM))
	p, err := a.c.ClaimPrepare(ctx, key, testBallot(1, "a"), 2)
	if err != nil || !p.Promised {
		t.Fatal("supported boundary could not promise", err, p.Refusal)
	}
	r, err := a.c.ClaimAccept(ctx, key, testBallot(1, "a"), value, 2, a.signer, nil)
	if err != nil || !r.Accepted || r.Accept == nil || len(r.Accept.CertPEM) != MaxAutomationSignerBytes {
		t.Fatal("supported boundary could not accept", err, r.Refusal)
	}
}
