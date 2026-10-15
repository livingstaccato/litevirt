package fleet

import (
	"bytes"
	"context"
	"fmt"
	"github.com/litevirt/litevirt/internal/automation/contract"
	"github.com/litevirt/litevirt/internal/corrosion"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/automation"
)

// Removing the barrier would turn a minority's empty replica into false absence.
func TestAutomationMinorityCannotDeclareAbsence(t *testing.T) {
	f := NewAutomationFixture(t, 3)
	known, err := f.Engine(0).Submit(f.Context(), f.Initialize("same-request"))
	if err != nil {
		t.Fatal(err)
	}
	f.Isolate(2)
	ctx, cancel := context.WithTimeout(f.Context(), 2*time.Second)
	defer cancel()
	if _, err := f.Engine(2).Observe(ctx, "unseen-resource", 0); automation.Code(err) != automation.CodeUnavailable {
		t.Fatalf("minority observation = %v; want unavailable", err)
	}
	opctx, opcancel := context.WithTimeout(f.Context(), 2*time.Second)
	defer opcancel()
	if _, err := f.Engine(2).Operation(opctx, known.OperationID); automation.Code(err) != automation.CodeUnavailable {
		t.Fatalf("minority operation = %v; want unavailable", err)
	}
	f.Heal(2)
	if _, err := f.Engine(2).Observe(f.Context(), "unseen-resource", 0); !automation.IsAbsent(err) {
		t.Fatalf("healed observation = %v; want authoritative absence", err)
	}
}

// Comparing assigned bytes instead of caller identity, or overwriting the winner,
// breaks concurrent retries with independently allocated server assignments.
func TestAutomationDecisionSameRequestContention(t *testing.T) {
	f := newAutomationFixture(t, 3, false)
	c := f.Initialize("same-request")
	var wg sync.WaitGroup
	receipts := make([]automation.Receipt, 2)
	errs := make([]error, 2)
	for i := range receipts {
		wg.Add(1)
		go func(i int) { defer wg.Done(); receipts[i], errs[i] = f.Engine(i).Submit(f.Context(), c) }(i)
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if receipts[0] != receipts[1] || receipts[0].Sequence != 1 || receipts[0].ResourceUID == "" {
		t.Fatalf("different winning receipts: %+v %+v", receipts[0], receipts[1])
	}
	f.Converge(t)
}

// Skipping another chosen value or changing caller facts on retry loses one request.
func TestAutomationDecisionDifferentRequestContention(t *testing.T) {
	f := NewAutomationFixture(t, 3)
	var wg sync.WaitGroup
	errs := make([]error, 2)
	rs := make([]automation.Receipt, 2)
	for i := range errs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rs[i], errs[i] = f.Engine(i).Submit(f.Context(), f.Barrier(i, []string{"left", "right"}[i]))
		}(i)
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if rs[0].Sequence == rs[1].Sequence || rs[0].Sequence < 2 || rs[1].Sequence < 2 {
		t.Fatalf("requests did not occupy distinct slots: %+v", rs)
	}
	f.Converge(t)
}

// A new method must not consume authority before its real semantic reducer exists.
func TestAutomationDecisionUnsupportedBeforeSlot(t *testing.T) {
	f := NewAutomationFixture(t, 3)
	before := f.Head(t, 0)
	c := f.Barrier(0, "unsupported")
	c.Kind = "admit_create"
	if _, err := f.Engine(0).Submit(f.Context(), c); automation.Code(err) != automation.CodeUnsupported {
		t.Fatalf("unsupported = %v", err)
	}
	if after := f.Head(t, 0); before != after {
		t.Fatal("unsupported command consumed a slot")
	}
}

// Splitting receipt/history/prefix commits exposes a receipt after failed apply.
func TestAutomationReplayAtomicProjectionFailure(t *testing.T) {
	f := newAutomationFixture(t, 3, false)
	n := f.cluster.Nodes[0]
	if err := localExec(f.Context(), n.DB, `CREATE TRIGGER fail_automation_prefix BEFORE INSERT ON local_automation_prefix BEGIN SELECT RAISE(ABORT,'injected prefix failure'); END`); err != nil {
		t.Fatal(err)
	}
	_, err := f.Engine(0).Submit(f.Context(), f.Initialize("same-request"))
	if err == nil {
		t.Fatal("failed projection succeeded")
	}
	for _, table := range []string{"local_automation_prefix", "local_automation_history", "local_automation_requests", "local_automation_anchors"} {
		rs, e := n.DB.Query(f.Context(), "SELECT count(*) AS n FROM "+table)
		if e != nil || rs[0].Int64("n") != 0 {
			t.Fatalf("partial %s after failed transaction: %v", table, e)
		}
	}
	if err := localExec(f.Context(), n.DB, `DROP TRIGGER fail_automation_prefix`); err != nil {
		t.Fatal(err)
	}
	r, err := f.Engine(1).Submit(f.Context(), f.Initialize("same-request"))
	if err != nil || r.Sequence != 1 {
		t.Fatalf("chosen request did not recover after failed apply: %+v %v", r, err)
	}
	f.Converge(t)
}

// Replay must retain assigned identity and permanent receipts, without depending
// on today's validity of the certificates already authenticated at admission.
func TestAutomationReplayAfterProjectionLoss(t *testing.T) {
	f := NewAutomationFixture(t, 3)
	r, err := f.Engine(0).Submit(f.Context(), f.Barrier(0, "before-loss"))
	if err != nil {
		t.Fatal(err)
	}
	f.Converge(t)
	want := f.Head(t, 2)
	n := f.cluster.Nodes[2]
	for _, table := range []string{"local_automation_requests", "local_automation_prefix"} {
		if err := localExec(f.Context(), n.DB, "DELETE FROM "+table); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.Engine(2).Recover(f.Context()); err != nil {
		t.Fatal(err)
	}
	if got := f.Head(t, 2); got != want {
		t.Fatalf("replay changed prefix %+v want %+v", got, want)
	}
	got, err := f.Engine(2).Operation(f.Context(), r.OperationID)
	if err != nil || got != r {
		t.Fatalf("replay receipt = %+v %v want %+v", got, err, r)
	}
	f.Converge(t)
}

// A skipped predecessor cannot become a durable promise, even if an accepted
// value exists at genesis. Only certified and applied history opens slot two.
func TestAutomationDecisionPredecessorGap(t *testing.T) {
	f := newAutomationFixture(t, 3, false)
	n := f.cluster.Nodes[1]
	key, _ := corrosion.AutomationClaimKey(2)
	p, err := n.DB.ClaimPrepare(f.Context(), key, corrosion.Ballot{Round: 1, Coordinator: n.Name, Nonce: []byte("gap")}, 1)
	if err != nil || p.Promised || p.Refusal != corrosion.RefusalAutomationUnavailable {
		t.Fatalf("gap promised: %+v %v", p, err)
	}
	if _, found, err := n.DB.ClaimState(f.Context(), key); err != nil || found {
		t.Fatalf("gap wrote state: %v", err)
	}
	signer, err := corrosion.LoadClaimSigner(n.PKIDir, n.Name)
	if err != nil {
		t.Fatal(err)
	}
	genesis := automation.Decision{Sequence: 1, Command: f.Initialize("same-request"), Assignment: []byte(`{"version":1,"cluster_uid":"accepted-only-cluster","operation_id":"accepted-only-operation","recorded_at":"2026-10-15T00:00:00Z"}`)}
	encoded, err := contract.EncodeDecision(genesis)
	if err != nil {
		t.Fatal(err)
	}
	gkey, _ := corrosion.AutomationClaimKey(1)
	accepted, err := n.DB.ClaimAccept(f.Context(), gkey, corrosion.Ballot{Round: 1, Coordinator: n.Name, Nonce: []byte("accepted-only")}, corrosion.ClaimValue{Automation: &corrosion.AutomationClaimValue{Envelope: encoded}}, 1, signer, nil)
	if err != nil || !accepted.Accepted {
		t.Fatalf("accepted-only fixture failed: %v %s", err, accepted.Refusal)
	}
	p, err = n.DB.ClaimPrepare(f.Context(), key, corrosion.Ballot{Round: 2, Coordinator: n.Name, Nonce: []byte("still-gap")}, 1)
	if err != nil || p.Promised || p.Refusal != corrosion.RefusalAutomationUnavailable {
		t.Fatalf("accepted-only predecessor authorized slot: %+v %v", p, err)
	}
	if _, err := f.Engine(0).Submit(f.Context(), f.Initialize("same-request")); err != nil {
		t.Fatal(err)
	}
	f.Converge(t)
	if _, err := f.Engine(1).Submit(f.Context(), f.Barrier(1, "after-gap")); err != nil {
		t.Fatal(err)
	}
	f.Converge(t)
}

// A quorum can choose a value while its proposer receives no certificate. The
// successor must run phase two again and recover the exact assigned bytes.
func TestAutomationDecisionProposerDeathAfterChosen(t *testing.T) {
	f := NewAutomationFixture(t, 3)
	first := f.cluster.Nodes[0]
	f.cluster.SetClaimScript(func(m ClaimMsg) ClaimFate {
		if m.From == first.Name && m.Method == "AcceptRecoveryClaim" {
			return ClaimDropReply
		}
		return ClaimDefault
	})
	_, err := f.Engine(0).Submit(f.Context(), f.Barrier(0, "lost-chosen"))
	if automation.Code(err) != automation.CodeUnavailable {
		t.Fatalf("lost reply unexpectedly succeeded: %v", err)
	}
	key, _ := corrosion.AutomationClaimKey(2)
	st, ok, err := f.cluster.Nodes[1].DB.ClaimState(f.Context(), key)
	if err != nil || !ok || st.Value == nil {
		t.Fatalf("no accepted chosen value: %v", err)
	}
	expected := append([]byte(nil), st.Value.Automation.Envelope...)
	digest := st.ValueDigest
	f.Isolate(0)
	f.cluster.SetClaimScript(nil)
	r, err := f.Engine(1).Submit(f.Context(), f.Barrier(1, "successor"))
	if err != nil || r.Sequence != 3 {
		t.Fatalf("successor did not recover chosen prefix: %+v %v", r, err)
	}
	rec, ok, err := f.cluster.Nodes[1].DB.AutomationRecord(f.Context(), 2)
	if err != nil || !ok || !bytes.Equal(rec.Value.Automation.Envelope, expected) || rec.Value.MustDigest() != digest {
		t.Fatalf("recovery changed chosen bytes: %v", err)
	}
	f.Heal(0)
	f.Converge(t)
}

// A fresh-head install must bring a voter through many missing predecessors;
// distributing only the head cannot make the next quorum decision progress.
func TestAutomationReplayLaggingVoterCatchesUp(t *testing.T) {
	f := NewAutomationFixture(t, 3)
	f.Isolate(2)
	for i := 0; i < 6; i++ {
		if _, err := f.Engine(0).Submit(f.Context(), f.Barrier(0, fmt.Sprintf("lag-%d", i))); err != nil {
			t.Fatal(err)
		}
	}
	f.Heal(2)
	f.Isolate(1)
	if _, err := f.Engine(0).Submit(f.Context(), f.Barrier(0, "needs-caught-up-voter")); err != nil {
		t.Fatalf("healed voter never caught up: %v", err)
	}
	f.Heal(1)
	f.Converge(t)
}

// An authenticated peer must not bypass the strict dispatcher by calling the
// claim acceptor directly and certifying incompatible history.
func TestAutomationDecisionDirectAcceptRejectsUnsupportedAndMalformed(t *testing.T) {
	f := NewAutomationFixture(t, 3)
	n := f.cluster.Nodes[1]
	h := f.Head(t, 1)
	signer, err := corrosion.LoadClaimSigner(n.PKIDir, n.Name)
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"unsupported", "assignment", "body", "cluster", "parent"} {
		d := automation.Decision{Sequence: h.Sequence + 1, ParentDigest: h.Digest, Command: f.Barrier(1, "direct-"+kind), Assignment: []byte(fmt.Sprintf(`{"version":1,"cluster_uid":%q,"operation_id":"direct","recorded_at":"2026-10-15T00:00:00Z"}`, h.ClusterUID))}
		switch kind {
		case "unsupported":
			d.Command.Kind = "admit_create"
		case "assignment":
			d.Assignment = []byte(`{"version":1,"operation":"not-real-schema"}`)
		case "body":
			d.Command.Body = []byte(`{"version":1,"unexpected":true}`)
		case "cluster":
			d.Command.ClusterUID = "another-cluster"
		case "parent":
			d.ParentDigest = strings.Repeat("f", 64)
		}
		b, err := contract.EncodeDecision(d)
		if err != nil {
			t.Fatal(err)
		}
		key, _ := corrosion.AutomationClaimKey(d.Sequence)
		result, err := n.DB.ClaimAccept(f.Context(), key, corrosion.Ballot{Round: 20, Coordinator: n.Name, Nonce: []byte("direct")}, corrosion.ClaimValue{Automation: &corrosion.AutomationClaimValue{Envelope: b}}, 1, signer, nil)
		if err != nil || result.Accepted || result.Accept != nil {
			t.Fatalf("%s direct acceptance succeeded/refused incorrectly: %+v %v", kind, result, err)
		}
		if _, found, err := n.DB.ClaimState(f.Context(), key); err != nil || found {
			t.Fatalf("%s wrote state: %v", kind, err)
		}
	}
}

// Bounded recovery must preserve disk checkpoints across budget exhaustion and
// clean its job when the last record lands exactly on the application budget.
func TestAutomationReplayBoundedResume(t *testing.T) {
	f := NewAutomationFixture(t, 3)
	f.Isolate(2)
	for i := 0; i < 256; i++ {
		if _, err := f.Engine(0).Submit(f.Context(), f.Barrier(0, fmt.Sprintf("bounded-%d", i))); err != nil {
			t.Fatalf("slot %d: %v", i, err)
		}
	}
	want := f.Head(t, 0)
	f.Heal(2)
	firstErr := f.Engine(2).Recover(f.Context())
	sawBudget := firstErr != nil
	// A newly certified install may advance beyond the just-completed recovery
	// target before the next bounded cleanup call.
	if h := f.Head(t, 2); h != want {
		t.Fatalf("first bounded application did not reach target: %+v want %+v", h, want)
	}
	if _, err := f.Engine(0).Submit(f.Context(), f.Barrier(0, "advance-before-job-cleanup")); err != nil {
		t.Fatal(err)
	}
	want = f.Head(t, 0)
	for i := 0; i < 4; i++ {
		err := f.Engine(2).Recover(f.Context())
		if err != nil {
			sawBudget = true
			continue
		}
		break
	}
	if !sawBudget {
		t.Fatal("unbounded recovery did not yield at budget")
	}
	if h := f.Head(t, 2); h != want {
		t.Fatalf("bounded resume head %+v want %+v", h, want)
	}
	rows, err := f.cluster.Nodes[2].DB.Query(f.Context(), `SELECT count(*) AS n FROM local_automation_recovery`)
	if err != nil || rows[0].Int64("n") != 0 {
		t.Fatalf("finished recovery retained checkpoint: %v", err)
	}
	f.Converge(t)
}

// Failed prefix/auth transport is not a proof of an unused installation.
func TestAutomationReplayTransportFailureNotEmptyGenesis(t *testing.T) {
	f := NewAutomationFixture(t, 3)
	f.Isolate(2)
	n := f.cluster.Nodes[2]
	for _, table := range []string{"local_automation_requests", "local_automation_prefix", "local_automation_history", "local_automation_anchors"} {
		if err := localExec(f.Context(), n.DB, "DELETE FROM "+table); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.Engine(2).Recover(f.Context()); automation.Code(err) != automation.CodeUnavailable {
		t.Fatalf("failed transport became empty genesis: %v", err)
	}
	f.Heal(2)
	f.Converge(t)
}

// A retained head counter without its authenticated parent bytes is not prefix
// authority, including when re-certifying an older key.
func TestAutomationDecisionMissingCertifiedParent(t *testing.T) {
	f := NewAutomationFixture(t, 3)
	n := f.cluster.Nodes[2]
	if err := localExec(f.Context(), n.DB, `DELETE FROM local_automation_history`); err != nil {
		t.Fatal(err)
	}
	if err := localExec(f.Context(), n.DB, `DELETE FROM local_automation_anchors`); err != nil {
		t.Fatal(err)
	}
	for _, seq := range []uint64{1, 2} {
		key, _ := corrosion.AutomationClaimKey(seq)
		p, err := n.DB.ClaimPrepare(f.Context(), key, corrosion.Ballot{Round: 100, Coordinator: n.Name, Nonce: []byte("no-parent")}, 1)
		if err != nil || p.Promised || p.Refusal != corrosion.RefusalAutomationUnavailable {
			t.Fatalf("slot %d promised without certified parent: %+v %v", seq, p, err)
		}
	}
}

// Prefix installs can be duplicated/reordered independently of claim replies.
// The recorded finite schedule must still converge once faults stop.
func TestAutomationDecisionPrefixReorderAndDuplicate(t *testing.T) {
	f := NewAutomationFixture(t, 3)
	var mu sync.Mutex
	held := false
	duplicated := false
	lost := false
	f.cluster.SetClaimScript(func(m ClaimMsg) ClaimFate {
		mu.Lock()
		defer mu.Unlock()
		if m.From == f.cluster.Nodes[0].Name && m.To == f.cluster.Nodes[2].Name && m.Method == "InstallAutomationDecision" {
			if !held {
				held = true
				return ClaimHold
			}
			if !duplicated {
				duplicated = true
				return ClaimDuplicate
			}
		}
		if m.From == f.cluster.Nodes[0].Name && m.To == f.cluster.Nodes[1].Name && m.Method == "AcceptRecoveryClaim" && !lost {
			lost = true
			return ClaimDropReply
		}
		return ClaimDefault
	})
	if _, err := f.Engine(0).Submit(f.Context(), f.Barrier(0, "finite-prefix-faults")); err != nil {
		t.Fatal(err)
	}
	f.cluster.SetClaimScript(nil)
	f.cluster.ReleaseHeldClaims()
	f.Converge(t)
	mu.Lock()
	defer mu.Unlock()
	if !held || !duplicated || !lost {
		t.Fatalf("fault schedule did not execute held=%v duplicate=%v lost=%v", held, duplicated, lost)
	}
	for i, n := range f.cluster.Nodes {
		rows, err := n.DB.Query(f.Context(), `SELECT count(*) AS n FROM local_automation_requests`)
		if err != nil || rows[0].Int64("n") != 2 || f.Head(t, i).Sequence != 2 {
			t.Fatalf("duplicate/reordered installs changed receipts on %d: %v", i, err)
		}
	}
}

// An old record's certificate need not be currently valid, but its exact bytes
// must be authenticated by the fresh head's backwards chain before staging.
func TestAutomationReplayRejectsWrongAnchoredPredecessor(t *testing.T) {
	f := NewAutomationFixture(t, 3)
	for _, id := range []string{"anchor-two", "anchor-three"} {
		if _, err := f.Engine(0).Submit(f.Context(), f.Barrier(0, id)); err != nil {
			t.Fatal(err)
		}
	}
	f.Converge(t)
	n := f.cluster.Nodes[2]
	head, _, err := f.cluster.Nodes[0].DB.AutomationRecord(f.Context(), 3)
	if err != nil {
		t.Fatal(err)
	}
	middle, _, err := f.cluster.Nodes[0].DB.AutomationRecord(f.Context(), 2)
	if err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"local_automation_requests", "local_automation_prefix", "local_automation_history", "local_automation_anchors"} {
		if err := localExec(f.Context(), n.DB, "DELETE FROM "+table); err != nil {
			t.Fatal(err)
		}
	}
	verifier, err := corrosion.LoadClaimVerifier(n.PKIDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := n.DB.AutomationBeginRecovery(f.Context(), head, verifier); err != nil {
		t.Fatal(err)
	}
	d, err := contract.DecodeDecision(middle.Value.Automation.Envelope)
	if err != nil {
		t.Fatal(err)
	}
	d.Assignment = []byte(fmt.Sprintf(`{"version":1,"cluster_uid":%q,"operation_id":"substituted-assignment","recorded_at":"2026-10-15T00:00:00Z"}`, f.Head(t, 0).ClusterUID))
	envelope, err := contract.EncodeDecision(d)
	if err != nil {
		t.Fatal(err)
	}
	wrong := middle
	wrong.Value = corrosion.ClaimValue{Automation: &corrosion.AutomationClaimValue{Envelope: envelope}}
	if err := n.DB.AutomationStagePredecessor(f.Context(), wrong); err == nil {
		t.Fatal("wrong backwards digest gained anchor authority")
	}
	if next, err := n.DB.AutomationRecoveryNext(f.Context()); err != nil || next != 2 {
		t.Fatalf("invalid predecessor advanced checkpoint: %d %v", next, err)
	}
	if err := f.Engine(2).Recover(f.Context()); err != nil {
		t.Fatal(err)
	}
	f.Converge(t)
}

// The reducer's bounded operation lookup must participate in the same real
// transaction as receipts/prefix, including deterministic rejection receipts.
func TestAutomationDecisionAssignedOperationCollision(t *testing.T) {
	f := NewAutomationFixture(t, 3)
	original, err := f.Engine(0).Submit(f.Context(), f.Barrier(0, "original-op-request"))
	if err != nil {
		t.Fatal(err)
	}
	f.Converge(t)
	h := f.Head(t, 0)
	c := f.Barrier(0, "colliding-op-request")
	d := automation.Decision{Sequence: h.Sequence + 1, ParentDigest: h.Digest, Command: c, Assignment: []byte(fmt.Sprintf(`{"version":1,"cluster_uid":%q,"operation_id":%q,"recorded_at":"2026-10-15T00:00:00Z"}`, h.ClusterUID, original.OperationID))}
	rec := f.certifyFixtureDecision(t, d)
	for _, e := range f.engines {
		if err := e.Install(f.Context(), rec); err != nil {
			t.Fatal(err)
		}
	}
	r, err := f.Engine(0).Submit(f.Context(), c)
	if automation.Code(err) != automation.CodeValidation || r.State != "rejected" || r.OperationID != "" {
		t.Fatalf("collision was not permanently rejected: %+v %v", r, err)
	}
	got, err := f.Engine(0).Operation(f.Context(), original.OperationID)
	if err != nil || got != original {
		t.Fatalf("collision replaced original operation: %+v %v", got, err)
	}
	f.Converge(t)
	if err := localExec(f.Context(), f.cluster.Nodes[2].DB, `DELETE FROM local_automation_prefix`); err != nil {
		t.Fatal(err)
	}
	if err := f.Engine(2).Recover(f.Context()); err != nil {
		t.Fatalf("retained rejection replay drifted: %v", err)
	}
	f.Converge(t)
}

// Permanent receipts can survive independently of the derived prefix. Replay
// of the original admission must reconstruct effects, unlike a later duplicate.
func TestAutomationReplayPrefixLossKeepsReceipts(t *testing.T) {
	f := NewAutomationFixture(t, 3)
	r, err := f.Engine(0).Submit(f.Context(), f.Barrier(0, "retained-receipts"))
	if err != nil {
		t.Fatal(err)
	}
	f.Converge(t)
	want := f.Head(t, 2)
	n := f.cluster.Nodes[2]
	if err := localExec(f.Context(), n.DB, `DELETE FROM local_automation_prefix`); err != nil {
		t.Fatal(err)
	}
	if err := f.Engine(2).Recover(f.Context()); err != nil {
		t.Fatalf("replay with retained receipts: %v", err)
	}
	if got := f.Head(t, 2); got != want {
		t.Fatalf("retained receipt prevented reconstruction: %+v want %+v", got, want)
	}
	got, err := f.Engine(2).Operation(f.Context(), r.OperationID)
	if err != nil || got != r {
		t.Fatalf("retained receipt drift: %+v %v", got, err)
	}
	f.Converge(t)
}

// Stored slot results are immutable evidence of this reducer version. A
// disagreement must block recovery instead of silently rewriting old receipts.
func TestAutomationReplayRejectsReceiptDrift(t *testing.T) {
	f := NewAutomationFixture(t, 3)
	n := f.cluster.Nodes[2]
	if err := localExec(f.Context(), n.DB, `UPDATE local_automation_history SET receipt_json=replace(receipt_json,'succeeded','rejected') WHERE sequence=1`); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"local_automation_prefix", "local_automation_requests"} {
		if err := localExec(f.Context(), n.DB, "DELETE FROM "+table); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.Engine(2).Recover(f.Context()); err == nil {
		t.Fatal("replay silently rewrote immutable slot result")
	}
	if h := f.Head(t, 2); h.Sequence != 0 {
		t.Fatalf("receipt drift granted prefix authority: %+v", h)
	}
}

// Genesis can be chosen before any certified head is published. A successor
// read must re-certify accepted slot1, recover its assigned UID, and append its
// own barrier; an empty local row is never permission to mint another UID.
func TestAutomationDecisionChosenGenesisWithoutPublishedCertificate(t *testing.T) {
	f := newAutomationFixture(t, 3, false)
	first := f.cluster.Nodes[0]
	f.cluster.SetClaimScript(func(m ClaimMsg) ClaimFate {
		if m.From == first.Name && m.Method == "AcceptRecoveryClaim" {
			return ClaimDropReply
		}
		return ClaimDefault
	})
	if _, err := f.Engine(0).Submit(f.Context(), f.Initialize("same-request")); automation.Code(err) != automation.CodeUnavailable {
		t.Fatalf("lost genesis replies = %v", err)
	}
	key, _ := corrosion.AutomationClaimKey(1)
	st, found, err := f.cluster.Nodes[1].DB.ClaimState(f.Context(), key)
	if err != nil || !found || st.Value == nil {
		t.Fatalf("genesis was not accepted: %v", err)
	}
	original := append([]byte(nil), st.Value.Automation.Envelope...)
	f.Isolate(0)
	f.cluster.SetClaimScript(nil)
	if _, err := f.Engine(1).Observe(f.Context(), "unseen-after-genesis", 0); !automation.IsAbsent(err) {
		t.Fatalf("chosen genesis was not recovered before barrier: %v", err)
	}
	record, ok, err := f.cluster.Nodes[1].DB.AutomationRecord(f.Context(), 1)
	if err != nil || !ok || !bytes.Equal(record.Value.Automation.Envelope, original) {
		t.Fatalf("genesis identity changed on recovery: %v", err)
	}
	if h := f.Head(t, 1); h.Sequence != 2 || h.ClusterUID == "" {
		t.Fatalf("successor barrier did not follow genesis: %+v", h)
	}
	f.Heal(0)
	f.Converge(t)
}
