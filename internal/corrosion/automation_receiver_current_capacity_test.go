package corrosion

import (
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/pki"
)

// This tests CURRENT capacity, including the private FULL consumer. Native G1
// historical bootstrap is the fixture premise, not production issuer custody.
// Removing originals, reducing the roster, or letting a stale proof succeed is
// a regression. A real capacity refusal must remain a failing result.
func TestReceiverCurrentCapacityLegalSevenToSix(t *testing.T) {
	ctx := context.Background()
	setup := time.Now()
	f := newAggregateFixture(t, aggregateFixtureOptions{
		Old: 7, Sources: 7, Continuing: true, Remove: "old-0",
		Heads: []int{130, 130, 130, 130, 130, 130, 130}, LocalHead: 130,
		BeforeFreeze: func(t *testing.T, voters []*claimTestVoter, local *claimTestVoter) {
			for n := 0; n < 37; n++ {
				key := LeaseTermClaimKey(fmt.Sprintf("capacity_%03d", n), 1)
				value := ClaimValue{LeaseTerm: &LeaseTermValue{Key: key.TargetName, Term: 1, Holder: "retained-holder"}}
				for i, voter := range voters {
					reply, err := voter.c.ClaimAccept(ctx, key, testBallot(uint64(i+2), "capacity"), value, 1, voter.signer, unreachable)
					if err != nil || !reply.Accepted {
						t.Fatalf("genuine retained acceptance %s/%d: %+v %v", voter.name, n, reply, err)
					}
				}
			}
		},
	})
	setupDuration := time.Since(setup)
	old, err := GetVoterConfig(ctx, f.local.c, 1)
	if err != nil {
		t.Fatal(err)
	}
	next, err := GetVoterConfig(ctx, f.local.c, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(old.Members) != 7 || len(next.Members) != 6 || next.Change != VoterChangeRm("old-0") || ValidateVoterChange(old, next.VoterConfigValue) != nil {
		t.Fatal("requires genuine legal old7 -> target6 removal")
	}
	cert, err := DecodeClaimCertificate(next.Certificate)
	if err != nil || len(cert.Accepts) != 7 {
		t.Fatal("missing independent successor votes", err)
	}
	seenDB, seenKey, seenPublication, seenCut := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	for i, producer := range f.producers {
		if _, err := os.Stat(filepath.Join(producer.client.dataDir, "state.db")); err != nil {
			t.Fatal(err)
		}
		pair, err := pki.ServedHostKeyPair(producer.dir)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(pair.Certificate[0])
		if err != nil {
			t.Fatal(err)
		}
		key, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		rows, err := producer.client.Query(ctx, `SELECT id,metadata,root FROM local_automation_cuts WHERE generation=1`)
		if err != nil || len(rows) != 1 {
			t.Fatal("missing genuine frozen cut", err)
		}
		cut := rows[0].String("id")
		if seenDB[producer.client.dsn] || seenKey[string(key)] || seenPublication[f.requests[i].Publication] || seenCut[cut] {
			t.Fatal("cloned producer")
		}
		seenDB[producer.client.dsn], seenKey[string(key)], seenPublication[f.requests[i].Publication], seenCut[cut] = true, true, true, true
		info, err := readAutomationCutMetadata(rows[0])
		if err != nil || info.Head.Sequence != 130 || info.Inventory[0].Records != 39 || info.Inventory[2].Records != 130 || info.Inventory[3].Records != 130 || info.Inventory[4].Records != 130 {
			t.Fatal("incomplete actual source history/claims", producer.client.hostName, info, err)
		}
	}
	if len(f.producers) != 7 || len(f.attempt.request.Sources) != 7 {
		t.Fatal("fixed source roster reduced")
	}
	staging := time.Now()
	for i := range f.producers {
		f.stage(t, i, 11, true)
	}
	stagingDuration := time.Since(staging)
	active, typed, spool := receiverActive(t, f.local.c), automationTypedSnapshot(t, f.local.c), receiverStored(t, f.local.c)
	// No read/driver/EXPLAIN observers, profiles, cached C gate, or retries.
	// Existing commit seams collect clocks only; they neither pause nor read.
	var before, after []time.Time
	f.receiver.seams = &localCommitSeams{
		beforeCommit: func(*sql.Tx) error { before = append(before, time.Now()); return nil },
		afterCommit:  func() { after = append(after, time.Now()) },
	}
	start := time.Now()
	p, proofErr := f.receiver.VerifyCurrent(ctx, f.attempt)
	verified := time.Now()
	verifyDuration := verified.Sub(start)
	var consumeErr error
	var consumeDuration, issuedAge, finalAge time.Duration
	if p != nil {
		defer p.Discard()
		issuedAge = verified.Sub(p.observed)
		if p.self != p || p.owner != f.receiver || p.attempt.self != p.attempt || p.attempt.owner != f.receiver || !f.receiver.proofs[p] || p.binding == "" || p.binding != p.exactBinding() || p.evidence.aggregate == "" || p.evidence.digest == "" {
			t.Fatal("proof lacks exact process owner/binding")
		}
		if len(p.sources) != 7 || len(p.publications) != 7 || len(p.caps) != 8 {
			t.Fatal("current authority omitted a fixed source or registration")
		}
		for i, s := range p.sources {
			if s.host.Name != f.voters[i].name || s.peer.Incarnation != f.voters[i].inc || s.observed.IsZero() || verified.Before(s.observed) || verified.Sub(s.observed) >= sourceTargetObservationLifetime || len(s.peer.Chain) == 0 || p.publications[i].id != f.requests[i].Publication || verified.Before(p.publications[i].notBefore) || !verified.Before(p.publications[i].notAfter) {
				t.Fatal("invalid actual current source/publication", i)
			}
		}
		if err := p.currentTime(); err != nil {
			t.Fatal("proof was stale at issuance", err)
		}
		consumeStart := time.Now()
		consumeErr = f.receiver.consumeCurrent(ctx, p)
		consumeDuration = time.Since(consumeStart)
		finalAge = time.Since(p.observed)
		if f.receiver.proofs[p] || len(p.caps) != 0 {
			t.Error("consume did not invalidate registration")
		}
	}
	f.receiver.seams = nil
	t.Logf("current capacity setupFreezePreparePublish=%s stageAll7AuditSource=%s actualVerifyCurrent=%s issuedObservationAge=%s actualConsumeCurrent=%s finalObservationAge=%s unchangedLifetime=%s proofError=%v consumeError=%v", setupDuration, stagingDuration, verifyDuration, issuedAge, consumeDuration, finalAge, sourceTargetObservationLifetime, proofErr, consumeErr)
	for i := range before {
		var terminal time.Duration
		if i < len(after) {
			terminal = after[i].Sub(start)
		}
		t.Logf("current clockOnlyCommit index=%d beforeFinalGuards=%s committed=%s", i, before[i].Sub(start), terminal)
	}
	if len(after) >= 3 {
		t.Logf("current phases BeginThroughCommit=%s CIncludingAuthAndCompleteCapture=%s currentAuthLeaseInitialFULL=%s finalFULLGuardsDigestCommit=%s sameTrustRegistrationAndReturn=%s", after[0].Sub(start), after[1].Sub(after[0]), before[2].Sub(after[1]), after[2].Sub(before[2]), verified.Sub(after[2]))
	}
	if active != receiverActive(t, f.local.c) || !reflect.DeepEqual(typed, automationTypedSnapshot(t, f.local.c)) || spool != receiverStored(t, f.local.c) {
		t.Error("current verification/consume changed ACTIVE, typed state or originals")
	}
	// All following observers run AFTER the first proof/consume clocks stop.
	// A refusal still attributes the exact real C rows without retrying C.
	id := ""
	if p != nil {
		id = p.evidence.aggregate
	}
	rows, err := f.local.c.Query(ctx, `SELECT id FROM local_automation_aggregates WHERE attempt=?`, f.attempt.id)
	if err != nil || len(rows) != 1 {
		t.Fatalf("current result=%v; C aggregate unavailable for attribution: %v rows=%d", proofErr, err, len(rows))
	}
	if id == "" {
		id = rows[0].String("id")
	}
	if id != rows[0].String("id") {
		t.Fatal("proof differs from actual C aggregate")
	}
	currentCapacityOriginals(t, f, id)
	if proofErr != nil || p == nil {
		t.Fatalf("actual legal maximal current proof capacity gap: elapsed=%s error=%v", verifyDuration, proofErr)
	}
	if consumeErr != nil {
		t.Fatalf("actual legal maximal FULL consume capacity gap: issuedAge=%s elapsed=%s finalAge=%s error=%v", issuedAge, consumeDuration, finalAge, consumeErr)
	}
	if issuedAge < 0 || issuedAge >= sourceTargetObservationLifetime || finalAge >= sourceTargetObservationLifetime {
		t.Fatal("actual maximum current proof exceeded unchanged freshness", issuedAge, finalAge)
	}
}

func currentCapacityOriginals(t *testing.T, f *aggregateFixture, id string) {
	t.Helper()
	ctx := context.Background()
	rows, err := f.local.c.Query(ctx, `SELECT source,incarnation FROM local_automation_aggregate_sources WHERE bundle=? ORDER BY source`, id)
	if err != nil || len(rows) != 7 {
		t.Fatal("fixed counted roster lost", rows, err)
	}
	for i, row := range rows {
		if row.String("source") != f.voters[i].name || row.String("incarnation") != f.voters[i].inc {
			t.Fatal("counted exact source differs", row)
		}
		// This helper inspects actual accepted originals and history components,
		// without running C or installing an observing driver.
		pages, err := f.local.c.Query(ctx, `SELECT COUNT(*) AS n FROM local_automation_receiver_pages WHERE attempt=? AND source=? AND component=5`, f.attempt.id, row.String("source"))
		if err != nil || len(pages) != 1 || pages[0].Int64("n") < 130 {
			t.Fatal("actual many-page history missing", err)
		}
		automationCapacityOriginals(t, f, row.String("source"), 130, 37, false, pages[0].Int64("n"))
	}
	rows, err = f.local.c.Query(ctx, `SELECT head FROM local_automation_aggregates WHERE id=?`, id)
	var head AutomationPrefix
	if err != nil || len(rows) != 1 || json.Unmarshal(rows[0].Bytes("head"), &head) != nil || head.Sequence != 130 {
		t.Fatal("logical certified130 history lost", head, err)
	}
	rows, err = f.local.c.Query(ctx, `SELECT COUNT(*) AS n FROM local_automation_history`)
	if err != nil || len(rows) != 1 || rows[0].Int64("n") != 130 {
		t.Fatal("local original130 history missing", rows, err)
	}
	rows, err = f.local.c.Query(ctx, `SELECT s.source,COUNT(c.ordinal) AS n FROM local_automation_aggregate_sources s LEFT JOIN local_automation_aggregate_copies c ON c.bundle=s.bundle AND c.origin_kind='source' AND c.origin_id=s.audit WHERE s.bundle=? GROUP BY s.source ORDER BY s.source`, id)
	if err != nil || len(rows) != 7 {
		t.Fatal("source original copies missing", err)
	}
	var sourceCopies int64
	for i, row := range rows {
		if row.String("source") != f.voters[i].name || row.Int64("n") != 37 {
			t.Fatal("lost source original copy", row)
		}
		sourceCopies += row.Int64("n")
	}
	rows, err = f.local.c.Query(ctx, `SELECT (SELECT COUNT(*) FROM local_automation_aggregate_copies WHERE bundle=?) AS copies,(SELECT COUNT(*) FROM local_automation_aggregate_copies WHERE bundle=? AND origin_kind='local' AND length(origin_ref)>0) AS local,(SELECT COUNT(*) FROM local_automation_aggregate_maxima WHERE bundle=?) AS maxima,(SELECT COUNT(*) FROM local_automation_aggregate_conflicts WHERE bundle=?) AS ballots`, id, id, id, id)
	if err != nil || len(rows) != 1 || sourceCopies != 259 || rows[0].Int64("copies") != 296 || rows[0].Int64("local") != 37 || rows[0].Int64("maxima") != 37 || rows[0].Int64("ballots") != 259 {
		t.Fatal("full original reconciliation differs", rows, sourceCopies, err)
	}
	t.Logf("current actualC aggregate=%s fixedSources=7 sourceCopies=%d additionalLocalCopies=%d allOriginalCopies=%d maxima=%d exactBallotEntries=%d sourceHistoryOriginals=910 additionalLocalHistory=130 logicalCertifiedHistory=%d", id, sourceCopies, rows[0].Int64("local"), rows[0].Int64("copies"), rows[0].Int64("maxima"), rows[0].Int64("ballots"), head.Sequence)
}
