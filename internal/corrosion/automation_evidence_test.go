package corrosion

import (
	"context"
	"testing"
	"time"
)

// evidenceVoters: a, b and c at generation 1, read from c's replica.
func evidenceVoters(t *testing.T) (a, b, c *claimTestVoter) {
	t.Helper()
	ca := newClaimTestCA(t)
	a, b, c = newClaimTestVoter(t, ca, "a"), newClaimTestVoter(t, ca, "b"), newClaimTestVoter(t, ca, "c")
	adoptHandBuilt(t, 1, membersOf(a, b, c), c)
	return a, b, c
}

func anchorCert(t *testing.T, gen int64, signers ...*claimTestVoter) string {
	t.Helper()
	cert := ClaimCertificate{ConfigGeneration: gen}
	for _, v := range signers {
		cert.Accepts = append(cert.Accepts, ClaimAccept{Voter: v.name, VoterIncarnation: v.inc, ConfigGeneration: gen})
	}
	enc, err := cert.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return enc
}

func insertAnchors(t *testing.T, c *claimTestVoter, from, to int64, gen int64, cert string) {
	t.Helper()
	tx, err := c.c.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	for seq := from; seq <= to; seq++ {
		if _, err := tx.Exec(`INSERT INTO local_automation_anchors (sequence,digest,generation,members_hash,certificate) VALUES (?,?,?,?,?)`,
			seq, "d", gen, "m", cert); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func evidenced(t *testing.T, c *claimTestVoter) int {
	t.Helper()
	st, err := c.c.AutomationMembershipStanding(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return len(st.ImportedVoters)
}

// One read scans a bounded number of anchors: b's only signature, beyond the
// first read's bound, is counted by a later read.
func TestAutomationEvidenceReadIsBounded(t *testing.T) {
	a, b, c := evidenceVoters(t)
	bound := int64(automationEvidencePage * automationEvidencePages)
	insertAnchors(t, c, 1, bound, 1, anchorCert(t, 1, a))
	insertAnchors(t, c, bound+1, bound+1, 1, anchorCert(t, 1, b))
	if got := evidenced(t, c); got != 1 {
		t.Fatalf("first read counted %d voters, want 1: it read past its bound of %d anchors", got, bound)
	}
	if got := evidenced(t, c); got != 2 {
		t.Fatalf("second read counted %d voters, want 2", got)
	}
}

// A certificate upgraded in place below the cursor is counted after an
// explicit reset of the scan, and after the rescan interval.
func TestAutomationEvidenceRevisitsUpgradedAnchors(t *testing.T) {
	a, b, c := evidenceVoters(t)
	insertAnchors(t, c, 1, 3, 1, anchorCert(t, 1, a))
	if got := evidenced(t, c); got != 1 {
		t.Fatalf("fixture: %d voters, want 1", got)
	}
	if _, err := c.c.db.Exec(`UPDATE local_automation_anchors SET certificate = ? WHERE sequence = 2`, anchorCert(t, 1, a, b)); err != nil {
		t.Fatal(err)
	}
	c.c.ResetAutomationEvidenceScan()
	if got := evidenced(t, c); got != 2 {
		t.Fatalf("after a reset of the scan: %d voters, want 2", got)
	}

	if _, err := c.c.db.Exec(`UPDATE local_automation_anchors SET certificate = ? WHERE sequence = 1`, anchorCert(t, 1, a, b, c)); err != nil {
		t.Fatal(err)
	}
	if got := evidenced(t, c); got != 2 {
		t.Fatalf("inside the rescan interval: %d voters, want still 2", got)
	}
	defer func(d time.Duration) { automationEvidenceRescanInterval = d }(automationEvidenceRescanInterval)
	automationEvidenceRescanInterval = 0
	if got := evidenced(t, c); got != 3 {
		t.Fatalf("after the rescan interval: %d voters, want 3", got)
	}
}

// Anchors of other generations are not read as evidence for this one, and
// do not use up the read's bound.
func TestAutomationEvidenceReadsOnlyItsGeneration(t *testing.T) {
	a, b, c := evidenceVoters(t)
	bound := int64(automationEvidencePage * automationEvidencePages)
	insertAnchors(t, c, 1, bound, 0, anchorCert(t, 1, a, b, c))
	insertAnchors(t, c, bound+1, bound+1, 1, anchorCert(t, 1, a))
	if got := evidenced(t, c); got != 1 {
		t.Fatalf("counted %d voters, want 1: anchors of another generation were read, or used up the bound", got)
	}
}
