package grpcapi

import (
	"context"
	"encoding/json"
	"math/big"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pki"
)

// With no voter generation nothing is signed, so a replaced certificate is
// revoked at once; a host's LIVE serial is never revoked through this path.
//
// Mutations: drop the hostRecordedWithSerial refusal — the live certificate is
// revoked (and its host would be fenced); drop the ReplicaCaughtUp check — the
// replica that has not caught up revokes at once.
func TestRevokeReplacedCertificate_PublishesOrRefuses(t *testing.T) {
	ctx := context.Background()
	s := voterTestServer(t)
	// Not caught up: even with no voter chain at all, the answer is "held",
	// never "revoked" — this replica cannot know there is no chain.
	early, err := s.RevokeReplacedCertificate(adminCtx(), &pb.RevokeReplacedCertificateRequest{
		Host: "node-r", Serial: "dead02", CrlPem: mintCRL(t, s.pkiDir, "dead02")})
	if err != nil || early.Revoked || !early.Held {
		t.Fatalf("a replica that has not caught up judged a revocation safe: %+v %v", early, err)
	}
	s.db.MarkReplicaCaughtUpForTests("test")
	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{Name: "node-r", Address: "10.0.0.9",
		State: "active", CertSerial: "abc123"}); err != nil {
		t.Fatal(err)
	}
	live := mintCRL(t, s.pkiDir, "abc123")
	if _, err := s.RevokeReplacedCertificate(adminCtx(), &pb.RevokeReplacedCertificateRequest{
		Host: "node-r", Serial: "abc123", CrlPem: live}); err == nil {
		t.Fatal("revoked a host's recorded certificate")
	}
	if _, err := s.RevokeReplacedCertificate(adminCtx(), &pb.RevokeReplacedCertificateRequest{
		Host: "node-r", Serial: "dead01", CrlPem: live}); err == nil {
		t.Fatal("accepted a CRL that does not list the serial")
	}
	replaced := mintCRL(t, s.pkiDir, "dead01")
	resp, err := s.RevokeReplacedCertificate(adminCtx(), &pb.RevokeReplacedCertificateRequest{
		Host: "node-r", Serial: "dead01", CrlPem: replaced})
	if err != nil || !resp.Revoked || resp.Held {
		t.Fatalf("a safe revocation was not published: %+v %v", resp, err)
	}
	if !pki.IsCertRevoked(s.pkiDir, big.NewInt(0xdead01)) {
		t.Fatal("the published revocation is not installed")
	}
}

func owedFixture(t *testing.T) (*Server, string) {
	t.Helper()
	s := voterTestServer(t)
	crl := mintCRL(t, s.pkiDir, "dead01")
	if err := s.recordRevocationOwed(context.Background(), "node-r", "dead01", "test", crl); err != nil {
		t.Fatal(err)
	}
	return s, crl
}

func dead01Revoked(s *Server) bool { return pki.IsCertRevoked(s.pkiDir, big.NewInt(0xdead01)) }

// An owed revocation is never judged safe from voter state this node cannot
// trust: a replica that has not caught up, one where the owed row arrived
// before voter_configs (no chain at all), one that has not adopted the newest
// generation it holds, or one where that generation does not verify.
//
// Mutations: treat "no voter rows" as safe for an owed revocation — the node
// with no chain publishes; drop the adopted-generation check — the node that
// has not adopted the newest generation publishes.
func TestOwedRevocation_HeldUntilTheVoterStateIsTrusted(t *testing.T) {
	ctx := context.Background()
	s, _ := owedFixture(t)

	s.ProcessOwedRevocations(ctx) // replica not caught up
	if dead01Revoked(s) {
		t.Fatal("published from a replica that has not caught up")
	}
	s.db.MarkReplicaCaughtUpForTests("test")
	s.ProcessOwedRevocations(ctx) // health_conditions arrived, voter_configs not yet
	if dead01Revoked(s) {
		t.Fatal("published from a replica that holds the owed row but no voter chain")
	}
	// A genuinely signed generation is present but this node has not adopted
	// it: still not judged.
	s.db.SetVoterConfigGate(func() bool { return true })
	inc, _ := s.db.VoterIncarnation(ctx)
	val := corrosion.VoterConfigValue{Generation: 1, Members: []corrosion.VoterMember{{Name: s.hostName, Incarnation: inc}},
		Change: corrosion.VoterChangeGenesis, CreatedBy: "test", CreatedAt: "test"}
	if err := corrosion.WriteVoterConfig(ctx, s.db, val, signGeneration(t, s, nil, val)); err != nil {
		t.Fatal(err)
	}
	s.ProcessOwedRevocations(ctx)
	if dead01Revoked(s) {
		t.Fatal("published from a node that has not adopted the newest generation")
	}
	// Adopted and verifying, and dead01 signed nothing in it: safe, published,
	// resolved.
	if err := corrosion.RecordVoterAdoption(ctx, s.db, 1); err != nil {
		t.Fatal(err)
	}
	s.ProcessOwedRevocations(ctx)
	if !dead01Revoked(s) {
		t.Fatal("a safe owed revocation was not published from a trusted voter state")
	}
	if c, _, _ := corrosion.GetHealthCondition(ctx, s.db, "certificate", "revocation_owed", "host", "node-r/dead01"); c.Lifecycle != corrosion.ConditionResolved {
		t.Fatalf("the published revocation's row is %s, not resolved", c.Lifecycle)
	}
}

// An adopted newest generation that does not verify here holds.
//
// Mutation: treat "does not verify here" as safe (the old rule).
func TestOwedRevocation_HeldWhenTheNewestGenerationDoesNotVerifyHere(t *testing.T) {
	ctx := context.Background()
	s, _ := owedFixture(t)
	s.db.MarkReplicaCaughtUpForTests("test")
	adoptTestGeneration(t, s, []corrosion.VoterMember{{Name: s.hostName, Incarnation: "i"}}) // unsigned row
	s.ProcessOwedRevocations(ctx)
	if dead01Revoked(s) {
		t.Fatal("published although the newest generation does not verify on this node")
	}
}

// signGeneration signs val as s alone (s must be prev's only member, or val a
// genesis of s alone).
func signGeneration(t *testing.T, s *Server, prev *corrosion.VoterConfig, val corrosion.VoterConfigValue) corrosion.ClaimCertificate {
	t.Helper()
	want, err := corrosion.ExpectedVoterConfigCertificate(prev, val)
	if err != nil {
		t.Fatal(err)
	}
	signer, _, err := s.claimIdentity()
	if err != nil {
		t.Fatal(err)
	}
	ballot := corrosion.Ballot{Round: 1, Coordinator: s.hostName, Nonce: []byte{1}}
	inc, _ := s.db.VoterIncarnation(context.Background())
	a, err := signer.Sign(want.Key, want.ConfigGeneration, ballot, want.ValueDigest, inc)
	if err != nil {
		t.Fatal(err)
	}
	return corrosion.ClaimCertificate{Key: want.Key, ConfigGeneration: want.ConfigGeneration, Ballot: ballot,
		ValueDigest: want.ValueDigest, Accepts: []corrosion.ClaimAccept{a}}
}

// A peer cannot drop an owed revocation silently: marking it resolved without
// the serial being revoked puts it back to owed and raises a critical
// condition, and so does replacing its evidence.
//
// Mutation: trust the row's lifecycle (skip resolved rows) — the dropped
// revocation stays dropped and nothing is raised.
func TestOwedRevocation_ADroppedRowIsRestoredAndRaised(t *testing.T) {
	ctx := context.Background()
	s, _ := owedFixture(t)
	cnd, ok, err := corrosion.GetHealthCondition(ctx, s.db, "certificate", "revocation_owed", "host", "node-r/dead01")
	if err != nil || !ok {
		t.Fatal("fixture: no owed row")
	}
	cnd.Lifecycle, cnd.ResolvedAt = corrosion.ConditionResolved, "2026-10-10T00:00:00Z"
	if err := corrosion.UpsertHealthCondition(ctx, s.db, cnd); err != nil {
		t.Fatal(err)
	}
	s.ProcessOwedRevocations(ctx)
	if dead01Revoked(s) {
		t.Fatal("fixture: nothing should be published here")
	}
	again, _, _ := corrosion.GetHealthCondition(ctx, s.db, "certificate", "revocation_owed", "host", "node-r/dead01")
	if again.Lifecycle == corrosion.ConditionResolved {
		t.Fatal("a revocation marked done without being published stayed done")
	}
	tamper, ok, _ := corrosion.GetHealthCondition(ctx, s.db, "certificate", "revocation_owed_tampered", "host", "node-r/dead01")
	if !ok || tamper.Severity != corrosion.SeverityCritical {
		t.Fatal("dropping an owed revocation raised nothing")
	}

	// Replacing the evidence with a genuine CRL that does not list the serial.
	s2, _ := owedFixture(t)
	c2, _, _ := corrosion.GetHealthCondition(ctx, s2.db, "certificate", "revocation_owed", "host", "node-r/dead01")
	c2.Evidence = `{"host":"node-r","serial":"dead01","crl_pem":` + jsonString(mintCRL(t, s2.pkiDir, "beef")) + `}`
	if err := corrosion.UpsertHealthCondition(ctx, s2.db, c2); err != nil {
		t.Fatal(err)
	}
	s2.ProcessOwedRevocations(ctx)
	if _, ok, _ := corrosion.GetHealthCondition(ctx, s2.db, "certificate", "revocation_owed_tampered", "host", "node-r/dead01"); !ok {
		t.Fatal("replacing an owed revocation's CRL raised nothing")
	}
}

// A late publish never revokes a serial a host is recorded with again.
//
// Mutation: make owedBlockedReason return "" — the recorded serial is reported
// publishable.
func TestOwedRevocation_NeverRevokesARecordedSerial(t *testing.T) {
	ctx := context.Background()
	s, _ := owedFixture(t)
	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{Name: "node-r", Address: "10.0.0.9",
		State: "active", CertSerial: "dead01"}); err != nil {
		t.Fatal(err)
	}
	if why := s.owedBlockedReason(ctx, "dead01"); why == "" {
		t.Fatal("a serial recorded as a host's live certificate is publishable")
	}
	if why := s.owedBlockedReason(ctx, "beef"); why != "" {
		t.Fatalf("an unrecorded serial is blocked: %s", why)
	}
}

func jsonString(v string) string {
	b, _ := json.Marshal(v)
	return string(b)
}
