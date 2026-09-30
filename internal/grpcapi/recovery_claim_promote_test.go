package grpcapi

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// claimingServer is a voter-ready server that is the whole adopted voter
// generation, with recovery claims enforced.
func claimingServer(t *testing.T) *Server {
	t.Helper()
	ctx := context.Background()
	s := recoveryClaimServer(t, true, capabilities.SplitBrainGateV1, capabilities.RecoveryClaimV1)
	s.db.SetRecoveryClaimGate(func() bool { return true })
	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{
		Name: s.hostName, Address: "10.0.0.1", SSHUser: "root", State: "active", CertSerial: "s",
	}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}
	inc, err := s.db.VoterIncarnation(ctx)
	if err != nil {
		t.Fatal(err)
	}
	adoptTestGeneration(t, s, []corrosion.VoterMember{{Name: s.hostName, Incarnation: inc}})
	if !s.RecoveryClaimEnforced(ctx) {
		t.Fatal("recovery claims are not enforced on the fixture; the rest is vacuous")
	}
	return s
}

// TestAutoPromote_ClaimsBeforeItPersists: an automated promotion's proof is
// claimed once its destination — the replica's host — is known, and the proof
// that is persisted and relayed carries the certificate (§3.13). The claim's
// source is the VM's recorded owner, the fenced host.
//
// Mutation: skip claimPromote in promoteResolvedIn — the persisted promote
// proof carries no certificate.
func TestAutoPromote_ClaimsBeforeItPersists(t *testing.T) {
	s := claimingServer(t)
	seedReplicaOfAge(t, s, "db-c", "0 * * * *", 10*time.Minute)
	err0 := s.AutoPromoteReplica(context.Background(), "db-c", "", 0) // may fail later: no libvirt here
	t.Logf("AutoPromoteReplica: %v", err0)

	rows, err := s.db.Query(context.Background(), `SELECT id FROM runtime_action_proofs WHERE target_name = 'db-c'`)
	if err != nil || len(rows) != 1 {
		t.Fatalf("want exactly one promote proof, got %d (%v)", len(rows), err)
	}
	pr, _, err := corrosion.GetActionProof(context.Background(), s.db, rows[0].String("id"))
	if err != nil {
		t.Fatal(err)
	}
	cert, err := corrosion.CertificateAuthorizesProof(pr.ClaimCertificate, pr.ActionProof)
	if err != nil {
		t.Fatalf("the persisted promote proof is not certified: %v (cert %q)", err, pr.ClaimCertificate)
	}
	if cert.SourceHost != "dead-host" {
		t.Fatalf("the promote was claimed with source %q, want the VM's recorded owner dead-host", cert.SourceHost)
	}
}
