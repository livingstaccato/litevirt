package grpcapi

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pki"
)

func TestProofComparisonRealServerAdapterWaitsOutsideDBAndClaims(t *testing.T) {
	for _, merge := range []bool{false, true} {
		t.Run(map[bool]string{false: "writer", true: "anti-entropy"}[merge], func(t *testing.T) {
			ctx := context.Background()
			s := claimingServer(t)
			signer, _, err := s.claimIdentity()
			if err != nil {
				t.Fatal(err)
			}
			inc, err := s.db.VoterIncarnation(ctx)
			if err != nil {
				t.Fatal(err)
			}
			proof := corrosion.ActionProof{ID: "trust-order", Action: corrosion.ActionReschedule, TargetKind: "vm", TargetName: "vm-order", DestHost: s.hostName, Coordinator: s.hostName, OwnerEpoch: "1"}
			key, err := corrosion.ClaimKeyForProof(proof, 1)
			if err != nil {
				t.Fatal(err)
			}
			value := corrosion.ClaimValue{Proof: &proof, SourceHost: "source"}
			ballot := corrosion.Ballot{Round: 1, Coordinator: s.hostName}
			accept, err := signer.Sign(key, 1, ballot, value.MustDigest(), inc)
			if err != nil {
				t.Fatal(err)
			}
			cert := corrosion.ClaimCertificate{Key: key, ConfigGeneration: 1, Ballot: ballot, ValueDigest: value.MustDigest(), SourceHost: "source", Accepts: []corrosion.ClaimAccept{accept}}
			proof.ClaimCertificate, err = cert.Encode()
			if err != nil {
				t.Fatal(err)
			}
			if err := corrosion.WriteActionProof(ctx, s.db, proof); err != nil {
				t.Fatal(err)
			}
			cert.Accepts[0].Signature = nil
			proof.ClaimCertificate, err = cert.Encode()
			if err != nil {
				t.Fatal(err)
			}
			var dump []byte
			if merge {
				peer := testServer(t)
				peer.db.SetRecoveryClaimGate(func() bool { return true })
				if err := corrosion.WriteActionProof(ctx, peer.db, proof); err != nil {
					t.Fatal(err)
				}
				dump = peer.db.DumpSensitiveStateBytes()
			}
			view, err := pki.CaptureHostTrust(ctx, s.pkiDir, s.hostName)
			if err != nil {
				t.Fatal(err)
			}
			pair, err := pki.ServedHostKeyPair(s.pkiDir)
			if err != nil {
				t.Fatal(err)
			}
			cap, err := view.ValidateHostCertificate(ctx, pair.Certificate, s.hostName)
			if err != nil {
				t.Fatal(err)
			}
			held, err := pki.AcquireHostCertificateLease(ctx, s.pkiDir, cap)
			if err != nil {
				t.Fatal(err)
			}
			defer held.Release()
			entered := make(chan struct{}, 1)
			s.db.SetClaimCertificateVerifier(func() *corrosion.ClaimVerifier { entered <- struct{}{}; return s.certificateVerifier() })
			done := make(chan error, 1)
			go func() {
				if merge {
					done <- s.db.MergeSensitiveStateBytesLWWContext(ctx, dump)
				} else {
					done <- corrosion.SetProofClaimCertificate(ctx, s.db, proof)
				}
			}()
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("comparison did not reach actual server adapter")
			}
			progress := make(chan error, 1)
			go func() { _, err := s.db.Query(ctx, `SELECT 1`); progress <- err }()
			select {
			case err := <-progress:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("server verifier waited on trust owner while holding DB")
			}
			claims := make(chan struct{})
			go func() { s.claims.mu.Lock(); s.claims.mu.Unlock(); close(claims) }()
			select {
			case <-claims:
			case <-time.After(time.Second):
				t.Fatal("served identity waited on owner while holding claims mutex")
			}
			select {
			case err := <-done:
				t.Fatalf("comparison crossed held PKI barrier: %v", err)
			case <-time.After(30 * time.Millisecond):
			}
			held.Release()
			select {
			case err := <-done:
				if merge && err != nil {
					t.Fatal(err)
				}
				if !merge && !errors.Is(err, corrosion.ErrNoRowsAffected) {
					t.Fatal(err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("comparison did not progress after owner release")
			}
		})
	}
}
