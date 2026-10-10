package grpcapi

import (
	"context"
	"math/big"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pki"
)

// With no voter generation nothing is signed, so a replaced certificate is
// revoked at once; a host's LIVE serial is never revoked through this path.
//
// Mutation: drop the hostRecordedWithSerial refusal — the live certificate is
// revoked (and its host would be fenced).
func TestRevokeReplacedCertificate_PublishesOrRefuses(t *testing.T) {
	ctx := context.Background()
	s := voterTestServer(t)
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
