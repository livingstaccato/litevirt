package fleet

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/auth"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/grpcapi"
	"github.com/litevirt/litevirt/internal/pki"
	automationv1 "github.com/livingstaccato/litevirt/api/gen/litevirt/automation/v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/emptypb"
)

// Fetch actual authenticated Get evidence before the trust writer changes its
// validity. The storage consumer receives the exact same signed native state;
// the RPC assertions below rule out silently substituting fixture evidence.
func remainingOwnerCheckGet(t *testing.T, c nativeOwnerClient, s corrosion.ClaimVoterState) {
	t.Helper()
	r, e := c.f.cluster.PeerClient(c.f.cluster.Nodes[1], c.f.cluster.Nodes[0]).GetRecoveryClaim(c.f.Context(), &pb.GetRecoveryClaimRequest{Key: claimKeyPB(s.Key)})
	if e != nil || r.GetAccept() == nil || r.GetState().GetVoter() != c.f.cluster.Nodes[0].Name || r.GetAdoptedGeneration() != s.ConfigGeneration || r.GetAccept().GetValueDigest() != s.ValueDigest || !bytes.Equal(r.GetAccept().GetSignature(), s.Accept.Signature) || !bytes.Equal(r.GetState().GetAcceptedValue().GetAutomation().GetEnvelope(), s.Value.Automation.Envelope) {
		t.Fatalf("actual Get did not supply the stored native evidence: %+v %v", r, e)
	}
}

// Empty real replication still requires peer mTLS. It observes the same
// source/target as the later Accept, without changing any claim or issuance.
func remainingOwnerCheckPeerTransport(t *testing.T, c nativeOwnerClient) {
	t.Helper()
	source, target := c.f.cluster.Nodes[1], c.f.cluster.Nodes[0]
	_, e := c.f.cluster.PeerClient(source, target).PushMutations(c.f.Context(), &pb.ReplicateRequest{
		Sender: source.Name, SenderVersion: source.DB.LocalVersion(),
		SenderSchemaVersion: int32(source.DB.EffectiveDBSchema()), SenderCapabilities: source.Server.DeclaredCapabilities(),
	})
	if e != nil {
		t.Fatalf("CAUSAL_PRECONDITION: fresh real peer transport is unavailable: %v", e)
	}
}

func TestAutomationOwnerSessionNativeCurrentCRLAfterGet(t *testing.T) {
	c := newNativeOwnerClient(t, false)
	before, s := nativeOwnerUnpublished(t, c)
	remainingOwnerCheckGet(t, c, s)
	// Positive storage-consumption control on node 1 uses the authentic native
	// acceptance. The signer is node 1's real key; Sign happens in production
	// ClaimAcceptOwnerEvidence/FULL, never in the fixture.
	control, recipient := c.f.cluster.Nodes[1], c.f.cluster.Nodes[2]
	signer, e := corrosion.LoadClaimSigner(control.PKIDir, control.Name)
	if e != nil {
		t.Fatal(e)
	}
	b := corrosion.Ballot{Round: s.Accepted.Round + 20, Coordinator: control.Name, Nonce: []byte("current-native-trust")}
	accepted, e := control.DB.ClaimAcceptOwnerEvidence(c.f.Context(), s.Key, b, *s.Value, s.ConfigGeneration, signer, c.f.cluster.Nodes[0].Name, s)
	if e != nil || !accepted.Accepted || accepted.Accept == nil {
		t.Fatalf("genuine evidence control was not eligible: %+v %v", accepted, e)
	}
	block, _ := pem.Decode([]byte(s.Accept.CertPEM))
	if block == nil {
		t.Fatal("actual acceptance omitted its signer certificate")
	}
	leaf, e := x509.ParseCertificate(block.Bytes)
	if e != nil {
		t.Fatal(e)
	}
	serial := strings.ToLower(leaf.SerialNumber.Text(16))
	// Actual trust-owner publication, AFTER Get and BEFORE the consumer owns
	// its current trust view. Only recipient 2 sees this CRL. No membership,
	// credential, parent, envelope or standing gate is modified.
	if e := pki.GenerateCRL(c.f.cluster.caCert, c.f.cluster.caKey, filepath.Join(recipient.PKIDir, "crl.pem"), []string{serial}); e != nil {
		t.Fatal(e)
	}
	signer, e = corrosion.LoadClaimSigner(recipient.PKIDir, recipient.Name)
	if e != nil {
		t.Fatal(e)
	}
	b.Coordinator = recipient.Name
	refused, e := recipient.DB.ClaimAcceptOwnerEvidence(c.f.Context(), s.Key, b, *s.Value, s.ConfigGeneration, signer, c.f.cluster.Nodes[0].Name, s)
	if refused.Accepted || refused.Accept != nil {
		t.Fatalf("previously fetched evidence ignored actual current CRL: %+v %v", refused, e)
	}
	stored, _, e := recipient.DB.ClaimState(c.f.Context(), s.Key)
	if e != nil || stored.Accept != nil || stored.Value != nil {
		t.Fatalf("revoked evidence left recipient authority: %+v %v", stored, e)
	}
	c.assertNoOwnerEffects(t, before, "unpublished-native-owner")
}

// The original actual Login fixture is reproduced only to select the EXISTING
// short-certificate callback before genesis/any cached transport credentials.
// Identity history remains the same retained prerequisite helper. No owner
// success certificate or owner permit is constructed here.
func remainingOwnerShortLeafClient(t *testing.T) (nativeOwnerClient, time.Time) {
	t.Helper()
	var expiry time.Time
	f := newAutomationFixtureWith(t, 3, true, func(cluster *Cluster) {
		expiry = time.Now().Add(15 * time.Second).Truncate(time.Second)
		shortAutomationCertificates(t, cluster, expiry)
	})
	n := f.cluster.Nodes[0]
	legacy := f.cluster.SelfClient(n)
	if _, e := legacy.CreateProject(f.Context(), &pb.CreateProjectRequest{Name: nativeOwnerProject}); e != nil {
		t.Fatal(e)
	}
	if _, e := legacy.CreateUser(f.Context(), &pb.CreateUserRequest{Username: nativeOwnerUsername, Password: "native-owner-password-0123456789", Role: "operator"}); e != nil {
		t.Fatal(e)
	}
	nativeOwnerPrerequisiteHistory(t, f)
	if e := auth.SeedBuiltinRoles(f.Context(), n.DB); e != nil {
		t.Fatal(e)
	}
	n.Server.SetAuthEngine(auth.NewEngine(n.DB))
	r, e := legacy.Login(f.Context(), &pb.LoginRequest{Username: nativeOwnerUsername, Password: "native-owner-password-0123456789", Realm: "local"})
	if e != nil || !strings.HasPrefix(r.GetToken(), grpcapi.SessionTokenPrefix) {
		t.Fatalf("real Login in short-leaf fixture: %v", e)
	}
	p, e := corrosion.AutomationSessionPrincipal(f.Context(), n.DB, strings.TrimPrefix(r.GetToken(), grpcapi.SessionTokenPrefix))
	if e != nil || p == nil || p.UID != nativeOwnerPrincipalUID || p.ClusterUID != f.Head(t, 0).ClusterUID {
		t.Fatalf("short-leaf real Login provenance: %+v %v", p, e)
	}
	ctx := metadata.AppendToOutgoingContext(f.Context(), "authorization", "Bearer "+r.GetToken())
	who, e := legacy.Whoami(ctx, &emptypb.Empty{})
	if e != nil || who.GetUsername() != nativeOwnerUsername || who.GetRealm() != "local" {
		t.Fatalf("short-leaf actual TLS authentication: %+v %v", who, e)
	}
	return nativeOwnerClient{f: f, ctx: ctx, public: automationv1.NewAutomationClient(n.selfConn), owner: &automationv1.OwnerRef{ProjectUid: nativeOwnerProjectUID, OwnerId: "native-owner"}}, expiry
}

func TestAutomationOwnerSessionNativeExpiredOwnLeafRenewal(t *testing.T) {
	c, expiry := remainingOwnerShortLeafClient(t)
	before, s := nativeOwnerUnpublished(t, c)
	block, _ := pem.Decode([]byte(s.Accept.CertPEM))
	if block == nil {
		t.Fatal("native acceptance omitted leaf")
	}
	oldLeaf, e := x509.ParseCertificate(block.Bytes)
	if e != nil || !oldLeaf.NotAfter.Equal(expiry) || !time.Now().Before(expiry) {
		t.Fatalf("actual native vote did not precede selected signer expiry: %v", e)
	}
	if _, e := c.f.cluster.SelfClient(c.f.cluster.Nodes[0]).Logout(c.ctx, &emptypb.Empty{}); e != nil {
		t.Fatal(e)
	}
	// Fixture startup registered A, then shortAutomationCertificates renewed
	// A -> B. Record the actual intermediate B through the running daemon's
	// owner before B -> C: current peer admission recognizes an immediate
	// CA-attested successor, not a jump over an unrecorded generation.
	shortSerials := map[string]string{}
	for _, n := range c.f.cluster.Nodes {
		serial, e := pki.CertSerial(filepath.Join(n.PKIDir, "host.crt"))
		if e != nil {
			t.Fatal(e)
		}
		shortSerials[n.Name] = serial
		if _, e := corrosion.RecordOwnCertSerial(c.f.Context(), n.DB, n.Name, serial); e != nil {
			t.Fatal(e)
		}
	}
	c.f.cluster.WaitConverged(t, convergeTimeout)
	for _, n := range c.f.cluster.Nodes {
		for host, serial := range shortSerials {
			rows, e := n.DB.Query(c.f.Context(), `SELECT cert_serial FROM hosts WHERE name=? AND deleted_at IS NULL`, host)
			if e != nil || len(rows) != 1 || !strings.EqualFold(rows[0].String("cert_serial"), serial) {
				t.Fatalf("CAUSAL_PRECONDITION: %s did not learn %s's intermediate serial: %v", n.Name, host, e)
			}
		}
	}
	remainingOwnerCheckPeerTransport(t, c)
	remainingOwnerCheckGet(t, c, s)
	if !time.Now().Before(expiry) {
		t.Fatal("CAUSAL_PRECONDITION: intermediate certificate expired before real transport renewal")
	}
	// Renew every transport identity while the real old certificates still
	// work. The origin's OWN saved acceptance intentionally retains its old
	// leaf until an actual later FULL Accept renews that exact stored value.
	for _, n := range c.f.cluster.Nodes {
		serial, _ := installRenewal(t, c.f.cluster, n)
		if serial == "" || strings.EqualFold(serial, shortSerials[n.Name]) {
			t.Fatalf("%s did not install a distinct successor certificate", n.Name)
		}
	}
	remainingOwnerCheckPeerTransport(t, c)
	remainingOwnerCheckGet(t, c, s) // Transport C has not rewritten saved vote B.
	nativeOwnerWaitExpiry(t, c.f.Context(), expiry)
	if time.Now().Before(oldLeaf.NotAfter) {
		t.Fatal("old acceptance leaf has not actually expired")
	}
	// Prevent foreign Get evidence from supplying a different inductive base.
	for _, n := range c.f.cluster.Nodes[1:] {
		t.Cleanup(n.DoNotImplement("GetRecoveryClaim"))
	}
	r := nativeOwnerPeerAccept(t, c, 0, s, s.Accepted.Round+30, nil)
	if !r.GetAccepted() || r.GetAccept() == nil || r.GetAccept().GetCertPem() == s.Accept.CertPEM {
		t.Fatalf("expired own native row did not renew through real Accept: %+v", r)
	}
	stored, found, e := c.f.cluster.Nodes[0].DB.ClaimState(c.f.Context(), s.Key)
	if e != nil || !found || stored.Accept == nil || stored.Value == nil || !bytes.Equal(stored.Value.Automation.Envelope, s.Value.Automation.Envelope) {
		t.Fatalf("renewal changed original owner bytes: %+v %v", stored, e)
	}
	cfg, e := corrosion.AdoptedVoterConfig(c.f.Context(), c.f.cluster.Nodes[0].DB)
	if e != nil {
		t.Fatal(e)
	}
	v, e := corrosion.LoadClaimVerifier(c.f.cluster.Nodes[0].PKIDir)
	if e != nil {
		t.Fatal(e)
	}
	if e := v.Verify(corrosion.ClaimCertificate{Key: s.Key, ConfigGeneration: stored.ConfigGeneration, Ballot: stored.Accepted, ValueDigest: stored.ValueDigest, Accepts: []corrosion.ClaimAccept{*stored.Accept}}, corrosion.CertExpectation{Key: s.Key, ConfigGeneration: cfg.Generation, ValueDigest: s.ValueDigest, Electorate: cfg.Members, Quorum: 1}); e != nil {
		t.Fatalf("renewed stored acceptance lacks current trust: %v", e)
	}
	c.assertNoOwnerEffects(t, before, "unpublished-native-owner")
}
