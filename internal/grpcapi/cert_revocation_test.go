package grpcapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pki"
)

// With no voter generation nothing is signed, so a replaced certificate is
// revoked at once; a host's LIVE serial is never revoked through this path.
//
// Mutations: drop the hostRecordedWithSerial refusal — the live certificate is
// revoked (and its host would be fenced); drop the ReplicaCaughtUp check in
// revocationHoldReason — the replica that has not caught up revokes at once.
func TestRevokeReplacedCertificate_PublishesOrRefuses(t *testing.T) {
	ctx := context.Background()
	s := voterTestServer(t)
	// Not caught up: this replica cannot rule out a node on an older build,
	// so the answer is "held", never "revoked".
	early, err := s.RevokeReplacedCertificate(adminCtx(), &pb.RevokeReplacedCertificateRequest{
		Host: "node-r", Serial: "dead02", CrlPem: mintCRL(t, s.pkiDir, "dead02")})
	if err != nil || early.Revoked || !early.Held {
		t.Fatalf("a replica that has not caught up judged a revocation safe: %+v %v", early, err)
	}
	s.db.MarkReplicaCaughtUpForTests("test")
	s.peerClientOverride = noPeersReachable
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

func noPeersReachable(context.Context, string) (pb.LiteVirtClient, func(), error) {
	return nil, nil, fmt.Errorf("unreachable")
}

// voterPeer answers GetVoterConfig as a peer at the given generations, and
// hands over its voter_configs rows (pages) when asked for them.
type voterPeer struct {
	pb.LiteVirtClient
	adopted, latest int64
	pages           []*pb.TableRowsPage
}

func (p voterPeer) GetVoterConfig(context.Context, *pb.GetVoterConfigRequest, ...grpc.CallOption) (*pb.GetVoterConfigResponse, error) {
	return &pb.GetVoterConfigResponse{AdoptedGeneration: p.adopted, LatestGeneration: p.latest}, nil
}

func (p voterPeer) StreamTableRows(context.Context, *pb.TableDumpRequest, ...grpc.CallOption) (grpc.ServerStreamingClient[pb.TableRowsPage], error) {
	return &pageStream{pages: append([]*pb.TableRowsPage(nil), p.pages...)}, nil
}

type pageStream struct {
	grpc.ClientStream
	pages []*pb.TableRowsPage
}

func (s *pageStream) Recv() (*pb.TableRowsPage, error) {
	if len(s.pages) == 0 {
		return nil, io.EOF
	}
	p := s.pages[0]
	s.pages = s.pages[1:]
	return p, nil
}

func peersWith(peers map[string]voterPeer) func(context.Context, string) (pb.LiteVirtClient, func(), error) {
	return func(_ context.Context, host string) (pb.LiteVirtClient, func(), error) {
		p, ok := peers[host]
		if !ok {
			return nil, nil, fmt.Errorf("%s unreachable", host)
		}
		return p, func() {}, nil
	}
}

// voterRowPages is a peer's voter_configs table holding rows, as
// StreamTableRows pages it.
func voterRowPages(t *testing.T, rows ...struct {
	val  corrosion.VoterConfigValue
	cert corrosion.ClaimCertificate
}) []*pb.TableRowsPage {
	t.Helper()
	ctx := context.Background()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	db.SetVoterConfigGate(func() bool { return true })
	for _, r := range rows {
		if err := corrosion.WriteVoterConfig(ctx, db, r.val, r.cert); err != nil {
			t.Fatal(err)
		}
	}
	var pages []*pb.TableRowsPage
	if err := db.StreamTableRowsScoped(ctx, []string{"voter_configs"}, nil, func(p *pb.TableRowsPage) error {
		pages = append(pages, p)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return pages
}

type voterRowAndCert = struct {
	val  corrosion.VoterConfigValue
	cert corrosion.ClaimCertificate
}

// gen2RmP2 is generation 2 (rm node-p2) of the 3-member generation 1 that
// adoptTestGeneration wrote — {s, node-p1 (i1), node-p2 (i2)} — decided by s
// and node-p1, a majority, when signed is true; with signed false it carries
// no accepts at all.
func gen2RmP2(t *testing.T, s *Server, signed bool) voterRowAndCert {
	t.Helper()
	ctx := context.Background()
	gen1, err := corrosion.GetVoterConfig(ctx, s.db, 1)
	if err != nil || gen1 == nil {
		t.Fatalf("generation 1: %v", err)
	}
	inc, _ := s.db.VoterIncarnation(ctx)
	val := corrosion.VoterConfigValue{Generation: 2, Members: corrosion.SortMembers([]corrosion.VoterMember{
		{Name: s.hostName, Incarnation: inc}, {Name: "node-p1", Incarnation: "i1"}}),
		Change: corrosion.VoterChangeRm("node-p2"), CreatedBy: "test", CreatedAt: "test"}
	want, err := corrosion.ExpectedVoterConfigCertificate(gen1, val)
	if err != nil {
		t.Fatal(err)
	}
	ballot := corrosion.Ballot{Round: 3, Coordinator: s.hostName, Nonce: []byte{3}}
	cert := corrosion.ClaimCertificate{Key: want.Key, ConfigGeneration: want.ConfigGeneration, Ballot: ballot,
		ValueDigest: want.ValueDigest}
	if !signed {
		return voterRowAndCert{val, cert}
	}
	self, _, err := s.claimIdentity()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := pki.GenerateHostCert(filepath.Join(s.pkiDir, "ca.crt"), filepath.Join(s.pkiDir, "ca.key"),
		filepath.Join(dir, "host.crt"), filepath.Join(dir, "host.key"), "node-p1", net.ParseIP("127.0.0.1")); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(s.pkiDir, "ca.crt"))
	_ = os.WriteFile(filepath.Join(dir, "ca.crt"), b, 0o600)
	p1, err := corrosion.LoadClaimSigner(dir, "node-p1")
	if err != nil {
		t.Fatal(err)
	}
	for _, sg := range []struct {
		signer *corrosion.ClaimSigner
		inc    string
	}{{self, inc}, {p1, "i1"}} {
		a, err := sg.signer.Sign(want.Key, want.ConfigGeneration, ballot, want.ValueDigest, sg.inc)
		if err != nil {
			t.Fatal(err)
		}
		cert.Accepts = append(cert.Accepts, a)
	}
	return voterRowAndCert{val, cert}
}

func peersAt(gens map[string][2]int64) func(context.Context, string) (pb.LiteVirtClient, func(), error) {
	return func(_ context.Context, host string) (pb.LiteVirtClient, func(), error) {
		g, ok := gens[host]
		if !ok {
			return nil, nil, fmt.Errorf("%s unreachable", host)
		}
		return voterPeer{adopted: g[0], latest: g[1]}, func() {}, nil
	}
}

// selfGenesis writes and adopts a generation 1 signed by s alone.
func selfGenesis(t *testing.T, s *Server) {
	t.Helper()
	ctx := context.Background()
	s.db.SetVoterConfigGate(func() bool { return true })
	inc, _ := s.db.VoterIncarnation(ctx)
	val := corrosion.VoterConfigValue{Generation: 1, Members: []corrosion.VoterMember{{Name: s.hostName, Incarnation: inc}},
		Change: corrosion.VoterChangeGenesis, CreatedBy: "test", CreatedAt: "test"}
	if err := corrosion.WriteVoterConfig(ctx, s.db, val, signGeneration(t, s, nil, val)); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.RecordVoterAdoption(ctx, s.db, 1); err != nil {
		t.Fatal(err)
	}
}

// mixedBuilds records two live hosts on different builds: a node that does
// not pin may exist, so a hold applies.
func mixedBuilds(t *testing.T, s *Server) {
	t.Helper()
	ctx := context.Background()
	for name, v := range map[string]string{s.hostName: "v2", "node-old": "v1"} {
		if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{Name: name, Address: "10.0.0.8",
			State: "active", Version: v}); err != nil {
			t.Fatal(err)
		}
	}
}

// With the pin in force everywhere, a replaced certificate is revoked AT ONCE,
// even when the newest voter generation needed its accept: no node on this
// build could count that accept anyway. Only a node that does not pin — an
// older build, or auth.trust_rotated_peer_certs anywhere — makes it owed, and
// once that is gone the owed revocation is published.
//
// Mutations: always return a hold reason from revocationHoldReason (the
// pinned cluster holds); ignore other nodes' trust_rotated_peer_certs
// condition (the cluster revokes while a node that does not pin depends on the
// generation); ignore differing builds (likewise).
func TestRevokeReplacedCertificate_RevokesAtOnceUnderThePin(t *testing.T) {
	ctx := context.Background()
	s := voterTestServer(t)
	s.db.MarkReplicaCaughtUpForTests("test")
	selfGenesis(t, s)
	signer, _, err := s.claimIdentity()
	if err != nil {
		t.Fatal(err)
	}
	needed := signer.Serial() // generation 1 needs this certificate's accept

	resp, err := s.RevokeReplacedCertificate(adminCtx(), &pb.RevokeReplacedCertificateRequest{
		Host: s.hostName, Serial: needed, CrlPem: mintCRL(t, s.pkiDir, needed)})
	if err != nil || !resp.Revoked || resp.Held {
		t.Fatalf("a pinned cluster held a revocation it gains nothing from holding: %+v %v", resp, err)
	}

	// Another node runs with trust_rotated_peer_certs: it does not pin, and
	// revoking would stall it. Owed.
	s2 := voterTestServer(t)
	s2.db.MarkReplicaCaughtUpForTests("test")
	s2.peerClientOverride = noPeersReachable
	selfGenesis(t, s2)
	sg2, _, _ := s2.claimIdentity()
	for _, h := range []string{s2.hostName, "node-tr"} {
		if err := corrosion.InsertHost(ctx, s2.db, corrosion.HostRecord{Name: h, Address: "10.0.0.8", State: "active"}); err != nil {
			t.Fatal(err)
		}
	}
	other := &Server{hostName: "node-tr", db: s2.db}
	other.SetTrustRotatedPeerCerts(true)
	other.reportTrustRotated(ctx)
	resp, err = s2.RevokeReplacedCertificate(adminCtx(), &pb.RevokeReplacedCertificateRequest{
		Host: s2.hostName, Serial: sg2.Serial(), CrlPem: mintCRL(t, s2.pkiDir, sg2.Serial())})
	if err != nil || resp.Revoked || !resp.Held || !strings.Contains(resp.Reason, "trust_rotated") {
		t.Fatalf("revoked while a node that does not pin needed it: %+v %v", resp, err)
	}
	// The node turns the switch off; the next tick publishes.
	other.SetTrustRotatedPeerCerts(false)
	other.reportTrustRotated(ctx)
	s2.ProcessOwedRevocations(ctx)
	n2, _ := new(big.Int).SetString(sg2.Serial(), 16)
	if !pki.IsCertRevoked(s2.pkiDir, n2) {
		t.Fatal("the owed revocation was not published once no node needed the hold")
	}

	// Different builds hold the same way.
	s3 := voterTestServer(t)
	s3.db.MarkReplicaCaughtUpForTests("test")
	selfGenesis(t, s3)
	sg3, _, _ := s3.claimIdentity()
	mixedBuilds(t, s3)
	resp, err = s3.RevokeReplacedCertificate(adminCtx(), &pb.RevokeReplacedCertificateRequest{
		Host: s3.hostName, Serial: sg3.Serial(), CrlPem: mintCRL(t, s3.pkiDir, sg3.Serial())})
	if err != nil || resp.Revoked || !resp.Held || !strings.Contains(resp.Reason, "builds") {
		t.Fatalf("revoked while a host on another build needed it: %+v %v", resp, err)
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

// An owed revocation is never published from a replica that cannot be
// trusted with the judgement: one that has not caught up, one where the owed
// row arrived before voter_configs (no chain here, while the voter majority
// has one), or one that has not adopted the newest generation it holds.
//
// Mutations: drop the ReplicaCaughtUp check from owedPublishTrust — the
// replica that has not caught up publishes; drop the newer-generation check
// there — the node without the chain publishes; drop the adopted-generation
// check — the node that has not adopted the newest generation publishes.
func TestOwedRevocation_HeldUntilTheVoterStateIsTrusted(t *testing.T) {
	ctx := context.Background()
	s, _ := owedFixture(t)
	for _, h := range []string{s.hostName, "node-p1"} {
		if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{Name: h, Address: "10.0.0.7", State: "active"}); err != nil {
			t.Fatal(err)
		}
	}
	s.peerClientOverride = peersAt(map[string][2]int64{"node-p1": {1, 1}})

	s.ProcessOwedRevocations(ctx) // replica not caught up
	if dead01Revoked(s) {
		t.Fatal("published from a replica that has not caught up")
	}
	s.db.MarkReplicaCaughtUpForTests("test")
	s.ProcessOwedRevocations(ctx) // health_conditions arrived, voter_configs not yet
	if dead01Revoked(s) {
		t.Fatal("published from a replica that holds the owed row but not the voter chain its peers hold")
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
	// Adopted, and nothing holds it: published, resolved.
	if err := corrosion.RecordVoterAdoption(ctx, s.db, 1); err != nil {
		t.Fatal(err)
	}
	s.ProcessOwedRevocations(ctx)
	if !dead01Revoked(s) {
		t.Fatal("an owed revocation was not published from a trusted voter state")
	}
	if c, _, _ := corrosion.GetHealthCondition(ctx, s.db, "certificate", "revocation_owed", "host", "node-r/dead01"); c.Lifecycle != corrosion.ConditionResolved {
		t.Fatalf("the published revocation's row is %s, not resolved", c.Lifecycle)
	}
}

// An owed revocation is published only from a node in contact with a voter
// majority of the newest generation that holds nothing newer: a minority side
// of a partition holds, and so does a node mid-exchange that peers tell of a
// newer generation.
//
// Mutations: drop the majority count in owedPublishTrust — the minority side
// publishes; drop the newer-generation check — the node that is behind
// publishes.
func TestOwedRevocation_PublishedOnlyInContactWithAVoterMajority(t *testing.T) {
	ctx := context.Background()
	s, _ := owedFixture(t)
	s.db.MarkReplicaCaughtUpForTests("test")
	inc, _ := s.db.VoterIncarnation(ctx)
	adoptTestGeneration(t, s, []corrosion.VoterMember{{Name: s.hostName, Incarnation: inc},
		{Name: "node-p1", Incarnation: "i1"}, {Name: "node-p2", Incarnation: "i2"}})

	s.peerClientOverride = peersAt(nil) // a minority of one
	s.ProcessOwedRevocations(ctx)
	if dead01Revoked(s) {
		t.Fatal("published from the minority side of a partition")
	}
	s.peerClientOverride = peersWith(map[string]voterPeer{
		"node-p1": {adopted: 2, latest: 2, pages: voterRowPages(t, gen2RmP2(t, s, true))},
		"node-p2": {adopted: 1, latest: 1}})
	s.ProcessOwedRevocations(ctx)
	if dead01Revoked(s) {
		t.Fatal("published although a member holds a newer voter generation than this node")
	}
	s.peerClientOverride = peersAt(map[string][2]int64{"node-p1": {1, 1}})
	s.ProcessOwedRevocations(ctx)
	if !dead01Revoked(s) {
		t.Fatal("not published although a majority of the newest generation is in contact and current")
	}
}

// m1 (re-review 3): a member's report of a newer generation is checked
// against the signed row it hands over, not believed. A compromised voter
// answering with a made-up generation, or holding a junk voter_configs row
// nobody can adopt, is not counted — it cannot hold every owed revocation
// and silence tamper judgement for good — while a member that hands over a
// generation that verifies still makes this node hold (the previous test).
//
// Mutation: treat any reported newer generation as a veto (drop the
// verifyNewerGeneration check) — the junk claim holds the publish.
func TestOwedRevocation_AnUnverifiableNewerGenerationDoesNotHold(t *testing.T) {
	ctx := context.Background()
	// node-p1 claims generation 9 and holds no such row; then it holds a
	// generation 2 row with no valid accept. Neither is a newer decision.
	for _, junkRow := range []bool{false, true} {
		s, _ := owedFixture(t)
		s.db.MarkReplicaCaughtUpForTests("test")
		inc, _ := s.db.VoterIncarnation(ctx)
		adoptTestGeneration(t, s, []corrosion.VoterMember{{Name: s.hostName, Incarnation: inc},
			{Name: "node-p1", Incarnation: "i1"}, {Name: "node-p2", Incarnation: "i2"}})
		var pages []*pb.TableRowsPage
		if junkRow {
			pages = voterRowPages(t, gen2RmP2(t, s, false))
		}
		s.peerClientOverride = peersWith(map[string]voterPeer{
			"node-p1": {adopted: 1, latest: 9, pages: pages},
			"node-p2": {adopted: 1, latest: 1}})
		s.ProcessOwedRevocations(ctx)
		if !dead01Revoked(s) {
			t.Fatalf("a member's unverifiable report of a newer voter generation (junk row: %v) held the owed revocation", junkRow)
		}
	}
}

// While a hold applies, an adopted newest generation that does not verify
// here holds.
//
// Mutation: treat "does not verify here" as safe (the old rule).
func TestOwedRevocation_HeldWhenTheNewestGenerationDoesNotVerifyHere(t *testing.T) {
	ctx := context.Background()
	s, _ := owedFixture(t)
	s.db.MarkReplicaCaughtUpForTests("test")
	mixedBuilds(t, s)
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

// trustedHeldFixture is an owed revocation on a replica trusted to judge it
// (caught up, adopted the newest generation, which has only this node), with
// a hold in force (mixed builds) and a newest generation that does not verify,
// so the revocation stays owed: what tamper handling sees.
func trustedHeldFixture(t *testing.T) *Server {
	t.Helper()
	s, _ := owedFixture(t)
	s.db.MarkReplicaCaughtUpForTests("test")
	mixedBuilds(t, s)
	adoptTestGeneration(t, s, []corrosion.VoterMember{{Name: s.hostName, Incarnation: "i"}})
	return s
}

func dropOwedRow(t *testing.T, s *Server) {
	t.Helper()
	ctx := context.Background()
	cnd, ok, err := corrosion.GetHealthCondition(ctx, s.db, "certificate", "revocation_owed", "host", "node-r/dead01")
	if err != nil || !ok {
		t.Fatal("fixture: no owed row")
	}
	cnd.Lifecycle, cnd.ResolvedAt = corrosion.ConditionResolved, "2026-10-10T00:00:00Z"
	if err := corrosion.UpsertHealthCondition(ctx, s.db, cnd); err != nil {
		t.Fatal(err)
	}
}

func setTamperSettle(t *testing.T, d time.Duration) {
	t.Helper()
	orig := owedTamperSettle
	owedTamperSettle = d
	t.Cleanup(func() { owedTamperSettle = orig })
}

// A peer cannot drop an owed revocation silently: marking it resolved without
// the serial being revoked puts it back to owed and raises a critical
// condition, and so does replacing its evidence.
//
// Mutation: trust the row's lifecycle (skip resolved rows) — the dropped
// revocation stays dropped and nothing is raised.
func TestOwedRevocation_ADroppedRowIsRestoredAndRaised(t *testing.T) {
	ctx := context.Background()
	setTamperSettle(t, 0)
	s := trustedHeldFixture(t)
	dropOwedRow(t, s)
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
	s2 := trustedHeldFixture(t)
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

// Tamper is judged only where it can be: never from a replica that has not
// caught up, never before the row has looked dropped here for
// owedTamperSettle (the CRL that justifies a legitimate resolve may still be
// on its way), and never by a node that cannot install the cluster CRL — that
// one raises crl_install_failed, once, and leaves the row alone.
//
// Mutations: drop the trust gate on tamper judgement — the untrusted replica
// accuses and rewrites; drop the settle wait — a freshly resolved row is
// accused at once; ignore SyncClusterCRL's error — the node that cannot
// install the CRL rewrites the row on every tick.
func TestOwedRevocation_TamperIsJudgedOnlyFromATrustedReplica(t *testing.T) {
	ctx := context.Background()
	notJudged := func(t *testing.T, s *Server, what string) {
		t.Helper()
		if _, ok, _ := corrosion.GetHealthCondition(ctx, s.db, "certificate", "revocation_owed_tampered", "host", "node-r/dead01"); ok {
			t.Fatalf("%s: raised a tamper alarm", what)
		}
		c, _, _ := corrosion.GetHealthCondition(ctx, s.db, "certificate", "revocation_owed", "host", "node-r/dead01")
		if c.Lifecycle != corrosion.ConditionResolved {
			t.Fatalf("%s: rewrote the row to %s", what, c.Lifecycle)
		}
	}

	setTamperSettle(t, 0)
	untrusted, _ := owedFixture(t) // not caught up
	dropOwedRow(t, untrusted)
	untrusted.ProcessOwedRevocations(ctx)
	notJudged(t, untrusted, "a replica that has not caught up")

	setTamperSettle(t, time.Hour)
	fresh := trustedHeldFixture(t)
	dropOwedRow(t, fresh)
	fresh.ProcessOwedRevocations(ctx)
	notJudged(t, fresh, "a row that has only just looked dropped")

	setTamperSettle(t, 0)
	broken := trustedHeldFixture(t)
	if err := corrosion.PublishCRL(ctx, broken.db, mintCRL(t, broken.pkiDir, "beef")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(broken.pkiDir, "crl.pem"), 0o700); err != nil {
		t.Fatal(err)
	}
	dropOwedRow(t, broken)
	for i := 0; i < 3; i++ {
		broken.ProcessOwedRevocations(ctx)
	}
	notJudged(t, broken, "a node that cannot install the cluster CRL")
	c, ok, _ := corrosion.GetHealthCondition(ctx, broken.db, "certificate", "crl_install_failed", "host", broken.hostName)
	if !ok || c.Lifecycle == corrosion.ConditionResolved {
		t.Fatal("a node that cannot install the cluster CRL raised nothing")
	}
	// m3: the same failure every tick is the same evidence, so the replicated
	// row is written once, not every tick (the temporary file's random name
	// is not part of it).
	broken.ProcessOwedRevocations(ctx)
	again, _, _ := corrosion.GetHealthCondition(ctx, broken.db, "certificate", "crl_install_failed", "host", broken.hostName)
	if again.Evidence != c.Evidence {
		t.Fatalf("the same CRL install failure rewrote its condition:\n  %s\n  %s", c.Evidence, again.Evidence)
	}
}

// The hosts.cert_serial column is peer-writable and decides nothing: an owed
// serial recorded again (a peer writing it back, or a pki dir restored from
// before the renewal) does not block the publish. It is reported.
//
// Mutation: block the publish while a host is recorded with the serial (the
// round-3 owedBlockedReason) — the rewritten column keeps the replaced
// certificate unrevoked.
func TestOwedRevocation_ARewrittenSerialDoesNotBlockThePublish(t *testing.T) {
	ctx := context.Background()
	s, _ := owedFixture(t)
	s.db.MarkReplicaCaughtUpForTests("test")
	selfGenesis(t, s)
	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{Name: "node-r", Address: "10.0.0.9",
		State: "active", CertSerial: "dead01"}); err != nil {
		t.Fatal(err)
	}
	s.ProcessOwedRevocations(ctx)
	if !dead01Revoked(s) {
		t.Fatal("a serial written back into the host's row blocked its owed revocation")
	}
	if _, ok, _ := corrosion.GetHealthCondition(ctx, s.db, "certificate", "serial_regressed", "host", "node-r/dead01"); !ok {
		t.Fatal("a host recorded with an owed serial was not reported")
	}
}

func jsonString(v string) string {
	b, _ := json.Marshal(v)
	return string(b)
}
