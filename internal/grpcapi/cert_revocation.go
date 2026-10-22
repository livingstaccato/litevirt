package grpcapi

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"math/big"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/notify"
	"github.com/litevirt/litevirt/internal/pki"
)

// Revoking the certificate a renewal replaced.
//
// Revocation is the default, and it is IMMEDIATE. A replaced key that stays
// CA-valid is a live client, server and vote-signing credential for the rest
// of its five years, and on this build nothing needs it: the voter and claim
// serial pin (corrosion.ClaimVerifier.WithSerialPin) already refuses its
// accepts, whether or not it is revoked, on every node that holds the
// successor — which every node collects from the renewed host's handshakes.
//
// A HOLD helps only a node that does NOT pin. Revoking the replaced serial
// makes the newest voter generation unverifiable, for a node that adopts it
// later, when that generation needed the serial's accept
// (docs/design/recovery-claims.md §4.1); a pinning node cannot count that
// accept either way, but a node that does not pin could, and revoking would
// stall it. Two kinds of node do not pin: one on an older build, and one
// running with auth.trust_rotated_peer_certs. So a revocation is held only
// while the cluster has one of those (revocationHoldReason) AND the newest
// generation would stop verifying for it (revocationSafeForVoters). Then it is
// OWED:
//
//   - the CA-signed CRL (minted on the CA machine, which holds the only key that
//     can sign one) is stored in a replicated health condition
//     (certificate/revocation_owed), which every node lists as a degraded
//     reason, and the host notifies certificate.revocation_owed daily;
//   - every node re-checks owed revocations on each certificate-watch tick and
//     publishes the CRL as soon as no hold applies — the older build upgraded,
//     trust_rotated_peer_certs turned off everywhere — or the newest generation
//     verifies with the serial revoked. It publishes only from a replica it
//     can trust with that judgement (owedPublishTrust): caught up, holding
//     and having adopted the newest generation, and in contact with a voter
//     majority of it that holds nothing newer.
//
// The storage reuses health_conditions' existing replicated statement shape, so
// it reaches peers on the previous release without a new table, shape or
// capability token; a peer that does not run this check stores the row and
// leaves the publishing to the nodes that do. The CRL itself is verified on
// every node before it is installed, and nodes enforce the union of every CRL
// they hold, so a delayed publication can never un-revoke anything.
const (
	certEvaluator       = "certificate"
	condRevocationOwed  = "revocation_owed"
	revocationOwedEvery = 24 * time.Hour

	// condTrustRotated is each node's own report that it runs with
	// auth.trust_rotated_peer_certs, which turns its serial pins off: the one
	// configuration, besides an older build, for which an owed hold protects
	// anything. Replicated so every node's hold decision can see it.
	condTrustRotated = "trust_rotated_peer_certs"
	// condCRLInstallFailed is raised by a node that cannot install the
	// cluster CRL. It judges no owed row while it stands.
	condCRLInstallFailed = "crl_install_failed"
	// condSerialRegressed is raised for a host recorded (hosts.cert_serial)
	// with a certificate whose revocation is owed: a pki dir restored from
	// backup, or a peer rewriting the column. Display only — the column is
	// peer-writable and decides nothing here.
	condSerialRegressed = "serial_regressed"
)

// owedTamperSettle is how long an owed row must have looked dropped — marked
// resolved or tombstoned with no CA-verified CRL revoking its serial — on THIS
// node before it is judged tampered. The row and the CRL that justifies a
// legitimate resolve replicate independently (health_conditions comes before
// cluster_crl in an anti-entropy exchange, and broadcasts can be lost), so a
// row resolved moments ago elsewhere is not yet evidence. The clock is local
// observation, not a timestamp in the row, which the writer chooses. A var so
// tests can shorten it.
var owedTamperSettle = 3 * time.Minute

// owedContactTimeout bounds each voter's answer in owedPublishTrust.
var owedContactTimeout = 3 * time.Second

// certRevocationState is what owed-revocation processing remembers between
// ticks on this node.
type certRevocationState struct {
	mu sync.Mutex
	// suspect is when this node first saw each owed row (subject id) dropped
	// without proof.
	suspect map[string]time.Time
}

func (st *certRevocationState) firstSuspect(subject string, now time.Time) time.Time {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.suspect == nil {
		st.suspect = map[string]time.Time{}
	}
	if at, ok := st.suspect[subject]; ok {
		return at
	}
	st.suspect[subject] = now
	return now
}

func (st *certRevocationState) clearSuspect(subject string) {
	st.mu.Lock()
	defer st.mu.Unlock()
	delete(st.suspect, subject)
}

type revocationOwedEvidence struct {
	Host   string `json:"host"`
	Serial string `json:"serial"`
	Reason string `json:"reason"`
	CRLPEM string `json:"crl_pem"`
}

// RevokeReplacedCertificate publishes req.CrlPem now, unless a hold applies
// (see above), in which case it records the revocation as owed.
func (s *Server) RevokeReplacedCertificate(ctx context.Context, req *pb.RevokeReplacedCertificateRequest) (*pb.RevokeReplacedCertificateResponse, error) {
	if err := RequireRole(ctx, "admin"); err != nil {
		return nil, err
	}
	serial := strings.ToLower(strings.TrimSpace(req.Serial))
	if req.Host == "" || serial == "" || req.CrlPem == "" {
		return nil, status.Error(codes.InvalidArgument, "host, serial and crl_pem are required")
	}
	version, err := pki.VerifiedCRLNumber(s.pkiDir, []byte(req.CrlPem))
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "refusing this CRL: %v", err)
	}
	if !crlLists(req.CrlPem, serial) {
		return nil, status.Errorf(codes.InvalidArgument, "the CRL does not revoke %s", serial)
	}
	// Never the certificate a host is recorded with — that is `lv host rm`'s
	// job, and done by accident it fences a healthy host — unless the CA has
	// demonstrably replaced it: the recorded column is replicated data any
	// peer can write back to a replaced serial, and that must not keep the
	// replaced certificate alive. The proof is the successor's CA signature,
	// which this node holds once it has seen the host present it (a handshake;
	// asked for here if need be).
	if owner, err := hostRecordedWithSerial(ctx, s.db, serial, req.GetHost()); err != nil {
		return nil, status.Errorf(codes.Unavailable, "read host records: %v", err)
	} else if owner != "" && !s.knownReplaced(ctx, owner, serial) {
		return nil, status.Errorf(codes.FailedPrecondition,
			"%s is the certificate the cluster records for %s; revoking it would cut that host off", serial, owner)
	}
	// The host's fence ssh row still signed by the serial: revoked now, every
	// peer refuses to fence the host until its daemon re-signs the row. Owed
	// instead, and published by ProcessOwedRevocations once it has.
	if why := s.fenceSSHHold(ctx, req.Host, serial); why != "" {
		if err := s.recordRevocationOwed(ctx, req.Host, serial, why, req.CrlPem); err != nil {
			return nil, status.Errorf(codes.Internal, "record the owed revocation: %v", err)
		}
		return &pb.RevokeReplacedCertificateResponse{Held: true, Reason: why, Version: version}, nil
	}
	hold, err := s.revocationHoldReason(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "check the cluster's builds: %v", err)
	}
	if hold == "" {
		if err := s.publishCRL(ctx, req.CrlPem); err != nil {
			return nil, err
		}
		return &pb.RevokeReplacedCertificateResponse{Revoked: true, Version: version}, nil
	}
	// Judging the voter chain for the node the hold protects needs the same
	// trusted view an owed publish does: a stale replica's "newest
	// generation" may not be the newest that exists.
	safe, why := false, ""
	if ok, untrusted := s.owedPublishTrust(ctx); !ok {
		why = untrusted
	} else if safe, why, err = s.revocationSafeForVoters(ctx, serial); err != nil {
		return nil, status.Errorf(codes.Unavailable, "check the voter chain: %v", err)
	}
	if safe {
		if err := s.publishCRL(ctx, req.CrlPem); err != nil {
			return nil, err
		}
		return &pb.RevokeReplacedCertificateResponse{Revoked: true, Version: version}, nil
	}
	why = hold + "; " + why
	if err := s.recordRevocationOwed(ctx, req.Host, serial, why, req.CrlPem); err != nil {
		return nil, status.Errorf(codes.Internal, "record the owed revocation: %v", err)
	}
	return &pb.RevokeReplacedCertificateResponse{Held: true, Reason: why, Version: version}, nil
}

// knownReplaced reports whether this node holds standing CA proof that host's
// certificate serial was replaced, asking the host for the certificate it
// presents (whose handshake hands over the proof) when it does not yet.
func (s *Server) knownReplaced(ctx context.Context, host, serial string) bool {
	if _, ok := pki.SupersededBy(s.pkiDir, host, serial); ok {
		return true
	}
	if host == s.hostName {
		if leaf, err := pki.ServedHostCertificate(s.pkiDir); err == nil {
			pki.NoteSuccessor(s.pkiDir, leaf)
		}
	} else {
		pctx, cancel := context.WithTimeout(ctx, owedContactTimeout)
		if cl, closer, err := s.dialPeer(pctx, host); err == nil {
			_, _ = cl.Ping(pctx, &pb.PingRequest{}) // the handshake is the point
			closer()
		}
		cancel()
	}
	_, ok := pki.SupersededBy(s.pkiDir, host, serial)
	return ok
}

func (s *Server) publishCRL(ctx context.Context, crlPEM string) error {
	if err := corrosion.PublishCRL(ctx, s.db, crlPEM); err != nil {
		return status.Errorf(codes.Internal, "publish CRL to the cluster: %v", err)
	}
	if _, err := corrosion.SyncClusterCRL(ctx, s.db, s.pkiDir); err != nil {
		return status.Errorf(codes.Internal, "CRL published but not installed locally: %v", err)
	}
	return nil
}

func crlLists(crlPEM, serial string) bool {
	for _, got := range pki.CRLSerials([]byte(crlPEM)) {
		if strings.EqualFold(got, serial) {
			return true
		}
	}
	return false
}

// hostRecordedWithSerial names the live host whose recorded certificate is
// serial, or "". When more than one row names it (a peer wrote the serial
// into another row), prefer's row is the one judged — the host the
// revocation is about — and otherwise the first by name, never an accident
// of row order.
func hostRecordedWithSerial(ctx context.Context, db *corrosion.Client, serial, prefer string) (string, error) {
	rows, err := db.Query(ctx, `SELECT name FROM hosts WHERE lower(cert_serial) = ? AND deleted_at IS NULL ORDER BY name`,
		strings.ToLower(serial))
	if err != nil || len(rows) == 0 {
		return "", err
	}
	for _, r := range rows {
		if r.String("name") == prefer {
			return prefer, nil
		}
	}
	return rows[0].String("name"), nil
}

// revocationHoldReason says why the cluster may have a node that does NOT pin
// voter and claim accepts to unreplaced certificates — the only node an owed
// hold protects — or "" when it has none: every live host reports this build,
// and no node runs with auth.trust_rotated_peer_certs. A replica that has not
// caught up cannot rule either out, and says so.
//
// Both inputs are replicated rows a compromised peer could write. Forging one
// only buys a HOLD, and a held certificate is still refused by every pinning
// node — as a voter, as a claim signer and on every RPC (connIdentityGate).
func (s *Server) revocationHoldReason(ctx context.Context) (string, error) {
	if ok, why := s.db.ReplicaCaughtUp(); !ok {
		return "this node's replica is not trusted yet (" + why + "), so a host on an older build cannot be ruled out", nil
	}
	if s.trustRotatedPeerCerts.Load() {
		return "this node runs with auth.trust_rotated_peer_certs, which turns its serial pins off", nil
	}
	hosts, err := corrosion.ListHosts(ctx, s.db)
	if err != nil {
		return "", err
	}
	builds := map[string][]string{}
	live := map[string]bool{}
	for _, h := range hosts {
		builds[h.Version] = append(builds[h.Version], h.Name)
		live[h.Name] = true
	}
	if len(builds) > 1 {
		var parts []string
		for v, names := range builds {
			if v == "" {
				v = "unknown"
			}
			sort.Strings(names)
			parts = append(parts, fmt.Sprintf("%s on %s", strings.Join(names, ","), v))
		}
		sort.Strings(parts)
		return "hosts run different builds (" + strings.Join(parts, "; ") + "), and an older one does not pin " +
			"accepts to unreplaced certificates", nil
	}
	conds, deleted, err := corrosion.ListHealthConditionsByCode(ctx, s.db, certEvaluator, condTrustRotated)
	if err != nil {
		return "", err
	}
	var on []string
	for i, c := range conds {
		if deleted[i] || c.Lifecycle == corrosion.ConditionResolved || !live[c.SubjectID] {
			continue
		}
		on = append(on, c.SubjectID)
	}
	if len(on) > 0 {
		sort.Strings(on)
		return "auth.trust_rotated_peer_certs is on at " + strings.Join(on, ",") + ", which turns their serial pins off", nil
	}
	return "", nil
}

// fenceSSHHold says why the revocation of host's replaced certificate serial
// must wait for host's fence ssh row: the row is still signed by that serial
// (internal/fencessh). Every peer verifies a row against the CRL and refuses
// to fence a host whose row does not verify — it never falls back to an
// unpinned fence — so revoking first would leave the host unfenceable until
// its daemon re-signed the row, which it does within a minute of adopting the
// renewal. "" when the host has no live row, or it is signed by another
// certificate.
func (s *Server) fenceSSHHold(ctx context.Context, host, serial string) string {
	row, ok, err := corrosion.GetHostFenceSSH(ctx, s.db, host)
	if err != nil || !ok || row.Deleted {
		return ""
	}
	cert, err := pki.ParseCertPEM([]byte(row.CertPEM))
	if err != nil || !strings.EqualFold(cert.SerialNumber.Text(16), serial) {
		return ""
	}
	return fmt.Sprintf("%s's fence ssh row is still signed by %s, and every peer refuses to fence a host whose row "+
		"does not verify; it is revoked once %s's daemon re-signs the row with its renewed certificate", host, serial, host)
}

// revocationSafeForVoters reports whether revoking serial keeps the newest
// voter generation verifiable against the CRL for a node that does NOT pin —
// the anchor such a node needs when it adopts it later (§4.1). Asked only
// while a hold applies (revocationHoldReason).
//
// It only ever says "safe" from a voter state this node can trust: a replica
// that has completed an anti-entropy exchange since it started (or last lost
// every peer), and that has ADOPTED the newest generation it holds. The owed
// row and the voter chain replicate independently — a reseeding, newly
// admitted or long-partitioned node can hold the row with an empty or partial
// chain — so anything less is "not yet known" and holds.
//
// No voter generation at all means nothing is signed with the serial: safe.
// Both callers ask only from a replica owedPublishTrust vouches for, so "none
// here" is "none at a voter majority". A newest generation that does not
// verify here holds: this replica cannot judge it.
func (s *Server) revocationSafeForVoters(ctx context.Context, serial string) (bool, string, error) {
	if ok, why := s.db.ReplicaCaughtUp(); !ok {
		return false, "this node's replica is not trusted yet (" + why + ")", nil
	}
	rows, err := corrosion.ListVoterConfigs(ctx, s.db)
	if err != nil {
		return false, "", err
	}
	if len(rows) == 0 {
		// Nothing is signed with the serial. For an owed revocation the
		// caller has established (owedPublishTrust) that a voter majority
		// holds no generation either.
		return true, "", nil
	}
	newest := rows[len(rows)-1]
	adopted, err := corrosion.AdoptedVoterGeneration(ctx, s.db)
	if err != nil {
		return false, "", err
	}
	if adopted < newest.Generation {
		return false, fmt.Sprintf("this node has adopted voter generation %d of %d; it judges only the chain it holds",
			adopted, newest.Generation), nil
	}
	var prev *corrosion.VoterConfig
	for _, r := range rows {
		if r.Generation == newest.Generation-1 {
			prev = r
		}
	}
	_, v, err := s.claimIdentity()
	if err != nil {
		return false, "", err
	}
	v = v.WithoutSerialPin() // the node the hold protects does not pin
	if err := verifyRowSignatures(v, prev, newest); err != nil {
		return false, fmt.Sprintf("voter generation %d does not verify on this node (%v)", newest.Generation, err), nil
	}
	if err := verifyRowSignatures(v.WithRevoked(serial), prev, newest); err != nil {
		return false, fmt.Sprintf("voter generation %d would no longer verify for a node that does not pin and "+
			"adopts it later (%v); the revocation is published once a newer generation does, or once no such "+
			"node is left", newest.Generation, err), nil
	}
	return true, "", nil
}

// owedPublishTrust reports whether this node may judge and publish owed
// revocations — and judge an owed row tampered — from its own replica. That is
// the voter-decision notion of a trusted replica:
//
//   - it has caught up (an anti-entropy exchange completed since it started or
//     last lost every peer);
//   - it has ADOPTED the newest voter generation it holds (none, before
//     genesis);
//   - a majority of that generation's members (the derived voter set when it
//     has none) answer now, each having adopted it, and none holds a newer
//     one. A minority partition cannot assemble that majority, and a node
//     mid-exchange after a heal — which can hold a peer's owed row before the
//     generation that supersedes its own, or before any generation at all —
//     hears of the newer generation from the members and holds. A reported
//     newer generation is checked, not believed (verifyNewerGeneration): the
//     member must hand over the next generation with a certificate that
//     verifies here, or its answer is not counted — so one compromised voter
//     answering with a made-up number, or a junk voter_configs row, can no
//     longer veto every judgement and silence tamper detection.
func (s *Server) owedPublishTrust(ctx context.Context) (bool, string) {
	if ok, why := s.db.ReplicaCaughtUp(); !ok {
		return false, "this node's replica is not trusted yet (" + why + ")"
	}
	rows, err := corrosion.ListVoterConfigs(ctx, s.db)
	if err != nil {
		return false, "voter generations could not be read: " + err.Error()
	}
	adopted, err := corrosion.AdoptedVoterGeneration(ctx, s.db)
	if err != nil {
		return false, "the adopted voter generation could not be read: " + err.Error()
	}
	newest := &corrosion.VoterConfig{}
	if len(rows) > 0 {
		newest = rows[len(rows)-1]
	}
	if adopted < newest.Generation {
		return false, fmt.Sprintf("this node has adopted voter generation %d of %d", adopted, newest.Generation)
	}
	var members []string
	if newest.Explicit() {
		members = newest.Names()
	} else {
		set, err := corrosion.DerivedVoterSet(ctx, s.db)
		if err != nil {
			return false, "the derived voter set could not be read: " + err.Error()
		}
		for n := range set {
			members = append(members, n)
		}
		sort.Strings(members)
	}
	need := corrosion.MajorityOf(len(members))
	type answer struct {
		name             string
		adopted, highest int64
		err              error
	}
	answers := make(chan answer, len(members))
	var wg sync.WaitGroup
	for _, m := range members {
		if m == s.hostName {
			answers <- answer{name: m, adopted: adopted, highest: newest.Generation}
			continue
		}
		wg.Add(1)
		go func(m string) {
			defer wg.Done()
			pctx, cancel := context.WithTimeout(ctx, owedContactTimeout)
			defer cancel()
			cl, closer, err := s.dialPeer(pctx, m)
			if err != nil {
				answers <- answer{name: m, err: err}
				return
			}
			defer closer()
			resp, err := cl.GetVoterConfig(pctx, &pb.GetVoterConfigRequest{})
			if err != nil {
				answers <- answer{name: m, err: err}
				return
			}
			answers <- answer{name: m, adopted: resp.GetAdoptedGeneration(), highest: resp.GetLatestGeneration()}
		}(m)
	}
	wg.Wait()
	close(answers)
	count := 0
	for a := range answers {
		if a.err != nil {
			continue
		}
		if a.highest > newest.Generation || a.adopted > newest.Generation {
			// A number is only a claim: any voter can answer with one, and any
			// peer can write a voter_configs row nobody can adopt. It vetoes
			// only when the member hands over a NEXT generation whose
			// certificate verifies here; otherwise it is not an answer.
			err := s.verifyNewerGeneration(ctx, a.name, newest)
			if err == nil {
				return false, fmt.Sprintf("%s holds voter generation %d, newer than this node's %d; this replica is "+
					"behind", a.name, max(a.highest, a.adopted), newest.Generation)
			}
			slog.Warn("a voter reports a newer voter generation that does not verify here; its answer is not counted",
				"member", a.name, "claimed", max(a.highest, a.adopted), "newest_here", newest.Generation, "error", err)
			continue
		}
		if a.adopted == newest.Generation {
			count++
		}
	}
	if count < need {
		return false, fmt.Sprintf("in contact with %d of the %d members of voter generation %d that have adopted it; "+
			"needs %d", count, len(members), newest.Generation, need)
	}
	return true, ""
}

// verifyNewerGeneration pulls member's voter_configs rows and checks the
// generation after newest (this node's newest; generation 0 means none)
// against it: a signed decision of newest's electorate, with authentic
// signatures (revocations since disregarded, as history). nil means the
// member really holds a newer generation, so this replica is behind.
func (s *Server) verifyNewerGeneration(ctx context.Context, member string, newest *corrosion.VoterConfig) error {
	pctx, cancel := context.WithTimeout(ctx, owedContactTimeout)
	defer cancel()
	cl, closer, err := s.dialPeer(pctx, member)
	if err != nil {
		return err
	}
	defer closer()
	st, err := cl.StreamTableRows(pctx, &pb.TableDumpRequest{Tables: []string{"voter_configs"}})
	if err != nil {
		return err
	}
	var pages []*pb.TableRowsPage
	for {
		p, err := st.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		pages = append(pages, p)
		if p.GetFinal() && p.GetTable() == "voter_configs" {
			break
		}
	}
	rows, err := corrosion.VoterConfigsFromPages(pages)
	if err != nil {
		return err
	}
	var prev *corrosion.VoterConfig
	if newest != nil && newest.Generation > 0 {
		prev = newest
	}
	var next *corrosion.VoterConfig
	for _, r := range rows {
		if r.Generation == newest.Generation+1 {
			next = r
			break
		}
	}
	if next == nil {
		return fmt.Errorf("it holds no generation %d", newest.Generation+1)
	}
	_, verifier, err := s.claimIdentity()
	if err != nil {
		return err
	}
	return verifyRowSignatures(verifier.Historical(), prev, next)
}

func (s *Server) recordRevocationOwed(ctx context.Context, host, serial, why, crlPEM string) error {
	ts := time.Now().UTC().Format(time.RFC3339)
	ev, _ := json.Marshal(revocationOwedEvidence{Host: host, Serial: serial, Reason: why, CRLPEM: crlPEM})
	if err := corrosion.UpsertHealthCondition(ctx, s.db, corrosion.HealthCondition{
		Evaluator: certEvaluator, Code: condRevocationOwed, SubjectKind: "host", SubjectID: host + "/" + serial,
		Lifecycle: corrosion.ConditionConfirmed, Severity: corrosion.SeverityWarning, Hosts: []string{host},
		Evidence: string(ev), ObserveCount: 1, FirstSeen: ts, LastSeen: ts, ConfirmedAt: ts, Reporter: s.hostName,
	}); err != nil {
		return err
	}
	slog.Warn("revocation of a replaced host certificate is owed", "host", host, "serial", serial, "reason", why)
	s.notify(ctx, notify.Notification{Kind: "certificate.revocation_owed", Severity: notify.SevWarn,
		Subject: host, Detail: fmt.Sprintf("the replaced certificate %s is not revoked yet: %s", serial, why)})
	return nil
}

// owedNotified throttles the daily reminder per condition on this node.
var owedNotified sync.Map // subject id -> time.Time

// condRevocationTampered is raised when an owed revocation's row says it is
// done (resolved, tombstoned) or its evidence was replaced, but the serial is
// not in the installed CRL: a peer dropped it without publishing it.
const condRevocationTampered = "revocation_owed_tampered"

// ProcessOwedRevocations runs on every certificate-watch tick. It reports this
// node's trust_rotated_peer_certs posture, then publishes every owed
// revocation that no hold applies to any more and resolves its condition; one
// still held is re-announced daily by the host it belongs to. Safe to run on
// every node at once: a CRL is stored keyed by its own bytes, and resolving
// twice writes the same state.
//
// "Done" requires proof, not a row state. The row is replicated data any peer
// can write, so a revocation counts as done only when its serial is in the
// CRL this node installed from CA-verified rows. A row marked resolved or
// tombstoned without that is put back to owed and raised as
// certificate/revocation_owed_tampered; so is a row whose evidence no longer
// carries a CA-signed CRL listing its serial (the serial is read from the
// row's key, which an overwrite cannot change). That judgement is made only
// from a trusted replica (owedPublishTrust), only after the cluster CRL has
// been installed this tick, and only once the row has looked dropped here for
// owedTamperSettle — so a node that holds a legitimately resolved row before
// the CRL that justifies it accuses no one. A node that cannot install the
// cluster CRL raises one condition (certificate/crl_install_failed) and judges
// nothing until it can, so it never contests a row it cannot check.
func (s *Server) ProcessOwedRevocations(ctx context.Context) {
	if s.db == nil {
		return
	}
	s.reportTrustRotated(ctx)
	conds, deleted, err := corrosion.ListHealthConditionsByCode(ctx, s.db, certEvaluator, condRevocationOwed)
	if err != nil || len(conds) == 0 {
		return
	}
	if _, err := corrosion.SyncClusterCRL(ctx, s.db, s.pkiDir); err != nil {
		s.setOwnCondition(ctx, condCRLInstallFailed, corrosion.SeverityWarning, true,
			"this node could not install the cluster CRL ("+stableErrorText(err)+"); it judges no owed revocation "+
				"until it can — check pki_dir/crl.pem and the daemon log")
		return
	}
	s.setOwnCondition(ctx, condCRLInstallFailed, corrosion.SeverityWarning, false, "")
	// Judged at most once per tick, and only when some row needs it.
	var (
		trustDone, trusted, holdDone bool
		untrustedWhy, hold           string
		holdErr                      error
	)
	trust := func() (bool, string) {
		if !trustDone {
			trusted, untrustedWhy = s.owedPublishTrust(ctx)
			trustDone = true
		}
		return trusted, untrustedWhy
	}
	holdReason := func() (string, error) {
		if !holdDone {
			hold, holdErr = s.revocationHoldReason(ctx)
			holdDone = true
		}
		return hold, holdErr
	}
	now := time.Now()
	for i, cnd := range conds {
		host, serial, ok := strings.Cut(cnd.SubjectID, "/")
		n := mustSerialInt(serial)
		if !ok || n == nil {
			continue
		}
		serial = strings.ToLower(serial)
		if pki.IsCertRevoked(s.pkiDir, n) {
			s.certRev.clearSuspect(cnd.SubjectID)
			s.settleTamper(ctx, host, serial)
			s.settleRegressed(ctx, serial)
			if cnd.Lifecycle != corrosion.ConditionResolved && !deleted[i] {
				s.resolveOwed(ctx, cnd)
			}
			continue
		}
		var ev revocationOwedEvidence
		evOK := json.Unmarshal([]byte(cnd.Evidence), &ev) == nil && ev.CRLPEM != "" && crlLists(ev.CRLPEM, serial)
		if evOK {
			if _, err := pki.VerifiedCRLNumber(s.pkiDir, []byte(ev.CRLPEM)); err != nil {
				evOK = false
			}
		}
		if !evOK {
			if ok, _ := trust(); ok {
				s.raiseTamper(ctx, host, serial, "its evidence no longer carries a CA-signed CRL revoking it — "+
					"publish one from the CA machine with `lv host revoke-cert "+host+" --serial "+serial+"`")
			}
			continue
		}
		if cnd.Lifecycle == corrosion.ConditionResolved || deleted[i] {
			if ok, _ := trust(); !ok {
				continue
			}
			if now.Sub(s.certRev.firstSuspect(cnd.SubjectID, now)) < owedTamperSettle {
				continue // the CRL that justifies it may still be on its way
			}
			s.raiseTamper(ctx, host, serial, "its row was marked done although the serial was never revoked; "+
				"it is owed again")
			cnd.Lifecycle, cnd.ResolvedAt = corrosion.ConditionConfirmed, ""
			if err := corrosion.UpsertHealthCondition(ctx, s.db, cnd); err != nil {
				slog.Warn("could not restore an owed revocation", "serial", serial, "error", err)
			}
		}
		s.certRev.clearSuspect(cnd.SubjectID)
		s.reportRegressed(ctx, host, serial)
		ok, why := trust()
		if !ok {
			s.remindOwed(ctx, cnd.SubjectID, host, serial, why)
			continue
		}
		if why := s.fenceSSHHold(ctx, host, serial); why != "" {
			s.remindOwed(ctx, cnd.SubjectID, host, serial, why)
			continue
		}
		h, err := holdReason()
		if err != nil {
			continue
		}
		if h != "" {
			safe, why, err := s.revocationSafeForVoters(ctx, serial)
			if err != nil {
				continue
			}
			if !safe {
				s.remindOwed(ctx, cnd.SubjectID, host, serial, h+"; "+why)
				continue
			}
		}
		if err := s.publishCRL(ctx, ev.CRLPEM); err != nil {
			slog.Warn("could not publish an owed revocation; retrying", "serial", serial, "error", err)
			continue
		}
		slog.Warn("published an owed revocation now that nothing holds it", "host", host, "serial", serial)
		s.notify(ctx, notify.Notification{Kind: "certificate.revoked", Severity: notify.SevInfo, Subject: host,
			Detail: fmt.Sprintf("the replaced certificate %s is now revoked", serial)})
		s.resolveOwed(ctx, cnd)
		s.settleRegressed(ctx, serial)
	}
}

// reportRegressed raises serial_regressed (display only) when a live host is
// recorded with an owed serial. It never blocks the publish: the column is
// peer-writable, and a host that really presents a replaced certificate is
// refused by every node that holds the successor anyway. Such a host — a pki
// dir restored from a backup taken before a renewal — is cut off once the
// revocation is published; renew it again, or re-initialise it.
func (s *Server) reportRegressed(ctx context.Context, host, serial string) {
	owner, err := hostRecordedWithSerial(ctx, s.db, serial, host)
	if err != nil || owner == "" {
		s.settleRegressed(ctx, serial)
		return
	}
	s.setCondition(ctx, condSerialRegressed, owner+"/"+serial, owner, corrosion.SeverityWarning, true,
		fmt.Sprintf("%s is recorded with %s, a certificate whose revocation is owed after a renewal of %s. "+
			"Either its pki dir was restored from before the renewal, or a peer rewrote the record. The "+
			"revocation is published regardless; if %s really presents %s, renew or re-initialise it",
			owner, serial, host, owner, serial))
}

func (s *Server) settleRegressed(ctx context.Context, serial string) {
	conds, deleted, err := corrosion.ListHealthConditionsByCode(ctx, s.db, certEvaluator, condSerialRegressed)
	if err != nil {
		return
	}
	for i, c := range conds {
		if deleted[i] || c.Lifecycle == corrosion.ConditionResolved || !strings.HasSuffix(c.SubjectID, "/"+serial) {
			continue
		}
		s.resolveOwed(ctx, c)
	}
}

// reportTrustRotated keeps this node's certificate/trust_rotated_peer_certs
// condition in step with its own flag, writing only on a change.
func (s *Server) reportTrustRotated(ctx context.Context) {
	s.setOwnCondition(ctx, condTrustRotated, corrosion.SeverityWarning, s.trustRotatedPeerCerts.Load(),
		"auth.trust_rotated_peer_certs is on: this node relaxes the peer serial pin, the voter and claim serial pins "+
			"and the stale-connection judge, and the cluster holds the revocation of replaced certificates while it "+
			"is on. Turn it off once the fleet has replicated its re-recorded serials")
}

// setOwnCondition raises or resolves a certificate condition about this host.
func (s *Server) setOwnCondition(ctx context.Context, code, severity string, raised bool, detail string) {
	s.setCondition(ctx, code, s.hostName, s.hostName, severity, raised, detail)
}

// setCondition raises (raised) or resolves the certificate condition
// code/subject, writing only when its state changes.
func (s *Server) setCondition(ctx context.Context, code, subject, host, severity string, raised bool, detail string) {
	if s.db == nil {
		return
	}
	cur, ok, err := corrosion.GetHealthCondition(ctx, s.db, certEvaluator, code, "host", subject)
	if err != nil {
		return
	}
	active := ok && cur.Lifecycle != corrosion.ConditionResolved
	ts := time.Now().UTC().Format(time.RFC3339)
	if !raised {
		if active {
			s.resolveOwed(ctx, cur)
		}
		return
	}
	ev, _ := json.Marshal(map[string]string{"host": host, "detail": detail})
	if active && cur.Evidence == string(ev) {
		return
	}
	first := ts
	if active && cur.FirstSeen != "" {
		first = cur.FirstSeen
	}
	if err := corrosion.UpsertHealthCondition(ctx, s.db, corrosion.HealthCondition{
		Evaluator: certEvaluator, Code: code, SubjectKind: "host", SubjectID: subject,
		Lifecycle: corrosion.ConditionConfirmed, Severity: severity, Hosts: []string{host},
		Evidence: string(ev), ObserveCount: 1, FirstSeen: first, LastSeen: ts, ConfirmedAt: first, Reporter: s.hostName,
	}); err != nil {
		slog.Warn("could not record a certificate condition", "code", code, "subject", subject, "error", err)
		return
	}
	if !active {
		slog.Warn("certificate condition raised", "code", code, "subject", subject, "detail", detail)
	}
}

func (s *Server) remindOwed(ctx context.Context, subject, host, serial, why string) {
	if host != s.hostName {
		return
	}
	if last, ok := owedNotified.Load(subject); ok && time.Since(last.(time.Time)) < revocationOwedEvery {
		return
	}
	owedNotified.Store(subject, time.Now())
	s.notify(ctx, notify.Notification{Kind: "certificate.revocation_owed", Severity: notify.SevWarn,
		Subject: host, Detail: fmt.Sprintf("the replaced certificate %s is still not revoked: %s", serial, why)})
}

func (s *Server) resolveOwed(ctx context.Context, cnd corrosion.HealthCondition) {
	ts := time.Now().UTC().Format(time.RFC3339)
	cnd.Lifecycle, cnd.ResolvedAt, cnd.LastSeen, cnd.Reporter = corrosion.ConditionResolved, ts, ts, s.hostName
	if err := corrosion.UpsertHealthCondition(ctx, s.db, cnd); err != nil {
		slog.Warn("could not resolve an owed revocation", "subject", cnd.SubjectID, "error", err)
	}
}

func (s *Server) raiseTamper(ctx context.Context, host, serial, why string) {
	subject := host + "/" + serial
	if cur, ok, err := corrosion.GetHealthCondition(ctx, s.db, certEvaluator, condRevocationTampered, "host", subject); err == nil &&
		ok && cur.Lifecycle != corrosion.ConditionResolved {
		return
	}
	ts := time.Now().UTC().Format(time.RFC3339)
	ev, _ := json.Marshal(map[string]string{"host": host, "serial": serial, "detail": why})
	if err := corrosion.UpsertHealthCondition(ctx, s.db, corrosion.HealthCondition{
		Evaluator: certEvaluator, Code: condRevocationTampered, SubjectKind: "host", SubjectID: subject,
		Lifecycle: corrosion.ConditionConfirmed, Severity: corrosion.SeverityCritical, Hosts: []string{host},
		Evidence: string(ev), ObserveCount: 1, FirstSeen: ts, LastSeen: ts, ConfirmedAt: ts, Reporter: s.hostName,
	}); err != nil {
		return
	}
	slog.Error("an owed revocation was dropped without being published", "host", host, "serial", serial, "detail", why)
	s.notify(ctx, notify.Notification{Kind: "certificate.revocation_owed_tampered", Severity: notify.SevError,
		Subject: host, Detail: fmt.Sprintf("the owed revocation of %s: %s", serial, why)})
}

func (s *Server) settleTamper(ctx context.Context, host, serial string) {
	cur, ok, err := corrosion.GetHealthCondition(ctx, s.db, certEvaluator, condRevocationTampered, "host", host+"/"+serial)
	if err != nil || !ok || cur.Lifecycle == corrosion.ConditionResolved {
		return
	}
	s.resolveOwed(ctx, cur)
}

// stableErrorText is err's text with the path of every file-system error
// left out — "install CRL: rename: file exists", not the random name of the
// temporary file it renamed. A condition's evidence carries it, and a
// condition is rewritten whenever its evidence changes: with the path in it, a
// node failing the same way every tick (a full disk) would upsert a
// replicated row every tick.
func stableErrorText(err error) string {
	msg := err.Error()
	var pe *fs.PathError
	if errors.As(err, &pe) {
		msg = strings.Replace(msg, pe.Error(), pe.Op+": "+pe.Err.Error(), 1)
	}
	var le *os.LinkError
	if errors.As(err, &le) {
		msg = strings.Replace(msg, le.Error(), le.Op+": "+le.Err.Error(), 1)
	}
	return msg
}

func mustSerialInt(hexSerial string) *big.Int {
	n, ok := new(big.Int).SetString(strings.TrimPrefix(hexSerial, "0x"), 16)
	if !ok {
		return nil
	}
	return n
}

// ConnJudge is this server's policy for established connections
// (pki.ConnTracker): a connection is closed AT ONCE when the client
// certificate it was made with has since been revoked, or the host certificate
// THIS side served on it has been, and that certificate has no standing
// CA-issued successor (an emergency revocation). It drains (no new RPC,
// closed once its RPCs in flight end, within the tracker's grace) when it was
// made with a host certificate that is no longer the host's — one the CA has
// replaced (pki.SupersededBy), revoked since or not (a renewal revokes the
// replaced certificate at once, and its in-flight transfers are left to
// finish), or, as the peer pin has it, one the cluster no longer records that
// is not the recorded serial's successor. The client reconnects with a fresh
// handshake.
//
// Build one per sweep: it reads the hosts table once, the first time a host
// certificate needs judging, and keeps it for that sweep only.
func (s *Server) ConnJudge(ctx context.Context) func(pki.TrackedConn) pki.Verdict {
	revoked := pki.RevocationChecker(s.pkiDir)
	var hosts map[string]hostPin
	return func(c pki.TrackedConn) pki.Verdict {
		if c.Peer != nil && revoked(c.Peer.SerialNumber) {
			if s.revokedByRenewal(c.Peer) {
				return pki.Verdict{Close: true, Reason: "the client certificate was replaced by a renewal and revoked"}
			}
			return pki.Verdict{Close: true, Immediate: true, Reason: "the client certificate was revoked"}
		}
		if n := mustSerialInt(c.ServedSerial); c.ServedSerial != "" && n != nil && revoked(n) {
			if s.servedRevokedByRenewal(c.ServedSerial) {
				return pki.Verdict{Close: true, Reason: "the certificate this host served on it was replaced by a renewal and revoked"}
			}
			return pki.Verdict{Close: true, Immediate: true, Reason: "the certificate this host served on it was revoked"}
		}
		if c.Peer != nil && isHostCert(c.Peer) && !s.trustRotatedPeerCerts.Load() {
			if err := pki.SupersededError(s.pkiDir, c.Peer); err != nil {
				return pki.Verdict{Close: true, Reason: err.Error()}
			}
			if hosts == nil {
				hosts = s.readHostPins(ctx)
			}
			if staleHostIdentity(hosts, c.Peer) {
				return pki.Verdict{Close: true, Reason: "made with a host certificate the cluster no longer records"}
			}
		}
		return pki.Verdict{}
	}
}

type hostPin struct {
	serial  string
	deleted bool
}

func (s *Server) readHostPins(ctx context.Context) map[string]hostPin {
	out := map[string]hostPin{}
	if s.db == nil {
		return out
	}
	rows, err := s.db.Query(ctx, `SELECT name, cert_serial, deleted_at FROM hosts`)
	if err != nil {
		return out // unreadable: judge nothing stale this sweep
	}
	for _, r := range rows {
		out[r.String("name")] = hostPin{serial: strings.ToLower(r.String("cert_serial")), deleted: r.String("deleted_at") != ""}
	}
	return out
}

func isHostCert(leaf *x509.Certificate) bool {
	for _, u := range leaf.ExtKeyUsage {
		if u == x509.ExtKeyUsageServerAuth {
			return true
		}
	}
	return false
}

// staleHostIdentity reports whether leaf is a host certificate that peer trust
// would no longer accept as its host: a live row records another serial, and
// leaf is not that serial's CA-attested successor.
func staleHostIdentity(hosts map[string]hostPin, leaf *x509.Certificate) bool {
	if leaf == nil || leaf.SerialNumber == nil {
		return false
	}
	h, ok := hosts[leaf.Subject.CommonName]
	if !ok || h.deleted || h.serial == "" || h.serial == "unknown" {
		return false
	}
	presented := strings.ToLower(leaf.SerialNumber.Text(16))
	if h.serial == presented {
		return false
	}
	if prev, ok := pki.RenewedFromSerial(leaf); ok && prev == h.serial {
		return false
	}
	return true
}
