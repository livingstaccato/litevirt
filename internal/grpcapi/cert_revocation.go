package grpcapi

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
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
// Revocation is the default — a replaced key that stays CA-valid is a live
// client, server and vote-signing credential for the rest of its five years.
// The one thing it can break is the voter chain: the newest voter generation's
// certificate carries each member's accept, signed with the certificate it held
// then, and a node that adopts that generation LATER verifies it against the
// CRL (docs/design/recovery-claims.md §4.1). When revoking the replaced serial
// would leave that generation short of a quorum of unrevoked signatures, the
// revocation is OWED instead of dropped:
//
//   - the CA-signed CRL (minted on the CA machine, which holds the only key that
//     can sign one) is stored in a replicated health condition
//     (certificate/revocation_owed), which every node lists as a degraded
//     reason, and the host notifies certificate.revocation_owed daily;
//   - every node re-checks owed revocations each minute and publishes the CRL
//     as soon as the newest generation verifies with the serial revoked —
//     typically after the next voter change, whose accepts the renewed voter
//     signs with its new certificate;
//   - meanwhile the claim serial pin (ClaimVerifier.PinnedTo) already refuses
//     accepts signed with the replaced key, and peer trust refuses it as a
//     peer, so what the hold leaves is a CA-valid client credential.
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
)

type revocationOwedEvidence struct {
	Host   string `json:"host"`
	Serial string `json:"serial"`
	Reason string `json:"reason"`
	CRLPEM string `json:"crl_pem"`
}

// RevokeReplacedCertificate publishes req.CrlPem now if that is safe for the
// voter chain, and otherwise records the revocation as owed (see above).
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
	// Never the certificate a host is recorded with: that is `lv host rm`'s job,
	// and done by accident it fences a healthy host.
	if owner, err := hostRecordedWithSerial(ctx, s.db, serial); err != nil {
		return nil, status.Errorf(codes.Unavailable, "read host records: %v", err)
	} else if owner != "" {
		return nil, status.Errorf(codes.FailedPrecondition,
			"%s is the certificate the cluster records for %s; revoking it would cut that host off", serial, owner)
	}
	safe, why, err := s.revocationSafeForVoters(ctx, serial, false)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "check the voter chain: %v", err)
	}
	if safe {
		if err := s.publishCRL(ctx, req.CrlPem); err != nil {
			return nil, err
		}
		return &pb.RevokeReplacedCertificateResponse{Revoked: true, Version: version}, nil
	}
	if err := s.recordRevocationOwed(ctx, req.Host, serial, why, req.CrlPem); err != nil {
		return nil, status.Errorf(codes.Internal, "record the owed revocation: %v", err)
	}
	return &pb.RevokeReplacedCertificateResponse{Held: true, Reason: why, Version: version}, nil
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
// serial, or "".
func hostRecordedWithSerial(ctx context.Context, db *corrosion.Client, serial string) (string, error) {
	rows, err := db.Query(ctx, `SELECT name FROM hosts WHERE lower(cert_serial) = ? AND deleted_at IS NULL`, strings.ToLower(serial))
	if err != nil || len(rows) == 0 {
		return "", err
	}
	return rows[0].String("name"), nil
}

// revocationSafeForVoters reports whether revoking serial keeps the newest
// voter generation verifiable against the CRL — the anchor a node adopting it
// later needs (§4.1).
//
// It only ever says "safe" from a voter state this node can trust: a replica
// that has completed an anti-entropy exchange since it started (or last lost
// every peer), and that has ADOPTED the newest generation it holds. The owed
// row and the voter chain replicate independently — a reseeding, newly
// admitted or long-partitioned node can hold the row with an empty or partial
// chain — so anything less is "not yet known" and holds.
//
// owed distinguishes the two callers. For an OWED revocation, a replica with
// no voter generation at all is incomplete by definition (the row exists
// because a generation needed the serial) and holds. For a fresh request it
// means the cluster has never decided a generation, so nothing is signed with
// the serial and it is safe. A newest generation that does not verify here
// holds in both cases: this replica cannot judge it.
func (s *Server) revocationSafeForVoters(ctx context.Context, serial string, owed bool) (bool, string, error) {
	if ok, why := s.db.ReplicaCaughtUp(); !ok {
		return false, "this node's replica is not trusted yet (" + why + ")", nil
	}
	rows, err := corrosion.ListVoterConfigs(ctx, s.db)
	if err != nil {
		return false, "", err
	}
	if len(rows) == 0 {
		if owed {
			return false, "this replica holds no voter generation yet, and an owed revocation implies one", nil
		}
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
	v = v.WithoutSerialPin() // revocation, not the pin, is the question here
	if err := verifyRowSignatures(v, prev, newest); err != nil {
		return false, fmt.Sprintf("voter generation %d does not verify on this node (%v)", newest.Generation, err), nil
	}
	if err := verifyRowSignatures(v.WithRevoked(serial), prev, newest); err != nil {
		return false, fmt.Sprintf("voter generation %d would no longer verify for a node that adopts it later "+
			"(%v); the revocation is published once a newer generation does", newest.Generation, err), nil
	}
	return true, "", nil
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

// ProcessOwedRevocations publishes every owed revocation that has become safe
// and resolves its condition; one that is still unsafe is re-announced daily
// by the host it belongs to. Safe to run on every node at once: a CRL is
// stored keyed by its own bytes, and resolving twice writes the same state.
//
// "Done" requires proof, not a row state. The row is replicated data any peer
// can write, so a revocation counts as done only when its serial is in the
// CRL this node installed from CA-verified rows. A row marked resolved or
// tombstoned without that is put back to owed and raised as
// certificate/revocation_owed_tampered; so is a row whose evidence no longer
// carries a CA-signed CRL listing its serial (the serial is read from the
// row's key, which an overwrite cannot change).
func (s *Server) ProcessOwedRevocations(ctx context.Context) {
	if s.db == nil {
		return
	}
	conds, deleted, err := corrosion.ListHealthConditionsByCode(ctx, s.db, certEvaluator, condRevocationOwed)
	if err != nil {
		return
	}
	_, _ = corrosion.SyncClusterCRL(ctx, s.db, s.pkiDir)
	for i, cnd := range conds {
		host, serial, ok := strings.Cut(cnd.SubjectID, "/")
		n := mustSerialInt(serial)
		if !ok || n == nil {
			continue
		}
		serial = strings.ToLower(serial)
		if pki.IsCertRevoked(s.pkiDir, n) {
			s.settleTamper(ctx, host, serial)
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
			s.raiseTamper(ctx, host, serial, "its evidence no longer carries a CA-signed CRL revoking it — "+
				"publish one from the CA machine with `lv host revoke-cert "+host+" --serial "+serial+"`")
			continue
		}
		if cnd.Lifecycle == corrosion.ConditionResolved || deleted[i] {
			s.raiseTamper(ctx, host, serial, "its row was marked done although the serial was never revoked; "+
				"it is owed again")
			cnd.Lifecycle, cnd.ResolvedAt = corrosion.ConditionConfirmed, ""
			if err := corrosion.UpsertHealthCondition(ctx, s.db, cnd); err != nil {
				slog.Warn("could not restore an owed revocation", "serial", serial, "error", err)
			}
		}
		if blocked := s.owedBlockedReason(ctx, serial); blocked != "" {
			s.remindOwed(ctx, cnd.SubjectID, host, serial, blocked)
			continue
		}
		safe, why, err := s.revocationSafeForVoters(ctx, serial, true)
		if err != nil {
			continue
		}
		if !safe {
			s.remindOwed(ctx, cnd.SubjectID, host, serial, why)
			continue
		}
		if err := s.publishCRL(ctx, ev.CRLPEM); err != nil {
			slog.Warn("could not publish an owed revocation; retrying", "serial", serial, "error", err)
			continue
		}
		slog.Warn("published an owed revocation now that the voter chain allows it", "host", host, "serial", serial)
		s.notify(ctx, notify.Notification{Kind: "certificate.revoked", Severity: notify.SevInfo, Subject: host,
			Detail: fmt.Sprintf("the replaced certificate %s is now revoked", serial)})
		s.resolveOwed(ctx, cnd)
	}
}

// owedBlockedReason is why an owed serial must not be published whatever the
// voter chain says: a host is recorded with it again (a pki dir restored from
// backup, say), and revoking it would cut that host off and get it fenced.
func (s *Server) owedBlockedReason(ctx context.Context, serial string) string {
	owner, err := hostRecordedWithSerial(ctx, s.db, serial)
	if err != nil {
		return "host records could not be read: " + err.Error()
	}
	if owner != "" {
		return fmt.Sprintf("%s is recorded as %s's live certificate again; publishing would fence %s — renew %s, "+
			"after which the revocation proceeds", serial, owner, owner, owner)
	}
	return ""
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

func mustSerialInt(hexSerial string) *big.Int {
	n, ok := new(big.Int).SetString(strings.TrimPrefix(hexSerial, "0x"), 16)
	if !ok {
		return nil
	}
	return n
}

// ConnJudge is this server's policy for established connections
// (pki.ConnTracker): a connection is closed when the client certificate it was
// made with has since been revoked, when the host certificate THIS side served
// on it has been, or when it was made with a host certificate the peer pin no
// longer accepts — the certificate a renewal replaced, once the renewed serial
// is recorded. The client reconnects with a fresh handshake.
//
// Build one per sweep: it reads the hosts table once, the first time a host
// certificate needs judging, and keeps it for that sweep only.
func (s *Server) ConnJudge(ctx context.Context) func(pki.TrackedConn) (bool, string) {
	revoked := pki.RevocationChecker(s.pkiDir)
	var hosts map[string]hostPin
	return func(c pki.TrackedConn) (bool, string) {
		if c.Peer != nil && revoked(c.Peer.SerialNumber) {
			return true, "the client certificate was revoked"
		}
		if n := mustSerialInt(c.ServedSerial); c.ServedSerial != "" && n != nil && revoked(n) {
			return true, "the certificate this host served on it was revoked"
		}
		if c.Peer != nil && isHostCert(c.Peer) && !s.trustRotatedPeerCerts {
			if hosts == nil {
				hosts = s.readHostPins(ctx)
			}
			if staleHostIdentity(hosts, c.Peer) {
				return true, "made with a host certificate the cluster no longer records"
			}
		}
		return false, ""
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
