package corrosion

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/litevirt/litevirt/internal/pki"
)

// AutomationReceiver owns inert, pinned transport evidence. It does not expose
// semantic completion, a finalizer proof, adoption, readiness, or cancellation.
// Construct with the application's actual configured local PKI directory.
type AutomationReceiver struct {
	client *Client
	dir    string
	mu     sync.Mutex
	// Only tests pause the real transaction, never supply authorization results.
	seams                   *localCommitSeams
	afterMembershipLearning func() // test-only pause; never supplies facts or trust
	afterCurrentObservation func() // test-only pause after reading the actual predecessor
}

// AutomationReceiverAttempt is process-local. Its identity alone cannot revive
// current authority; Begin re-verifies local membership and PKI after restart.
type AutomationReceiverAttempt struct {
	self                    *AutomationReceiverAttempt
	owner                   *AutomationReceiver
	id                      string
	request                 AutomationSourceRequest
	facts                   receiverFacts
	binding                 []byte
	view                    *pki.HostTrust
	pair                    *tls.Certificate
	at, notBefore, notAfter time.Time
	publications            map[string]receiverPublication
}

// Progress describes transport inventory only, never an old-quorum completion.
type AutomationReceiverProgress struct {
	Component               uint32
	Records, Bytes          int64
	Cursor                  string
	Terminal, Authenticated bool
}

type receiverFacts struct {
	Incarnation, Chain, Certificates string
	Adopted                          int64
	Target                           sourceHost
	Old, Next                        *VoterConfig
}
type receiverPublication struct {
	id              string
	manifest        sourceManifest
	chain           [][]byte
	metadataBytes   [3]int64
	metadataDigests [3][32]byte
}

func NewAutomationReceiver(c *Client, dir string) *AutomationReceiver {
	return &AutomationReceiver{client: c, dir: dir}
}
func (r *AutomationReceiver) lock(ctx context.Context) error {
	if r == nil || r.client == nil || r.dir == "" {
		return errors.New("missing receiver owner")
	}
	for !r.mu.TryLock() {
		timer := time.NewTimer(5 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	if err := ctx.Err(); err != nil {
		r.mu.Unlock()
		return err
	}
	return nil
}

// Walk exactly one bounded ordinary config at a time. This is receiver
// membership authority, deliberately independent of source old adoption/cuts.
func (r *AutomationReceiver) factsTx(ctx context.Context, tx *LocalTx, intent AutomationSourceRequest, view *pki.HostTrust) (receiverFacts, time.Time, time.Time, error) {
	var f receiverFacts
	var before, after time.Time
	fail := func(err error) (receiverFacts, time.Time, time.Time, error) { return f, before, after, err }
	rows, err := tx.Query(ctx, `SELECT incarnation FROM local_voter_incarnation WHERE id=1 AND length(CAST(incarnation AS BLOB)) BETWEEN 1 AND 128`)
	if err != nil || len(rows) != 1 {
		return fail(errors.New("receiver incarnation unavailable"))
	}
	f.Incarnation = rows[0].String("incarnation")
	rows, err = tx.Query(ctx, `SELECT (SELECT COUNT(*) FROM reseed_in_progress) AS incomplete,COALESCE((SELECT generation FROM reseed_generation WHERE id=1),0) AS reseeds,COALESCE((SELECT MAX(generation) FROM local_voter_adoption),0) AS adopted`)
	if err != nil || len(rows) != 1 || rows[0].Int64("incomplete") != 0 || rows[0].Int64("reseeds") != 0 {
		return fail(errors.New("receiver membership lost through reseed"))
	}
	f.Adopted = rows[0].Int64("adopted")
	if f.Adopted > intent.Generation {
		return fail(errors.New("receiver already adopted successor or later membership"))
	}
	f.Target, err = sourceReadHost(ctx, tx, r.client.hostName)
	if err != nil {
		return fail(err)
	}
	h := sha256.New()
	sourceHash(h, []byte("litevirt/receiver-local-membership/v1"))
	certificateHash := sha256.New()
	sourceHash(certificateHash, []byte("litevirt/receiver-learned-membership/v1"))
	var prev *VoterConfig
	for g := int64(1); g <= intent.Generation+1; g++ {
		if err := ctx.Err(); err != nil {
			return fail(err)
		}
		cfg, err := sourceReadConfig(ctx, tx, g)
		if err != nil {
			return fail(err)
		}
		if err = ValidateVoterChange(prev, cfg.VoterConfigValue); err != nil {
			return fail(err)
		}
		// An empty reset/re-genesis is not the normal certified predecessor chain.
		if len(cfg.Members) == 0 {
			return fail(errors.New("receiver reset membership is unavailable"))
		}
		sourceHash(h, []byte(sourceConfigDigest(cfg)), []byte(cfg.Certificate))
		sourceHash(certificateHash, []byte(cfg.Certificate))
		if view != nil {
			cert, err := sourceCertificate(cfg.Certificate)
			if err != nil {
				return fail(err)
			}
			v := &ClaimVerifier{sourceTrust: view, pinned: true}
			if err = VerifyVoterConfigRow(v, prev, cfg); err != nil {
				return fail(err)
			}
			want, err := ExpectedVoterConfigCertificate(prev, cfg.VoterConfigValue)
			if err != nil {
				return fail(err)
			}
			electorate := make(map[string]string, len(want.Electorate))
			for _, m := range want.Electorate {
				electorate[m.Name] = m.Incarnation
			}
			for _, a := range cert.Accepts {
				if v.verifyAccept(cert, a, electorate) != nil {
					continue
				}
				leaf, err := parseCertPEM([]byte(a.CertPEM))
				if err != nil {
					return fail(err)
				}
				b, e, err := view.VerifyOrdinaryCertificate(leaf.Raw, false, true)
				if err != nil {
					return fail(err)
				}
				if b.After(before) {
					before = b
				}
				if after.IsZero() || e.Before(after) {
					after = e
				}
			}
		}
		if g == intent.Generation {
			f.Old = cfg
		}
		prev = cfg
	}
	f.Next = prev
	f.Chain = hex.EncodeToString(h.Sum(nil))
	f.Certificates = hex.EncodeToString(certificateHash.Sum(nil))
	target, ok := f.Next.Member(r.client.hostName)
	if !ok || intent.Target != r.client.hostName || target.Incarnation != f.Incarnation {
		return fail(errors.New("receiver is not exact successor lifetime"))
	}
	if err = sourceRoster(intent, sourceDiscovery{old: f.Old, next: f.Next}, intent.Sources[0].Name); err != nil {
		return fail(err)
	}
	return f, before, after, nil
}
func receiverBinding(intent AutomationSourceRequest, f receiverFacts, view *pki.HostTrust) []byte {
	root := view.RootDigest()
	b, _ := json.Marshal(receiverAttemptBinding{1, "automation", intent, f, hex.EncodeToString(root[:])})
	return b
}
func sameReceiverFacts(a, b receiverFacts) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}

// Begin selects a durable current attempt. Exact starts resume it after fresh
// verification. Supersession requires the actual current private handle and a
// greater revision, even for another job name; numeric source revisions do not
// select a receiver. Superseded rows are retained permanently and stay inert.
func (r *AutomationReceiver) Begin(ctx context.Context, intent AutomationSourceRequest, previous *AutomationReceiverAttempt) (*AutomationReceiverAttempt, error) {
	return r.begin(ctx, intent, previous, false)
}
func (r *AutomationReceiver) begin(ctx context.Context, intent AutomationSourceRequest, previous *AutomationReceiverAttempt, replace bool) (*AutomationReceiverAttempt, error) {
	if err := r.lock(ctx); err != nil {
		return nil, err
	}
	defer r.mu.Unlock()
	var err error
	intent, err = sourceRequest(intent)
	if err != nil {
		return nil, err
	}
	if intent.Target != r.client.hostName {
		return nil, errors.New("receiver target differs")
	}
	if previous != nil && (previous.self != previous || previous.owner != r) {
		return nil, errors.New("foreign receiver predecessor")
	}
	var predecessor *receiverPredecessor
	if replace {
		predecessor, err = r.observePredecessor(ctx)
		if err != nil {
			return nil, err
		}
		if r.afterCurrentObservation != nil {
			r.afterCurrentObservation()
		}
	}
	// Learn CA-issued renewals before snapshot capture, without any held SQL/PKI
	// lock inversion. No membership assertion is inferred from these certificates.
	learned := sha256.New()
	sourceHash(learned, []byte("litevirt/receiver-learned-membership/v1"))
	for g := int64(1); g <= intent.Generation+1; g++ {
		rows, e := r.client.sourceExportQuery(ctx, `SELECT certificate FROM voter_configs WHERE generation=? AND length(CAST(certificate AS BLOB)) BETWEEN 1 AND ? LIMIT 1`, g, maxSourceCertificateBytes)
		if e != nil || len(rows) != 1 {
			return nil, errors.New("receiver certified predecessor missing")
		}
		cert, e := sourceCertificate(rows[0].String("certificate"))
		if e != nil {
			return nil, e
		}
		sourceLearnMembership(r.dir, cert)
		sourceHash(learned, []byte(rows[0].String("certificate")))
	}
	if r.afterMembershipLearning != nil {
		r.afterMembershipLearning()
	}
	pair, err := pki.ServedHostKeyPair(r.dir)
	if err != nil {
		return nil, err
	}
	view, err := pki.CaptureHostTrust(ctx, r.dir, r.client.hostName)
	if err != nil {
		return nil, err
	}
	if err = r.client.sourceExportReadLock(ctx); err != nil {
		return nil, err
	}
	tx, err := r.client.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		r.client.mu.RUnlock()
		return nil, err
	}
	facts, before, after, err := r.factsTx(ctx, &LocalTx{tx: tx}, intent, view)
	tx.Rollback()
	r.client.mu.RUnlock()
	if err != nil {
		return nil, err
	}
	if facts.Certificates != hex.EncodeToString(learned.Sum(nil)) {
		return nil, errors.New("receiver membership changed during trust learning; retry current authorization")
	}
	if err = sourceAdmission(view, facts.Target, pair.Certificate[0]); err != nil {
		return nil, err
	}
	binding := receiverBinding(intent, facts, view)
	if len(binding) > 2*maxSourceCertificateBytes+3*maxSourceConfigBytes {
		return nil, errors.New("receiver binding exceeds bound")
	}
	if predecessor != nil {
		root := view.RootDigest()
		if err = predecessor.compatible(intent, facts, hex.EncodeToString(root[:])); err != nil {
			return nil, err
		}
	}
	id := sourceDigest([]byte("litevirt/receiver-attempt/v1"), binding)
	a := &AutomationReceiverAttempt{owner: r, id: id, request: intent, facts: facts, binding: binding, view: view, pair: pair, at: time.Now(), notBefore: before, notAfter: after, publications: map[string]receiverPublication{}}
	a.self = a
	evidence, err := view.PublicEvidence()
	if err != nil {
		return nil, err
	}
	cap, err := view.ValidateServedHost(ctx, pair)
	if err != nil {
		return nil, err
	}
	defer cap.Discard()
	lease, err := pki.AcquireHostCertificateLease(ctx, r.dir, cap)
	if err != nil {
		return nil, err
	}
	defer lease.Release()
	err = r.transaction(ctx, a, lease, time.Time{}, func(tx *LocalTx) error {
		rows, err := tx.Query(ctx, `SELECT attempt FROM local_automation_receiver_current WHERE id=1 AND length(CAST(attempt AS BLOB))=64`)
		if err != nil {
			return err
		}
		if predecessor != nil {
			observed, e := receiverReadPredecessor(ctx, tx)
			if e != nil || observed.id != predecessor.id || !bytes.Equal(observed.binding, predecessor.binding) {
				return errors.New("receiver observed predecessor changed")
			}
		} else if len(rows) == 0 {
			// A corrupt/over-bound head cannot masquerade as no current selection.
			count, e := tx.Query(ctx, `SELECT COUNT(*) AS n FROM local_automation_receiver_current`)
			if e != nil || len(count) != 1 || count[0].Int64("n") != 0 {
				return errors.New("invalid receiver current selection")
			}
			if previous != nil {
				return errors.New("receiver predecessor no longer current")
			}
		} else if rows[0].String("attempt") != id {
			if previous == nil || rows[0].String("attempt") != previous.id || intent.Revision <= previous.request.Revision {
				return errors.New("receiver current selection conflict")
			}
			if err := r.currentTx(ctx, tx, previous); err != nil {
				return err
			}
		}
		rows, err = tx.Query(ctx, `SELECT CASE WHEN length(CAST(id AS BLOB))=64 THEN id END AS id FROM local_automation_receiver_jobs WHERE job=? AND revision=? LIMIT 1`, intent.Job, intent.Revision)
		if err != nil {
			return err
		}
		if len(rows) > 0 && rows[0].String("id") != id {
			return errors.New("immutable receiver job/revision differs")
		}
		if len(rows) == 0 {
			if _, err = tx.Exec(ctx, `INSERT INTO local_automation_receiver_jobs(id,job,revision,binding,evidence) VALUES(?,?,?,?,?)`, id, intent.Job, intent.Revision, binding, evidence); err != nil {
				return err
			}
		} else {
			rows, err = tx.Query(ctx, `SELECT binding FROM local_automation_receiver_jobs WHERE id=? AND length(CAST(binding AS BLOB))=? LIMIT 1`, id, len(binding))
			if err != nil || len(rows) != 1 || !bytes.Equal(rows[0].Bytes("binding"), binding) {
				return errors.New("receiver immutable binding unavailable")
			}
		}
		digest := view.EvidenceDigest()
		if _, err = tx.Exec(ctx, `INSERT OR IGNORE INTO local_automation_receiver_validations(attempt,digest,evidence) VALUES(?,?,?)`, id, hex.EncodeToString(digest[:]), evidence); err != nil {
			return err
		}
		if predecessor != nil {
			result, e := tx.Exec(ctx, `UPDATE local_automation_receiver_current SET attempt=? WHERE id=1 AND attempt=?`, id, predecessor.id)
			if e != nil {
				return e
			}
			n, e := result.RowsAffected()
			if e != nil {
				return e
			}
			if n != 1 {
				return errors.New("receiver current compare-and-swap lost")
			}
			return nil
		}
		_, err = tx.Exec(ctx, `INSERT INTO local_automation_receiver_current(id,attempt) VALUES(1,?) ON CONFLICT(id) DO UPDATE SET attempt=excluded.attempt`, id)
		return err
	})
	if err != nil {
		return nil, err
	}
	return a, nil
}

func (r *AutomationReceiver) currentTx(ctx context.Context, tx *LocalTx, a *AutomationReceiverAttempt) error {
	if a == nil || a.self != a || a.owner != r {
		return errors.New("foreign receiver attempt")
	}
	rows, err := tx.Query(ctx, `SELECT attempt FROM local_automation_receiver_current WHERE id=1 AND attempt=? LIMIT 1`, a.id)
	if err != nil || len(rows) != 1 {
		return errors.New("receiver attempt is not current")
	}
	rows, err = tx.Query(ctx, `SELECT binding FROM local_automation_receiver_jobs WHERE id=? AND length(CAST(binding AS BLOB))=? LIMIT 1`, a.id, len(a.binding))
	if err != nil || len(rows) != 1 || !bytes.Equal(rows[0].Bytes("binding"), a.binding) {
		return errors.New("receiver attempt binding differs")
	}
	return nil
}

// The real PKI lease encloses the actual SQLite FULL commit, including every
// SQL/mutex wait and the final locally timed guard. No callback supplies trust.
func (r *AutomationReceiver) transaction(ctx context.Context, a *AutomationReceiverAttempt, lease *pki.HostCertificateLease, observed time.Time, fn func(*LocalTx) error) error {
	c := r.client
	for !c.mu.TryLock() {
		timer := time.NewTimer(5 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	defer c.mu.Unlock()
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	local := &LocalTx{tx: tx}
	if err = requireAutomationFull(ctx, local); err != nil {
		return err
	}
	facts, _, _, err := r.factsTx(ctx, local, a.request, nil)
	if err != nil {
		return err
	}
	if !sameReceiverFacts(facts, a.facts) {
		return errors.New("receiver local authorization dependencies changed")
	}
	if err = fn(local); err != nil {
		return err
	}
	if r.seams != nil && r.seams.beforeCommit != nil {
		if err = r.seams.beforeCommit(tx); err != nil {
			return err
		}
	}
	// Recheck the final transaction snapshot after all storage work and test
	// commit seams. Durable inert rows never outlive a changed selection or
	// membership binding, even if transaction-local work changes dependencies.
	if err = r.currentTx(ctx, local, a); err != nil {
		return err
	}
	finalFacts, _, _, err := r.factsTx(ctx, local, a.request, nil)
	if err != nil {
		return err
	}
	if !sameReceiverFacts(finalFacts, a.facts) {
		return errors.New("receiver final authorization dependencies changed")
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	now := time.Now()
	if now.Before(a.at) || now.Before(a.notBefore) || !now.Before(a.notAfter) {
		return errors.New("receiver membership authorization expired")
	}
	if !observed.IsZero() && (now.Before(observed) || now.Sub(observed) >= sourceTargetObservationLifetime) {
		return errors.New("receiver source observation expired")
	}
	if err = lease.Check(); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	if r.seams != nil && r.seams.afterCommit != nil {
		r.seams.afterCommit()
	}
	return nil
}

// Supersede deliberately selects a replacement under freshly verified local
// authority. The durable predecessor is owned by this receiver, never a caller ID.
func (r *AutomationReceiver) Supersede(ctx context.Context, intent AutomationSourceRequest) (*AutomationReceiverAttempt, error) {
	return r.begin(ctx, intent, nil, true)
}
