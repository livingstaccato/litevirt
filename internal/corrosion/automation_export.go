package corrosion

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/tls"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/litevirt/litevirt/internal/pki"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

const AutomationExportMaxRecords = 64
const AutomationExportMaxBytes = maxAutomationCutRecordBytes
const AutomationExportChunkBytes = 1 << 20
const AutomationExportMaxCursor = 1024

// AutomationExportRequest is bounded intent. Authority comes from the actual
// transport, current owned membership/PKI and exact committed publication.
type AutomationExportRequest struct {
	Intent               AutomationSourceRequest
	Publication          string
	Component            uint32
	Cursor               string
	MaxRecords, MaxBytes uint32
}
type AutomationExportPage struct {
	Publication                    string
	Component                      uint32
	Metadata                       []byte
	Records                        [][]byte
	Chunk                          []byte
	Cursor                         string
	Terminal                       bool
	TerminalRecords, TerminalBytes int64
	TerminalDigest                 string
}

type sourceExportAuthority struct {
	facts                         sourceDiscovery
	pair                          *tls.Certificate
	view                          *pki.HostTrust
	validations                   []*pki.HostCertificateValidation
	target                        sourceTarget
	observed, notBefore, notAfter time.Time
}

func (a *sourceExportAuthority) discard() {
	for _, v := range a.validations {
		v.Discard()
	}
}

func sourceExportRequest(r AutomationExportRequest) (AutomationExportRequest, error) {
	var err error
	r.Intent, err = sourceRequest(r.Intent)
	if err != nil {
		return r, err
	}
	if r.Component >= 12 || len(r.Cursor) > AutomationExportMaxCursor || r.MaxRecords > AutomationExportMaxRecords || r.MaxBytes > AutomationExportMaxBytes {
		return r, errors.New("export request exceeds bound")
	}
	for _, c := range []byte(r.Cursor) {
		if c > 127 {
			return r, errors.New("non-ASCII export cursor")
		}
	}
	if r.Publication != "" {
		raw, e := hex.DecodeString(r.Publication)
		if e != nil || len(raw) != 32 || hex.EncodeToString(raw) != r.Publication {
			return r, errors.New("invalid publication identifier")
		}
	}
	if r.Cursor != "" && r.Publication == "" {
		return r, errors.New("cursor requires exact publication")
	}
	if r.MaxRecords == 0 {
		r.MaxRecords = AutomationExportMaxRecords
	}
	if r.MaxBytes == 0 {
		r.MaxBytes = AutomationExportMaxBytes
	}
	return r, nil
}

// facts reads owned live authorization only, never archived content. The
// membership lineage checks use bounded rows and do not decode archive history.
func (c *Client) sourceExportFactsTx(ctx context.Context, tx *LocalTx, r AutomationSourceRequest) (sourceDiscovery, error) {
	d, err := c.sourceLineageTx(ctx, tx, r)
	if err != nil {
		return d, err
	}
	if err = sourceRoster(r, d, c.hostName); err != nil {
		return d, err
	}
	if d.adopted == r.Generation {
		st, e := readStandingTx(ctx, tx, c.hostName)
		if e != nil || !st.sealed {
			return d, errors.New("source generation is not sealed")
		}
	}
	d.source, err = sourceReadHost(ctx, tx, c.hostName)
	if err != nil {
		return d, err
	}
	d.target, err = sourceReadHost(ctx, tx, r.Target)
	return d, err
}
func (c *Client) sourceExportFacts(ctx context.Context, r AutomationSourceRequest) (sourceDiscovery, error) {
	if err := c.sourceExportReadLock(ctx); err != nil {
		return sourceDiscovery{}, err
	}
	defer c.mu.RUnlock()
	tx, err := c.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return sourceDiscovery{}, err
	}
	defer tx.Rollback()
	return c.sourceExportFactsTx(ctx, &LocalTx{tx: tx}, r)
}

// authorize is before publication/cursor/content reads. Context evidence is
// read from the real gRPC transport; the handler separately excludes root and
// all user/forwarded principals before invoking this storage owner.
func (p *AutomationSourcePreparer) authorizeSourceExport(ctx context.Context, r AutomationSourceRequest) (a *sourceExportAuthority, err error) {
	a = &sourceExportAuthority{}
	defer func() {
		if err != nil {
			a.discard()
		}
	}()
	connection, ok := peer.FromContext(ctx)
	if !ok {
		return a, errors.New("missing export TLS peer")
	}
	info, ok := connection.AuthInfo.(credentials.TLSInfo)
	if !ok || !info.State.HandshakeComplete || len(info.State.PeerCertificates) == 0 || info.State.PeerCertificates[0].Subject.CommonName != r.Target {
		return a, errors.New("export TLS peer differs from target")
	}
	if len(info.State.PeerCertificates) > 8 {
		return a, errors.New("over-bound export peer chain")
	}
	var chain [][]byte
	for _, cert := range info.State.PeerCertificates {
		chain = append(chain, cert.Raw)
	}
	if err = sourceChainBounds(chain); err != nil {
		return a, err
	}
	a.pair, err = pki.ServedHostKeyPair(p.dir)
	if err != nil {
		return a, err
	}
	a.facts, err = p.client.sourceExportFacts(ctx, r)
	if err != nil {
		return a, err
	}
	cert, e := sourceCertificate(a.facts.next.Certificate)
	if e != nil {
		return a, e
	}
	sourceLearnMembership(p.dir, cert)
	a.view, err = pki.CaptureHostTrust(ctx, p.dir, p.client.hostName)
	if err != nil {
		return a, err
	}
	a.notBefore, a.notAfter, err = verifySourceTransition(a.view, a.facts.old, a.facts.next)
	if err != nil {
		signer, e := ClaimSignerFromKeyPair(p.client.hostName, a.pair)
		if e != nil {
			return a, e
		}
		renewed, e := p.reattestSourceTransition(ctx, a.facts, signer)
		if e != nil {
			return a, e
		}
		a.view, err = pki.CaptureHostTrust(ctx, p.dir, p.client.hostName)
		if err != nil {
			return a, err
		}
		a.notBefore, a.notAfter, err = verifySourceTransition(a.view, a.facts.old, renewed)
		if err != nil {
			return a, err
		}
	}
	if err = sourceAdmission(a.view, a.facts.source, a.pair.Certificate[0]); err != nil {
		return a, err
	}
	if err = sourceAdmission(a.view, a.facts.target, chain[0]); err != nil {
		return a, err
	}
	sourceCap, e := a.view.ValidateServedHost(ctx, a.pair)
	if e != nil {
		return a, e
	}
	a.validations = append(a.validations, sourceCap)
	targetCap, e := a.view.ValidateHostCertificate(ctx, chain, r.Target)
	if e != nil {
		return a, e
	}
	a.validations = append(a.validations, targetCap)
	a.observed = time.Now()
	if r.Target == p.client.hostName {
		fp := sha256.Sum256(chain[0])
		a.target = sourceTarget{Host: a.facts.target, Incarnation: a.facts.incarnation, Local: true, Fingerprint: hex.EncodeToString(fp[:]), Chain: chain}
	} else {
		_, a.target, err = sourceQueryPeer(ctx, p.dir, a.facts.target, r.Generation, false)
		if err != nil {
			return a, err
		}
	}
	fp := sha256.Sum256(chain[0])
	member, _ := a.facts.next.Member(r.Target)
	if a.target.Incarnation != member.Incarnation || a.target.Fingerprint != hex.EncodeToString(fp[:]) {
		return a, errors.New("current target storage/transport lifetime differs")
	}
	return a, nil
}

// ExportAutomationSource reads only exact terminal publications. The initial
// component open decodes its finite evidence; continuation uses a signed cursor
// and bounded artifact/membership checks, never a whole archive walk.
func (p *AutomationSourcePreparer) ExportAutomationSource(ctx context.Context, r AutomationExportRequest) (page AutomationExportPage, err error) {
	if p == nil || p.client == nil {
		return page, errors.New("missing source export owner")
	}
	r, err = sourceExportRequest(r)
	if err != nil {
		return page, err
	}
	a, err := p.authorizeSourceExport(ctx, r.Intent)
	if err != nil {
		return page, err
	}
	defer a.discard()
	c := p.client
	if err = c.lockSourcePublication(ctx); err != nil {
		return page, err
	}
	ready := c.automationPublicationReady && c.automationPublicationDir == p.dir
	c.automationPublicationMu.Unlock()
	if !ready {
		return page, errors.New("source publication floors unavailable")
	}
	if r.Publication == "" {
		candidate, e := p.Prepare(ctx, r.Intent)
		if e != nil {
			return page, e
		}
		r.Publication, err = p.Publish(ctx, candidate)
		if err != nil {
			return page, err
		}
		// Publication may have learned current membership/identity evidence.
		a.discard()
		a, err = p.authorizeSourceExport(ctx, r.Intent)
		if err != nil {
			return page, err
		}
		defer a.discard()
	}
	if err = sourceExportCursorPreflight(r, a.pair); err != nil {
		return page, err
	}
	publication, err := c.sourceExportPublication(ctx, r, a)
	if err != nil {
		return page, err
	}
	cursor, err := sourceExportOpenCursor(r, publication, a.pair)
	if err != nil {
		return page, err
	}
	// No key/network acquisition while the current PKI lease or SQL is held.
	lease, err := pki.AcquireHostCertificateLease(ctx, p.dir, a.validations...)
	if err != nil {
		return page, err
	}
	defer lease.Release()
	if c.automationExportBeforeRead != nil {
		c.automationExportBeforeRead()
	}
	if err = c.sourceExportReadLock(ctx); err != nil {
		return page, err
	}
	defer c.mu.RUnlock()
	tx, err := c.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return page, err
	}
	defer tx.Rollback()
	local := &LocalTx{tx: tx}
	current, err := c.sourceExportFactsTx(ctx, local, r.Intent)
	if err != nil {
		return page, err
	}
	if sourceDiscoveryDigest(current) != sourceDiscoveryDigest(a.facts) {
		return page, errors.New("current source dependencies changed")
	}
	if err = sourceExportCheckPin(ctx, local, publication); err != nil {
		return page, err
	}
	page, err = sourceExportReadPage(ctx, local, r, publication, &cursor)
	if err != nil {
		return page, err
	}
	if err = ctx.Err(); err != nil {
		return page, err
	}
	now := time.Now()
	if now.Before(a.observed) || now.Sub(a.observed) >= sourceTargetObservationLifetime || now.Before(a.notBefore) || !now.Before(a.notAfter) {
		return page, errors.New("source export authorization expired")
	}
	if err = lease.Check(); err != nil {
		return page, err
	}
	c.automationSourceMu.Lock()
	closed := c.automationSourceClosed
	c.automationSourceMu.Unlock()
	if closed {
		return page, errors.New("source client is closed")
	}
	if !page.Terminal {
		page.Cursor, err = cursor.encode(a.pair.PrivateKey.(*ecdsa.PrivateKey))
	}
	return page, err
}

func sameSourceRequest(a, b AutomationSourceRequest) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}
func sourceExportCheckPin(ctx context.Context, tx *LocalTx, p sourcePublication) error {
	m := p.manifest
	selected, err := tx.Query(ctx, `SELECT artifact FROM local_automation_publications WHERE id=? AND job=? AND revision=? AND length(artifact) BETWEEN 1 AND ? LIMIT 1`, p.id, m.Request.Job, m.Request.Revision, maxSourceArtifactBytes)
	if err != nil || len(selected) != 1 || !bytes.Equal(selected[0].Bytes("artifact"), p.artifact) {
		return errors.New("exact selected publication unavailable")
	}
	rows, err := tx.Query(ctx, `SELECT length(binding) AS size,publications FROM local_automation_source_jobs WHERE job=? AND revision=? LIMIT 1`, m.Request.Job, m.Request.Revision)
	if err != nil || len(rows) != 1 || rows[0].Int64("size") < 1 || rows[0].Int64("size") > maxSourceManifestBytes || rows[0].Int64("publications") <= 0 {
		return errors.New("source publication pin unavailable")
	}
	count := rows[0].Int64("publications")
	rows, err = tx.Query(ctx, `SELECT binding FROM local_automation_source_jobs WHERE job=? AND revision=? AND length(binding)<=? LIMIT 1`, m.Request.Job, m.Request.Revision, maxSourceManifestBytes)
	if err != nil || len(rows) != 1 || !bytes.Equal(rows[0].Bytes("binding"), sourcePin(m)) {
		return errors.New("source publication pin differs")
	}
	rows, err = tx.Query(ctx, `SELECT COUNT(*) AS n FROM local_automation_publications WHERE job=? AND revision=?`, m.Request.Job, m.Request.Revision)
	if err != nil || len(rows) != 1 || rows[0].Int64("n") != count {
		return errors.New("completed source publication evidence missing")
	}
	rows, err = tx.Query(ctx, `SELECT length(metadata) AS size,length(CAST(root AS BLOB)) AS root FROM local_automation_cuts WHERE id=? LIMIT 1`, m.Cut.ID)
	if err != nil || len(rows) != 1 || rows[0].Int64("size") < 1 || rows[0].Int64("size") > maxAutomationCutMetadataBytes || rows[0].Int64("root") != 64 {
		return errors.New("invalid published cut header bounds")
	}
	rows, err = tx.Query(ctx, `SELECT id,metadata,root FROM local_automation_cuts WHERE id=? AND length(metadata) BETWEEN 1 AND ? AND length(CAST(root AS BLOB))=64 LIMIT 1`, m.Cut.ID, maxAutomationCutMetadataBytes)
	if err != nil || len(rows) != 1 {
		return errors.New("published cut missing")
	}
	actual, e := readAutomationCutMetadata(rows[0])
	if e != nil {
		return e
	}
	x, _ := json.Marshal(actual)
	y, _ := json.Marshal(m.Cut)
	if !bytes.Equal(x, y) || rows[0].String("root") != m.Root {
		return errors.New("published cut binding differs")
	}
	rows, err = tx.Query(ctx, `SELECT section FROM local_automation_cut_records WHERE cut_id=? AND (section<0 OR section>=9 OR ordinal<=0) LIMIT 1`, m.Cut.ID)
	if err != nil || len(rows) != 0 {
		return fmt.Errorf("invalid published cut section: %v", err)
	}
	return nil
}

// Only the export owner's waits are changed. No goroutine waits for a lock
// after its caller has cancelled, and a cancelled lease holder releases promptly.
func (c *Client) sourceExportReadLock(ctx context.Context) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if c.mu.TryRLock() {
			return nil
		}
		timer := time.NewTimer(5 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}
func (c *Client) sourceExportQuery(ctx context.Context, q string, args ...any) ([]Row, error) {
	if err := c.sourceExportReadLock(ctx); err != nil {
		return nil, err
	}
	defer c.mu.RUnlock()
	tx, err := c.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	return (&LocalTx{tx: tx}).Query(ctx, q, args...)
}
