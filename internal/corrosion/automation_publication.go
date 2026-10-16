package corrosion

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/litevirt/litevirt/internal/pki"
)

// Publication rows are terminal only. There is no durable current ticket, or
// public export API. The opaque ID is returned only after the actual Commit.
// JSON byte arrays use base64; allow per-certificate framing plus the full chain.
const maxSourceMembershipEvidenceBytes = maxSourceCertificateBytes + 2*maxSourceConfigBytes + 4*maxSourceFieldBytes + 4*((maxSourceChainBytes+2)/3) + 128
const maxSourcePublicationBytes = maxSourceArtifactBytes + pki.MaxHostTrustEvidenceBytes + maxSourceMembershipEvidenceBytes
const sourceTargetObservationLifetime = 10 * time.Second

type sourcePublicationPin struct {
	Request                                                                             AutomationSourceRequest
	Source, Incarnation, TargetIncarnation, OldValue, NextValue, TrustDomain, Cut, Root string
}

func sourcePin(m sourceManifest) []byte {
	b, _ := json.Marshal(sourcePublicationPin{m.Request, m.Source, m.Incarnation, m.Target.Incarnation, m.OldValue, m.NextValue, m.TrustDomain, m.Cut.ID, m.Root})
	return b
}

type sourceMembershipEvidence struct {
	Old, Next   VoterConfigValue
	Certificate string
	TargetChain [][]byte
}

type sourcePublication struct {
	id                             string
	manifest                       sourceManifest
	artifact, evidence, membership []byte
	trust                          *pki.HostTrustEvidence
}

func decodeSourcePublication(id string, artifact, evidence, membership []byte) (sourcePublication, error) {
	out := sourcePublication{id: id, artifact: artifact, evidence: evidence, membership: membership}
	if len(artifact) == 0 || len(artifact) > maxSourceArtifactBytes || len(evidence) > pki.MaxHostTrustEvidenceBytes || len(membership) > maxSourceMembershipEvidenceBytes || len(artifact)+len(evidence)+len(membership) > maxSourcePublicationBytes {
		return out, errors.New("publication exceeds bound")
	}
	var signed sourceSignedArtifact
	if err := json.Unmarshal(artifact, &signed); err != nil {
		return out, err
	}
	canonical, err := json.Marshal(signed)
	if err != nil || !bytes.Equal(canonical, artifact) || len(signed.Manifest) > maxSourceManifestBytes || len(signed.Signature) > 256 {
		return out, errors.New("noncanonical signed publication")
	}
	if err := json.Unmarshal(signed.Manifest, &out.manifest); err != nil {
		return out, err
	}
	m := out.manifest
	canonical, err = json.Marshal(m)
	if err != nil || !bytes.Equal(canonical, signed.Manifest) || m.Version != 1 || m.Purpose != "automation-membership-source" || m.Stream != "automation" || len(m.Source) == 0 || len(m.Source) > 253 || len(m.Incarnation) == 0 || len(m.Incarnation) > 128 {
		return out, errors.New("invalid publication manifest")
	}
	request, err := sourceRequest(m.Request)
	if err != nil {
		return out, err
	}
	original, _ := json.Marshal(m.Request)
	normalized, _ := json.Marshal(request)
	if !bytes.Equal(original, normalized) || m.Target.Host != request.Target || len(m.Target.Incarnation) == 0 || len(m.Target.Incarnation) > 128 || m.Cut.Source != m.Source || m.Cut.Incarnation != m.Incarnation || m.Cut.Generation != request.Generation {
		return out, errors.New("publication identity mismatch")
	}
	metadata, root, err := automationCutRoot(m.Cut)
	if err != nil || root != m.Root {
		return out, errors.New("publication cut root mismatch")
	}
	if _, err := readAutomationCutMetadata(Row{Columns: []string{"id", "metadata", "root"}, Values: []any{m.Cut.ID, metadata, root}}); err != nil {
		return out, err
	}
	out.trust, err = pki.DecodeHostTrustEvidence(evidence)
	if err != nil {
		return out, err
	}
	var publicMembership sourceMembershipEvidence
	if err := json.Unmarshal(membership, &publicMembership); err != nil {
		return out, err
	}
	canonical, err = json.Marshal(publicMembership)
	if err != nil || !bytes.Equal(canonical, membership) {
		return out, errors.New("noncanonical membership evidence")
	}
	old := &VoterConfig{VoterConfigValue: publicMembership.Old, MembersHash: MembersHash(publicMembership.Old.Members)}
	next := &VoterConfig{VoterConfigValue: publicMembership.Next, MembersHash: MembersHash(publicMembership.Next.Members), Certificate: publicMembership.Certificate}
	if sourceMembers(old.Members) != nil || sourceMembers(next.Members) != nil || old.Generation != m.Request.Generation || sourceConfigDigest(old) != m.OldValue || sourceConfigDigest(next) != m.NextValue || old.MembersHash != m.OldMembers || next.MembersHash != m.NextMembers {
		return out, errors.New("complete membership values differ")
	}
	if err := ValidateVoterChange(old, next.VoterConfigValue); err != nil {
		return out, err
	}
	if err := sourceRoster(m.Request, sourceDiscovery{old: old, next: next}, m.Source); err != nil {
		return out, err
	}
	member, _ := next.Member(m.Request.Target)
	if member.Incarnation != m.Target.Incarnation {
		return out, errors.New("retained target is not exact successor member")
	}
	domain, digest := out.trust.RootDigest(), out.trust.Digest()
	if m.TrustDomain != hex.EncodeToString(domain[:]) || m.TrustEvidence != hex.EncodeToString(digest[:]) || m.MembershipEvidence != sourceDigest([]byte(publicMembership.Certificate)) {
		return out, errors.New("publication evidence mismatch")
	}
	if _, err := sourceCertificate(publicMembership.Certificate); err != nil {
		return out, err
	}
	if err := out.trust.VerifyRecordedHost(signed.Chain, m.Source); err != nil {
		return out, err
	}
	if err := out.trust.VerifyRecordedPeer(publicMembership.TargetChain, m.Target.Host); err != nil {
		return out, err
	}
	targetFingerprint := sha256.Sum256(publicMembership.TargetChain[0])
	if hex.EncodeToString(targetFingerprint[:]) != m.Target.Certificate {
		return out, errors.New("recorded target fingerprint differs")
	}
	leaf, err := x509.ParseCertificate(signed.Chain[0])
	if err != nil {
		return out, err
	}
	fp := sha256.Sum256(leaf.Raw)
	key, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	hash, _ := hex.DecodeString(sourceDigest([]byte(sourceManifestDomain), signed.Manifest))
	if !ok || m.Signer != hex.EncodeToString(fp[:]) || !ecdsa.VerifyASN1(key, hash, signed.Signature) || id != sourceDigest(signed.Manifest, evidence, membership) {
		return out, errors.New("invalid exact source signature")
	}
	return out, nil
}

// readSourcePublication reads lengths first and then exactly one indexed row.
// It never materializes the full publication history or an arbitrary DB body.
func (c *Client) readSourcePublication(ctx context.Context, after, high int64) (sourcePublication, int64, error) {
	rows, err := c.Query(ctx, `SELECT rowid AS cursor,length(CAST(id AS BLOB)) AS id,length(CAST(job AS BLOB)) AS job,length(artifact) AS artifact,length(evidence) AS evidence,length(membership) AS membership FROM local_automation_publications WHERE rowid>? AND rowid<=? ORDER BY rowid LIMIT 1`, after, high)
	if err != nil || len(rows) == 0 {
		return sourcePublication{}, 0, err
	}
	r := rows[0]
	if r.Int64("id") != 64 || r.Int64("job") < 1 || r.Int64("job") > 128 || r.Int64("artifact") > maxSourceArtifactBytes || r.Int64("evidence") > pki.MaxHostTrustEvidenceBytes || r.Int64("membership") > maxSourceMembershipEvidenceBytes {
		return sourcePublication{}, 0, errors.New("over-bound persisted publication")
	}
	cursor := r.Int64("cursor")
	rows, err = c.Query(ctx, `SELECT id,job,revision,artifact,evidence,membership FROM local_automation_publications WHERE rowid=? AND length(artifact)<=? AND length(evidence)<=? AND length(membership)<=? AND length(CAST(id AS BLOB))=64 AND length(CAST(job AS BLOB)) BETWEEN 1 AND 128 LIMIT 1`, cursor, maxSourceArtifactBytes, pki.MaxHostTrustEvidenceBytes, maxSourceMembershipEvidenceBytes)
	if err != nil || len(rows) != 1 {
		return sourcePublication{}, 0, errors.New("publication disappeared")
	}
	r = rows[0]
	p, err := decodeSourcePublication(r.String("id"), r.Bytes("artifact"), r.Bytes("evidence"), r.Bytes("membership"))
	if err != nil {
		return p, 0, err
	}
	if r.String("job") != p.manifest.Request.Job || r.Int64("revision") != p.manifest.Request.Revision || p.manifest.Source != c.hostName {
		return p, 0, errors.New("publication row identity differs")
	}
	rows, err = c.Query(ctx, `SELECT binding FROM local_automation_source_jobs WHERE job=? AND revision=? AND length(binding)<=? LIMIT 1`, r.String("job"), r.Int64("revision"), maxSourceManifestBytes)
	if err != nil || len(rows) != 1 || !bytes.Equal(rows[0].Bytes("binding"), sourcePin(p.manifest)) {
		return p, 0, errors.New("publication immutable job pin differs")
	}
	// Completed signatures do not replace retained immutable source content.
	// Reopen and verify the archived cut in a consistent DB snapshot before
	// installing any completed floor; there is no PKI ownership in this read.
	err = c.ExecuteLocal(ctx, func(tx *LocalTx) error {
		rows, err := tx.Query(ctx, `SELECT id,metadata,root FROM local_automation_cuts WHERE id=? AND length(metadata)<=? LIMIT 1`, p.manifest.Cut.ID, maxAutomationCutMetadataBytes)
		if err != nil || len(rows) != 1 {
			return errors.New("completed publication cut is missing")
		}
		cut, err := readAutomationCutMetadata(rows[0])
		if err != nil {
			return err
		}
		actual, _ := json.Marshal(cut)
		expected, _ := json.Marshal(p.manifest.Cut)
		if !bytes.Equal(actual, expected) || rows[0].String("root") != p.manifest.Root {
			return errors.New("completed publication cut binding differs")
		}
		return verifyAutomationCutRecordsTx(ctx, tx, cut)
	})
	if err != nil {
		return p, 0, err
	}
	return p, cursor, nil
}

// InitializePublication is called after identity/schema recovery and configured
// policy. Only authenticated completed rows establish floors. It reads one row
// outside PKI ownership, then reconciles under the actual owner/file lock. No
// constructor-ready default or serialized current capability is accepted.
func (producer *AutomationSourcePreparer) InitializePublication(ctx context.Context) error {
	if producer == nil || producer.client == nil {
		return errors.New("missing source owner")
	}
	c := producer.client
	if err := c.lockSourcePublication(ctx); err != nil {
		return err
	}
	defer c.automationPublicationMu.Unlock()
	c.automationPublicationReady = false
	rows, err := c.Query(ctx, `SELECT rowid FROM local_automation_publications WHERE rowid<=0 LIMIT 1`)
	if err != nil || len(rows) != 0 {
		return errors.New("invalid publication cursor")
	}
	rows, err = c.Query(ctx, `SELECT 1 FROM local_automation_source_jobs j WHERE publications<=0 OR publications!=(SELECT COUNT(*) FROM local_automation_publications p WHERE p.job=j.job AND p.revision=j.revision) LIMIT 1`)
	if err != nil || len(rows) != 0 {
		return errors.New("job lacks completed signed evidence")
	}
	rows, err = c.Query(ctx, `SELECT COALESCE(MAX(rowid),0) AS high,COUNT(*) AS n FROM local_automation_publications`)
	if err != nil || len(rows) != 1 {
		return errors.New("cannot bound completed publication traversal")
	}
	high, total := rows[0].Int64("high"), rows[0].Int64("n")
	for after := int64(0); ; {
		p, cursor, err := c.readSourcePublication(ctx, after, high)
		if err != nil {
			return err
		}
		if cursor == 0 {
			break
		}
		if err := pki.ReconcileCompletedHostTrust(ctx, producer.dir, c.hostName, p.trust); err != nil {
			return err
		}
		after = cursor
	}
	rows, err = c.Query(ctx, `SELECT COALESCE(MAX(rowid),0) AS high,COUNT(*) AS n FROM local_automation_publications`)
	if err != nil || len(rows) != 1 || rows[0].Int64("high") != high || rows[0].Int64("n") != total {
		return errors.New("publication history changed during startup")
	}
	if _, err := pki.CaptureHostTrust(ctx, producer.dir, c.hostName); err != nil {
		return err
	}
	c.automationSourceMu.Lock()
	closed := c.automationSourceClosed
	c.automationSourceMu.Unlock()
	if closed {
		return errors.New("source client is closed")
	}
	c.automationPublicationDir = producer.dir
	c.automationPublicationReady = true
	return nil
}

// Publish consumes only the approved exact process/client/attempt preparation.
// Remote lifetime is a bounded observation, not atomic remote authority: a new
// expected-host GetRecoveryClaim occurs immediately before lease acquisition,
// must match the prepared identity/endpoint, and may be at most ten seconds old
// at the guarded local authorization instant. Receiver import must independently
// bind its own current lifetime. Local target lifetime is rechecked in SQL.
func (producer *AutomationSourcePreparer) Publish(ctx context.Context, p *AutomationSourcePreparation) (id string, err error) {
	if producer == nil || producer.client == nil || p == nil {
		return "", errors.New("missing source publication owner")
	}
	c := producer.client
	if err := c.lockSourcePublication(ctx); err != nil {
		return "", err
	}
	defer c.automationPublicationMu.Unlock()
	if !c.automationPublicationReady || c.automationPublicationDir != producer.dir {
		return "", errors.New("completed source floors have not reconciled")
	}
	p.mu.Lock()
	defer func() { p.mu.Unlock(); p.Discard() }()
	if p.owner != producer {
		return "", errors.New("foreign source preparation owner")
	}
	if err := p.checkPreparedLocked(); err != nil {
		return "", err
	}
	observed := time.Now()
	if !p.manifest.Target.Local {
		_, target, err := sourceQueryPeer(ctx, producer.dir, p.discovery.target, p.request.Generation, false)
		if err != nil {
			return "", err
		}
		m := p.manifest.Target
		if target.Incarnation != m.Incarnation || target.Fingerprint != m.Certificate || target.Endpoint != m.Endpoint || target.Connected != m.Connected {
			return "", errors.New("target observation changed; fresh preparation required")
		}
	}
	evidence, err := p.trust.PublicEvidence()
	if err != nil {
		return "", err
	}
	membership, err := json.Marshal(sourceMembershipEvidence{p.discovery.old.VoterConfigValue, p.discovery.next.VoterConfigValue, p.transitionEvidence, p.targetChain})
	if err != nil || len(membership) > maxSourceMembershipEvidenceBytes {
		return "", errors.New("source membership evidence exceeds bound")
	}
	id = sourceDigest(p.body, evidence, membership)
	retained, err := decodeSourcePublication(id, p.artifact, evidence, membership)
	if err != nil {
		return "", err
	}
	_ = retained // Inert decoding authenticates exact persisted representation only.
	lease, err := pki.AcquireHostCertificateLease(ctx, producer.dir, p.validations...)
	if err != nil {
		return "", err
	}
	defer lease.Release()
	// Lock order: publication serialization -> candidate -> PKI owner/file ->
	// client -> actual SQL transaction. No owner/network/key calls below.
	// A cancellable local mutex wait does not hold the trust lease hostage to
	// unrelated SQL work. This is lock acquisition, never a network retry.
	for !c.mu.TryLock() {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		if err := p.checkPreparedLocked(); err != nil {
			return "", err
		}
		timer := time.NewTimer(5 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return "", ctx.Err()
		case <-timer.C:
		}
	}
	defer c.mu.Unlock()
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	local := &LocalTx{tx: tx}
	if err := requireAutomationFull(ctx, local); err != nil {
		return "", err
	}
	current, err := c.auditSourceTx(ctx, local, p.request)
	if err != nil {
		return "", err
	}
	if sourceDiscoveryDigest(current) != p.dependency {
		return "", errors.New("source dependencies changed before publication")
	}
	if err := sourceRoster(p.request, current, c.hostName); err != nil {
		return "", err
	}
	next := *current.next
	next.Certificate = p.transitionEvidence
	if _, _, err := verifySourceTransition(p.trust, current.old, &next); err != nil {
		return "", err
	}
	if p.manifest.Target.Local && (p.manifest.Target.Host != c.hostName || p.manifest.Target.Incarnation != current.incarnation || p.manifest.Target.Certificate != p.manifest.Signer) {
		return "", errors.New("local target lifetime changed")
	}
	pin := sourcePin(p.manifest)
	rows, err := local.Query(ctx, `SELECT length(binding) AS size,publications FROM local_automation_source_jobs WHERE job=? AND revision=? LIMIT 1`, p.request.Job, p.request.Revision)
	if err != nil {
		return "", err
	}
	if len(rows) != 0 {
		if rows[0].Int64("size") > maxSourceManifestBytes {
			return "", errors.New("over-bound job pin")
		}
		expectedCount := rows[0].Int64("publications")
		counts, err := local.Query(ctx, `SELECT COUNT(*) AS n FROM local_automation_publications WHERE job=? AND revision=?`, p.request.Job, p.request.Revision)
		if err != nil || len(counts) != 1 || expectedCount <= 0 || counts[0].Int64("n") != expectedCount {
			return "", errors.New("established completed publication evidence is missing")
		}
		rows, err = local.Query(ctx, `SELECT binding FROM local_automation_source_jobs WHERE job=? AND revision=? LIMIT 1`, p.request.Job, p.request.Revision)
		if err != nil || len(rows) != 1 || !bytes.Equal(rows[0].Bytes("binding"), pin) {
			return "", errors.New("immutable source job/revision binding conflict")
		}
	} else {
		if _, err := local.Exec(ctx, `INSERT INTO local_automation_source_jobs(job,revision,binding,publications) VALUES(?,?,?,0)`, p.request.Job, p.request.Revision, pin); err != nil {
			return "", err
		}
	}
	rows, err = local.Query(ctx, `SELECT length(artifact) AS artifact,length(evidence) AS evidence,length(membership) AS membership FROM local_automation_publications WHERE id=? LIMIT 1`, id)
	if err != nil {
		return "", err
	}
	if len(rows) == 0 {
		if _, err := local.Exec(ctx, `INSERT INTO local_automation_publications(id,job,revision,artifact,evidence,membership) VALUES(?,?,?,?,?,?)`, id, p.request.Job, p.request.Revision, p.artifact, evidence, membership); err != nil {
			return "", err
		}
		if _, err := local.Exec(ctx, `UPDATE local_automation_source_jobs SET publications=publications+1 WHERE job=? AND revision=?`, p.request.Job, p.request.Revision); err != nil {
			return "", err
		}
	} else {
		r := rows[0]
		if r.Int64("artifact") > maxSourceArtifactBytes || r.Int64("evidence") > pki.MaxHostTrustEvidenceBytes || r.Int64("membership") > maxSourceMembershipEvidenceBytes {
			return "", errors.New("over-bound retained publication")
		}
		rows, err = local.Query(ctx, `SELECT artifact,evidence,membership FROM local_automation_publications WHERE id=? LIMIT 1`, id)
		if err != nil || len(rows) != 1 {
			return "", errors.New("missing retained publication")
		}
		previous, err := decodeSourcePublication(id, rows[0].Bytes("artifact"), rows[0].Bytes("evidence"), rows[0].Bytes("membership"))
		if err != nil || !bytes.Equal(sourcePin(previous.manifest), pin) {
			return "", errors.New("retained publication conflict")
		}
	}
	if seams := c.automationPublicationSeams; seams != nil && seams.beforeCommit != nil {
		if err := seams.beforeCommit(tx); err != nil {
			return "", err
		}
	}
	// Last guarded checks occur after ALL waits/test pauses immediately before
	// actual Commit. The owner/file lease survives Commit failure and rollback.
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if err := p.checkPreparedLocked(); err != nil {
		return "", err
	}
	if !p.manifest.Target.Local && (time.Now().Before(observed) || time.Since(observed) >= sourceTargetObservationLifetime) {
		return "", errors.New("target observation expired before commit")
	}
	if err := lease.Check(); err != nil {
		return "", err
	}
	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("commit source publication: %w", err)
	}
	if seams := c.automationPublicationSeams; seams != nil && seams.afterCommit != nil {
		seams.afterCommit()
	}
	return id, nil
}

// Publication serialization precedes every candidate/PKI/SQL lock. Waiting
// callers can cancel without acquiring or retaining any current capability.
func (c *Client) lockSourcePublication(ctx context.Context) error {
	for !c.automationPublicationMu.TryLock() {
		timer := time.NewTimer(5 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	return nil
}
