package corrosion

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/litevirt/litevirt/internal/pki"
)

func (c *Client) sourceExportPublication(ctx context.Context, r AutomationExportRequest, a *sourceExportAuthority) (sourcePublication, error) {
	out := sourcePublication{id: r.Publication}
	// The bounded storage-owned immutable pin authorizes exact recipient and
	// context BEFORE any artifact/public-trust/membership body or nested decode.
	headers, err := c.sourceExportQuery(ctx, `SELECT job,revision FROM local_automation_publications WHERE id=? AND length(CAST(job AS BLOB)) BETWEEN 1 AND 128 LIMIT 1`, r.Publication)
	if err != nil || len(headers) != 1 || headers[0].String("job") != r.Intent.Job || headers[0].Int64("revision") != r.Intent.Revision {
		return out, errors.New("publication context unavailable")
	}
	pins, err := c.sourceExportQuery(ctx, `SELECT length(binding) AS size FROM local_automation_source_jobs WHERE job=? AND revision=? AND publications>0 LIMIT 1`, r.Intent.Job, r.Intent.Revision)
	if err != nil || len(pins) != 1 || pins[0].Int64("size") < 1 || pins[0].Int64("size") > maxSourceManifestBytes {
		return out, errors.New("publication pin unavailable")
	}
	pins, err = c.sourceExportQuery(ctx, `SELECT binding FROM local_automation_source_jobs WHERE job=? AND revision=? AND publications>0 AND length(binding) BETWEEN 1 AND ? LIMIT 1`, r.Intent.Job, r.Intent.Revision, maxSourceManifestBytes)
	if err != nil || len(pins) != 1 {
		return out, errors.New("publication pin disappeared")
	}
	var pin sourcePublicationPin
	if json.Unmarshal(pins[0].Bytes("binding"), &pin) != nil {
		return out, errors.New("invalid publication pin")
	}
	canonicalPin, e := json.Marshal(pin)
	domain := a.view.RootDigest()
	if e != nil || !bytes.Equal(canonicalPin, pins[0].Bytes("binding")) || !sameSourceRequest(pin.Request, r.Intent) || pin.Source != c.hostName || pin.Incarnation != a.facts.incarnation || pin.TargetIncarnation != a.target.Incarnation || pin.OldValue != sourceConfigDigest(a.facts.old) || pin.NextValue != sourceConfigDigest(a.facts.next) || pin.TrustDomain != hex.EncodeToString(domain[:]) {
		return out, errors.New("publication pin recipient/context differs")
	}
	rows, err := c.sourceExportQuery(ctx, `SELECT length(artifact) AS artifact,length(evidence) AS evidence,length(membership) AS membership,length(CAST(job AS BLOB)) AS job FROM local_automation_publications WHERE id=? LIMIT 1`, r.Publication)
	if err != nil || len(rows) != 1 {
		return out, errors.New("committed source publication unavailable")
	}
	lengths := rows[0]
	if lengths.Int64("artifact") < 1 || lengths.Int64("artifact") > maxSourceArtifactBytes || lengths.Int64("evidence") < 1 || lengths.Int64("evidence") > pki.MaxHostTrustEvidenceBytes || lengths.Int64("membership") < 1 || lengths.Int64("membership") > maxSourceMembershipEvidenceBytes || lengths.Int64("job") < 1 || lengths.Int64("job") > 128 {
		return out, errors.New("over-bound persisted export evidence")
	}
	// All three lengths are preflighted even when only a compact continuation
	// is requested. Full trust bytes are loaded only on a component's first page.
	columns := "job,revision,artifact,membership"
	if r.Cursor == "" {
		columns += ",evidence"
	}
	rows, err = c.sourceExportQuery(ctx, `SELECT `+columns+` FROM local_automation_publications WHERE id=? AND length(artifact) BETWEEN 1 AND ? AND length(evidence) BETWEEN 1 AND ? AND length(membership) BETWEEN 1 AND ? AND length(CAST(job AS BLOB)) BETWEEN 1 AND 128 LIMIT 1`, r.Publication, maxSourceArtifactBytes, pki.MaxHostTrustEvidenceBytes, maxSourceMembershipEvidenceBytes)
	if err != nil || len(rows) != 1 {
		return out, errors.New("source publication changed")
	}
	row := rows[0]
	if row.String("job") != r.Intent.Job || row.Int64("revision") != r.Intent.Revision {
		return out, errors.New("source publication request differs")
	}
	out.artifact, out.membership = row.Bytes("artifact"), row.Bytes("membership")
	if r.Cursor == "" {
		out, err = decodeSourcePublication(r.Publication, out.artifact, row.Bytes("evidence"), out.membership)
		if err != nil {
			return out, err
		}
	}
	var signed sourceSignedArtifact
	if json.Unmarshal(out.artifact, &signed) != nil || len(signed.Manifest) > maxSourceManifestBytes || len(signed.Signature) > 256 || sourceChainBounds(signed.Chain) != nil {
		return out, errors.New("invalid export artifact")
	}
	canonical, e := json.Marshal(signed)
	if e != nil || !bytes.Equal(canonical, out.artifact) {
		return out, errors.New("noncanonical export artifact")
	}
	if json.Unmarshal(signed.Manifest, &out.manifest) != nil {
		return out, errors.New("invalid export manifest")
	}
	m := out.manifest
	canonical, e = json.Marshal(m)
	if e != nil || !bytes.Equal(canonical, signed.Manifest) {
		return out, errors.New("noncanonical export manifest")
	}
	signer := sha256.Sum256(a.pair.Certificate[0])
	root := a.view.RootDigest()
	trust := a.view.EvidenceDigest()
	if m.Version != 1 || m.Purpose != "automation-membership-source" || m.Stream != "automation" || !sameSourceRequest(m.Request, r.Intent) || m.Source != c.hostName || m.Incarnation != a.facts.incarnation || m.OldValue != sourceConfigDigest(a.facts.old) || m.NextValue != sourceConfigDigest(a.facts.next) || m.OldMembers != a.facts.old.MembersHash || m.NextMembers != a.facts.next.MembersHash || m.Signer != hex.EncodeToString(signer[:]) || m.TrustDomain != hex.EncodeToString(root[:]) || m.TrustEvidence != hex.EncodeToString(trust[:]) || !bytes.Equal(signed.Chain[0], a.pair.Certificate[0]) {
		return out, errors.New("publication no longer matches current source authority")
	}
	target := m.Target
	if target.Host != r.Intent.Target || target.Incarnation != a.target.Incarnation || target.Certificate != a.target.Fingerprint || target.Local != a.target.Local || target.Endpoint != a.target.Endpoint || target.Connected != a.target.Connected {
		return out, errors.New("publication target lifetime changed")
	}
	key, ok := a.pair.PrivateKey.(*ecdsa.PrivateKey)
	digest, _ := hex.DecodeString(sourceDigest([]byte(sourceManifestDomain), signed.Manifest))
	if !ok || !ecdsa.VerifyASN1(&key.PublicKey, digest, signed.Signature) {
		return out, errors.New("invalid source artifact signature")
	}
	metadata, cutRoot, e := automationCutRoot(m.Cut)
	if e != nil || cutRoot != m.Root || m.Cut.Source != m.Source || m.Cut.Incarnation != m.Incarnation || m.Cut.Generation != m.Request.Generation {
		return out, errors.New("export cut binding differs")
	}
	if _, e = readAutomationCutMetadata(Row{Columns: []string{"id", "metadata", "root"}, Values: []any{m.Cut.ID, metadata, m.Root}}); e != nil {
		return out, e
	}
	var membership sourceMembershipEvidence
	if json.Unmarshal(out.membership, &membership) != nil {
		return out, errors.New("invalid export membership evidence")
	}
	canonical, e = json.Marshal(membership)
	if e != nil || !bytes.Equal(canonical, out.membership) {
		return out, errors.New("noncanonical export membership evidence")
	}
	old := &VoterConfig{VoterConfigValue: membership.Old, MembersHash: MembersHash(membership.Old.Members)}
	next := &VoterConfig{VoterConfigValue: membership.Next, MembersHash: MembersHash(membership.Next.Members), Certificate: membership.Certificate}
	if sourceConfigDigest(old) != m.OldValue || sourceConfigDigest(next) != m.NextValue || sourceDigest([]byte(membership.Certificate)) != m.MembershipEvidence {
		return out, errors.New("export membership binding differs")
	}
	if _, _, e = verifySourceTransition(a.view, old, next); e != nil {
		return out, e
	}
	return out, nil
}
