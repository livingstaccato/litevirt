package corrosion

import (
	"context"
	"database/sql"
	"math"
	"unicode/utf8"

	"github.com/litevirt/litevirt/internal/automation/contract"
)

const automationProofOrigin = "origin"
const automationProofContinuity = "continuity"

// A mode selects one proof forever. Unselected origin observations do not
// acquire meaning from a continuity attachment, and selected failures refuse.
type automationCredentialProof struct {
	mode            string
	witness         string
	generation      uint64
	originalWitness string
	parent          contract.ParentLifetime
}

func (p automationCredentialProof) valid(kind string) bool {
	switch p.mode {
	case automationProofOrigin:
		return p.witness != "" && len(p.witness) <= contract.MaxStringBytes && utf8.ValidString(p.witness) && p.generation == 0 && p.originalWitness == "" && p.parent == (contract.ParentLifetime{})
	case automationProofContinuity:
		return kind == "session" && p.witness == "" && p.generation > 0 && p.generation <= math.MaxInt64 && p.originalWitness != "" && len(p.originalWitness) <= contract.MaxStringBytes && utf8.ValidString(p.originalWitness) && p.parent.Kind == "principal" && p.parent.Realm == "local" && p.parent.Alias != "" && p.parent.Birth != "" && len(p.parent.Alias) <= contract.MaxStringBytes && len(p.parent.Birth) <= contract.MaxStringBytes && utf8.ValidString(p.parent.Alias) && utf8.ValidString(p.parent.Birth)
	default:
		return false
	}
}

// The caller owns Client.mu and this exact SQL snapshot. A present projection
// must have one original identity and one exact alias, under current authority.
func automationCertifiedIdentityForAliasTx(ctx context.Context, tx *sql.Tx, kind, name string) (*contract.IdentityRecord, error) {
	var candidates int
	err := tx.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM local_automation_identities WHERE stage='' AND kind=? AND alias=?) + (SELECT count(*) FROM local_automation_aliases WHERE stage='' AND kind=? AND alias=?)`, kind, name, kind, name).Scan(&candidates)
	if err != nil {
		return nil, err
	}
	if candidates == 0 {
		return nil, nil
	}
	local := &LocalTx{tx: tx}
	if err := automationProjectionAuthorityTx(ctx, local); err != nil {
		return nil, err
	}
	var count, wellFormed int
	var uid string
	err = tx.QueryRowContext(ctx, `SELECT count(*),COALESCE(min(i.uid),''),COALESCE(min(typeof(i.generation)='integer' AND i.generation>0 AND typeof(i.retired)='integer' AND i.retired=0 AND i.uid<>'' AND i.cluster_uid<>'' AND i.witness<>'' AND typeof(i.uid)='text' AND typeof(i.cluster_uid)='text' AND typeof(i.project_uid)='text' AND typeof(i.kind)='text' AND typeof(i.alias)='text' AND typeof(i.witness)='text' AND length(CAST(i.uid AS BLOB))<=? AND length(CAST(i.cluster_uid AS BLOB))<=? AND length(CAST(i.witness AS BLOB))<=?),0)
 FROM local_automation_identities i JOIN local_automation_aliases a ON a.stage=i.stage AND a.uid=i.uid AND a.cluster_uid=i.cluster_uid AND a.project_scope=i.project_uid AND a.kind=i.kind AND a.alias=i.alias AND a.generation=i.generation
 WHERE i.stage='' AND i.kind=? AND i.project_uid='' AND i.alias=?`, contract.MaxStringBytes, contract.MaxStringBytes, contract.MaxStringBytes, kind, name).Scan(&count, &uid, &wellFormed)
	if err != nil {
		return nil, err
	}
	if candidates != 2 || count != 1 || wellFormed != 1 {
		return nil, ErrAutomationLifecycleUnavailable
	}
	i, err := automationIdentityRecordTx(ctx, local, "", uid)
	if err != nil {
		return nil, err
	}
	head, err := automationHeadTx(ctx, local)
	if err != nil {
		return nil, err
	}
	if i == nil || i.Retired || i.Kind != kind || i.Alias != name || i.ProjectUID != "" || i.ClusterUID != head.ClusterUID || i.Generation == 0 || i.Generation > math.MaxInt64 || !utf8.ValidString(i.Witness) {
		return nil, ErrAutomationLifecycleUnavailable
	}
	return i, nil
}

func automationIdentityContinuityProofTx(ctx context.Context, c *Client, tx *sql.Tx, i *contract.IdentityRecord) (*automationCredentialProof, error) {
	if i == nil {
		return nil, ErrAutomationLifecycleUnavailable
	}
	local := &LocalTx{tx: tx}
	if err := automationProjectionAuthorityTx(ctx, local); err != nil {
		return nil, err
	}
	f, err := automationContinuityRecordTx(ctx, local, "", i.ClusterUID, i.UID, i.Generation)
	if err != nil {
		return nil, err
	}
	if f == nil {
		var present int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM local_automation_identity_continuity WHERE stage='' AND uid=?`, i.UID).Scan(&present); err != nil {
			return nil, err
		}
		if present != 0 {
			return nil, ErrAutomationLifecycleUnavailable
		}
		return nil, nil
	}
	parent, err := readAutomationParentLifetimeTx(ctx, c, tx, i.Kind, i.Alias)
	if err != nil {
		return nil, err
	}
	if f.ClusterUID != i.ClusterUID || f.UID != i.UID || f.Generation != i.Generation || f.OriginalWitness != i.Witness || f.Parent != parent {
		return nil, ErrAutomationLifecycleUnavailable
	}
	return &automationCredentialProof{mode: automationProofContinuity, generation: f.Generation, originalWitness: f.OriginalWitness, parent: f.Parent}, nil
}
