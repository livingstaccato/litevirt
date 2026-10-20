package corrosion

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"
	"unicode/utf8"

	"github.com/litevirt/litevirt/internal/automation/contract"
)

type automationReadError string

func (e automationReadError) Error() string { return "automation: " + string(e) }
func (e automationReadError) Code() string  { return string(e) }

func automationReadString(s string, empty bool) bool {
	return (empty || s != "") && len(s) <= contract.MaxStringBytes && utf8.ValidString(s) && strings.IndexByte(s, 0) < 0
}

// AutomationObserve consumes the existing complete semantic projection after a
// caller's certified barrier. Its local transaction fences projection reset;
// this method issues neither a barrier nor business admission authority.
func (c *Client) AutomationObserve(ctx context.Context, cluster, uid string, barrier uint64) (view contract.View, found bool, err error) {
	if !automationReadString(cluster, false) || !automationReadString(uid, false) || barrier == 0 || barrier > math.MaxInt64 {
		return contract.View{}, false, automationReadError(contract.CodeValidation)
	}
	err = c.ExecuteLocal(ctx, func(tx *LocalTx) error {
		var e error
		view, found, e = automationObserveTx(ctx, tx, cluster, uid, barrier)
		return e
	})
	if err != nil {
		return contract.View{}, false, err
	}
	return view, found, nil
}

func automationReadFrontierTx(ctx context.Context, tx *LocalTx, cluster string, barrier uint64) (AutomationPrefix, error) {
	unavailable := automationReadError(contract.CodeUnavailable)
	// Probe types and sizes before the existing typed helpers can coerce SQL
	// values or load an oversized scalar. SQLite INTEGER already bounds int64.
	rows, err := tx.Query(ctx, `SELECT CASE WHEN typeof(cluster_uid)='text' AND length(CAST(cluster_uid AS BLOB)) BETWEEN 1 AND ? AND typeof(sequence)='integer' AND sequence>0 AND typeof(digest)='text' AND length(CAST(digest AS BLOB))=64 THEN 1 ELSE 0 END AS valid FROM local_automation_prefix WHERE id=1 UNION ALL SELECT CASE WHEN typeof(cluster_uid)='text' AND length(CAST(cluster_uid AS BLOB)) BETWEEN 1 AND ? AND typeof(sequence)='integer' AND sequence>0 AND typeof(digest)='text' AND length(CAST(digest AS BLOB))=64 THEN 1 ELSE 0 END FROM local_automation_semantic_heads WHERE stage=''`, contract.MaxStringBytes, contract.MaxStringBytes)
	if err != nil {
		return AutomationPrefix{}, err
	}
	if len(rows) != 2 || rows[0].Int64("valid") != 1 || rows[1].Int64("valid") != 1 {
		return AutomationPrefix{}, unavailable
	}
	if err := automationProjectionAuthorityTx(ctx, tx); err != nil {
		if errors.Is(err, errAutomationAuthority) {
			return AutomationPrefix{}, unavailable
		}
		return AutomationPrefix{}, err
	}
	head, err := automationHeadTx(ctx, tx)
	if err != nil {
		return AutomationPrefix{}, err
	}
	retained, err := automationRetainedHeadTx(ctx, tx)
	if err != nil {
		return AutomationPrefix{}, err
	}
	if head != retained || head.ClusterUID != cluster || head.Sequence < barrier || !automationReadString(head.ClusterUID, false) {
		return AutomationPrefix{}, unavailable
	}
	return head, nil
}

func automationObserveTx(ctx context.Context, tx *LocalTx, cluster, uid string, barrier uint64) (contract.View, bool, error) {
	unavailable := automationReadError(contract.CodeUnavailable)
	head, err := automationReadFrontierTx(ctx, tx, cluster, barrier)
	if err != nil {
		return contract.View{}, false, err
	}
	rows, err := tx.Query(ctx, `SELECT CASE WHEN typeof(uid)='text' AND typeof(cluster_uid)='text' AND typeof(project_uid)='text' AND typeof(name)='text' AND typeof(domain_uuid)='text' AND typeof(incarnation)='text' AND typeof(owner_id)='text' AND typeof(management_key)='text' AND typeof(revision)='text' AND typeof(last_operation_id)='text' AND typeof(original_operation_id)='text' AND max(length(CAST(uid AS BLOB)),length(CAST(cluster_uid AS BLOB)),length(CAST(project_uid AS BLOB)),length(CAST(name AS BLOB)),length(CAST(domain_uuid AS BLOB)),length(CAST(incarnation AS BLOB)),length(CAST(owner_id AS BLOB)),length(CAST(management_key AS BLOB)),length(CAST(revision AS BLOB)),length(CAST(last_operation_id AS BLOB)),length(CAST(original_operation_id AS BLOB)))<=? AND typeof(binding_generation)='integer' AND binding_generation>=0 AND typeof(retired)='integer' AND retired IN (0,1) AND typeof(applied_sequence)='integer' AND applied_sequence>0 THEN 1 ELSE 0 END AS valid FROM local_automation_resources WHERE stage='' AND uid=? LIMIT 1`, contract.MaxStringBytes, uid)
	if err != nil {
		return contract.View{}, false, err
	}
	if len(rows) == 0 {
		// A missing resource with surviving typed references is a partial
		// projection, not evidence of absence. Full reset removes the semantic
		// frontier too, which was checked above in this same transaction.
		dangling, err := tx.Query(ctx, `SELECT EXISTS(SELECT 1 FROM local_automation_identities WHERE stage='' AND uid=? AND kind='vm') OR EXISTS(SELECT 1 FROM local_automation_names WHERE stage='' AND resource_uid=?) OR EXISTS(SELECT 1 FROM local_automation_bindings WHERE stage='' AND resource_uid=?) OR EXISTS(SELECT 1 FROM local_automation_admissions WHERE stage='' AND resource_uid=?) AS present`, uid, uid, uid, uid)
		if err != nil {
			return contract.View{}, false, err
		}
		if len(dangling) != 1 || dangling[0].Int64("present") != 0 {
			return contract.View{}, false, unavailable
		}
		return contract.View{}, false, nil
	}
	if rows[0].Int64("valid") != 1 {
		return contract.View{}, false, fmt.Errorf("invalid resource projection scalar types or bounds")
	}
	r, err := automationResourceRecordTx(ctx, tx, "", uid)
	if err != nil {
		return contract.View{}, false, err
	}
	if r == nil || r.ClusterUID != cluster || r.AppliedSequence > head.Sequence {
		return contract.View{}, false, unavailable
	}
	for _, s := range []string{r.ClusterUID, r.ProjectUID, r.UID, r.Name, r.DomainUUID, r.Incarnation, r.Revision, r.LastOperationID} {
		if !automationReadString(s, false) {
			return contract.View{}, false, fmt.Errorf("invalid resource projection string")
		}
	}
	for _, s := range []string{r.OwnerID, r.ManagementKey, r.OriginalOperationID} {
		if !automationReadString(s, true) {
			return contract.View{}, false, fmt.Errorf("invalid resource projection string")
		}
	}
	retired := 0
	if r.Retired {
		retired = 1
	}
	// Enrollment's source witness and the VM runtime incarnation are distinct
	// recorded facts. Validate the witness without inventing an equality rule.
	identity, err := tx.Query(ctx, `SELECT witness FROM local_automation_identities WHERE stage='' AND uid=? AND typeof(uid)='text' AND cluster_uid=? AND typeof(cluster_uid)='text' AND project_uid=? AND typeof(project_uid)='text' AND kind='vm' AND typeof(kind)='text' AND alias=? AND typeof(alias)='text' AND typeof(witness)='text' AND length(CAST(witness AS BLOB)) BETWEEN 1 AND ? AND typeof(generation)='integer' AND generation>0 AND typeof(retired)='integer' AND retired=? LIMIT 1`, uid, cluster, r.ProjectUID, r.Name, contract.MaxStringBytes, retired)
	if err != nil {
		return contract.View{}, false, err
	}
	if len(identity) != 1 || !automationReadString(identity[0].String("witness"), false) {
		return contract.View{}, false, unavailable
	}
	return contract.View{ClusterUID: r.ClusterUID, ResourceUID: r.UID, Name: r.Name, DomainUUID: r.DomainUUID, ResourceRevision: r.Revision, Generation: r.BindingGeneration, AppliedSequence: head.Sequence, Retired: r.Retired}, true, nil
}
