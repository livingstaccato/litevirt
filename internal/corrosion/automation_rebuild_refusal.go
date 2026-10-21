package corrosion

import (
	"context"
	"errors"

	"github.com/litevirt/litevirt/internal/automation/contract"
	"github.com/litevirt/litevirt/internal/safename"
)

// ErrRetainedManagedRebuild is definite local retained ownership, not uncertainty.
var ErrRetainedManagedRebuild = errors.New("retained managed VM cannot be rebuilt through the native API")

// CheckRetainedManagedRebuildRefusal refuses native rebuild of a name already
// managed in this local retained snapshot. Nil means no local retained refusal;
// it is not an effect permit, freshness proof, or exclusion of concurrent adoption.
// This read never initializes automation authority or proposes a barrier.
func (c *Client) CheckRetainedManagedRebuildRefusal(ctx context.Context, name string) error {
	return c.checkRetainedManagedRebuildRefusal(ctx, name, nil)
}

func (c *Client) checkRetainedManagedRebuildRefusal(ctx context.Context, name string, seams *localCommitSeams) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	unavailable := automationReadError(contract.CodeUnavailable)
	if !automationReadString(name, false) || safename.ValidateVMName(name) != nil {
		return unavailable
	}
	managed := false
	err := c.executeLocal(ctx, func(tx *LocalTx) error {
		// Pending recovery blocks both pristine and established branches.
		pending, err := tx.Query(ctx, `SELECT EXISTS(SELECT 1 FROM local_automation_recovery) OR EXISTS(SELECT 1 FROM local_automation_staging) AS present`)
		if err != nil {
			return err
		}
		if len(pending) != 1 || pending[0].Int64("present") != 0 {
			return unavailable
		}
		// Bound/types-only inspection before materializing retained scalars.
		heads, err := tx.Query(ctx, `SELECT CASE WHEN id=1 AND typeof(cluster_uid)='text' AND length(CAST(cluster_uid AS BLOB)) BETWEEN 1 AND ? AND typeof(sequence)='integer' AND sequence>0 AND typeof(digest)='text' AND length(CAST(digest AS BLOB))=64 THEN 1 ELSE 0 END AS valid FROM local_automation_prefix`, contract.MaxStringBytes)
		if err != nil {
			return err
		}
		if len(heads) == 0 {
			// Schema84 fixed inventory, all stages. Missing tables/query errors are not
			// empty state. Ordinary native lifetime/credential/voter bookkeeping stays allowed.
			for _, table := range []string{
				"local_automation_prefix",
				"local_automation_history",
				"local_automation_anchors",
				"local_automation_requests",
				"local_automation_authority",
				"local_automation_recovery",
				"local_automation_staging",
				"local_automation_semantic_heads",
				"local_automation_identities",
				"local_automation_aliases",
				"local_automation_owners",
				"local_automation_resources",
				"local_automation_names",
				"local_automation_bindings",
				"local_automation_admissions",
				"local_automation_key_epochs",
				"local_automation_key_recipients",
				"local_automation_payload_wrappings",
				"local_automation_retained_deliveries",
				"local_automation_retained_objects",
				"local_automation_retained_completions",
				"local_automation_aggregates",
				"local_automation_aggregate_sources",
				"local_automation_aggregate_copies",
				"local_automation_aggregate_maxima",
				"local_automation_aggregate_conflicts",
				"local_automation_receiver_audits",
				"local_automation_receiver_refs",
				"local_automation_receiver_requests",
				"local_automation_receiver_jobs",
				"local_automation_receiver_current",
				"local_automation_receiver_established",
				"local_automation_receiver_validations",
				"local_automation_receiver_sources",
				"local_automation_receiver_components",
				"local_automation_receiver_records",
				"local_automation_receiver_pages",
				"local_automation_target_operations",
				"local_automation_target_reservations",
			} {
				rows, err := tx.Query(ctx, "SELECT EXISTS(SELECT 1 FROM "+table+") AS present")
				if err != nil {
					return err
				}
				if len(rows) != 1 || rows[0].Int64("present") != 0 {
					return unavailable
				}
			}
			for _, table := range []string{"local_recovery_claims", "local_incarnation_claims"} {
				rows, err := tx.Query(ctx, "SELECT EXISTS(SELECT 1 FROM "+table+" WHERE typeof(target_kind)<>'text' OR target_kind='automation') AS present")
				if err != nil {
					return err
				}
				if len(rows) != 1 || rows[0].Int64("present") != 0 {
					return unavailable
				}
			}
			return nil
		}
		if len(heads) != 1 || heads[0].Int64("valid") != 1 {
			return unavailable
		}
		head, err := automationRetainedHeadTx(ctx, tx)
		if err != nil {
			return err
		}
		observed, err := automationObserveNameTx(ctx, tx, head.ClusterUID, name, head.Sequence)
		if err != nil {
			return err
		}
		switch observed.State {
		case AutomationNameAbsent:
			return nil
		case AutomationNamePresent:
			if observed.Record == nil {
				return unavailable
			}
			r := observed.Record
			if r.Resource.OwnerID == "" {
				if r.Owner != nil || r.Binding != nil {
					return unavailable
				}
				return nil
			}
			if r.Owner == nil || r.Binding == nil {
				return unavailable
			}
			managed = true
			return nil
		default:
			return unavailable
		}
	}, seams)
	// No callback result escapes a failed transaction, including a failed commit.
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return context.Canceled
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return context.DeadlineExceeded
		}
		return unavailable
	}
	if managed {
		return ErrRetainedManagedRebuild
	}
	return nil
}
