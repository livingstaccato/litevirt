package corrosion

import (
	"context"
	"encoding/json"
)

type aggregateRebuild struct {
	id, temporary, coverage string
	head                    AutomationPrefix
	headRaw, rosterRaw      []byte
	roster                  []aggregateRosterEntry
}

// Both current and transferred original inputs use C's exact compatible-history,
// coverage, losing-copy, conflict and maximum selection in the same order.
func aggregateRebuildClaimsTx(ctx context.Context, tx *LocalTx, attempt string, binding []byte, sources []aggregateSource, local aggregateLocalAudit) (aggregateRebuild, error) {
	var out aggregateRebuild
	var err error
	head, baseline := local.head, local.store
	for _, s := range sources {
		if s.head.Sequence > head.Sequence {
			head, baseline = s.head, s.store
		}
	}
	if err = aggregateCompatibleHistory(ctx, local.store, baseline); err != nil {
		return out, err
	}
	if err = aggregateCoverage(ctx, local.store); err != nil {
		return out, err
	}
	roster := make([]aggregateRosterEntry, 0, len(sources))
	for _, s := range sources {
		if err = aggregateCompatibleHistory(ctx, s.store, baseline); err != nil {
			return out, err
		}
		if err = aggregateCoverage(ctx, s.store); err != nil {
			return out, err
		}
		roster = append(roster, aggregateRosterEntry{s.member.Name, s.member.Incarnation, s.audit, s.publication.id, s.publication.manifest.Root, s.publication.manifest.Cut.ID, s.coverage})
	}
	rosterRaw, _ := json.Marshal(roster)
	headRaw, _ := json.Marshal(head)
	coverage := sourceDigest([]byte("litevirt/aggregate-coverage/v1"), []byte(local.coverage), rosterRaw)
	id := sourceDigest([]byte("litevirt/receiver-aggregate/v1"), []byte(attempt), binding, []byte(local.id), []byte(local.dependency), headRaw, []byte(coverage), rosterRaw)
	// Build maxima in a fresh namespace. A retry cannot temporarily overwrite
	// even a winning or losing row of an already published immutable aggregate.
	temporary, err := aggregateTemporaryTx(ctx, tx)
	if err != nil {
		return out, err
	}
	stores := make([]aggregateEvidenceStore, 0, len(sources)+1)
	for _, s := range sources {
		stores = append(stores, aggregateEvidenceStore{"source", s.audit, s.store})
	}
	stores = append(stores, aggregateEvidenceStore{"local", local.id, local.store})
	for _, s := range stores {
		if err = aggregateClaimsTx(ctx, tx, temporary, s, stores, local); err != nil {
			return out, err
		}
	}
	if err = aggregateAcceptedBaselineTx(ctx, tx, temporary, stores, baseline, head); err != nil {
		return out, err
	}
	return aggregateRebuild{id, temporary, coverage, head, headRaw, rosterRaw, roster}, nil
}
