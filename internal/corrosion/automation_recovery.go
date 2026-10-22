package corrosion

import (
	"context"
	"encoding/json"
	"fmt"
)

// Recovery staging is on disk. The single checkpoint is authenticated by a
// fresh head certificate; every predecessor must hash to the next linked digest.
// No peer-selected clock, CA, membership, or trust flag is accepted.
func (c *Client) AutomationBeginRecovery(ctx context.Context, r AutomationRecord, v *ClaimVerifier) error {
	r = copyContinuityRecord(r)
	if err := validateAutomationRecordSize(r); err != nil {
		return err
	}
	d, err := automationDecision(r.Value)
	if err != nil {
		return err
	}
	digest, err := r.Value.Digest()
	if err != nil {
		return err
	}
	cfg, err := c.AutomationMembership(ctx)
	if err != nil {
		return err
	}
	key, _ := AutomationClaimKey(d.Sequence)
	if err = v.Verify(r.Certificate, CertExpectation{Key: key, ValueDigest: digest, ConfigGeneration: cfg.Generation, Electorate: cfg.Members, Quorum: MajorityOf(len(cfg.Members))}); err != nil {
		return err
	}
	request, err := automationPrepareKeyLookup(ctx, d, r.Certificate)
	if err != nil {
		return err
	}
	if request != nil && request.configDigest != cfg.MembersHash {
		return fmt.Errorf("key transition differs from original certified config")
	}
	return c.executeContinuityMaterialization(ctx, r, continuityCertificate, func(tx *LocalTx) error {
		if err := requireAutomationFull(ctx, tx); err != nil {
			return err
		}
		current, err := automationAuthorityTx(ctx, tx, c.hostName, cfg.Generation)
		if err != nil {
			return err
		}
		if MembersHash(current.Members) != MembersHash(cfg.Members) {
			return fmt.Errorf("automation membership changed")
		}
		rs, err := tx.Query(ctx, `SELECT sequence,digest FROM local_automation_recovery WHERE id=1`)
		if err != nil {
			return err
		}
		// Resume the existing authenticated job instead of discarding bounded work.
		if len(rs) != 0 {
			return nil
		}
		head, err := automationHeadTx(ctx, tx)
		if err != nil {
			return err
		}
		if d.Sequence <= head.Sequence {
			return nil
		}
		cert, err := r.Certificate.Encode()
		if err != nil {
			return err
		}
		value, err := json.Marshal(r.Value)
		if err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `INSERT INTO local_automation_recovery (id,sequence,digest,next_sequence,next_digest,base_sequence,base_digest,generation,members_hash,certificate) VALUES (1,?,?,?,?,?,?,?,?,?)`, d.Sequence, digest, d.Sequence-1, d.ParentDigest, head.Sequence, head.Digest, cfg.Generation, MembersHash(cfg.Members), cert); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO local_automation_staging (sequence,digest,value_json,certificate) VALUES (?,?,?,?)`, d.Sequence, digest, string(value), cert)
		return err
	})
}
func (c *Client) AutomationRecoveryNext(ctx context.Context) (next uint64, e error) {
	e = c.ExecuteLocal(ctx, func(tx *LocalTx) error {
		rs, err := tx.Query(ctx, `SELECT next_sequence,next_digest,base_sequence,base_digest FROM local_automation_recovery WHERE id=1`)
		if err != nil || len(rs) == 0 {
			return err
		}
		r := rs[0]
		if r.Int64("next_sequence") == r.Int64("base_sequence") {
			if r.String("next_digest") != r.String("base_digest") {
				return fmt.Errorf("automation recovery does not connect to local prefix")
			}
			return nil
		}
		next = uint64(r.Int64("next_sequence"))
		return nil
	})
	return
}
func (c *Client) AutomationStagePredecessor(ctx context.Context, r AutomationRecord) error {
	r = copyContinuityRecord(r)
	if err := validateAutomationRecordSize(r); err != nil {
		return err
	}
	d, err := automationDecision(r.Value)
	if err != nil {
		return err
	}
	digest, err := r.Value.Digest()
	if err != nil {
		return err
	}
	value, err := json.Marshal(r.Value)
	if err != nil || len(value) > MaxAutomationClaimBytes {
		return fmt.Errorf("automation staged value too large")
	}
	cert, err := r.Certificate.Encode()
	if err != nil {
		return err
	}
	return c.executeContinuityMaterialization(ctx, r, continuityPredecessor, func(tx *LocalTx) error {
		if err := requireAutomationFull(ctx, tx); err != nil {
			return err
		}
		rs, err := tx.Query(ctx, `SELECT next_sequence,next_digest,base_sequence FROM local_automation_recovery WHERE id=1`)
		if err != nil {
			return err
		}
		if len(rs) != 1 || rs[0].Int64("next_sequence") <= rs[0].Int64("base_sequence") || uint64(rs[0].Int64("next_sequence")) != d.Sequence || rs[0].String("next_digest") != digest {
			return fmt.Errorf("unanchored automation predecessor")
		}
		if _, err = tx.Exec(ctx, `INSERT INTO local_automation_staging (sequence,digest,value_json,certificate) VALUES (?,?,?,?)`, d.Sequence, digest, string(value), cert); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE local_automation_recovery SET next_sequence=?,next_digest=? WHERE id=1`, d.Sequence-1, d.ParentDigest)
		return err
	})
}
func (c *Client) AutomationFinishRecovery(ctx context.Context, reduce AutomationReducer, budget int) error {
	for range budget {
		var sequence uint64
		var digest string
		var anchorSeq, gen int64
		var members, anchorCert string
		done := false
		err := c.ExecuteLocal(ctx, func(tx *LocalTx) error {
			rs, err := tx.Query(ctx, `SELECT sequence,digest,next_sequence,next_digest,base_sequence,base_digest,generation,members_hash,certificate FROM local_automation_recovery WHERE id=1`)
			if err != nil {
				return err
			}
			if len(rs) == 0 {
				done = true
				return nil
			}
			job := rs[0]
			if job.Int64("next_sequence") != job.Int64("base_sequence") || job.String("next_digest") != job.String("base_digest") {
				return fmt.Errorf("automation predecessor chain incomplete")
			}
			head, err := automationHeadTx(ctx, tx)
			if err != nil {
				return err
			}
			if head.Sequence >= uint64(job.Int64("sequence")) {
				digest, found, err := automationTrustedDigestTx(ctx, tx, uint64(job.Int64("sequence")))
				if err != nil {
					return err
				}
				if !found || digest != job.String("digest") {
					return fmt.Errorf("automation completed recovery anchor mismatch")
				}

				if _, err = tx.Exec(ctx, `DELETE FROM local_automation_staging`); err != nil {
					return err
				}
				_, err = tx.Exec(ctx, `DELETE FROM local_automation_recovery WHERE id=1`)
				done = true
				return err
			}
			rows, err := tx.Query(ctx, `SELECT sequence,digest FROM local_automation_staging WHERE sequence=? LIMIT 1`, head.Sequence+1)
			if err != nil {
				return err
			}
			if len(rows) != 1 {
				return fmt.Errorf("automation staged predecessor missing")
			}
			row := rows[0]
			digest = row.String("digest")
			sequence = uint64(row.Int64("sequence"))
			anchorSeq = job.Int64("sequence")
			gen = job.Int64("generation")
			members = job.String("members_hash")
			anchorCert = job.String("certificate")
			return err
		})
		if err != nil {
			return err
		}
		if done {
			return nil
		}
		// The verified head checkpoint supplies the ancestry provenance. Use the
		// same FULL transaction-local application path as fresh admission/replay.
		err = c.ExecuteLocal(ctx, func(tx *LocalTx) error {
			_, err := automationApplyStoredTx(ctx, tx, sequence, digest, reduce, automationApplicationProvenance{
				kind: automationStagedAnchor, sequence: uint64(anchorSeq), generation: gen,
				membersHash: members, certificate: anchorCert,
			}, true)
			return err
		})
		if err != nil {
			return err
		}
	}
	return fmt.Errorf("automation recovery budget exhausted")
}

func (c *Client) AutomationRecoveryPending(ctx context.Context) (pending bool, e error) {
	e = c.ExecuteLocal(ctx, func(tx *LocalTx) error {
		rows, err := tx.Query(ctx, `SELECT id FROM local_automation_recovery WHERE id=1`)
		pending = len(rows) != 0
		return err
	})
	return
}
