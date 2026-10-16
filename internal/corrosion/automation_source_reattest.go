package corrosion

import (
	"context"
	"database/sql"
	"errors"
)

// Repair only asks the fixed old electorate for its own stored exact accepts.
// It does not propose, count reachable hosts as an electorate, or create votes.
func (p *AutomationSourcePreparer) reattestSourceTransition(ctx context.Context, d sourceDiscovery, signer *ClaimSigner) (*VoterConfig, error) {
	cert, err := sourceCertificate(d.next.Certificate)
	if err != nil {
		return nil, err
	}
	c := p.client
	for _, member := range d.old.Members {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		var a *ClaimAccept
		if member.Name == c.hostName {
			// Bound and read this actual voter's retained accept while DB is owned;
			// key acquisition and re-signing occur after releasing the transaction.
			var st ClaimVoterState
			c.mu.RLock()
			tx, e := c.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
			if e == nil {
				local := &LocalTx{tx: tx}
				rows, readErr := local.Query(ctx, `SELECT `+automationCutRowSize(automationCutSections[0])+` AS size FROM local_recovery_claims WHERE target_kind=? AND target_name='' AND owner_epoch=? AND attempt=0 LIMIT 1`, ClaimKindVoterConfig, d.old.Generation)
				if readErr == nil && len(rows) == 1 && rows[0].Int64("size") <= maxSourceCertificateBytes+maxSourceConfigBytes {
					rows, readErr = local.Query(ctx, `SELECT `+automationCutSections[0].columns+` FROM local_recovery_claims WHERE target_kind=? AND target_name='' AND owner_epoch=? AND attempt=0 LIMIT 1`, ClaimKindVoterConfig, d.old.Generation)
					if readErr == nil && len(rows) == 1 {
						st, readErr = scanClaimRow(cert.Key, rows[0])
					}
				}
				e = readErr
				tx.Rollback()
			}
			c.mu.RUnlock()
			if e != nil || st.Accept == nil || st.Value == nil || st.Accept.Voter != c.hostName || st.Accept.VoterIncarnation != d.incarnation || st.Accepted.IsZero() {
				continue
			}
			digest, e := st.Value.Digest()
			if e != nil || digest != st.ValueDigest || validateRetainedAutomationAccept(*st.Accept, cert.Key, st.Accepted, d.old.Generation, digest) != nil {
				continue
			}
			renewed, e := signer.Sign(cert.Key, d.old.Generation, st.Accepted, digest, d.incarnation)
			if e != nil {
				return nil, e
			}
			a = &renewed
		} else {
			c.mu.RLock()
			tx, e := c.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
			var h sourceHost
			if e == nil {
				h, e = sourceReadHost(ctx, &LocalTx{tx: tx}, member.Name)
				tx.Rollback()
			}
			c.mu.RUnlock()
			if e != nil {
				continue
			}
			resp, observed, e := sourceQueryPeer(ctx, p.dir, h, d.old.Generation, true)
			if e != nil || observed.Incarnation != member.Incarnation {
				continue
			}
			a = sourceAcceptFromPB(resp.GetReattested())
			if a == nil {
				a = sourceAcceptFromPB(resp.GetAccept())
			}
		}
		if a == nil || a.Voter != member.Name || a.VoterIncarnation != member.Incarnation || a.Key != cert.Key || a.ConfigGeneration != cert.ConfigGeneration || a.ValueDigest != cert.ValueDigest || !a.Ballot.Equal(cert.Ballot) {
			continue
		}
		cert.Accepts = append(cert.Accepts, *a)
		if len(cert.Accepts) > maxSourceAccepts {
			return nil, errors.New("membership repair exceeds accept bound")
		}
	}
	raw, err := cert.Encode()
	if err != nil {
		return nil, err
	}
	if _, err = sourceCertificate(raw); err != nil {
		return nil, err
	}
	next := *d.next
	next.Certificate = raw
	sourceLearnMembership(p.dir, cert)
	return &next, nil
}
