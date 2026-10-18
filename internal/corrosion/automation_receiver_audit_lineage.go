package corrosion

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
)

// Original certificates here describe native established frozen storage under
// the authenticated exporter model. They do not bypass current PKI verification
// or authorize a future imported origin. No authority comes from provenance text.
func receiverRetainedMembership(prev, cfg *VoterConfig) error {
	if err := ValidateVoterChange(prev, cfg.VoterConfigValue); err != nil {
		return err
	}
	want, err := ExpectedVoterConfigCertificate(prev, cfg.VoterConfigValue)
	if err != nil {
		return err
	}
	cert, err := sourceCertificate(cfg.Certificate)
	if err != nil {
		return err
	}
	if cert.Key != want.Key || cert.ConfigGeneration != want.ConfigGeneration || cert.ValueDigest != want.ValueDigest || validateAutomationBallot(cert.Ballot, false) != nil {
		return errors.New("frozen membership certificate binding")
	}
	seen := map[string]bool{}
	incs := map[string]bool{}
	for _, a := range cert.Accepts {
		for _, m := range want.Electorate {
			if a.Voter == m.Name && a.VoterIncarnation == m.Incarnation && !seen[m.Name] && !incs[m.Incarnation] && validateRetainedAutomationAccept(a, cert.Key, cert.Ballot, cert.ConfigGeneration, cert.ValueDigest) == nil {
				seen[m.Name] = true
				incs[m.Incarnation] = true
				break
			}
		}
	}
	if len(seen) < want.Quorum {
		return errors.New("frozen membership original quorum missing")
	}
	return nil
}

func (s receiverAuditStore) membership(ctx context.Context, g int64) (*VoterConfig, error) {
	row, err := s.sequence(ctx, 11, g)
	if err != nil {
		return nil, err
	}
	return sourceConfigRow(row)
}

func (s receiverAuditStore) lineage(ctx context.Context, a *AutomationReceiverAttempt) (string, error) {
	m := s.publication.manifest
	if m.Cut.Generation != a.request.Generation || m.Cut.Incarnation != m.Incarnation || m.Cut.Source != s.source || (s.ownedCutID == "" && !receiverDigest(m.Lineage)) {
		return "", errors.New("frozen source lineage binding")
	}
	var previous *VoterConfig
	var configs int64
	err := s.walk(ctx, 11, func(_ int64, row Row) error {
		cfg, err := sourceConfigRow(row)
		if err != nil {
			return err
		}
		if cfg.Generation != configs+1 || len(cfg.Members) == 0 {
			return errors.New("frozen membership lineage gap/reset")
		}
		if err = receiverRetainedMembership(previous, cfg); err != nil {
			return err
		}
		// Begin independently authenticates the receiver's entire ordinary chain.
		// Frozen certificate metadata stays original; compare stable full values.
		if cfg.Generation <= a.request.Generation+1 {
			local, err := sourceReadConfig(ctx, s.tx, cfg.Generation)
			if err != nil {
				return err
			}
			if sourceConfigDigest(local) != sourceConfigDigest(cfg) {
				return errors.New("frozen membership differs from authorized chain")
			}
		}
		previous = cfg
		configs++
		return nil
	})
	if err != nil {
		return "", err
	}
	if configs < a.request.Generation {
		return "", errors.New("frozen old membership missing")
	}
	old, err := s.membership(ctx, a.request.Generation)
	if err != nil {
		return "", err
	}
	member, ok := old.Member(s.source)
	if !ok || member.Incarnation != m.Incarnation || old.MembersHash != m.Cut.MembersHash || sourceConfigDigest(old) != m.OldValue {
		return "", errors.New("frozen source old lifetime differs")
	}
	h := sha256.New()
	sourceHash(h, []byte("litevirt/receiver-frozen-lineage/v1"), []byte(s.evidenceIdentity()), []byte(m.Incarnation))
	var adopted int64
	err = s.walk(ctx, 9, func(_ int64, row Row) error {
		g := row.Int64("generation")
		if g != adopted+1 || g > a.request.Generation || len(row.String("imported_from")) > maxSourceFieldBytes || len(row.String("adopted_at")) == 0 || len(row.String("adopted_at")) > 128 {
			return errors.New("frozen adoption lineage gap/bound")
		}
		cfg, err := s.membership(ctx, g)
		if err != nil {
			return err
		}
		sourceHash(h, automationCutInteger(g), []byte(sourceConfigDigest(cfg)), []byte(row.String("imported_from")), []byte(row.String("adopted_at")))
		adopted = g
		return nil
	})
	if err != nil {
		return "", err
	}
	if adopted != a.request.Generation {
		return "", errors.New("complete frozen adoption missing")
	}
	sealed := false
	err = s.walk(ctx, 10, func(_ int64, row Row) error {
		if row.Int64("generation") > a.request.Generation || row.String("reason") == "" || row.String("sealed_at") == "" || len(row.String("reason")) > maxSourceFieldBytes || len(row.String("sealed_at")) > maxSourceFieldBytes {
			return errors.New("invalid frozen seal")
		}
		if row.Int64("generation") == a.request.Generation {
			sealed = true
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	// Native ordinary sealing can be the source's own retained next-config
	// acceptance. An unrelated voter's valid acceptance does not seal this source.
	var nativeClaims, acceptedGenesis bool
	var genesisPrincipal, genesisRequest string
	err = s.walk(ctx, 3, func(_ int64, row Row) error {
		if row.String("target_kind") == ClaimKindAutomation {
			nativeClaims = true
			// Native Prepare also requires the exact authority row, but supplies no
			// candidate. At H=0 only an actual accepted genesis carries the bootstrap
			// identity enforced by admitAutomationTx. Losing values at H>0 are not
			// compared to this candidate; their retained semantics remain separate.
			if m.Cut.Head.Sequence == 0 && row.Int64("owner_epoch") == 1 && row.Int64("accepted_round") > 0 {
				key, _ := AutomationClaimKey(1)
				state, err := scanClaimRow(key, row)
				if err != nil {
					return err
				}
				if err = validateRetainedClaimState(state); err != nil {
					return err
				}
				if state.Value == nil {
					return errors.New("native accepted genesis missing")
				}
				decision, err := automationDecision(*state.Value)
				if err != nil {
					return err
				}
				acceptedGenesis = true
				genesisPrincipal = decision.Command.PrincipalID
				genesisRequest = decision.Command.RequestID
			}
			return nil
		}
		if row.String("target_kind") != ClaimKindVoterConfig || row.Int64("owner_epoch") != a.request.Generation || row.Int64("accepted_round") == 0 {
			return nil
		}
		key := ClaimKey{TargetKind: row.String("target_kind"), TargetName: row.String("target_name"), OwnerEpoch: row.Int64("owner_epoch"), Attempt: row.Int64("attempt")}
		st, err := scanClaimRow(key, row)
		if err != nil {
			return err
		}
		if err = validateRetainedClaimState(st); err != nil {
			return err
		}
		if st.Accept == nil || st.Value == nil || st.Value.Config == nil || st.Accept.Voter != s.source || st.Accept.VoterIncarnation != m.Incarnation || st.Accept.ConfigGeneration != a.request.Generation {
			return errors.New("frozen membership seal source differs")
		}
		if err = ValidateVoterChange(old, *st.Value.Config); err != nil {
			return err
		}
		sealed = true
		return nil
	})
	if err != nil {
		return "", err
	}
	if !sealed {
		return "", errors.New("frozen source seal missing")
	}
	var authorities int
	err = s.walk(ctx, 8, func(_ int64, row Row) error {
		authorities++
		if authorities != 1 || row.Int64("id") != 1 || row.Int64("generation") != a.request.Generation || row.String("members_hash") != old.MembersHash || row.String("incarnation") != m.Incarnation {
			return errors.New("frozen authority identity differs")
		}
		for _, field := range []string{"bootstrap_principal", "bootstrap_request", "provenance"} {
			if len(row.String(field)) > maxSourceFieldBytes {
				return errors.New("frozen authority field exceeds bound")
			}
		}
		if m.Cut.Head.Sequence > 0 {
			genesis, err := s.sequence(ctx, 5, 1)
			if err != nil {
				return err
			}
			value, _, err := receiverHistoryValue(genesis)
			if err != nil {
				return err
			}
			d, err := automationDecision(value)
			if err != nil {
				return err
			}
			if d.Command.PrincipalID != row.String("bootstrap_principal") || d.Command.RequestID != row.String("bootstrap_request") {
				return errors.New("frozen bootstrap identity differs")
			}
		}
		if acceptedGenesis && (row.String("bootstrap_principal") != genesisPrincipal || row.String("bootstrap_request") != genesisRequest) {
			return errors.New("frozen native accepted bootstrap identity differs")
		}
		// Preserve opaque provenance bytes in the spool. Their content cannot
		// establish an import receipt, origin kind, or receiver active authority.
		return nil
	})
	if err != nil {
		return "", err
	}
	if (m.Cut.Head.Sequence > 0 || nativeClaims) && authorities != 1 {
		return "", errors.New("frozen history authority inventory missing")
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// localLineage validates current native storage without importing frozen-source
// seal/adoption requirements. Begin remains the current membership/PKI owner.
func (s receiverAuditStore) localLineage(ctx context.Context, a *AutomationReceiverAttempt, incarnation string) error {
	var previous *VoterConfig
	var configs, adopted int64
	err := s.walk(ctx, 11, func(_ int64, row Row) error {
		cfg, err := sourceConfigRow(row)
		if err != nil {
			return err
		}
		if cfg.Generation != configs+1 {
			return errors.New("local membership lineage gap")
		}
		if err = receiverRetainedMembership(previous, cfg); err != nil {
			return err
		}
		if cfg.Generation == a.request.Generation && sourceConfigDigest(cfg) != sourceConfigDigest(a.facts.Old) {
			return errors.New("local old membership differs")
		}
		if cfg.Generation == a.request.Generation+1 && sourceConfigDigest(cfg) != sourceConfigDigest(a.facts.Next) {
			return errors.New("local successor membership differs")
		}
		previous = cfg
		configs++
		return nil
	})
	if err != nil {
		return err
	}
	if configs < a.request.Generation+1 {
		return errors.New("local membership inventory differs")
	}
	err = s.walk(ctx, 9, func(_ int64, row Row) error {
		if row.Int64("generation") != adopted+1 || row.Int64("generation") > a.request.Generation || row.String("adopted_at") == "" {
			return errors.New("local adoption lineage differs")
		}
		adopted++
		return nil
	})
	if err != nil {
		return err
	}
	if adopted != a.facts.Adopted {
		return errors.New("local adopted standing changed")
	}
	err = s.walk(ctx, 10, func(_ int64, row Row) error {
		if row.Int64("generation") > adopted || row.String("reason") == "" || row.String("sealed_at") == "" {
			return errors.New("invalid local seal")
		}
		return nil
	})
	if err != nil {
		return err
	}
	var native, acceptedGenesis bool
	var genesisPrincipal, genesisRequest string
	err = s.walk(ctx, 3, func(_ int64, row Row) error {
		if row.String("target_kind") == ClaimKindAutomation {
			native = true
			// At H=0 only an actual accepted genesis carries a candidate identity.
			// Prepare-only state supplies none; losing candidates at H>0 are separate.
			if s.publication.manifest.Cut.Head.Sequence == 0 && row.Int64("owner_epoch") == 1 && row.Int64("accepted_round") > 0 {
				key, _ := AutomationClaimKey(1)
				state, err := scanClaimRow(key, row)
				if err != nil {
					return err
				}
				if err = validateRetainedClaimState(state); err != nil {
					return err
				}
				if state.Value == nil {
					return errors.New("local native accepted genesis missing")
				}
				decision, err := automationDecision(*state.Value)
				if err != nil {
					return err
				}
				acceptedGenesis = true
				genesisPrincipal = decision.Command.PrincipalID
				genesisRequest = decision.Command.RequestID
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	var authorities int
	err = s.walk(ctx, 8, func(_ int64, row Row) error {
		authorities++
		if authorities != 1 || row.Int64("id") != 1 || row.Int64("generation") != adopted || row.String("incarnation") != incarnation {
			return errors.New("local authority lifetime differs")
		}
		cfg, err := s.membership(ctx, adopted)
		if err != nil {
			return err
		}
		member, ok := cfg.Member(s.source)
		if !ok || member.Incarnation != incarnation || row.String("members_hash") != cfg.MembersHash {
			return errors.New("local authority membership differs")
		}
		if s.publication.manifest.Cut.Head.Sequence > 0 {
			genesis, err := s.sequence(ctx, 5, 1)
			if err != nil {
				return err
			}
			value, _, err := receiverHistoryValue(genesis)
			if err != nil {
				return err
			}
			decision, err := automationDecision(value)
			if err != nil {
				return err
			}
			if decision.Command.PrincipalID != row.String("bootstrap_principal") || decision.Command.RequestID != row.String("bootstrap_request") {
				return errors.New("local native bootstrap identity differs")
			}
		}
		if acceptedGenesis && (genesisPrincipal != row.String("bootstrap_principal") || genesisRequest != row.String("bootstrap_request")) {
			return errors.New("local native accepted bootstrap identity differs")
		}
		// Retain provenance as opaque original bytes. It is never interpreted as an
		// imported-origin receipt or current class/activation permission.
		return nil
	})
	if err != nil {
		return err
	}
	if (native || s.publication.manifest.Cut.Head.Sequence > 0) && authorities != 1 {
		return errors.New("local native history authority missing")
	}
	return nil
}
