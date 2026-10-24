package automation

import (
	"bytes"
	"context"

	"github.com/litevirt/litevirt/internal/automation/contract"
	"github.com/litevirt/litevirt/internal/claims"
	"github.com/litevirt/litevirt/internal/corrosion"
)

type keyPhase2Transport interface {
	PrepareKeyPhase2(context.Context, corrosion.ClaimKey, corrosion.Ballot, corrosion.ClaimValue, *corrosion.VoterConfig, *corrosion.AutomationKeyAdmission) (corrosion.Ballot, error)
}
type automationFreshBuilder func(context.Context) (*automationFreshValue, error)
type automationFreshValue struct {
	value   corrosion.ClaimValue
	accept  func(context.Context, corrosion.ClaimKey, corrosion.Ballot, corrosion.ClaimValue, *corrosion.VoterConfig) (corrosion.Ballot, error)
	release func()
}

// This cell decides only which existing callback owns the selected round. It
// cannot issue a native credential, change quorum, or replace the proposer.
type automationFreshCell struct {
	engine           *Engine
	ctx              context.Context
	key              corrosion.ClaimKey
	cfg              corrosion.VoterConfig
	build            automationFreshBuilder
	built, attempted bool
	buildErr         error
	value            corrosion.ClaimValue
	digest           string
	live             *automationFreshValue
	eligible         corrosion.Ballot
}

func (e *Engine) newAutomationFreshCell(ctx context.Context, cfg *corrosion.VoterConfig, seq uint64, build automationFreshBuilder) (*automationFreshCell, error) {
	key, err := corrosion.AutomationClaimKey(seq)
	if err != nil || cfg == nil || cfg.Generation <= 0 || len(cfg.Members) == 0 || cfg.MembersHash != corrosion.MembersHash(cfg.Members) {
		return nil, fail(CodeUnavailable)
	}
	copyCfg := *cfg
	copyCfg.Members = append([]corrosion.VoterMember(nil), cfg.Members...)
	return &automationFreshCell{engine: e, ctx: ctx, key: key, cfg: copyCfg, build: build}, nil
}
func (c *automationFreshCell) retire() {
	c.attempted = true
	c.eligible = corrosion.Ballot{}
	if live := c.live; live != nil {
		c.live = nil
		if live.release != nil {
			live.release()
		}
	}
}
func (c *automationFreshCell) propose(promises map[string]corrosion.PrepareResult) (corrosion.ClaimValue, error) {
	c.eligible = corrosion.Ballot{}
	if c.ctx.Err() != nil {
		return corrosion.ClaimValue{}, c.ctx.Err()
	}
	if len(promises) < corrosion.MajorityOf(len(c.cfg.Members)) {
		return corrosion.ClaimValue{}, fail(CodeUnavailable)
	}
	members := map[string]string{}
	for _, m := range c.cfg.Members {
		if m.Name == "" || m.Incarnation == "" || members[m.Name] != "" {
			return corrosion.ClaimValue{}, fail(CodeUnavailable)
		}
		members[m.Name] = m.Incarnation
	}
	var ballot corrosion.Ballot
	for name, promise := range promises {
		if members[name] == "" || promise.Voter != name || promise.Incarnation != members[name] || !promise.Promised || promise.PromisedBallot.IsZero() || promise.State.Key != c.key || !promise.State.Accepted.IsZero() || promise.State.Value != nil {
			return corrosion.ClaimValue{}, fail(CodeUnavailable)
		}
		if ballot.IsZero() {
			ballot = promise.PromisedBallot
			ballot.Nonce = append([]byte(nil), ballot.Nonce...)
		} else if !ballot.Equal(promise.PromisedBallot) {
			return corrosion.ClaimValue{}, fail(CodeUnavailable)
		}
	}
	if !c.built {
		c.built = true
		if c.build == nil {
			c.buildErr = claims.ErrNoValue
		} else {
			c.live, c.buildErr = c.build(c.ctx)
		}
		if c.buildErr == nil {
			if c.live == nil || c.live.accept == nil || c.live.release == nil || c.live.value.Automation == nil {
				c.buildErr = fail(CodeUnavailable)
			} else {
				d, err := contractDecode(c.live.value)
				if err != nil || d.Sequence != uint64(c.key.OwnerEpoch) {
					c.buildErr = fail(CodeUnavailable)
				} else {
					c.value = corrosion.ClaimValue{Automation: &corrosion.AutomationClaimValue{Envelope: append([]byte(nil), c.live.value.Automation.Envelope...)}}
					c.digest, c.buildErr = c.value.Digest()
				}
			}
		}
	}
	if c.buildErr != nil {
		c.retire()
		return corrosion.ClaimValue{}, c.buildErr
	}
	if !c.attempted {
		c.eligible = ballot
	}
	return corrosion.ClaimValue{Automation: &corrosion.AutomationClaimValue{Envelope: append([]byte(nil), c.value.Automation.Envelope...)}}, nil
}
func (c *automationFreshCell) beforeAccept(ctx context.Context, ballot corrosion.Ballot, selected corrosion.ClaimValue) (corrosion.Ballot, error) {
	eligible := c.eligible
	c.eligible = corrosion.Ballot{}
	if c.ctx.Err() != nil || ctx.Err() != nil {
		c.retire()
		return corrosion.Ballot{}, fail(CodeUnavailable)
	}
	digest, err := selected.Digest()
	if err != nil {
		c.retire()
		return corrosion.Ballot{}, err
	}
	matching := c.built && !c.attempted && c.live != nil && !eligible.IsZero() && eligible.Equal(ballot) && digest == c.digest && selected.Automation != nil && bytes.Equal(selected.Automation.Envelope, c.value.Automation.Envelope)
	if matching {
		// Detach and spend before the callback, including stale/lost/error outcomes.
		c.attempted = true
		live := c.live
		c.live = nil
		defer live.release()
		nativeValue := corrosion.ClaimValue{Automation: &corrosion.AutomationClaimValue{Envelope: append([]byte(nil), selected.Automation.Envelope...)}}
		nativeConfig := c.cfg
		nativeConfig.Members = append([]corrosion.VoterMember(nil), c.cfg.Members...)
		ballot.Nonce = append([]byte(nil), ballot.Nonce...)
		return live.accept(ctx, c.key, ballot, nativeValue, &nativeConfig)
	}
	c.retire()
	return c.engine.prepareSelectedAutomationPhase2(ctx, c.key, ballot, selected, &c.cfg)
}
func (e *Engine) decideFreshAutomationUsing(ctx context.Context, cfg *corrosion.VoterConfig, seq uint64, p *claims.Proposer, build automationFreshBuilder) (claims.Outcome, error) {
	cell, err := e.newAutomationFreshCell(ctx, cfg, seq, build)
	if err != nil {
		return claims.Outcome{}, err
	}
	defer cell.retire()
	return e.decideAutomationUsing(ctx, &cell.cfg, seq, p, cell.propose, cell.beforeAccept)
}
func (e *Engine) prepareSelectedAutomationPhase2(ctx context.Context, key corrosion.ClaimKey, ballot corrosion.Ballot, value corrosion.ClaimValue, cfg *corrosion.VoterConfig) (corrosion.Ballot, error) {
	d, err := contractDecode(value)
	if err != nil {
		return corrosion.Ballot{}, err
	}
	if d.Command.Kind == contract.CustodyImportCommand || d.Command.Kind == "activate_key_epoch" {
		t, ok := e.transport.(keyPhase2Transport)
		if !ok {
			return corrosion.Ballot{}, fail(CodeUnavailable)
		}
		return t.PrepareKeyPhase2(ctx, key, ballot, value, cfg, nil)
	}
	if d.Command.Kind == contract.IdentityContinuityCommand {
		t, ok := e.transport.(continuityPhase2Transport)
		if !ok {
			return corrosion.Ballot{}, fail(CodeUnavailable)
		}
		return t.PrepareContinuityPhase2(ctx, key, ballot, value, cfg, nil)
	}
	if corrosion.IsAutomationOwnerKind(d.Command.Kind) {
		t, ok := e.transport.(ownerPhase2Transport)
		if !ok {
			return corrosion.Ballot{}, fail(CodeUnavailable)
		}
		return t.PrepareOwnerPhase2(ctx, key, ballot, value, cfg, nil)
	}
	return corrosion.Ballot{}, nil
}

// SubmitInitialKeyEpoch certifies physical custody before initial activation.
func (e *Engine) SubmitInitialKeyEpoch(ctx context.Context, ready *corrosion.AutomationCustodyReady) (Receipt, Decision, error) {
	if !ready.UsesClient(e.db) {
		return Receipt{}, Decision{}, fail(CodeUnavailable)
	}
	if err := e.enter(ctx); err != nil {
		return Receipt{}, Decision{}, err
	}
	defer e.leave()
	if receipt, decision, found, err := ready.CertifiedActivation(ctx); found || err != nil {
		return receipt, decision, err
	}
	command, err := ready.ImportCommand()
	if err != nil {
		return Receipt{}, Decision{}, err
	}
	imported, err := e.submitPreparedFresh(ctx, command, nil, nil, func(call context.Context, base Decision) (*automationFreshValue, error) {
		value, native, err := ready.PrepareImport(call, base)
		if err != nil {
			return nil, err
		}
		return e.keyFreshValue(value, native), nil
	}, nil)
	if err != nil {
		return imported, Decision{}, err
	}
	record, found, err := e.db.AutomationRecord(ctx, imported.Sequence)
	if err != nil || !found {
		return Receipt{}, Decision{}, fail(CodeUnavailable)
	}
	reference := contract.HistoryReference{Sequence: imported.Sequence, Digest: record.Value.MustDigest()}
	head, err := e.db.AutomationHead(ctx)
	if err != nil {
		return Receipt{}, Decision{}, err
	}
	command, err = ready.ActivationCommand(contract.HistoryReference{Sequence: head.Sequence, Digest: head.Digest})
	if err != nil {
		return Receipt{}, Decision{}, err
	}
	var decision Decision
	receipt, err := e.submitPreparedFresh(ctx, command, nil, nil, func(call context.Context, base Decision) (*automationFreshValue, error) {
		body, err := contract.DecodeActivateKeyEpochBody(base.Command)
		if err != nil {
			return nil, err
		}
		if body.Prefix != (contract.HistoryReference{Sequence: base.Sequence - 1, Digest: base.ParentDigest}) {
			// The common loop already looked up the prior original. This runs
			// only for an actually fresh phase1 round and only once per cell.
			base.Command, err = ready.AdvanceActivation(call)
			if err != nil {
				return nil, err
			}
		}
		value, native, err := ready.PrepareActivation(call, reference, base)
		if err != nil {
			return nil, err
		}
		return e.keyFreshValue(value, native), nil
	}, &decision)
	if err == nil {
		err = ready.ConfirmActivationOriginal(ctx, reference, receipt, decision)
	}
	return receipt, decision, err
}
func (e *Engine) keyFreshValue(value corrosion.ClaimValue, native *corrosion.AutomationKeyAdmission) *automationFreshValue {
	return &automationFreshValue{value: value, release: native.Release, accept: func(ctx context.Context, key corrosion.ClaimKey, ballot corrosion.Ballot, selected corrosion.ClaimValue, cfg *corrosion.VoterConfig) (corrosion.Ballot, error) {
		transport, ok := e.transport.(keyPhase2Transport)
		if !ok {
			return corrosion.Ballot{}, fail(CodeUnavailable)
		}
		return transport.PrepareKeyPhase2(ctx, key, ballot, selected, cfg, native)
	}}
}
