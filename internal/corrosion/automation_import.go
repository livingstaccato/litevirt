package corrosion

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/litevirt/litevirt/internal/capabilities"
)

// Certified-prefix import for a voter new to the automation electorate (F1
// Task 5G).
//
// A voter that joins the electorate at an ordinary generation G adopts it
// through the sealed-majority claim import like every member, but holds no
// automation authority (automation_membership.go). That import already gives
// it, as claim rows, every automation value chosen before G-1 sealed:
// automation claim rows are never pruned, and a sealed majority of G-1
// intersects every quorum that chose one. What it lacks is the certified
// history those values were applied as, and the authority row.
//
// The import supplies both. The history comes from the maximum certified head
// a majority of G-1 attests while holding authority at G. It is verified the
// way lagging-voter recovery verifies it: the tip's certificate against the
// electorate of the generation that certified it, every predecessor by the
// parent digest chain. It is applied through the same staged-anchor path
// (local_automation_recovery / local_automation_staging). Authority is then
// granted in ONE transaction that re-checks every condition, and that grant is
// the only step that confers anything. History applied before it is certified
// and inert: a voter without authority refuses every automation vote.
//
// Every write here is automation state, so each writer takes the
// automation_state release-feature grant: the use is recorded before the first
// write, and automation_v1's safe_if_unused rollback rule stays sound.

// ErrAutomationImportIneligible wraps every reason this voter may not import
// automation authority at its adopted generation. It is a standing refusal,
// not a transient failure.
var ErrAutomationImportIneligible = errors.New("automation prefix import not allowed")

// ErrAutomationAlreadyImported: this voter already holds automation authority
// at its adopted generation; there is nothing to import.
var ErrAutomationAlreadyImported = errors.New("automation authority already held at the adopted generation")

func importIneligible(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrAutomationImportIneligible, fmt.Sprintf(format, args...))
}

// AutomationImportPlan is what an import at Generation is checked against:
// the adopted generation (Current), the one it replaced (Previous), and this
// voter.
type AutomationImportPlan struct {
	Self              string
	Generation        int64
	Previous, Current *VoterConfig
}

// AutomationImportSource is one source's attestation, as
// GetAutomationImportSource returns it.
type AutomationImportSource struct {
	Voter       string
	Incarnation string
	Adopted     int64
	Authority   bool
	Head        AutomationPrefix
}

// automationImportEligibleTx checks that self may import automation authority
// at gen, its adopted generation, and returns the plan. It writes nothing.
func automationImportEligibleTx(ctx context.Context, tx *LocalTx, self string, gen int64) (AutomationImportPlan, error) {
	plan := AutomationImportPlan{Self: self, Generation: gen}
	st, err := readStandingTx(ctx, tx, self)
	if err != nil {
		return plan, err
	}
	if gen <= 0 || st.adopted != gen || st.cfg == nil {
		return plan, importIneligible("adopted voter generation is %d, not %d", st.adopted, gen)
	}
	cur := st.cfg
	switch {
	case !cur.Explicit():
		return plan, importIneligible("voter generation %d has no explicit members", gen)
	case IsForcedChange(cur.Change):
		return plan, importIneligible("voter generation %d is forced (%s): it imported nothing from the old voter majority", gen, cur.Change)
	case cur.Change == VoterChangeReset:
		return plan, importIneligible("voter generation %d is a reset: it imported nothing from the old voter majority", gen)
	case len(cur.Members) < 3 || automationElectorateBudget(cur.Members) != nil:
		return plan, importIneligible("voter generation %d (%d members) is not an automation electorate", gen, len(cur.Members))
	}
	if m, ok := cur.Member(self); !ok || m.Incarnation != st.incarnation {
		return plan, importIneligible("%s is not a member of voter generation %d under its incarnation", self, gen)
	}
	if _, err := automationEstablishedAuthorityTx(ctx, tx, self, gen); err == nil {
		return plan, ErrAutomationAlreadyImported
	} else if !errors.Is(err, errAutomationAuthority) {
		return plan, err
	}
	rows, err := tx.Query(ctx, `SELECT generation FROM local_automation_authority WHERE id = 1`)
	if err != nil {
		return plan, err
	}
	if len(rows) == 1 && rows[0].Int64("generation") >= gen {
		return plan, importIneligible("%s holds an automation authority row at generation %d that does not hold at %d", self, rows[0].Int64("generation"), gen)
	}
	// The safety of the import rests on this adoption having merged the
	// sealed old majority's claim state (the package comment). A generation
	// adopted without it — a non-member pass, an implicit predecessor — does
	// not qualify.
	rows, err = tx.Query(ctx, `SELECT imported_from FROM local_voter_adoption WHERE generation = ?`, gen)
	if err != nil {
		return plan, err
	}
	if len(rows) != 1 || strings.TrimSpace(rows[0].String("imported_from")) == "" {
		return plan, importIneligible("%s adopted voter generation %d without importing the sealed old majority's claim state", self, gen)
	}
	rows, err = tx.Query(ctx, `SELECT `+voterConfigCols+` FROM voter_configs WHERE generation = ? AND deleted_at IS NULL`, gen-1)
	if err != nil {
		return plan, err
	}
	if len(rows) == 0 {
		return plan, importIneligible("voter generation %d has no voter_configs row", gen-1)
	}
	prev, err := scanVoterConfig(rows[0])
	if err != nil {
		return plan, err
	}
	if !prev.Explicit() || len(prev.Members) < 3 {
		return plan, importIneligible("voter generation %d (%d members) is not an automation electorate to import from", gen-1, len(prev.Members))
	}
	plan.Previous, plan.Current = prev, cur
	return plan, nil
}

// AutomationImportPlan reports whether this voter may import automation
// authority at its adopted generation. ErrAutomationAlreadyImported and
// ErrAutomationImportIneligible are standing answers; any other error is a
// failure to tell.
func (c *Client) AutomationImportPlan(ctx context.Context) (AutomationImportPlan, error) {
	var plan AutomationImportPlan
	err := c.ExecuteLocal(ctx, func(tx *LocalTx) error {
		st, err := readStandingTx(ctx, tx, c.hostName)
		if err != nil {
			return err
		}
		plan, err = automationImportEligibleTx(ctx, tx, c.hostName, st.adopted)
		if err != nil {
			return err
		}
		// Nothing to import on a cluster that never used automation: no
		// automation claim row reached this replica through its adoption.
		// This keeps the daemon from asking peers, and from recording the
		// release-feature use, there.
		used, _, err := automationUsedTx(ctx, tx)
		if err == nil && !used {
			err = importIneligible("%s holds no automation state: there is no automation prefix to import", c.hostName)
		}
		return err
	})
	return plan, err
}

// Target picks the import target from the sources' attestations: the maximum
// certified head among members of the previous generation that are members
// of the current one under the same incarnation, have adopted exactly the
// current generation and hold authority there. Their number must be a
// majority of the WHOLE previous generation. The target must be a nonempty
// prefix: an empty one is never proof. It returns the target and the
// qualifying sources, sorted.
func (p AutomationImportPlan) Target(attested []AutomationImportSource) (AutomationPrefix, []string, error) {
	if p.Previous == nil || p.Current == nil {
		return AutomationPrefix{}, nil, importIneligible("no import plan")
	}
	var target AutomationPrefix
	seen := map[string]bool{}
	var sources []string
	clusterUID := ""
	for _, a := range attested {
		if a.Voter == p.Self || seen[a.Voter] || !a.Authority || a.Adopted != p.Generation || a.Head.Sequence == 0 || a.Head.Digest == "" {
			continue
		}
		old, ok := p.Previous.Member(a.Voter)
		if !ok || old.Incarnation != a.Incarnation {
			continue
		}
		if now, ok := p.Current.Member(a.Voter); !ok || now.Incarnation != a.Incarnation {
			continue
		}
		if clusterUID == "" {
			clusterUID = a.Head.ClusterUID
		} else if a.Head.ClusterUID != clusterUID {
			return AutomationPrefix{}, nil, fmt.Errorf("automation import sources disagree on the automation cluster (%q, %q)", clusterUID, a.Head.ClusterUID)
		}
		seen[a.Voter] = true
		sources = append(sources, a.Voter)
		if a.Head.Sequence > target.Sequence {
			target = a.Head
		}
	}
	sort.Strings(sources)
	if need := MajorityOf(len(p.Previous.Members)); len(sources) < need {
		return AutomationPrefix{}, sources, fmt.Errorf("only %d of the %d members of voter generation %d needed attest automation authority at generation %d (%s)",
			len(sources), need, p.Generation-1, p.Generation, strings.Join(sources, ","))
	}
	return target, sources, nil
}

// AutomationImportSourceState is a source's answer to an importer at gen: its
// adopted generation, whether it holds automation authority there (only when
// that is gen), and its certified head. Local read only.
func (c *Client) AutomationImportSourceState(ctx context.Context, gen int64) (AutomationImportSource, error) {
	out := AutomationImportSource{Voter: c.hostName}
	err := c.ExecuteLocal(ctx, func(tx *LocalTx) error {
		st, err := readStandingTx(ctx, tx, c.hostName)
		if err != nil {
			return err
		}
		out.Incarnation, out.Adopted = st.incarnation, st.adopted
		if st.adopted != gen {
			return nil
		}
		if _, err := automationAuthorityTx(ctx, tx, c.hostName, gen); err != nil {
			if errors.Is(err, errAutomationAuthority) {
				return nil
			}
			return err
		}
		out.Head, err = automationHeadTx(ctx, tx)
		out.Authority = err == nil
		return err
	})
	return out, err
}

// AutomationBeginImport verifies tip, the import target, and opens the staged
// import job that AutomationStagePredecessor and AutomationFinishRecovery then
// complete: the same job lagging-voter recovery uses, which a voter without
// authority can have only through this call. tip's certificate is verified
// against the electorate of the generation that certified it, at most gen. An
// existing job resumes; a tip at or below the local head writes nothing.
func (c *Client) AutomationBeginImport(ctx context.Context, grant capabilities.FeatureGrant, tip AutomationRecord, v *ClaimVerifier, gen int64) error {
	if err := grant.Check(capabilities.FeatureAutomationState); err != nil {
		return err
	}
	if v == nil {
		return fmt.Errorf("automation import: no verifier")
	}
	r := copyContinuityRecord(tip)
	if err := validateAutomationRecordSize(r); err != nil {
		return err
	}
	if isAutomationContinuityValue(r.Value) {
		return fmt.Errorf("automation import: certified continuity records need the continuity materialization owner, which requires authority; this build cannot import them")
	}
	d, err := automationDecision(r.Value)
	if err != nil {
		return err
	}
	digest, err := r.Value.Digest()
	if err != nil {
		return err
	}
	certGen := r.Certificate.ConfigGeneration
	var certCfg *VoterConfig
	err = c.ExecuteLocal(ctx, func(tx *LocalTx) error {
		if _, err := automationImportEligibleTx(ctx, tx, c.hostName, gen); err != nil {
			return err
		}
		var err error
		certCfg, err = automationImportCertConfigTx(ctx, tx, certGen, gen)
		return err
	})
	if err != nil {
		return err
	}
	key, _ := AutomationClaimKey(d.Sequence)
	if err := v.Verify(r.Certificate, CertExpectation{Key: key, ValueDigest: digest, ConfigGeneration: certGen,
		Electorate: certCfg.Members, Quorum: MajorityOf(len(certCfg.Members))}); err != nil {
		return fmt.Errorf("automation import: tip %d certificate: %w", d.Sequence, err)
	}
	request, err := automationPrepareKeyLookup(ctx, d, r.Certificate)
	if err != nil {
		return err
	}
	if request != nil && request.configDigest != MembersHash(certCfg.Members) {
		return fmt.Errorf("automation import: key transition differs from its original certified config")
	}
	cert, err := r.Certificate.Encode()
	if err != nil {
		return err
	}
	value, err := json.Marshal(r.Value)
	if err != nil || len(value) > MaxAutomationClaimBytes {
		return fmt.Errorf("automation import: staged value too large")
	}
	return c.ExecuteLocal(ctx, func(tx *LocalTx) error {
		if err := requireAutomationFull(ctx, tx); err != nil {
			return err
		}
		if _, err := automationImportEligibleTx(ctx, tx, c.hostName, gen); err != nil {
			return err
		}
		if again, err := automationImportCertConfigTx(ctx, tx, certGen, gen); err != nil {
			return err
		} else if MembersHash(again.Members) != MembersHash(certCfg.Members) {
			return fmt.Errorf("automation import: voter generation %d changed", certGen)
		}
		rs, err := tx.Query(ctx, `SELECT sequence FROM local_automation_recovery WHERE id=1`)
		if err != nil {
			return err
		}
		if len(rs) != 0 {
			return nil // resume the existing verified job
		}
		head, err := automationHeadTx(ctx, tx)
		if err != nil {
			return err
		}
		if d.Sequence <= head.Sequence {
			return nil
		}
		if _, err = tx.Exec(ctx, `INSERT INTO local_automation_recovery (id,sequence,digest,next_sequence,next_digest,base_sequence,base_digest,generation,members_hash,certificate) VALUES (1,?,?,?,?,?,?,?,?,?)`,
			d.Sequence, digest, d.Sequence-1, d.ParentDigest, head.Sequence, head.Digest, certGen, MembersHash(certCfg.Members), cert); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO local_automation_staging (sequence,digest,value_json,certificate) VALUES (?,?,?,?)`, d.Sequence, digest, string(value), cert)
		return err
	})
}

// automationImportCertConfigTx is the electorate a tip certified at certGen
// is verified against: an explicit, ordinary automation electorate no later
// than the import generation.
func automationImportCertConfigTx(ctx context.Context, tx *LocalTx, certGen, gen int64) (*VoterConfig, error) {
	if certGen <= 0 || certGen > gen {
		return nil, fmt.Errorf("automation import: tip certified at voter generation %d, outside 1..%d", certGen, gen)
	}
	rows, err := tx.Query(ctx, `SELECT `+voterConfigCols+` FROM voter_configs WHERE generation = ? AND deleted_at IS NULL`, certGen)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("automation import: voter generation %d has no voter_configs row", certGen)
	}
	cfg, err := scanVoterConfig(rows[0])
	if err != nil {
		return nil, err
	}
	if !cfg.Explicit() || IsForcedChange(cfg.Change) || len(cfg.Members) < 3 || automationElectorateBudget(cfg.Members) != nil {
		return nil, fmt.Errorf("automation import: voter generation %d is not an automation electorate", certGen)
	}
	return cfg, nil
}

// AutomationGrantImportedAuthority is the import's one conferring step: in a
// single FULL transaction it re-checks that this voter may import at gen,
// that attested is a majority of gen-1 holding authority at gen, that the
// local certified history reaches their maximum head with the same digest
// there, that no import job is pending and the semantic projection matches
// the certified head, and then writes the authority row. The bootstrap fields
// come from this voter's own certified record 1, never from a source.
func (c *Client) AutomationGrantImportedAuthority(ctx context.Context, grant capabilities.FeatureGrant, gen int64, attested []AutomationImportSource) error {
	if err := grant.Check(capabilities.FeatureAutomationState); err != nil {
		return err
	}
	return c.ExecuteLocal(ctx, func(tx *LocalTx) error {
		if err := requireAutomationFull(ctx, tx); err != nil {
			return err
		}
		plan, err := automationImportEligibleTx(ctx, tx, c.hostName, gen)
		if err != nil {
			return err
		}
		target, sources, err := plan.Target(attested)
		if err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT sequence FROM local_automation_recovery WHERE id=1`)
		if err != nil {
			return err
		}
		if len(rows) != 0 {
			return fmt.Errorf("automation import: the staged import is not finished")
		}
		head, err := automationHeadTx(ctx, tx)
		if err != nil {
			return err
		}
		if head.Sequence < target.Sequence {
			return fmt.Errorf("automation import: local certified head %d is below the old majority's %d", head.Sequence, target.Sequence)
		}
		if head.ClusterUID != target.ClusterUID {
			return fmt.Errorf("automation import: local automation cluster %q differs from the old majority's %q", head.ClusterUID, target.ClusterUID)
		}
		digest, found, err := automationTrustedDigestTx(ctx, tx, target.Sequence)
		if err != nil {
			return err
		}
		if !found || digest != target.Digest {
			return fmt.Errorf("automation import: local certified history differs from the old majority's at %d", target.Sequence)
		}
		if err := automationProjectionAuthorityTx(ctx, tx); err != nil {
			return fmt.Errorf("automation import: semantic projection does not match the certified head: %w", err)
		}
		rows, err = tx.Query(ctx, `SELECT value_json FROM local_automation_history WHERE sequence = 1`)
		if err != nil {
			return err
		}
		if len(rows) != 1 {
			return fmt.Errorf("automation import: no certified record 1")
		}
		var first ClaimValue
		if err := json.Unmarshal([]byte(rows[0].String("value_json")), &first); err != nil {
			return err
		}
		genesis, err := automationDecision(first)
		if err != nil {
			return err
		}
		if genesis.Command.PrincipalID == "" || genesis.Command.RequestID == "" {
			return fmt.Errorf("automation import: certified record 1 names no bootstrap principal and request")
		}
		inc, err := tx.Query(ctx, `SELECT incarnation FROM local_voter_incarnation WHERE id = 1`)
		if err != nil || len(inc) != 1 {
			return fmt.Errorf("automation import: no voter incarnation recorded: %v", err)
		}
		provenance := fmt.Sprintf("import:v1;g=%d;head=%d:%s;sources=%s", gen, target.Sequence, target.Digest, strings.Join(sources, ","))
		_, err = tx.Exec(ctx, `INSERT INTO local_automation_authority (id,generation,members_hash,incarnation,bootstrap_principal,bootstrap_request,provenance)
			VALUES (1,?,?,?,?,?,?)
			ON CONFLICT(id) DO UPDATE SET generation=excluded.generation, members_hash=excluded.members_hash, incarnation=excluded.incarnation,
				bootstrap_principal=excluded.bootstrap_principal, bootstrap_request=excluded.bootstrap_request, provenance=excluded.provenance
			WHERE local_automation_authority.generation < excluded.generation`,
			gen, MembersHash(plan.Current.Members), inc[0].String("incarnation"), genesis.Command.PrincipalID, genesis.Command.RequestID, provenance)
		if err != nil {
			return err
		}
		if _, err := automationEstablishedAuthorityTx(ctx, tx, c.hostName, gen); err != nil {
			return fmt.Errorf("automation import: authority did not establish: %w", err)
		}
		return nil
	})
}
