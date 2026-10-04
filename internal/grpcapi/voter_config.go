package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/claims"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// The explicit voter set (colonelpanik/litevirt#251 step 2,
// docs/design/recovery-claims.md §4): readiness for voter_config_v1,
// adoption, automatic genesis, and the `lv cluster voter` changes.
//
// Every change from generation g to g+1 is a claim at key
// (voter_config, "", g, 0) decided by a majority of g — or, after an empty
// generation (none yet, or a reset), unanimously by the proposed members. The
// decided value is written to voter_configs with its certificate, and each
// node adopts it once the certificate verifies against the generation it
// replaces, importing claim state first if it is a member of the new one.

// VoterConfigReadiness evaluates whether this node may advertise
// voter_config_v1: it commits a promise durably (PRAGMA synchronous is FULL)
// and can sign an accept (the host key loads). The claim RPCs are compiled
// into this build, which is what advertising the token says in the first
// place.
//
// Called from advertisedCapabilities, inside the Ping handler, so every
// predicate is a LOCAL read — the lease_term_v1 rule. A positive answer is
// cached: none of these can regress within one process.
func (s *Server) VoterConfigReadiness(ctx context.Context) (bool, string) {
	if s.voterConfigReady.Load() {
		return true, ""
	}
	if s.db == nil {
		return false, "no database"
	}
	lvl, err := synchronousLevel(ctx, s.db)
	if err != nil {
		return false, "cannot read PRAGMA synchronous: " + err.Error()
	}
	if lvl < corrosion.SynchronousFull {
		return false, fmt.Sprintf("state.db is at synchronous=%d; a voter must commit a promise durably "+
			"(FULL, %d) before it replies", lvl, corrosion.SynchronousFull)
	}
	if _, _, err := s.claimIdentity(); err != nil {
		return false, err.Error()
	}
	if _, err := s.db.VoterIncarnation(ctx); err != nil {
		return false, "cannot read the voter incarnation: " + err.Error()
	}
	s.voterConfigReady.Store(true)
	return true, ""
}

// synchronousLevel reads PRAGMA synchronous; a var so a test can present a
// database opened below FULL, which an in-memory test client cannot be.
var synchronousLevel = func(ctx context.Context, db *corrosion.Client) (int, error) {
	return db.SynchronousLevel(ctx)
}

// voterConfigAdvertisable is the advertisement-side call, bounded because it
// runs on the Ping path.
func (s *Server) voterConfigAdvertisable() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	ok, reason := s.VoterConfigReadiness(ctx)
	if !ok {
		slog.Debug("voter_config_v1 readiness withheld", "reason", reason)
	}
	return ok
}

// voterConfigTimeout bounds one voter-config decision or import.
const voterConfigTimeout = 15 * time.Second

// ── adoption (§4.1, §4.4) ──────────────────────────────────────────────────

// verifyVoterConfigRow checks row against the generation it replaces: a
// permitted change, the members hash, and a certificate from the right
// electorate, verified by v (this node's verifier, or its Historical form for
// a generation at or below the anchor — voterAnchor).
func verifyVoterConfigRow(v *corrosion.ClaimVerifier, prev, row *corrosion.VoterConfig) error {
	if err := corrosion.ValidateVoterChange(prev, row.VoterConfigValue); err != nil {
		return err
	}
	if row.MembersHash != corrosion.MembersHash(row.Members) {
		return fmt.Errorf("members_hash does not match members_json")
	}
	want, err := corrosion.ExpectedVoterConfigCertificate(prev, row.VoterConfigValue)
	if err != nil {
		return err
	}
	cert, err := corrosion.DecodeClaimCertificate(row.Certificate)
	if err != nil {
		return err
	}
	return v.Verify(cert, want)
}

// verifyVoterConfigRowNow checks row with this node's verifier as it stands
// now: for a generation being decided, never for history.
func (s *Server) verifyVoterConfigRowNow(prev, row *corrosion.VoterConfig) error {
	_, verifier, err := s.claimIdentity()
	if err != nil {
		return err
	}
	return verifyVoterConfigRow(verifier, prev, row)
}

// verifyRowSignatures is everything about row that needs no network: the
// ordinary checks above, or a forced row's shape and its survivors'
// signatures (the probes are verifyForcedRow's).
func verifyRowSignatures(v *corrosion.ClaimVerifier, prev, row *corrosion.VoterConfig) error {
	if !corrosion.IsForcedChange(row.Change) {
		return verifyVoterConfigRow(v, prev, row)
	}
	ev, err := corrosion.DecodeForcedVoterEvidence(row.Certificate)
	if err != nil {
		return err
	}
	if row.MembersHash != corrosion.MembersHash(row.Members) {
		return fmt.Errorf("members_hash does not match members_json")
	}
	return v.ValidateForcedChange(prev, row.VoterConfigValue, ev)
}

// voterAnchor is the generation a node judges the voter chain above adopted
// from (docs/design/recovery-claims.md §4.1 "History and revocation"): the
// newest generation whose certificate verifies against this node's CURRENT
// CRL, such that every generation from adopted+1 up to it links to the one
// before it with authentic signatures. Zero when there is none.
//
// A generation at or below the anchor is adopted even if signers of its
// certificate have been revoked since. The anchor's quorum could only have
// signed the anchor after adopting the generation before it (a voter answers
// a voter_config key only at its adopted generation), and each generation's
// membership is fixed by the change of the one after it, one member at a time:
// a chain that a holder of revoked keys alone could write never links up to a
// generation that verifies today. Above the anchor nothing is relaxed, so a
// revoked key still decides nothing new.
func voterAnchor(ctx context.Context, db *corrosion.Client, v *corrosion.ClaimVerifier, adopted *corrosion.VoterConfig) (int64, error) {
	rows, err := corrosion.ListVoterConfigs(ctx, db)
	if err != nil {
		return 0, err
	}
	hist := v.Historical()
	prev, anchor := adopted, int64(0)
	for _, row := range rows {
		var prevGen int64
		if prev != nil {
			prevGen = prev.Generation
		}
		if row.Generation <= prevGen {
			continue
		}
		if row.Generation != prevGen+1 || verifyRowSignatures(hist, prev, row) != nil {
			break
		}
		if verifyRowSignatures(v, prev, row) == nil {
			anchor = row.Generation
		}
		prev = row
	}
	return anchor, nil
}

// memberAs reports whether this node is a member of cfg as the voter it is
// now: its name with ITS incarnation. An entry under this node's name with
// another incarnation is an earlier machine — removed and rebuilt under the
// name, or one whose state.db was lost — and this node abstains in that
// generation (§3.11), so it has no claim state to import for it.
func memberAs(cfg *corrosion.VoterConfig, name, incarnation string) bool {
	m, ok := cfg.Member(name)
	return ok && m.Incarnation == incarnation
}

// AdoptVoterConfigs adopts every voter_configs generation above this node's
// adopted one whose certificate verifies, in order, and returns the adopted
// generation. A member of a new generation imports claim state from a sealed
// majority of the old one first; if it cannot reach one it stops there and the
// next pass retries. A row that does not verify is never adopted — it is
// reported, and nothing above it is considered.
//
// Generations up to the anchor (voterAnchor) are history, verified without
// regard to revocations since; above it every certificate must verify against
// today's CRL.
func (s *Server) AdoptVoterConfigs(ctx context.Context) (int64, error) {
	var (
		verifier *corrosion.ClaimVerifier
		inc      string
		anchor   int64
	)
	for {
		prev, err := corrosion.AdoptedVoterConfig(ctx, s.db)
		if err != nil {
			return 0, err
		}
		var adopted int64
		if prev != nil {
			adopted = prev.Generation
		}
		row, err := corrosion.GetVoterConfig(ctx, s.db, adopted+1)
		if err != nil {
			return adopted, err
		}
		if row == nil {
			return adopted, nil
		}
		if verifier == nil {
			// Once per pass, and only when there is something to adopt.
			if _, verifier, err = s.claimIdentity(); err != nil {
				return adopted, err
			}
			if inc, err = s.db.VoterIncarnation(ctx); err != nil {
				return adopted, err
			}
			if anchor, err = voterAnchor(ctx, s.db, verifier, prev); err != nil {
				return adopted, err
			}
		}
		v := verifier
		if row.Generation <= anchor {
			v = verifier.Historical()
		}
		member := memberAs(row, s.hostName, inc)
		if corrosion.IsForcedChange(row.Change) {
			// A forced generation (§4.6) is checked by its own rule — the
			// survivors' unanimous signatures, the lost hosts' fences, and this
			// node's own probes of the lost hosts — and a member imports from
			// every survivor rather than from a sealed majority.
			if err := s.verifyForcedRow(ctx, v, prev, row); err != nil {
				slog.Error("voter set: refusing to adopt a FORCED voter generation", "generation", row.Generation,
					"change", row.Change, "created_by", row.CreatedBy, "error", err)
				s.noteForcedConflict(row.Generation, err.Error())
				return adopted, fmt.Errorf("forced generation %d: %w", row.Generation, err)
			}
			if member {
				n, from, err := s.importForForced(ctx, prev, row)
				if err != nil {
					return adopted, fmt.Errorf("adopt forced generation %d: %w", row.Generation, err)
				}
				slog.Warn("voter set: adopted a FORCED generation after importing claim state from every survivor",
					"generation", row.Generation, "change", row.Change, "imported", n, "from", strings.Join(from, ","))
			} else {
				if err := corrosion.RecordVoterAdoption(ctx, s.db, row.Generation); err != nil {
					return adopted, err
				}
				slog.Warn("voter set: adopted a FORCED generation", "generation", row.Generation, "change", row.Change,
					"members", strings.Join(row.Names(), ","))
			}
			continue
		}
		if err := verifyVoterConfigRow(v, prev, row); err != nil {
			slog.Error("voter set: refusing to adopt a voter generation whose certificate does not verify",
				"generation", row.Generation, "change", row.Change, "created_by", row.CreatedBy, "error", err)
			return adopted, fmt.Errorf("generation %d does not verify: %w", row.Generation, err)
		}
		if member && prev.Explicit() {
			n, from, err := s.importFromSealedMajority(ctx, prev, row.Generation)
			if err != nil {
				return adopted, fmt.Errorf("adopt generation %d: %w", row.Generation, err)
			}
			slog.Info("voter set: adopted a generation after importing claim state",
				"generation", row.Generation, "change", row.Change, "imported", n, "from", strings.Join(from, ","))
		} else {
			if err := corrosion.RecordVoterAdoption(ctx, s.db, row.Generation); err != nil {
				return adopted, err
			}
			slog.Info("voter set: adopted a generation", "generation", row.Generation, "change", row.Change,
				"members", strings.Join(row.Names(), ","))
		}
	}
}

// importFromSealedMajority pulls claim state from every member of prev and
// imports it only if a majority of prev answered frozen (§4.4 rule 2).
func (s *Server) importFromSealedMajority(ctx context.Context, prev *corrosion.VoterConfig, newGen int64) (int, []string, error) {
	ictx, cancel := context.WithTimeout(ctx, voterConfigTimeout)
	defer cancel()
	var mu sync.Mutex
	var wg sync.WaitGroup
	var from []string
	var states []corrosion.ClaimVoterState
	for _, m := range prev.Members {
		wg.Add(1)
		go func(voter string) {
			defer wg.Done()
			src, err := s.fetchImportSource(ictx, voter, prev.Generation)
			if err != nil || !src.Frozen {
				return
			}
			mu.Lock()
			from = append(from, voter)
			states = append(states, src.States...)
			mu.Unlock()
		}(m.Name)
	}
	wg.Wait()
	need := corrosion.MajorityOf(len(prev.Members))
	if len(from) < need {
		sort.Strings(from)
		return 0, from, fmt.Errorf("only %d of the %d sealed members of generation %d needed to import from "+
			"answered (%s); retrying", len(from), need, prev.Generation, strings.Join(from, ","))
	}
	n, err := s.db.ImportClaimsAndAdopt(ictx, newGen, from, states)
	return n, from, err
}

// ── deciding a change (§4.2, §4.3) ─────────────────────────────────────────

// voterChange is one change to propose.
type voterChange struct {
	op         string   // genesis | init | add | rm | reset
	host       string   // add, rm
	members    []string // genesis, init
	createdBy  string
	startRound uint64
}

// errVoterGate is the refusal before voter_config_v1 has durably latched.
func errVoterGate() error {
	return status.Errorf(codes.FailedPrecondition, "%v", corrosion.ErrVoterConfigGateClosed)
}

// decideVoterChange drives one change to a decided generation, writes it and
// adopts it. ours reports whether the decided value is the one proposed here:
// when it is not, a concurrent change decided the generation and this call
// completed that one instead.
func (s *Server) decideVoterChange(ctx context.Context, ch voterChange) (corrosion.VoterConfigValue, bool, error) {
	s.voterChangeMu.Lock()
	defer s.voterChangeMu.Unlock()
	if !s.db.MayWriteVoterConfigs() {
		return corrosion.VoterConfigValue{}, false, errVoterGate()
	}
	if ok, reason := s.VoterConfigReadiness(ctx); !ok {
		return corrosion.VoterConfigValue{}, false, status.Errorf(codes.FailedPrecondition, "this node cannot vote: %s", reason)
	}
	if _, err := s.AdoptVoterConfigs(ctx); err != nil {
		return corrosion.VoterConfigValue{}, false, status.Errorf(codes.FailedPrecondition,
			"this node has not adopted the latest voter generation yet: %v", err)
	}
	prev, err := corrosion.AdoptedVoterConfig(ctx, s.db)
	if err != nil {
		return corrosion.VoterConfigValue{}, false, status.Errorf(codes.Unavailable, "%v", err)
	}
	var g int64
	if prev != nil {
		g = prev.Generation
	}
	if next, err := corrosion.GetVoterConfig(ctx, s.db, g+1); err != nil || next != nil {
		return corrosion.VoterConfigValue{}, false, status.Errorf(codes.FailedPrecondition,
			"generation %d already exists on this node but is not adopted yet; retry shortly", g+1)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	spec := claims.Spec{
		Key:        corrosion.ClaimKey{TargetKind: corrosion.ClaimKindVoterConfig, OwnerEpoch: g},
		Generation: g,
		StartRound: ch.startRound,
	}
	value := func(members []corrosion.VoterMember, change string) corrosion.ClaimValue {
		return corrosion.ClaimValue{Config: &corrosion.VoterConfigValue{
			Generation: g + 1, Members: corrosion.SortMembers(members), Change: change,
			CreatedBy: ch.createdBy, CreatedAt: now,
		}}
	}
	if !prev.Explicit() {
		if ch.op != corrosion.VoterChangeGenesis && ch.op != "init" {
			return corrosion.VoterConfigValue{}, false, status.Errorf(codes.FailedPrecondition,
				"no voter generation with members is adopted; start one with `lv cluster voter init`")
		}
		voters := dedupSorted(ch.members)
		if len(voters) == 0 {
			return corrosion.VoterConfigValue{}, false, status.Error(codes.InvalidArgument, "a genesis needs members")
		}
		// Genesis is unanimous: no earlier config has a majority that could
		// decide it (§4.2). Phase 1 learns each member's incarnation.
		spec.Voters, spec.PrepareQuorum = voters, len(voters)
		spec.Electorate = func(v corrosion.ClaimValue) ([]string, int) {
			if v.Config == nil {
				return nil, 1
			}
			var names []string
			for _, m := range v.Config.Members {
				names = append(names, m.Name)
			}
			return names, len(names)
		}
		spec.Propose = func(promises map[string]corrosion.PrepareResult) (corrosion.ClaimValue, error) {
			var ms []corrosion.VoterMember
			for _, n := range voters {
				pr, ok := promises[n]
				if !ok || pr.Incarnation == "" {
					return corrosion.ClaimValue{}, fmt.Errorf("%s did not report its incarnation", n)
				}
				ms = append(ms, corrosion.VoterMember{Name: n, Incarnation: pr.Incarnation})
			}
			return value(ms, corrosion.VoterChangeGenesis), nil
		}
	} else {
		names := prev.Names()
		q := corrosion.MajorityOf(len(names))
		spec.Voters, spec.PrepareQuorum = names, q
		spec.Electorate = func(corrosion.ClaimValue) ([]string, int) { return names, q }
		var proposal corrosion.ClaimValue
		switch ch.op {
		case "add":
			if _, ok := prev.Member(ch.host); ok {
				return corrosion.VoterConfigValue{}, false, status.Errorf(codes.AlreadyExists,
					"%s is already a member of voter generation %d", ch.host, g)
			}
			inc, err := s.remoteIncarnation(ctx, ch.host, g)
			if err != nil {
				return corrosion.VoterConfigValue{}, false, status.Errorf(codes.Unavailable,
					"%s must be reachable to join the voter set (it supplies its incarnation): %v", ch.host, err)
			}
			proposal = value(append(append([]corrosion.VoterMember(nil), prev.Members...),
				corrosion.VoterMember{Name: ch.host, Incarnation: inc}), corrosion.VoterChangeAdd(ch.host))
		case "rm":
			if _, ok := prev.Member(ch.host); !ok {
				return corrosion.VoterConfigValue{}, false, status.Errorf(codes.NotFound,
					"%s is not a member of voter generation %d", ch.host, g)
			}
			var rest []corrosion.VoterMember
			for _, m := range prev.Members {
				if m.Name != ch.host {
					rest = append(rest, m)
				}
			}
			if len(rest) == 0 {
				return corrosion.VoterConfigValue{}, false, status.Errorf(codes.FailedPrecondition,
					"%s is the last voter; `lv cluster voter reset` returns the cluster to the derived set", ch.host)
			}
			proposal = value(rest, corrosion.VoterChangeRm(ch.host))
		case corrosion.VoterChangeReset:
			proposal = value(nil, corrosion.VoterChangeReset)
		default:
			return corrosion.VoterConfigValue{}, false, status.Errorf(codes.FailedPrecondition,
				"generation %d is adopted; change it one member at a time with `lv cluster voter add` or "+
					"`lv cluster voter rm`, or leave it with `lv cluster voter reset`", g)
		}
		spec.Propose = func(map[string]corrosion.PrepareResult) (corrosion.ClaimValue, error) { return proposal, nil }
	}

	dctx, cancel := context.WithTimeout(ctx, voterConfigTimeout)
	defer cancel()
	out, err := s.claimProposer().Decide(dctx, spec)
	if err != nil {
		var nm *claims.NoMajorityError
		if errors.As(err, &nm) {
			return corrosion.VoterConfigValue{}, false, status.Errorf(codes.Unavailable,
				"generation %d was not decided: %v", g+1, err)
		}
		return corrosion.VoterConfigValue{}, false, status.Errorf(codes.Unavailable, "generation %d: %v", g+1, err)
	}
	if out.Value.Config == nil {
		return corrosion.VoterConfigValue{}, false, status.Error(codes.Internal, "a voter_config claim decided a non-config value")
	}
	decided := *out.Value.Config
	want, err := corrosion.ExpectedVoterConfigCertificate(prev, decided)
	if err == nil {
		_, verifier, verr := s.claimIdentity()
		if verr != nil {
			err = verr
		} else {
			err = verifier.Verify(out.Certificate, want)
		}
	}
	if err != nil {
		return corrosion.VoterConfigValue{}, false, status.Errorf(codes.Internal,
			"the certificate collected for generation %d does not verify: %v", g+1, err)
	}
	if err := corrosion.WriteVoterConfig(ctx, s.db, decided, out.Certificate); err != nil {
		return corrosion.VoterConfigValue{}, false, status.Errorf(codes.Unavailable, "record generation %d: %v", g+1, err)
	}
	if _, err := s.AdoptVoterConfigs(ctx); err != nil {
		// Decided and recorded; adoption retries on the daemon's loop.
		slog.Warn("voter set: decided a generation but could not adopt it yet", "generation", g+1, "error", err)
	}
	return decided, out.Ours, nil
}

// remoteIncarnation asks host for its voter incarnation (a read-only
// GetRecoveryClaim), which a joining member supplies (§4.3).
func (s *Server) remoteIncarnation(ctx context.Context, host string, gen int64) (string, error) {
	key := corrosion.ClaimKey{TargetKind: corrosion.ClaimKindVoterConfig, OwnerEpoch: gen}
	if host == s.hostName {
		return s.db.VoterIncarnation(ctx)
	}
	cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	cl, closer, err := s.dialPeer(cctx, host)
	if err != nil {
		return "", err
	}
	defer closer()
	resp, err := cl.GetRecoveryClaim(cctx, &pb.GetRecoveryClaimRequest{Key: keyToPB(key)})
	if err != nil {
		return "", err
	}
	if resp.GetState().GetVoter() != host || resp.GetState().GetVoterIncarnation() == "" {
		return "", fmt.Errorf("%s did not report an incarnation as itself", host)
	}
	return resp.GetState().GetVoterIncarnation(), nil
}

func dedupSorted(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// ── automatic genesis (§4.2) ───────────────────────────────────────────────

const (
	voterEvaluator          = "voter_config"
	condVoterGenesisPending = "ha.voter.genesis_pending"
	voterConditionSubject   = "voters"
)

// VoterGenesisTick proposes generation 1 once voter_config_v1 has durably
// latched, on a CLEAN cluster only: every non-deleted host voting-eligible and
// reachable. It is the leader-lease holder's job (the failover coordinator
// calls it each tick it holds the lease), so ordinarily one node proposes; two
// nodes that each believe they hold the lease decide one value, because
// genesis is itself a claim.
//
// It runs only while voter_configs is EMPTY, which is what makes a reset
// sticky: after one, only `lv cluster voter init` starts a new generation.
//
// While it cannot run, ha.voter.genesis_pending names every host holding it
// back and what clears it.
func (s *Server) VoterGenesisTick(ctx context.Context, leaseTerm int64) {
	if s.db == nil || !s.db.MayWriteVoterConfigs() {
		return
	}
	empty, err := corrosion.VoterConfigsEmpty(ctx, s.db)
	if err != nil {
		slog.Warn("voter genesis: read voter_configs", "error", err)
		return
	}
	if !empty {
		s.applyGenesisPending(ctx, nil)
		return
	}
	blocked, members, err := s.genesisBlockers(ctx)
	if err != nil {
		slog.Warn("voter genesis: read hosts", "error", err)
		return
	}
	if len(blocked) > 0 {
		s.applyGenesisPending(ctx, blocked)
		return
	}
	round := uint64(1)
	if leaseTerm > 0 {
		round = uint64(leaseTerm)
	}
	decided, ours, err := s.decideVoterChange(ctx, voterChange{
		op: corrosion.VoterChangeGenesis, members: members,
		createdBy: "automatic genesis by " + s.hostName, startRound: round,
	})
	if err != nil {
		s.applyGenesisPending(ctx, genesisRefusals(err, members))
		return
	}
	slog.Warn("voter set: generation 1 decided", "members", strings.Join(members, ","), "ours", ours,
		"created_by", decided.CreatedBy)
	s.applyGenesisPending(ctx, nil)
}

// genesisBlockers is every host that keeps the cluster from being clean, with
// its state and what clears it. members is the derived voter set, which is
// what genesis proposes (§4.2) — on a clean cluster, every host.
func (s *Server) genesisBlockers(ctx context.Context) (map[string]string, []string, error) {
	hosts, err := corrosion.ListHosts(ctx, s.db)
	if err != nil {
		return nil, nil, err
	}
	derived, err := corrosion.DerivedVoterSet(ctx, s.db)
	if err != nil {
		return nil, nil, err
	}
	var members []string
	for n := range derived {
		members = append(members, n)
	}
	blocked := map[string]string{}
	for _, h := range hosts {
		if health.VotingEligible(h.State) {
			continue
		}
		var clear string
		switch h.State {
		case "maintenance":
			clear = "finish the maintenance"
		case "offline", "fenced":
			clear = "bring the host back, or remove it"
		default:
			clear = "return it to active"
		}
		blocked[h.Name] = fmt.Sprintf("%s is %s: %s (or run `lv cluster voter init --members` without it)",
			h.Name, h.State, clear)
	}
	sort.Strings(members)
	return blocked, members, nil
}

// genesisRefusals turns a failed genesis into per-host reasons.
func genesisRefusals(err error, members []string) map[string]string {
	out := map[string]string{}
	var nm *claims.NoMajorityError
	if errors.As(err, &nm) {
		for _, r := range nm.Refusals {
			out[r.Voter] = fmt.Sprintf("%s did not sign generation 1 (%s: %s)", r.Voter, r.Reason, r.Detail)
		}
	}
	if len(out) == 0 {
		out[voterConditionSubject] = fmt.Sprintf("generation 1 over %s was not decided: %v", strings.Join(members, ","), err)
	}
	return out
}

// applyGenesisPending raises ha.voter.genesis_pending with one line per
// blocking host, or resolves it when blocked is empty. The lease holder is the
// only writer, which is what the LWW row merge assumes.
func (s *Server) applyGenesisPending(ctx context.Context, blocked map[string]string) {
	now := time.Now().UTC().Format(time.RFC3339)
	row, found, err := corrosion.GetHealthCondition(ctx, s.db, voterEvaluator, condVoterGenesisPending, "cluster", voterConditionSubject)
	if err != nil {
		slog.Warn("voter genesis: read health condition", "error", err)
		return
	}
	if len(blocked) == 0 {
		if !found || row.Lifecycle == corrosion.ConditionResolved {
			return
		}
		row.Lifecycle, row.ResolvedAt, row.LastSeen, row.Reporter = corrosion.ConditionResolved, now, now, s.hostName
		row.ObserveCount, row.CleanCount = 0, row.CleanCount+1
		if err := corrosion.UpsertHealthCondition(ctx, s.db, row); err != nil {
			slog.Warn("voter genesis: resolve health condition", "error", err)
		}
		return
	}
	var hosts, lines []string
	for h, why := range blocked {
		if h != voterConditionSubject {
			hosts = append(hosts, h)
		}
		lines = append(lines, why)
	}
	sort.Strings(hosts)
	sort.Strings(lines)
	detail := "automatic voter genesis is waiting for a clean cluster: " + strings.Join(lines, "; ")
	if !found || row.Lifecycle == corrosion.ConditionResolved {
		row = corrosion.HealthCondition{Evaluator: voterEvaluator, Code: condVoterGenesisPending,
			SubjectKind: "cluster", SubjectID: voterConditionSubject,
			Lifecycle: corrosion.ConditionObserved, FirstSeen: now}
	} else if row.Lifecycle == corrosion.ConditionObserved && row.ObserveCount >= 1 {
		row.Lifecycle, row.ConfirmedAt = corrosion.ConditionConfirmed, now
	}
	row.ObserveCount++
	row.CleanCount = 0
	row.Severity = corrosion.SeverityWarning
	row.Hosts = hosts
	row.Evidence = encodeEvidence(detail, hosts)
	row.LastSeen, row.ResolvedAt, row.Reporter = now, "", s.hostName
	if err := corrosion.UpsertHealthCondition(ctx, s.db, row); err != nil {
		slog.Warn("voter genesis: persist health condition", "error", err)
	}
}

// genesisPendingDetail is the active condition's text, "" when none.
func (s *Server) genesisPendingDetail(ctx context.Context) string {
	row, found, err := corrosion.GetHealthCondition(ctx, s.db, voterEvaluator, condVoterGenesisPending, "cluster", voterConditionSubject)
	if err != nil || !found || row.Lifecycle == corrosion.ConditionResolved {
		return ""
	}
	return row.Evidence
}

// ── operator RPCs ──────────────────────────────────────────────────────────

// ChangeVoterConfig decides the next voter generation for `lv cluster voter
// init|add|rm|reset`.
func (s *Server) ChangeVoterConfig(ctx context.Context, req *pb.ChangeVoterConfigRequest) (*pb.ChangeVoterConfigResponse, error) {
	if err := s.RequirePerm(ctx, "/", "cluster.voter.update", "admin"); err != nil {
		return nil, err
	}
	if !s.db.MayWriteVoterConfigs() {
		return nil, errVoterGate()
	}
	op := req.GetOp()
	ch := voterChange{op: op, host: strings.TrimSpace(req.GetHost()),
		createdBy: fmt.Sprintf("%s via %s", callerUsername(ctx), s.hostName)}
	switch op {
	case "init":
		members, err := s.initMembers(ctx, req.GetMembers())
		if err != nil {
			return nil, err
		}
		ch.members = members
		if req.GetDryRun() {
			return &pb.ChangeVoterConfigResponse{Members: namesToPB(members), Change: corrosion.VoterChangeGenesis,
				Detail: "dry run: every listed host must be reachable and sign; nothing was changed"}, nil
		}
	case "add", "rm":
		if ch.host == "" {
			return nil, status.Errorf(codes.InvalidArgument, "%s needs a host", op)
		}
		if op == "add" {
			if h, err := corrosion.GetHost(ctx, s.db, ch.host); err != nil || h == nil {
				return nil, status.Errorf(codes.NotFound, "%s is not a host in this cluster", ch.host)
			}
		}
	case corrosion.VoterChangeReset:
	default:
		return nil, status.Errorf(codes.InvalidArgument, "unknown voter change %q (init, add, rm or reset)", op)
	}
	if req.GetDryRun() {
		cfg, err := corrosion.AdoptedVoterConfig(ctx, s.db)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "%v", err)
		}
		if !cfg.Explicit() {
			return nil, status.Error(codes.FailedPrecondition, "no voter generation with members is adopted")
		}
		names := cfg.Names()
		switch op {
		case "add":
			names = dedupSorted(append(names, ch.host))
		case "rm":
			var rest []string
			for _, n := range names {
				if n != ch.host {
					rest = append(rest, n)
				}
			}
			names = rest
		case corrosion.VoterChangeReset:
			names = nil
		}
		return &pb.ChangeVoterConfigResponse{Generation: cfg.Generation + 1, Members: namesToPB(names),
			Detail: "dry run: nothing was changed"}, nil
	}
	decided, ours, err := s.decideVoterChange(ctx, ch)
	if err != nil {
		s.audit(ctx, "cluster.voter."+op, ch.host, err.Error(), "error")
		return nil, err
	}
	detail := fmt.Sprintf("decided generation %d (%s)", decided.Generation, decided.Change)
	if !ours {
		detail = fmt.Sprintf("a concurrent change decided generation %d first (%s by %s); this node completed "+
			"that one instead — re-run if yours is still needed", decided.Generation, decided.Change, decided.CreatedBy)
	}
	s.audit(ctx, "cluster.voter."+op, ch.host, detail, "ok")
	resp := &pb.ChangeVoterConfigResponse{Generation: decided.Generation, Members: membersToPB(decided.Members),
		Change: decided.Change, Applied: ours, Detail: detail}
	if !ours {
		return resp, status.Error(codes.Aborted, detail)
	}
	return resp, nil
}

func namesToPB(names []string) []*pb.ClaimVoterMember {
	out := make([]*pb.ClaimVoterMember, 0, len(names))
	for _, n := range names {
		out = append(out, &pb.ClaimVoterMember{Name: n})
	}
	return out
}

// initMembers is `lv cluster voter init`'s member list: the one given, or the
// derived voter set. It is refused while automatic genesis could still succeed
// without it — one path for the common case (§4.2).
func (s *Server) initMembers(ctx context.Context, given []string) ([]string, error) {
	cfg, err := corrosion.AdoptedVoterConfig(ctx, s.db)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "%v", err)
	}
	if cfg.Explicit() {
		return nil, status.Errorf(codes.FailedPrecondition,
			"voter generation %d is adopted; change it with `lv cluster voter add` or `lv cluster voter rm`, "+
				"or leave it with `lv cluster voter reset` first", cfg.Generation)
	}
	empty, err := corrosion.VoterConfigsEmpty(ctx, s.db)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "%v", err)
	}
	if empty {
		blocked, _, err := s.genesisBlockers(ctx)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "%v", err)
		}
		if len(blocked) == 0 && s.genesisPendingDetail(ctx) == "" {
			return nil, status.Error(codes.FailedPrecondition,
				"every host is voting-eligible, so automatic genesis will write generation 1 on the lease "+
					"holder's next tick; `lv cluster voter init` is for a cluster that cannot become clean")
		}
	}
	if len(given) == 0 {
		derived, err := corrosion.DerivedVoterSet(ctx, s.db)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "%v", err)
		}
		for n := range derived {
			given = append(given, n)
		}
	}
	members := dedupSorted(given)
	for _, m := range members {
		if h, err := corrosion.GetHost(ctx, s.db, m); err != nil || h == nil {
			return nil, status.Errorf(codes.NotFound, "%s is not a host in this cluster", m)
		}
	}
	if len(members) == 0 {
		return nil, status.Error(codes.FailedPrecondition, "no voting-eligible hosts to propose")
	}
	return members, nil
}

// GetVoterConfig reports this host's adopted voter generation for
// `lv cluster voter ls`.
func (s *Server) GetVoterConfig(ctx context.Context, _ *pb.GetVoterConfigRequest) (*pb.GetVoterConfigResponse, error) {
	if err := s.RequirePerm(ctx, "/", "cluster.voter.read", "viewer"); err != nil {
		return nil, err
	}
	cfg, err := corrosion.AdoptedVoterConfig(ctx, s.db)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "%v", err)
	}
	rows, err := corrosion.ListVoterConfigs(ctx, s.db)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "%v", err)
	}
	resp := &pb.GetVoterConfigResponse{ReportingHost: s.hostName, GateOpen: s.db.MayWriteVoterConfigs(),
		GenesisPending: s.genesisPendingDetail(ctx)}
	if len(rows) > 0 {
		resp.LatestGeneration = rows[len(rows)-1].Generation
	}
	if cfg != nil {
		resp.AdoptedGeneration, resp.Change, resp.CreatedBy, resp.CreatedAt = cfg.Generation, cfg.Change, cfg.CreatedBy, cfg.CreatedAt
	}
	if !cfg.Explicit() {
		derived, err := corrosion.DerivedVoterSet(ctx, s.db)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "%v", err)
		}
		for n := range derived {
			resp.DerivedVoters = append(resp.DerivedVoters, n)
		}
		sort.Strings(resp.DerivedVoters)
		return resp, nil
	}
	resp.Explicit = true
	resp.Members = s.memberStatuses(ctx, cfg)
	return resp, nil
}

// memberStatuses asks every member for its incarnation, in parallel: a member
// that answers with a different one abstains (§3.11).
func (s *Server) memberStatuses(ctx context.Context, cfg *corrosion.VoterConfig) []*pb.VoterMemberStatus {
	out := make([]*pb.VoterMemberStatus, len(cfg.Members))
	var wg sync.WaitGroup
	for i, m := range cfg.Members {
		st := &pb.VoterMemberStatus{Name: m.Name, Incarnation: m.Incarnation, HostState: "removed"}
		if h, err := corrosion.GetHost(ctx, s.db, m.Name); err == nil && h != nil {
			st.HostState = h.State
		}
		out[i] = st
		wg.Add(1)
		go func(st *pb.VoterMemberStatus) {
			defer wg.Done()
			inc, err := s.remoteIncarnation(ctx, st.Name, cfg.Generation)
			if err != nil {
				st.Detail = "unreachable: " + err.Error()
				return
			}
			st.Reachable = true
			if inc != st.Incarnation {
				st.Abstaining = true
				st.Detail = fmt.Sprintf("incarnation %s does not match its entry; heal with `lv cluster voter rm %s` "+
					"then `lv cluster voter add %s`", shortID(inc), st.Name, st.Name)
			}
		}(st)
	}
	wg.Wait()
	return out
}

func shortID(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

// voterRemovalRefusal is `lv host rm`'s check: deleting a hosts row must no
// longer change the voting population implicitly (§4.3).
func (s *Server) voterRemovalRefusal(ctx context.Context, host string) error {
	cfg, err := corrosion.AdoptedVoterConfig(ctx, s.db)
	if err != nil {
		return status.Errorf(codes.Unavailable, "read the voter set: %v", err)
	}
	if _, ok := cfg.Member(host); ok {
		return status.Errorf(codes.FailedPrecondition,
			"%s is a member of voter generation %d; removing the host would not remove its vote. "+
				"Run `lv cluster voter rm %s` first, then remove the host — or, if it is fenced and gone for "+
				"good, `lv host rm --dead %s`, which does both", host, cfg.Generation, host, host)
	}
	return nil
}
