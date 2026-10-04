package grpcapi

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// Forced reconfiguration of the voter set (docs/design/recovery-claims.md
// §4.6): `lv cluster voter force-reconfigure --lost <host>[,<host>...]`.
//
// `voter rm` is decided by a majority of the current generation g, so once a
// majority of g is gone for good neither it nor any recovery claim can ever
// succeed. This is the break-glass, in the style of etcd's
// --force-new-cluster: run against one survivor, it checks the preconditions,
// has every survivor seal g and sign g+1 unanimously, and writes g+1 with the
// survivors as members. Every node adopts it only after checking it for
// itself — including probing the named lost hosts — and every survivor
// imports, as it adopts, every value any survivor accepted and every
// certificate any reachable host holds.
//
// What it gives up is §4.6's to explain; the short form is that a value
// accepted only by the lost voters, whose certificate reached no reachable
// host, is invisible to the survivors, and G1 then rests on the lost hosts
// being off. That is why each must be fenced proof-grade first.

const (
	condVoterForced = "ha.voter.forced"
	forceTimeout    = 30 * time.Second
)

// forcedProbe is the fresh reachability check a forced reconfiguration uses:
// the owner probe's transport and verdict, never its cached result — the
// question is whether a host is reachable NOW. It runs under the operator's
// context, and a probe that context cut short learned nothing, so it reads as
// reached (§10.9): a voter is named lost only on a probe that finished.
func (s *Server) forcedProbe(ctx context.Context, host string) (bool, string) {
	if host == s.hostName {
		return true, "this host"
	}
	reached, detail := s.probeOnce(ctx, s.claims.probe.dial, host)
	if !reached && ctx.Err() != nil {
		return true, fmt.Sprintf("probe interrupted before it finished: %v", ctx.Err())
	}
	return reached, detail
}

// ForceReconfigureVoters is the operator RPC.
func (s *Server) ForceReconfigureVoters(ctx context.Context, req *pb.ForceReconfigureVotersRequest) (*pb.ForceReconfigureVotersResponse, error) {
	if err := s.RequirePerm(ctx, "/", "cluster.voter.update", "admin"); err != nil {
		return nil, err
	}
	if !s.db.MayWriteVoterConfigs() {
		return nil, errVoterGate()
	}
	s.voterChangeMu.Lock()
	defer s.voterChangeMu.Unlock()
	fctx, cancel := context.WithTimeout(ctx, forceTimeout)
	defer cancel()
	resp, value, prev, fences, err := s.planForcedReconfiguration(fctx, req.GetLost())
	if err != nil {
		s.audit(ctx, "cluster.voter.force-reconfigure", strings.Join(req.GetLost(), ","), err.Error(), "refused")
		return nil, err
	}
	if req.GetDryRun() {
		resp.Detail = "dry run: every check passed; nothing was changed"
		return resp, nil
	}

	// Converge (§4.6 step 2): one full anti-entropy pass from every reachable
	// host, so each survivor's replica holds every proof, certificate and
	// ownership row any reachable host holds.
	s.convergeSurvivors(fctx, value.Members)
	if row, err := corrosion.GetVoterConfig(fctx, s.db, value.Generation); err == nil && row != nil &&
		!corrosion.IsForcedChange(row.Change) && s.verifyVoterConfigRowNow(prev, row) == nil {
		_, _ = s.AdoptVoterConfigs(ctx)
		return nil, status.Errorf(codes.FailedPrecondition,
			"an ordinary generation %d (%s by %s) has arrived that this node never saw, decided by generation %d's "+
				"majority: it is adopted instead; re-run against it if a forced change is still needed",
			row.Generation, row.Change, row.CreatedBy, prev.Generation)
	}

	// Seal and sign (§4.6 steps 1 and 4): unanimous among the survivors.
	ev := corrosion.ForcedVoterEvidence{FromGeneration: prev.Generation, Lost: forcedLost(value), Fences: fences}
	sigs, err := s.collectForcedSignatures(fctx, prev.Generation, value, ev)
	if err != nil {
		s.audit(ctx, "cluster.voter.force-reconfigure", strings.Join(ev.Lost, ","), err.Error(), "error")
		return nil, err
	}
	ev.Signatures = sigs
	if err := corrosion.WriteForcedVoterConfig(ctx, s.db, value, ev); err != nil {
		return nil, status.Errorf(codes.Unavailable, "record forced generation %d: %v", value.Generation, err)
	}
	detail := fmt.Sprintf("forced generation %d: members %s, lost %s (from generation %d)", value.Generation,
		strings.Join(namesOf(value.Members), ","), strings.Join(ev.Lost, ","), prev.Generation)
	// Announce (§4.6 step 5): the audit event, and ha.voter.forced until every
	// lost host has been removed and revoked.
	s.audit(ctx, "voter.force_reconfigured", strings.Join(ev.Lost, ","), detail, "ok")
	slog.Warn("voter set: FORCED reconfiguration written", "generation", value.Generation,
		"members", strings.Join(namesOf(value.Members), ","), "lost", strings.Join(ev.Lost, ","))
	if _, err := s.AdoptVoterConfigs(ctx); err != nil {
		slog.Warn("voter set: wrote the forced generation but could not adopt it yet", "generation", value.Generation, "error", err)
	}
	s.applyVoterConditions(ctx)
	resp.Generation, resp.Applied = value.Generation, true
	resp.Detail = detail + ". Next: `lv host rm --dead` each lost host (" + strings.Join(ev.Lost, ", ") + ")"
	return resp, nil
}

func namesOf(ms []corrosion.VoterMember) []string {
	out := make([]string, 0, len(ms))
	for _, m := range ms {
		out = append(out, m.Name)
	}
	return out
}

func forcedLost(v corrosion.VoterConfigValue) []string { return corrosion.ForcedLost(v.Change) }

// planForcedReconfiguration checks every precondition of §4.6 and builds the
// forced value. It changes nothing.
func (s *Server) planForcedReconfiguration(ctx context.Context, lostIn []string) (*pb.ForceReconfigureVotersResponse, corrosion.VoterConfigValue, *corrosion.VoterConfig, []corrosion.ForcedFence, error) {
	var none corrosion.VoterConfigValue
	if _, err := s.AdoptVoterConfigs(ctx); err != nil {
		slog.Warn("voter set: adoption pass before a forced reconfiguration did not complete", "error", err)
	}
	prev, err := corrosion.AdoptedVoterConfig(ctx, s.db)
	if err != nil {
		return nil, none, nil, nil, status.Errorf(codes.Unavailable, "%v", err)
	}
	if !prev.Explicit() {
		return nil, none, nil, nil, status.Error(codes.FailedPrecondition, "no voter generation with members is adopted; there is nothing to force")
	}
	lost := dedupSorted(lostIn)
	if len(lost) == 0 {
		return nil, none, nil, nil, status.Error(codes.InvalidArgument, "--lost names at least one member of the adopted generation")
	}
	var survivors []corrosion.VoterMember
	lostSet := map[string]bool{}
	for _, l := range lost {
		if _, ok := prev.Member(l); !ok {
			return nil, none, nil, nil, status.Errorf(codes.FailedPrecondition, "%s is not a member of voter generation %d", l, prev.Generation)
		}
		lostSet[l] = true
	}
	for _, m := range prev.Members {
		if !lostSet[m.Name] {
			survivors = append(survivors, m)
		}
	}
	majority := corrosion.MajorityOf(len(prev.Members))
	// Precondition 2: the survivors are fewer than a majority, or `voter rm`
	// can do this without giving anything up.
	if len(survivors) >= majority {
		return nil, none, nil, nil, status.Errorf(codes.FailedPrecondition,
			"the %d members of generation %d not named lost are a majority of %d: a decided change can remove the lost "+
				"ones without forcing anything — `lv cluster voter rm <host>` for each (or `lv host rm --dead <host>`)",
			len(survivors), prev.Generation, len(prev.Members))
	}
	if !isMemberName(survivors, s.hostName) {
		return nil, none, nil, nil, status.Errorf(codes.FailedPrecondition,
			"%s is not a surviving member of generation %d; run force-reconfigure against a survivor", s.hostName, prev.Generation)
	}
	// Precondition 1: every lost host is fenced proof-grade.
	var fences []corrosion.ForcedFence
	var pbFences []*pb.ForcedFenceEvidence
	for _, l := range lost {
		fr, ok, err := corrosion.HostProofGradeFence(ctx, s.db, l)
		if err != nil {
			return nil, none, nil, nil, status.Errorf(codes.Unavailable, "read fencing_log: %v", err)
		}
		if !ok {
			return nil, none, nil, nil, status.Errorf(codes.FailedPrecondition,
				"%s has no proof-grade fence (an IPMI power-off, or `lv host fence-confirm %s` once it is powered off); "+
					"a lost voter must be proven off before its vote is dropped — a lost majority that is merely partitioned "+
					"could go on certifying under generation %d", l, l, prev.Generation)
		}
		fences = append(fences, corrosion.ForcedFence{Host: l, FenceID: fr.ID, Method: fr.Method, Result: fr.Result, Timestamp: fr.Timestamp})
		pbFences = append(pbFences, &pb.ForcedFenceEvidence{Host: l, FenceId: fr.ID, Method: fr.Method, Result: fr.Result, Timestamp: fr.Timestamp})
	}
	// Precondition 3: probe every member of g; refuse on reaching a majority,
	// or any named lost host. Precondition 4: every survivor answers.
	type probed struct {
		reached bool
		detail  string
	}
	res := map[string]probed{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, m := range prev.Members {
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			r, d := s.forcedProbe(ctx, name)
			mu.Lock()
			res[name] = probed{r, d}
			mu.Unlock()
		}(m.Name)
	}
	wg.Wait()
	reached := 0
	for _, m := range prev.Members {
		if res[m.Name].reached {
			reached++
		}
	}
	for _, l := range lost {
		if res[l].reached {
			return nil, none, nil, nil, status.Errorf(codes.FailedPrecondition,
				"%s is named lost but %s reaches it (%s): a host that answers is not lost", l, s.hostName, res[l].detail)
		}
	}
	if reached >= majority {
		return nil, none, nil, nil, status.Errorf(codes.FailedPrecondition,
			"%s reaches %d of generation %d's %d members, a majority: this is not the break-glass case", s.hostName, reached,
			prev.Generation, len(prev.Members))
	}
	for _, m := range survivors {
		if !res[m.Name].reached {
			return nil, none, nil, nil, status.Errorf(codes.FailedPrecondition,
				"survivor %s is not reachable (%s): every survivor must sign a forced generation", m.Name, res[m.Name].detail)
		}
	}
	// Precondition 5: every other host is reachable or fenced proof-grade — a
	// live host the survivors cannot see may hold a certificate they cannot see.
	hosts, err := corrosion.ListHosts(ctx, s.db)
	if err != nil {
		return nil, none, nil, nil, status.Errorf(codes.Unavailable, "%v", err)
	}
	for _, h := range hosts {
		if _, member := prev.Member(h.Name); member {
			continue
		}
		if r, _ := s.forcedProbe(ctx, h.Name); r {
			continue
		}
		if _, ok, _ := corrosion.HostProofGradeFence(ctx, s.db, h.Name); ok {
			continue
		}
		return nil, none, nil, nil, status.Errorf(codes.FailedPrecondition,
			"%s is neither reachable nor fenced proof-grade: a live host out of sight may hold a certificate the "+
				"survivors cannot see — bring it back, or fence it (`lv host fence-confirm %s`)", h.Name, h.Name)
	}
	value := corrosion.VoterConfigValue{
		Generation: prev.Generation + 1, Members: corrosion.SortMembers(survivors), Change: corrosion.VoterChangeForce(lost),
		CreatedBy: fmt.Sprintf("%s via %s (force-reconfigure)", callerUsername(ctx), s.hostName),
		CreatedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
	resp := &pb.ForceReconfigureVotersResponse{FromGeneration: prev.Generation, Survivors: namesOf(value.Members),
		Lost: lost, Fences: pbFences, ImportKeys: int64(s.forcedImportEstimate(ctx, prev, value.Members))}
	return resp, value, prev, fences, nil
}

func isMemberName(ms []corrosion.VoterMember, name string) bool {
	for _, m := range ms {
		if m.Name == name {
			return true
		}
	}
	return false
}

// forcedImportEstimate is the number of claim keys the survivors will import,
// for the plan: the distinct keys any survivor holds an accepted value for,
// plus the certified proofs.
func (s *Server) forcedImportEstimate(ctx context.Context, prev *corrosion.VoterConfig, survivors []corrosion.VoterMember) int {
	keys := map[corrosion.ClaimKey]bool{}
	for _, m := range survivors {
		src, err := s.fetchImportSource(ctx, m.Name, prev.Generation)
		if err != nil {
			continue
		}
		for _, st := range src.States {
			keys[st.Key] = true
		}
	}
	if _, verifier, err := s.claimIdentity(); err == nil {
		if states, err := corrosion.CertifiedProofStates(ctx, s.db, verifier, prev.Generation); err == nil {
			for _, st := range states {
				keys[st.Key] = true
			}
		}
	}
	return len(keys)
}

// convergeSurvivors runs an anti-entropy pass on this node and asks every
// other survivor to run one, best-effort.
func (s *Server) convergeSurvivors(ctx context.Context, survivors []corrosion.VoterMember) {
	if s.antiEntropy != nil {
		s.antiEntropy.RunOnce(ctx)
	}
	for _, m := range survivors {
		if m.Name == s.hostName {
			continue
		}
		cl, closer, err := s.dialPeer(ctx, m.Name)
		if err != nil {
			continue
		}
		_, _ = cl.TriggerAntiEntropy(ctx, &pb.TriggerAntiEntropyRequest{})
		closer()
	}
}

// collectForcedSignatures has every survivor check, seal and sign.
func (s *Server) collectForcedSignatures(ctx context.Context, from int64, value corrosion.VoterConfigValue, ev corrosion.ForcedVoterEvidence) ([]corrosion.ForcedSignature, error) {
	var out []corrosion.ForcedSignature
	for _, m := range value.Members {
		var sig corrosion.ForcedSignature
		var err error
		if m.Name == s.hostName {
			sig, err = s.signForced(ctx, from, value, ev)
		} else {
			sig, err = s.remoteSignForced(ctx, m.Name, from, value, ev)
		}
		if err != nil {
			return nil, status.Errorf(codes.FailedPrecondition, "survivor %s did not sign forced generation %d: %v "+
				"(nothing was written; the survivors that did sign have sealed generation %d)", m.Name, value.Generation, err, from)
		}
		out = append(out, sig)
	}
	return out, nil
}

func fencesToPB(fs []corrosion.ForcedFence) []*pb.ForcedFenceEvidence {
	out := make([]*pb.ForcedFenceEvidence, 0, len(fs))
	for _, f := range fs {
		out = append(out, &pb.ForcedFenceEvidence{Host: f.Host, FenceId: f.FenceID, Method: f.Method, Result: f.Result, Timestamp: f.Timestamp})
	}
	return out
}

func fencesFromPB(fs []*pb.ForcedFenceEvidence) []corrosion.ForcedFence {
	out := make([]corrosion.ForcedFence, 0, len(fs))
	for _, f := range fs {
		out = append(out, corrosion.ForcedFence{Host: f.GetHost(), FenceID: f.GetFenceId(), Method: f.GetMethod(),
			Result: f.GetResult(), Timestamp: f.GetTimestamp()})
	}
	return out
}

func (s *Server) remoteSignForced(ctx context.Context, host string, from int64, value corrosion.VoterConfigValue, ev corrosion.ForcedVoterEvidence) (corrosion.ForcedSignature, error) {
	cl, closer, err := s.dialPeer(ctx, host)
	if err != nil {
		return corrosion.ForcedSignature{}, err
	}
	defer closer()
	resp, err := cl.SignForcedVoterConfig(ctx, &pb.SignForcedVoterConfigRequest{FromGeneration: from,
		Value: valueToPB(&corrosion.ClaimValue{Config: &value}).GetVoterConfig(), Lost: ev.Lost, Fences: fencesToPB(ev.Fences)})
	if err != nil {
		return corrosion.ForcedSignature{}, err
	}
	if resp.GetVoter() != host {
		return corrosion.ForcedSignature{}, fmt.Errorf("%s answered as %q", host, resp.GetVoter())
	}
	return corrosion.ForcedSignature{Voter: resp.GetVoter(), Incarnation: resp.GetIncarnation(), CertPEM: resp.GetCertPem(),
		Signature: resp.GetSignature()}, nil
}

// SignForcedVoterConfig is a survivor's part (§4.6): it checks the forced
// generation for itself — the shape, the named lost hosts' proof-grade fences
// in its own replica, and that it reaches none of them — then seals the
// generation it replaces and signs. Peer-only.
func (s *Server) SignForcedVoterConfig(ctx context.Context, req *pb.SignForcedVoterConfigRequest) (*pb.SignForcedVoterConfigResponse, error) {
	if err := s.requirePeerCert(ctx); err != nil {
		return nil, err
	}
	v := valueFromPB(&pb.RecoveryClaimValue{VoterConfig: req.GetValue()})
	if v == nil || v.Config == nil {
		return nil, status.Error(codes.InvalidArgument, "a forced generation is needed")
	}
	sig, err := s.signForced(ctx, req.GetFromGeneration(), *v.Config,
		corrosion.ForcedVoterEvidence{FromGeneration: req.GetFromGeneration(), Lost: req.GetLost(), Fences: fencesFromPB(req.GetFences())})
	if err != nil {
		return nil, err
	}
	return &pb.SignForcedVoterConfigResponse{Voter: sig.Voter, Incarnation: sig.Incarnation, CertPem: sig.CertPEM, Signature: sig.Signature}, nil
}

func (s *Server) signForced(ctx context.Context, from int64, value corrosion.VoterConfigValue, ev corrosion.ForcedVoterEvidence) (corrosion.ForcedSignature, error) {
	prev, err := corrosion.AdoptedVoterConfig(ctx, s.db)
	if err != nil {
		return corrosion.ForcedSignature{}, status.Errorf(codes.Unavailable, "%v", err)
	}
	if prev == nil || prev.Generation != from {
		return corrosion.ForcedSignature{}, status.Errorf(codes.FailedPrecondition,
			"%s has not adopted generation %d, the one being replaced", s.hostName, from)
	}
	if err := corrosion.ValidateForcedShape(prev, value, ev); err != nil {
		return corrosion.ForcedSignature{}, status.Errorf(codes.FailedPrecondition, "%v", err)
	}
	inc, err := s.db.VoterIncarnation(ctx)
	if err != nil {
		return corrosion.ForcedSignature{}, status.Errorf(codes.Unavailable, "%v", err)
	}
	me, ok := valueMember(value, s.hostName)
	if !ok || me.Incarnation != inc {
		return corrosion.ForcedSignature{}, status.Errorf(codes.FailedPrecondition,
			"%s is not a survivor of the forced generation with its own incarnation", s.hostName)
	}
	for _, l := range ev.Lost {
		if _, ok, err := corrosion.HostProofGradeFence(ctx, s.db, l); err != nil || !ok {
			return corrosion.ForcedSignature{}, status.Errorf(codes.FailedPrecondition,
				"%s holds no proof-grade fence of %s in its own replica", s.hostName, l)
		}
		if r, d := s.forcedProbe(ctx, l); r {
			return corrosion.ForcedSignature{}, status.Errorf(codes.FailedPrecondition,
				"%s still reaches %s (%s): a host that answers is not lost", s.hostName, l, d)
		}
	}
	if err := s.db.SealVoterGeneration(ctx, from, "forced reconfiguration dropping "+strings.Join(ev.Lost, ",")); err != nil {
		return corrosion.ForcedSignature{}, status.Errorf(codes.Unavailable, "seal generation %d: %v", from, err)
	}
	signer, _, err := s.claimIdentity()
	if err != nil {
		return corrosion.ForcedSignature{}, status.Errorf(codes.FailedPrecondition, "%v", err)
	}
	slog.Warn("voter set: sealed a generation and signed a FORCED reconfiguration", "from", from,
		"generation", value.Generation, "lost", strings.Join(ev.Lost, ","))
	return signer.SignForced(from, value, inc)
}

// member reports a member entry of a voter-config value.
func valueMember(v corrosion.VoterConfigValue, name string) (corrosion.VoterMember, bool) {
	for _, m := range v.Members {
		if m.Name == name {
			return m, true
		}
	}
	return corrosion.VoterMember{}, false
}

// verifyForcedRow is a receiver's check before it adopts a forced generation
// (§4.6 "Adopting a forced row"): the evidence verifies against the
// generation it replaces, with v (Historical at or below the anchor), and the
// receiver itself reaches none of the named lost voters. A receiver that is
// itself named lost refuses outright: it is running, so it is not lost (§10
// records why this departs from the text).
//
// A lost voter is a member ENTRY of prev: a name with the incarnation it was
// admitted as. A host answering under that name with another incarnation is
// a later machine, rebuilt after `lv host rm --dead`, whose empty state.db
// never voted under prev — not the lost voter come back (§10 item 38). A host
// that is reached but cannot say which incarnation it is counts as the lost
// voter.
func (s *Server) verifyForcedRow(ctx context.Context, v *corrosion.ClaimVerifier, prev, row *corrosion.VoterConfig) error {
	ev, err := corrosion.DecodeForcedVoterEvidence(row.Certificate)
	if err != nil {
		return err
	}
	if row.MembersHash != corrosion.MembersHash(row.Members) {
		return fmt.Errorf("members_hash does not match members_json")
	}
	if err := v.ValidateForcedChange(prev, row.VoterConfigValue, ev); err != nil {
		return err
	}
	mine, err := s.db.VoterIncarnation(ctx)
	if err != nil {
		return err
	}
	for _, l := range ev.Lost {
		lost, _ := prev.Member(l)
		if l == s.hostName {
			if lost.Incarnation == mine {
				return fmt.Errorf("forced generation %d names %s lost, and %s is running: a host that can adopt it is not lost",
					row.Generation, s.hostName, s.hostName)
			}
			continue
		}
		r, d := s.forcedProbe(ctx, l)
		if !r {
			continue
		}
		inc, err := s.remoteIncarnation(ctx, l, prev.Generation)
		if err == nil && inc != lost.Incarnation {
			continue
		}
		if err != nil {
			d = fmt.Sprintf("%s, and it did not say which incarnation it is: %v", d, err)
		}
		return fmt.Errorf("forced generation %d names %s lost, but %s reaches it (%s): valid signatures do not make "+
			"a false claim of loss true", row.Generation, l, s.hostName, d)
	}
	return nil
}

// importForForced imports, for a member adopting a forced generation, from
// EVERY survivor — each sealed — plus the certificates any reachable host's
// proofs carry (§4.6 step 3). There is no sealed majority of the replaced
// generation to import from; the survivors are all that is left of it.
func (s *Server) importForForced(ctx context.Context, prev, row *corrosion.VoterConfig) (int, []string, error) {
	ictx, cancel := context.WithTimeout(ctx, voterConfigTimeout)
	defer cancel()
	var from []string
	var states []corrosion.ClaimVoterState
	for _, m := range row.Members {
		src, err := s.fetchImportSource(ictx, m.Name, prev.Generation)
		if err != nil {
			return 0, nil, fmt.Errorf("import from survivor %s: %w", m.Name, err)
		}
		if !src.Frozen {
			return 0, nil, fmt.Errorf("survivor %s has not sealed generation %d yet", m.Name, prev.Generation)
		}
		from = append(from, m.Name)
		states = append(states, src.States...)
	}
	_, verifier, err := s.claimIdentity()
	if err != nil {
		return 0, nil, err
	}
	certified, err := corrosion.CertifiedProofStates(ictx, s.db, verifier, prev.Generation)
	if err != nil {
		return 0, nil, err
	}
	states = append(states, certified...)
	n, err := s.db.ImportClaimsAndAdopt(ictx, row.Generation, from, states)
	return n, from, err
}

// forcedConflicts records forced generations this node refused to adopt, for
// ha.voter.forced.
type forcedConflicts struct {
	mu   sync.Mutex
	byGe map[int64]string
}

func (s *Server) noteForcedConflict(gen int64, detail string) {
	s.forced.mu.Lock()
	defer s.forced.mu.Unlock()
	if s.forced.byGe == nil {
		s.forced.byGe = map[int64]string{}
	}
	s.forced.byGe[gen] = detail
}

// lostVoterStill returns "" once the lost voter l of prev, the generation the
// forced generation gen replaced, is gone for good, and otherwise the line
// ha.voter.forced carries for it. Gone is any of: removed and revoked
// (RemovedHostEvidence); replaced in current, the adopted generation, by an
// entry under l's name with another incarnation; or the name answering as
// another incarnation. The lost voter is the member ENTRY, name and
// incarnation (§10 item 38), so a machine rebuilt under l's name after
// `lv host rm --dead` — a live hosts row again, the old serial gone with the
// tombstone AdmitHost replaced — is a later machine whose empty state.db
// never voted, not the lost voter come back.
//
// `lv host rm --dead` is advised only for a host that is not a live, unfenced
// member: never for one in service that merely did not answer, nor for a
// current voter.
func (s *Server) lostVoterStill(ctx context.Context, gen int64, prev, current *corrosion.VoterConfig, l string) string {
	removed := corrosion.RemovedHostEvidence(ctx, s.db, s.pkiDir, l)
	if removed == nil {
		return ""
	}
	advise := fmt.Sprintf("forced generation %d dropped %s's vote; until %s is removed and revoked "+
		"(`lv host rm --dead %s`) it must not come back as it left: %v", gen, l, l, l, removed)
	lost, ok := prev.Member(l)
	if !ok || lost.Incarnation == "" {
		return advise
	}
	cur, isVoter := current.Member(l)
	if isVoter && cur.Incarnation != lost.Incarnation {
		return ""
	}
	// A fenced row is the lost machine's own, never removed: nothing to ask,
	// and a dead host is not dialled on every tick.
	h, err := corrosion.GetHost(ctx, s.db, l)
	if err != nil || h == nil || h.State == "fenced" {
		return advise
	}
	inc, err := s.remoteIncarnation(ctx, l, prev.Generation)
	switch {
	case err != nil:
		return fmt.Sprintf("forced generation %d dropped %s's vote, and the %s in service now did not say which "+
			"incarnation it is (%v), so it is not yet known to be a new machine rather than the lost voter "+
			"(incarnation %s) come back; check it can be reached", gen, l, l, err, shortInc(lost.Incarnation))
	case inc != lost.Incarnation:
		return ""
	case isVoter:
		return fmt.Sprintf("forced generation %d dropped %s's vote, and %s is a voter again as the same "+
			"incarnation %s, holding the claim state the force gave up: it came back as it left. Do not remove "+
			"it while it votes; see docs/design/recovery-claims.md §4.6", gen, l, l, shortInc(inc))
	default:
		return fmt.Sprintf("forced generation %d dropped %s's vote, and %s answers as the same incarnation %s: "+
			"the lost voter came back as it left. Keep it out of the voter set; rebuild it, or remove it with "+
			"`lv host rm --dead %s`", gen, l, l, shortInc(inc), l)
	}
}

func shortInc(s string) string {
	if len(s) > 8 {
		return s[:8]
	}
	return s
}

// applyVoterConditions raises ha.voter.forced (§4.6 step 5) while any lost
// host of an adopted forced generation is still a member host or not yet
// revoked, and for any forced generation this node refused to adopt.
func (s *Server) applyVoterConditions(ctx context.Context) {
	lines := map[string]string{}
	var hosts []string
	adopted, err := corrosion.AdoptedVoterGeneration(ctx, s.db)
	if err != nil {
		return
	}
	current, err := corrosion.AdoptedVoterConfig(ctx, s.db)
	if err != nil {
		return
	}
	rows, err := corrosion.ListVoterConfigs(ctx, s.db)
	if err != nil {
		return
	}
	for _, r := range rows {
		if r.Generation > adopted || !corrosion.IsForcedChange(r.Change) {
			continue
		}
		prev, _ := corrosion.GetVoterConfig(ctx, s.db, r.Generation-1)
		for _, l := range corrosion.ForcedLost(r.Change) {
			if line := s.lostVoterStill(ctx, r.Generation, prev, current, l); line != "" {
				lines[l] = line
				hosts = append(hosts, l)
			}
		}
	}
	s.forced.mu.Lock()
	for g, d := range s.forced.byGe {
		if g > adopted {
			lines[fmt.Sprintf("refused-%d", g)] = fmt.Sprintf("%s refused forced generation %d: %s", s.hostName, g, d)
		}
	}
	s.forced.mu.Unlock()
	for g, d := range s.db.RefusedForcedVoterConfigs() {
		lines[fmt.Sprintf("refused-%d", g)] = fmt.Sprintf("%s refused forced generation %d: %s", s.hostName, g, d)
	}
	s.applyClusterCondition(ctx, voterEvaluator, condVoterForced, voterConditionSubject, lines, hosts,
		"the voter set was reconfigured by force: ")
}
