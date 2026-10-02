package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/claims"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// Recovery-claim voter RPCs and the proposer's transport
// (docs/design/recovery-claims.md §3.3, §3.5, §3.13).
//
// The voter's rules are corrosion.ClaimPrepare / ClaimAccept; these handlers
// authenticate, convert, and keep each key's last refusal in memory for
// GetRecoveryClaim (diagnostic only, not persisted). A voter answers whatever
// enforcement.recovery_claim says: answering changes nothing unless someone
// relies on the answer, and it keeps promise history unbroken across a staged
// rollout or a stand-down (§5.1).

// claimRuntime is the per-process claim state: the signing identity, the
// verifier, the proposer (whose boot nonce is this process's), the owner-probe
// cache and the last refusal per key.
type claimRuntime struct {
	mu       sync.Mutex
	signer   *corrosion.ClaimSigner
	verifier *corrosion.ClaimVerifier
	loadErr  error
	loadedAt time.Time
	proposer *claims.Proposer

	refusals map[corrosion.ClaimKey][2]string
	// legacyHeld is ha.claim.legacy_held's source (noteLegacyHeld).
	legacyHeld map[corrosion.ClaimKey][2]string // line, destination
	probe      ownerProbeCache
	// observer sees every vote this voter casts (SetClaimVoteObserverForTest).
	observer func(ClaimVote)
}

// ClaimVote is one promise or accept this voter answered, after it was
// committed. It is what a fleet scenario needs to check Paxos's acceptor-side
// invariants across every voter, the local path included, which no network
// interceptor sees (SetClaimVoteObserverForTest).
type ClaimVote struct {
	Voter      string
	Phase      string // "prepare" | "accept"
	Key        corrosion.ClaimKey
	Ballot     corrosion.Ballot
	Generation int64
	// Digest is the accepted value's digest (accept only).
	Digest string
	// AcceptedBallot / AcceptedDigest are what a promise reported as already
	// accepted (prepare only; zero when nothing was).
	AcceptedBallot corrosion.Ballot
	AcceptedDigest string
}

func (s *Server) observeClaimVote(v ClaimVote) {
	c := &s.claims
	c.mu.Lock()
	fn := c.observer
	c.mu.Unlock()
	if fn != nil {
		fn(v)
	}
}

// claimIdentityRetry bounds how often a failed identity load is retried.
const claimIdentityRetry = 10 * time.Second

// claimIdentity loads the host signing key and the cluster CA once. A failure
// is retried after claimIdentityRetry, so a host whose key was repaired starts
// voting without a restart.
func (s *Server) claimIdentity() (*corrosion.ClaimSigner, *corrosion.ClaimVerifier, error) {
	c := &s.claims
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.signer != nil && c.verifier != nil {
		return c.signer, c.verifier, nil
	}
	if c.loadErr != nil && time.Since(c.loadedAt) < claimIdentityRetry {
		return nil, nil, c.loadErr
	}
	c.loadedAt = time.Now()
	signer, err := corrosion.LoadClaimSigner(s.pkiDir, s.hostName)
	if err != nil {
		c.loadErr = fmt.Errorf("load claim signing key: %w", err)
		return nil, nil, c.loadErr
	}
	verifier, err := corrosion.LoadClaimVerifier(s.pkiDir)
	if err != nil {
		c.loadErr = fmt.Errorf("load claim verifier: %w", err)
		return nil, nil, c.loadErr
	}
	c.signer, c.verifier, c.loadErr = signer, verifier, nil
	return signer, verifier, nil
}

// claimProposer is this process's proposer. Its boot nonce is drawn once, so
// every ballot this process ever uses is distinct from every other
// incarnation's (§3.2).
func (s *Server) claimProposer() *claims.Proposer {
	c := &s.claims
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.proposer == nil {
		c.proposer = claims.NewProposer(s.hostName, serverClaimTransport{s})
	}
	return c.proposer
}

func (s *Server) noteClaimRefusal(key corrosion.ClaimKey, reason, detail string) {
	if reason == "" {
		return
	}
	c := &s.claims
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.refusals == nil {
		c.refusals = map[corrosion.ClaimKey][2]string{}
	}
	c.refusals[key] = [2]string{reason, detail}
}

func (s *Server) lastClaimRefusal(key corrosion.ClaimKey) (string, string) {
	c := &s.claims
	c.mu.Lock()
	defer c.mu.Unlock()
	r := c.refusals[key]
	return r[0], r[1]
}

// claimDurable refuses to vote on a database that would not survive a crash
// at the instant of the reply (§3.7).
func (s *Server) claimDurable(ctx context.Context) error {
	lvl, err := synchronousLevel(ctx, s.db)
	if err != nil {
		return status.Errorf(codes.Unavailable, "read PRAGMA synchronous: %v", err)
	}
	if lvl < corrosion.SynchronousFull {
		return status.Errorf(codes.FailedPrecondition,
			"state.db is at synchronous=%d; a voter must not promise below FULL (%d)", lvl, corrosion.SynchronousFull)
	}
	return nil
}

// ── conversions ────────────────────────────────────────────────────────────

func keyFromPB(k *pb.RecoveryClaimKey) corrosion.ClaimKey {
	return corrosion.ClaimKey{TargetKind: k.GetTargetKind(), TargetName: k.GetTargetName(),
		OwnerEpoch: k.GetOwnerEpoch(), Attempt: k.GetAttempt(), Incarnation: k.GetIncarnation()}
}

func keyToPB(k corrosion.ClaimKey) *pb.RecoveryClaimKey {
	return &pb.RecoveryClaimKey{TargetKind: k.TargetKind, TargetName: k.TargetName, OwnerEpoch: k.OwnerEpoch,
		Attempt: k.Attempt, Incarnation: k.Incarnation}
}

func ballotFromPB(b *pb.ClaimBallot) corrosion.Ballot {
	if b == nil {
		return corrosion.Ballot{}
	}
	out := corrosion.Ballot{Round: b.GetRound(), Coordinator: b.GetCoordinator(), Nonce: b.GetBootNonce()}
	if len(out.Nonce) == 0 {
		out.Nonce = nil
	}
	return out
}

func ballotToPB(b corrosion.Ballot) *pb.ClaimBallot {
	if b.IsZero() {
		return nil
	}
	return &pb.ClaimBallot{Round: b.Round, Coordinator: b.Coordinator, BootNonce: b.Nonce}
}

func membersToPB(ms []corrosion.VoterMember) []*pb.ClaimVoterMember {
	out := make([]*pb.ClaimVoterMember, 0, len(ms))
	for _, m := range ms {
		out = append(out, &pb.ClaimVoterMember{Name: m.Name, Incarnation: m.Incarnation})
	}
	return out
}

func membersFromPB(ms []*pb.ClaimVoterMember) []corrosion.VoterMember {
	out := make([]corrosion.VoterMember, 0, len(ms))
	for _, m := range ms {
		out = append(out, corrosion.VoterMember{Name: m.GetName(), Incarnation: m.GetIncarnation()})
	}
	return out
}

func valueFromPB(v *pb.RecoveryClaimValue) *corrosion.ClaimValue {
	if v == nil {
		return nil
	}
	if cfg := v.GetVoterConfig(); cfg != nil {
		return &corrosion.ClaimValue{Config: &corrosion.VoterConfigValue{
			Generation: cfg.GetGeneration(), Members: corrosion.SortMembers(membersFromPB(cfg.GetMembers())),
			Change: cfg.GetChange(), CreatedBy: cfg.GetCreatedBy(), CreatedAt: cfg.GetCreatedAt(),
		}}
	}
	return &corrosion.ClaimValue{
		Proof: &corrosion.ActionProof{
			ID: v.GetId(), Action: v.GetAction(), TargetKind: v.GetTargetKind(), TargetName: v.GetTargetName(),
			DestHost: v.GetDestHost(), Coordinator: v.GetCoordinator(), RelocationToken: v.GetRelocationToken(),
			FenceEpoch: v.GetFenceEpoch(), OwnerEpoch: v.GetOwnerEpoch(), LeaseTerm: v.GetLeaseTerm(), LeaseKey: v.GetLeaseKey(),
		},
		SourceHost: v.GetSourceHost(),
	}
}

func valueToPB(v *corrosion.ClaimValue) *pb.RecoveryClaimValue {
	if v == nil {
		return nil
	}
	if v.Config != nil {
		c := v.Config
		return &pb.RecoveryClaimValue{VoterConfig: &pb.VoterConfigValue{
			Generation: c.Generation, Members: membersToPB(c.Members), Change: c.Change,
			CreatedBy: c.CreatedBy, CreatedAt: c.CreatedAt,
		}}
	}
	out := &pb.RecoveryClaimValue{SourceHost: v.SourceHost}
	if p := v.Proof; p != nil {
		out.Id, out.Action, out.TargetKind, out.TargetName = p.ID, p.Action, p.TargetKind, p.TargetName
		out.DestHost, out.Coordinator, out.RelocationToken = p.DestHost, p.Coordinator, p.RelocationToken
		out.FenceEpoch, out.OwnerEpoch, out.LeaseTerm, out.LeaseKey = p.FenceEpoch, p.OwnerEpoch, p.LeaseTerm, p.LeaseKey
	}
	return out
}

func acceptToPB(a *corrosion.ClaimAccept) *pb.ClaimAccept {
	if a == nil {
		return nil
	}
	return &pb.ClaimAccept{Voter: a.Voter, VoterIncarnation: a.VoterIncarnation, ConfigGeneration: a.ConfigGeneration,
		Ballot: ballotToPB(a.Ballot), ValueDigest: a.ValueDigest, CertPem: a.CertPEM, Signature: a.Signature, Key: keyToPB(a.Key)}
}

func acceptFromPB(a *pb.ClaimAccept) *corrosion.ClaimAccept {
	if a == nil {
		return nil
	}
	return &corrosion.ClaimAccept{Voter: a.GetVoter(), VoterIncarnation: a.GetVoterIncarnation(),
		ConfigGeneration: a.GetConfigGeneration(), Ballot: ballotFromPB(a.GetBallot()), ValueDigest: a.GetValueDigest(),
		CertPEM: a.GetCertPem(), Signature: a.GetSignature(), Key: keyFromPB(a.GetKey())}
}

func prepareToPB(r corrosion.PrepareResult) *pb.PrepareRecoveryClaimResponse {
	out := &pb.PrepareRecoveryClaimResponse{
		Promised: r.Promised, PromisedBallot: ballotToPB(r.PromisedBallot),
		AcceptedBallot: ballotToPB(r.State.Accepted), AcceptedValue: valueToPB(r.State.Value),
		Voter: r.Voter, VoterIncarnation: r.Incarnation, RefusalReason: r.Refusal, RefusalDetail: r.Detail,
	}
	if l := r.Legacy; l != nil {
		out.LegacyAcceptedBallot, out.LegacyAcceptedValue = ballotToPB(l.Accepted), valueToPB(l.Value)
	}
	return out
}

func prepareFromPB(r *pb.PrepareRecoveryClaimResponse, key corrosion.ClaimKey) corrosion.PrepareResult {
	out := corrosion.PrepareResult{
		Promised: r.GetPromised(), PromisedBallot: ballotFromPB(r.GetPromisedBallot()),
		Voter: r.GetVoter(), Incarnation: r.GetVoterIncarnation(), Refusal: r.GetRefusalReason(), Detail: r.GetRefusalDetail(),
	}
	out.State.Key = key
	out.State.Accepted = ballotFromPB(r.GetAcceptedBallot())
	out.State.Value = valueFromPB(r.GetAcceptedValue())
	if out.State.Value != nil {
		out.State.ValueDigest, _ = out.State.Value.Digest()
	}
	if lv := valueFromPB(r.GetLegacyAcceptedValue()); lv != nil && key.Incarnation != "" {
		l := corrosion.ClaimVoterState{Key: key.Legacy(), Accepted: ballotFromPB(r.GetLegacyAcceptedBallot()), Value: lv}
		l.ValueDigest, _ = lv.Digest()
		if !l.Accepted.IsZero() {
			out.Legacy = &l
		}
	}
	return out
}

func acceptResultToPB(r corrosion.AcceptResult) *pb.AcceptRecoveryClaimResponse {
	return &pb.AcceptRecoveryClaimResponse{Accepted: r.Accepted, PromisedBallot: ballotToPB(r.PromisedBallot),
		Accept: acceptToPB(r.Accept), Voter: r.Voter, RefusalReason: r.Refusal, RefusalDetail: r.Detail}
}

func acceptResultFromPB(r *pb.AcceptRecoveryClaimResponse) corrosion.AcceptResult {
	return corrosion.AcceptResult{Accepted: r.GetAccepted(), PromisedBallot: ballotFromPB(r.GetPromisedBallot()),
		Accept: acceptFromPB(r.GetAccept()), Voter: r.GetVoter(), Refusal: r.GetRefusalReason(), Detail: r.GetRefusalDetail()}
}

// ── voter handlers ─────────────────────────────────────────────────────────

// ballotSenderCheck refuses a ballot that does not name its sender. Paxos does
// not need it for safety, but it keeps one peer from spending another's
// ballots, and it makes every refusal attributable.
func ballotSenderCheck(b corrosion.Ballot, sender string) error {
	if b.Coordinator != sender {
		return status.Errorf(codes.PermissionDenied, "ballot names coordinator %q but was sent by %q", b.Coordinator, sender)
	}
	return nil
}

// localPrepare is the voter step, after authentication. A workload key past
// attempt 0 is promised only on supersede evidence this voter checks for
// itself (§3.12); a refusal writes nothing.
func (s *Server) localPrepare(ctx context.Context, key corrosion.ClaimKey, b corrosion.Ballot, gen int64, ev *corrosion.SupersedeEvidence) (corrosion.PrepareResult, error) {
	if err := s.claimDurable(ctx); err != nil {
		return corrosion.PrepareResult{}, err
	}
	// Start the owner probe the round's Accept will want, so it has finished
	// by the time the Accept arrives (§3.5.1, §10 item 36).
	s.primeOwnerProbe(ctx, key)
	if key.IsWorkload() && key.Attempt > 0 {
		// A voter that already holds an accepted value at this key admitted
		// the attempt when it accepted it — or imported it from voters that
		// did (§4.4, §4.6) — so a proposer learning or re-certifying that value
		// needs no fresh evidence. Anything else does.
		st, found, err := s.db.ClaimState(ctx, key)
		if err != nil {
			return corrosion.PrepareResult{}, status.Errorf(codes.Unavailable, "read claim state: %v", err)
		}
		if !found || st.Accepted.IsZero() {
			if reason, detail := s.checkSupersede(ctx, key, ev); reason != "" {
				res := corrosion.PrepareResult{Voter: s.hostName, Refusal: reason, Detail: detail}
				s.noteClaimRefusal(key, reason, detail)
				return res, nil
			}
		}
	}
	res, err := s.db.ClaimPrepare(ctx, key, b, gen)
	if err != nil {
		return corrosion.PrepareResult{}, status.Errorf(codes.Unavailable, "record promise: %v", err)
	}
	s.noteClaimRefusal(key, res.Refusal, res.Detail)
	if res.Promised {
		s.observeClaimVote(ClaimVote{Voter: s.hostName, Phase: "prepare", Key: key, Ballot: b, Generation: gen,
			AcceptedBallot: res.State.Accepted, AcceptedDigest: res.State.ValueDigest})
	}
	return res, nil
}

func (s *Server) localAccept(ctx context.Context, key corrosion.ClaimKey, b corrosion.Ballot, v corrosion.ClaimValue, gen int64) (corrosion.AcceptResult, error) {
	if err := s.claimDurable(ctx); err != nil {
		return corrosion.AcceptResult{}, err
	}
	signer, _, err := s.claimIdentity()
	if err != nil {
		return corrosion.AcceptResult{}, status.Errorf(codes.FailedPrecondition, "%v", err)
	}
	if key.IsWorkload() && key.Attempt > 0 {
		// The supersede evidence is checked when this voter promises; an Accept
		// at attempt > 0 is taken only by a voter that has promised at the key,
		// and so has checked it.
		st, found, err := s.db.ClaimState(ctx, key)
		if err != nil {
			return corrosion.AcceptResult{}, status.Errorf(codes.Unavailable, "read claim state: %v", err)
		}
		if !found || st.Promised.IsZero() {
			res := corrosion.AcceptResult{Voter: s.hostName, Refusal: corrosion.RefusalSupersedeUnproven,
				Detail: fmt.Sprintf("%s has not promised at %s, so it has not checked the supersede evidence", s.hostName, key)}
			s.noteClaimRefusal(key, res.Refusal, res.Detail)
			return res, nil
		}
	}
	s.rememberClaimSource(key, v.SourceHost)
	res, err := s.db.ClaimAccept(ctx, key, b, v, gen, signer, s.probeOwner)
	if err != nil {
		return corrosion.AcceptResult{}, status.Errorf(codes.Unavailable, "record accept: %v", err)
	}
	s.noteClaimRefusal(key, res.Refusal, res.Detail)
	if res.Accepted && res.Accept != nil {
		s.observeClaimVote(ClaimVote{Voter: s.hostName, Phase: "accept", Key: key, Ballot: b, Generation: gen,
			Digest: res.Accept.ValueDigest})
	}
	return res, nil
}

// PrepareRecoveryClaim is phase 1 at this voter.
func (s *Server) PrepareRecoveryClaim(ctx context.Context, req *pb.PrepareRecoveryClaimRequest) (*pb.PrepareRecoveryClaimResponse, error) {
	if err := s.requirePeerCert(ctx); err != nil {
		return nil, err
	}
	if req.GetKey() == nil || req.GetBallot() == nil {
		return nil, status.Error(codes.InvalidArgument, "key and ballot are required")
	}
	b := ballotFromPB(req.GetBallot())
	if err := ballotSenderCheck(b, callerMTLSCommonName(ctx)); err != nil {
		return nil, err
	}
	res, err := s.localPrepare(ctx, keyFromPB(req.GetKey()), b, req.GetConfigGeneration(), supersedeFromPB(req.GetSupersede()))
	if err != nil {
		return nil, err
	}
	return prepareToPB(res), nil
}

// AcceptRecoveryClaim is phase 2 at this voter.
func (s *Server) AcceptRecoveryClaim(ctx context.Context, req *pb.AcceptRecoveryClaimRequest) (*pb.AcceptRecoveryClaimResponse, error) {
	if err := s.requirePeerCert(ctx); err != nil {
		return nil, err
	}
	if req.GetKey() == nil || req.GetBallot() == nil || req.GetValue() == nil {
		return nil, status.Error(codes.InvalidArgument, "key, ballot and value are required")
	}
	b := ballotFromPB(req.GetBallot())
	if err := ballotSenderCheck(b, callerMTLSCommonName(ctx)); err != nil {
		return nil, err
	}
	res, err := s.localAccept(ctx, keyFromPB(req.GetKey()), b, *valueFromPB(req.GetValue()), req.GetConfigGeneration())
	if err != nil {
		return nil, err
	}
	return acceptResultToPB(res), nil
}

// GetRecoveryClaim reports this voter's state for one key. Read-only; it
// answers even while the voter abstains, so an incarnation mismatch is
// visible (§3.11).
func (s *Server) GetRecoveryClaim(ctx context.Context, req *pb.GetRecoveryClaimRequest) (*pb.GetRecoveryClaimResponse, error) {
	if err := s.requirePeerOrRole(ctx, "operator"); err != nil {
		return nil, err
	}
	return s.localGetRecoveryClaim(ctx, keyFromPB(req.GetKey()))
}

func (s *Server) localGetRecoveryClaim(ctx context.Context, key corrosion.ClaimKey) (*pb.GetRecoveryClaimResponse, error) {
	st, _, err := s.db.ClaimState(ctx, key)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "read claim state: %v", err)
	}
	inc, err := s.db.VoterIncarnation(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "read voter incarnation: %v", err)
	}
	adopted, err := corrosion.AdoptedVoterGeneration(ctx, s.db)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "read adopted generation: %v", err)
	}
	reason, detail := s.lastClaimRefusal(key)
	return &pb.GetRecoveryClaimResponse{
		State: &pb.PrepareRecoveryClaimResponse{
			PromisedBallot: ballotToPB(st.Promised), AcceptedBallot: ballotToPB(st.Accepted),
			AcceptedValue: valueToPB(st.Value), Voter: s.hostName, VoterIncarnation: inc,
		},
		Accept:            acceptToPB(st.Accept),
		LastRefusalReason: reason, LastRefusalDetail: detail,
		AdoptedGeneration: adopted,
	}, nil
}

// ListRecoveryClaims streams this voter's accepted workload states for an
// importer (§4.4 rule 2). The header says whether the importer's generation is
// frozen here; an importer counts only frozen sources.
func (s *Server) ListRecoveryClaims(req *pb.ListRecoveryClaimsRequest, stream grpc.ServerStreamingServer[pb.RecoveryClaimState]) error {
	ctx := stream.Context()
	if err := s.requirePeerCert(ctx); err != nil {
		return err
	}
	src, err := s.db.ClaimStatesForImport(ctx, req.GetConfigGeneration())
	if err != nil {
		return status.Errorf(codes.Unavailable, "read claim states: %v", err)
	}
	if err := stream.Send(&pb.RecoveryClaimState{Header: true, Voter: src.Voter, Frozen: src.Frozen,
		AdoptedGeneration: src.Adopted}); err != nil {
		return err
	}
	for _, st := range src.States {
		if err := stream.Send(&pb.RecoveryClaimState{
			Key: keyToPB(st.Key), Promised: ballotToPB(st.Promised), Accepted: ballotToPB(st.Accepted),
			Value: valueToPB(st.Value), ValueDigest: st.ValueDigest,
		}); err != nil {
			return err
		}
	}
	return nil
}

// ── the proposer's transport ───────────────────────────────────────────────

// serverClaimTransport reaches each voter: this node's own voter directly,
// peers over the claim RPCs with this node's host certificate.
type serverClaimTransport struct{ s *Server }

func (t serverClaimTransport) Prepare(ctx context.Context, voter string, key corrosion.ClaimKey, b corrosion.Ballot, gen int64, ev *corrosion.SupersedeEvidence) (corrosion.PrepareResult, error) {
	if voter == t.s.hostName {
		return t.s.localPrepare(ctx, key, b, gen, ev)
	}
	cl, closer, err := t.s.dialPeer(ctx, voter)
	if err != nil {
		return corrosion.PrepareResult{}, err
	}
	defer closer()
	resp, err := cl.PrepareRecoveryClaim(ctx, &pb.PrepareRecoveryClaimRequest{
		Key: keyToPB(key), Ballot: ballotToPB(b), ConfigGeneration: gen, Supersede: supersedeToPB(ev)})
	if err != nil {
		return corrosion.PrepareResult{}, err
	}
	if resp.GetVoter() != voter {
		return corrosion.PrepareResult{}, fmt.Errorf("%s answered as %q", voter, resp.GetVoter())
	}
	return prepareFromPB(resp, key), nil
}

func (t serverClaimTransport) Accept(ctx context.Context, voter string, key corrosion.ClaimKey, b corrosion.Ballot, v corrosion.ClaimValue, gen int64) (corrosion.AcceptResult, error) {
	if voter == t.s.hostName {
		return t.s.localAccept(ctx, key, b, v, gen)
	}
	cl, closer, err := t.s.dialPeer(ctx, voter)
	if err != nil {
		return corrosion.AcceptResult{}, err
	}
	defer closer()
	resp, err := cl.AcceptRecoveryClaim(ctx, &pb.AcceptRecoveryClaimRequest{
		Key: keyToPB(key), Ballot: ballotToPB(b), Value: valueToPB(&v), ConfigGeneration: gen})
	if err != nil {
		return corrosion.AcceptResult{}, err
	}
	return acceptResultFromPB(resp), nil
}

// fetchImportSource pulls one voter's states for an import.
func (s *Server) fetchImportSource(ctx context.Context, voter string, gen int64) (corrosion.ClaimImportSource, error) {
	if voter == s.hostName {
		return s.db.ClaimStatesForImport(ctx, gen)
	}
	cl, closer, err := s.dialPeer(ctx, voter)
	if err != nil {
		return corrosion.ClaimImportSource{}, err
	}
	defer closer()
	stream, err := cl.ListRecoveryClaims(ctx, &pb.ListRecoveryClaimsRequest{ConfigGeneration: gen})
	if err != nil {
		return corrosion.ClaimImportSource{}, err
	}
	var out corrosion.ClaimImportSource
	first := true
	for {
		m, err := stream.Recv()
		if err != nil {
			if !first && errors.Is(err, io.EOF) {
				return out, nil
			}
			return out, err
		}
		if first {
			if !m.GetHeader() || m.GetVoter() != voter {
				return out, fmt.Errorf("%s: import stream did not start with its header", voter)
			}
			out.Voter, out.Frozen, out.Adopted = m.GetVoter(), m.GetFrozen(), m.GetAdoptedGeneration()
			first = false
			continue
		}
		v := valueFromPB(m.GetValue())
		st := corrosion.ClaimVoterState{Key: keyFromPB(m.GetKey()), Promised: ballotFromPB(m.GetPromised()),
			Accepted: ballotFromPB(m.GetAccepted()), Value: v, ValueDigest: m.GetValueDigest()}
		out.States = append(out.States, st)
	}
}

// DecideRecoveryClaim drives one workload claim under this node's adopted
// voter generation: every member is asked, a majority decides, and the
// returned outcome carries the certificate (§3.13 steps 3–5).
//
// Under recovery_claim_v1 (colonelpanik/litevirt#250) the failover
// coordinator calls it at each ownership-transfer mint site — after the fence
// and before any proof is written — and writes the decided value's proof with
// the certificate; the server calls it for an automated promote once the
// replica's host is known (claimPromote).
//
// ev is the supersede evidence a key past attempt 0 needs (§3.12), nil at
// attempt 0.
func (s *Server) DecideRecoveryClaim(ctx context.Context, key corrosion.ClaimKey, proposal corrosion.ClaimValue, startRound uint64, ev *corrosion.SupersedeEvidence) (claims.Outcome, error) {
	if !key.IsWorkload() {
		return claims.Outcome{}, fmt.Errorf("%s is not a workload key", key)
	}
	cfg, err := corrosion.AdoptedVoterConfig(ctx, s.db)
	if err != nil {
		return claims.Outcome{}, err
	}
	if !cfg.Explicit() {
		return claims.Outcome{}, fmt.Errorf("no voter generation with members is adopted on %s", s.hostName)
	}
	names := cfg.Names()
	q := corrosion.MajorityOf(len(names))
	spec := claims.Spec{
		Key: key, Generation: cfg.Generation, Voters: names, PrepareQuorum: q,
		Electorate: func(corrosion.ClaimValue) ([]string, int) { return names, q },
		Propose:    func(map[string]corrosion.PrepareResult) (corrosion.ClaimValue, error) { return proposal, nil },
		StartRound: startRound,
		// A coordinator re-proposing the value the voters refused because the
		// owner was reachable retries at the same round (§3.13 step 6); the
		// proposer's per-round binding refuses a different value there.
		ReuseRound: true,
		Supersede:  ev,
	}
	if key.Incarnation != "" {
		spec.AdoptLegacy = func(v corrosion.ClaimValue) bool {
			excluded, why := s.legacyValueExcluded(ctx, key, v)
			if !excluded {
				s.noteLegacyHeld(key, v, why)
			}
			return !excluded
		}
	}
	out, err := s.claimProposer().Decide(ctx, spec)
	if err == nil {
		s.clearLegacyHeld(key)
	}
	return out, err
}

// noteLegacyHeld records that key's claim re-proposed a legacy value it could
// not exclude (legacyValueExcluded), for ha.claim.legacy_held. Cleared when the
// key decides.
func (s *Server) noteLegacyHeld(key corrosion.ClaimKey, v corrosion.ClaimValue, why string) {
	c := &s.claims
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.legacyHeld == nil {
		c.legacyHeld = map[corrosion.ClaimKey][2]string{}
	}
	c.legacyHeld[key] = [2]string{fmt.Sprintf("%s/%s: its claim %s carries a decision made before claim_incarnation_v1 latched "+
		"(proof %s, %s to %s, source %s) that cannot be shown to be another incarnation's (%s). If %s is gone for good, "+
		"`lv host rm --dead %s` releases it; while %s answers, it decides.", key.TargetKind, key.TargetName, key,
		v.Proof.ID, v.Proof.Action, v.Proof.DestHost, v.SourceHost, why, v.Proof.DestHost, v.Proof.DestHost, v.Proof.DestHost),
		v.Proof.DestHost}
}

func (s *Server) clearLegacyHeld(key corrosion.ClaimKey) {
	c := &s.claims
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.legacyHeld, key)
}

// legacyHeldLines is ha.claim.legacy_held's text, one line per workload, and
// the destinations of the decisions that hold them.
func (s *Server) legacyHeldLines() (map[string]string, []string) {
	c := &s.claims
	c.mu.Lock()
	defer c.mu.Unlock()
	out := map[string]string{}
	var dests []string
	for k, held := range c.legacyHeld {
		out[k.TargetKind+"/"+k.TargetName] = held[0]
		dests = append(dests, held[1])
	}
	return out, dests
}

// IncarnationScopedClaims reports whether workload claims are keyed by
// incarnation here: claim_incarnation_v1 has latched (§10 item 37). Before
// then every coordinator claims the legacy key, so a recovery is never
// claimed under two keys by two coordinators that disagree about the format.
func (s *Server) IncarnationScopedClaims(ctx context.Context) bool {
	return s.gate != nil && s.gate.Enforced(ctx, capabilities.ClaimIncarnationV1)
}

// ClaimKeyFor is the key a recovery of the workload row whose created_at is
// createdAt, at owner epoch epoch, is claimed under on this node: scoped to
// the row's incarnation (corrosion.IncarnationOf, so an unstamped row is
// scoped too) once IncarnationScopedClaims holds, the legacy key before.
func (s *Server) ClaimKeyFor(ctx context.Context, kind, name string, epoch int64, createdAt string) corrosion.ClaimKey {
	key := corrosion.ClaimKey{TargetKind: kind, TargetName: name, OwnerEpoch: epoch}
	if s.IncarnationScopedClaims(ctx) {
		key.Incarnation = corrosion.IncarnationOf(createdAt)
	}
	return key
}

// claimExclusionTimeout bounds the bridge's request for a destination's
// foreign abandonment (legacyValueExcluded).
const claimExclusionTimeout = 2 * time.Second

// legacyValueExcluded is the bridge's test for a value a voter accepted at the
// LEGACY form of an incarnation-scoped key (claims.Spec.AdoptLegacy, §10
// item 37): is it PROVEN that this value will never execute and is not this
// incarnation's decision? Only then may the proposer decide a fresh value
// beside it. Proof comes from the value's destination, the one host that can
// execute it:
//
//   - it signs a foreign abandonment (corrosion.AbandonForeignProof), shown
//     from its own database: it ran or failed the proof while this
//     incarnation stayed at the epoch, or the proof never started and this
//     incarnation is not pending on it; or
//   - it has been removed for good (corrosion.RemovedHostEvidence): fenced
//     proof-grade, no live hosts row, revoked, so it can execute nothing.
//
// Anything short of that — the destination unreachable, refusing, or unable
// to show it — and the value is ADOPTED, as the legacy key itself would have
// done: ambiguity costs liveness, never a second decision. Wall clocks play no
// part. A value adopted this way that its voters then refuse is reported by
// ha.claim.legacy_held, naming the workload, the decision and the way out.
func (s *Server) legacyValueExcluded(ctx context.Context, key corrosion.ClaimKey, v corrosion.ClaimValue) (bool, string) {
	if v.Proof == nil || v.Proof.ID == "" || v.Proof.DestHost == "" {
		return false, "the legacy value names no proof or destination"
	}
	dest := v.Proof.DestHost
	if err := corrosion.RemovedHostEvidence(ctx, s.db, s.pkiDir, dest); err == nil {
		return true, ""
	}
	// Bounded: it runs inside the claim's phase 1, whose deadline is the
	// whole claim's.
	ctx, cancel := context.WithTimeout(ctx, claimExclusionTimeout)
	defer cancel()
	enc, err := s.requestAbandonment(ctx, dest, key, v.Proof.ID,
		"a decision at the legacy key that is not "+key.String()+"'s (claim_incarnation_v1 bridge)", true)
	if err != nil {
		return false, fmt.Sprintf("%s did not show proof %s is not this incarnation's: %v", dest, v.Proof.ID, err)
	}
	ab, err := corrosion.DecodeClaimAbandonment(enc)
	if err != nil {
		return false, err.Error()
	}
	_, verifier, err := s.claimIdentity()
	if err != nil {
		return false, err.Error()
	}
	if err := verifier.VerifyAbandonment(ab, dest, v.Proof.ID, key); err != nil {
		return false, fmt.Sprintf("%s's exclusion of proof %s does not verify: %v", dest, v.Proof.ID, err)
	}
	return true, ""
}
