package grpcapi

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// `lv cluster claim <kind>/<name>` and ha.voter.unavailable
// (docs/design/recovery-claims.md §4.3, §5.4).

// maxInspectAttempts bounds how many attempts of one key a diagnosis walks.
const maxInspectAttempts = 8

// InspectRecoveryClaim asks every member of the adopted voter generation for
// its recorded state for a workload's claim keys — promised and accepted
// ballot, value digest, destination, source, incarnation, last refusal — and
// reports each attempt that any voter has state for. It is the one place a
// stuck claim can be diagnosed (§5.4). Read-only.
func (s *Server) InspectRecoveryClaim(ctx context.Context, req *pb.InspectRecoveryClaimRequest) (*pb.InspectRecoveryClaimResponse, error) {
	if err := s.requirePeerOrRole(ctx, "viewer"); err != nil {
		return nil, err
	}
	kind, name := strings.TrimSpace(req.GetKind()), strings.TrimSpace(req.GetName())
	if kind != corrosion.ClaimKindVM && kind != corrosion.ClaimKindContainer {
		return nil, status.Errorf(codes.InvalidArgument, "a claim is for a vm or a container, not %q", kind)
	}
	if name == "" {
		return nil, status.Error(codes.InvalidArgument, "name the workload: <kind>/<name>")
	}
	epoch := req.GetOwnerEpoch()
	if !req.GetEpochSet() {
		e, err := s.currentOwnerEpoch(ctx, kind, name)
		if err != nil {
			return nil, err
		}
		epoch = e
	}
	// The live row's incarnation, which the key carries once
	// claim_incarnation_v1 has latched (§10 item 37). A name with no live row
	// is inspected at its legacy key.
	incarnation, live, err := corrosion.WorkloadIncarnation(ctx, s.db, kind, name)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "read the incarnation of %s/%s: %v", kind, name, err)
	}
	base := corrosion.ClaimKey{TargetKind: kind, TargetName: name, OwnerEpoch: epoch}
	if live {
		base = s.ClaimKeyFor(ctx, kind, name, epoch, incarnation)
	}
	cfg, err := corrosion.AdoptedVoterConfig(ctx, s.db)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "%v", err)
	}
	if !cfg.Explicit() {
		return nil, status.Error(codes.FailedPrecondition, "no voter generation with members is adopted; nothing is claimed")
	}
	resp := &pb.InspectRecoveryClaimResponse{Generation: cfg.Generation}
	for attempt := int64(0); attempt < maxInspectAttempts; attempt++ {
		key := base
		key.Attempt = attempt
		view := s.inspectKey(ctx, cfg, key)
		held := false
		for _, v := range view.GetVoters() {
			if v.GetPromised() != "" || v.GetLastRefusal() != "" {
				held = true
			}
		}
		if !held && attempt > 0 {
			break
		}
		resp.Attempts = append(resp.Attempts, view)
		if !held {
			break
		}
	}
	if base.Incarnation != "" {
		// The legacy key of the same epoch, where it holds anything: a claim
		// made before claim_incarnation_v1 latched, or a previous
		// incarnation's decision the scoped key no longer meets. Shown so an
		// operator can tell the two keys apart (§10 item 37).
		for attempt := int64(0); attempt < maxInspectAttempts; attempt++ {
			key := base.Legacy()
			key.Attempt = attempt
			view := s.inspectKey(ctx, cfg, key)
			held := false
			for _, v := range view.GetVoters() {
				if v.GetPromised() != "" {
					held = true
				}
			}
			if !held {
				break
			}
			resp.Attempts = append(resp.Attempts, view)
		}
	}
	resp.Detail = fmt.Sprintf("%s/%s at owner epoch %d, voter generation %d (%s)", kind, name, epoch, cfg.Generation,
		strings.Join(cfg.Names(), ", "))
	if base.Incarnation != "" {
		resp.Detail = fmt.Sprintf("%s/%s, incarnation %s, at owner epoch %d, voter generation %d (%s)", kind, name,
			base.Incarnation, epoch, cfg.Generation, strings.Join(cfg.Names(), ", "))
	}
	return resp, nil
}

// currentOwnerEpoch is the generation a recovery of the workload is decided
// under now: the row's owner epoch.
func (s *Server) currentOwnerEpoch(ctx context.Context, kind, name string) (int64, error) {
	switch kind {
	case corrosion.ClaimKindVM:
		vm, err := corrosion.GetVM(ctx, s.db, name)
		if err != nil || vm == nil {
			return 0, status.Errorf(codes.NotFound, "vm %q not found (pass --epoch to inspect a past generation)", name)
		}
		return vm.OwnerEpoch, nil
	default:
		rows, err := s.db.Query(ctx, `SELECT owner_epoch FROM containers WHERE name = ? AND deleted_at IS NULL LIMIT 1`, name)
		if err != nil || len(rows) == 0 {
			return 0, status.Errorf(codes.NotFound, "container %q not found (pass --epoch to inspect a past generation)", name)
		}
		return rows[0].Int64("owner_epoch"), nil
	}
}

// inspectKey collects every member's view of one key, in parallel.
func (s *Server) inspectKey(ctx context.Context, cfg *corrosion.VoterConfig, key corrosion.ClaimKey) *pb.RecoveryClaimAttemptView {
	out := &pb.RecoveryClaimAttemptView{Key: keyToPB(key)}
	views := make([]*pb.RecoveryClaimVoterView, len(cfg.Members))
	var wg sync.WaitGroup
	for i, m := range cfg.Members {
		wg.Add(1)
		go func(i int, m corrosion.VoterMember) {
			defer wg.Done()
			views[i] = s.inspectVoter(ctx, m, key)
		}(i, m)
	}
	wg.Wait()
	out.Voters = views
	count := map[string]int{}
	dest := map[string]string{}
	for _, v := range views {
		if v.GetAccepted() != "" && v.GetValueDigest() != "" {
			count[v.GetValueDigest()]++
			dest[v.GetValueDigest()] = v.GetDestHost()
		}
	}
	for d, n := range count {
		if n >= corrosion.MajorityOf(len(cfg.Members)) {
			out.DecidedDigest, out.DecidedDest = d, dest[d]
		}
	}
	return out
}

func (s *Server) inspectVoter(ctx context.Context, m corrosion.VoterMember, key corrosion.ClaimKey) *pb.RecoveryClaimVoterView {
	v := &pb.RecoveryClaimVoterView{Voter: m.Name}
	var resp *pb.GetRecoveryClaimResponse
	var err error
	if m.Name == s.hostName {
		resp, err = s.localGetRecoveryClaim(ctx, key)
	} else {
		cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		var cl pb.LiteVirtClient
		var closer func()
		cl, closer, err = s.dialPeer(cctx, m.Name)
		if err == nil {
			defer closer()
			resp, err = cl.GetRecoveryClaim(cctx, &pb.GetRecoveryClaimRequest{Key: keyToPB(key)})
		}
	}
	if err != nil {
		v.Error = err.Error()
		return v
	}
	v.Reachable = true
	st := resp.GetState()
	v.Incarnation = st.GetVoterIncarnation()
	v.IncarnationOk = v.Incarnation == m.Incarnation
	v.AdoptedGeneration = resp.GetAdoptedGeneration()
	if b := ballotFromPB(st.GetPromisedBallot()); !b.IsZero() {
		v.Promised = b.String()
	}
	if b := ballotFromPB(st.GetAcceptedBallot()); !b.IsZero() {
		v.Accepted = b.String()
	}
	if val := valueFromPB(st.GetAcceptedValue()); val != nil && val.Proof != nil {
		v.ValueDigest, _ = val.Digest()
		v.ProofId, v.DestHost, v.SourceHost = val.Proof.ID, val.Proof.DestHost, val.SourceHost
	}
	v.LastRefusal, v.LastRefusalDetail = resp.GetLastRefusalReason(), resp.GetLastRefusalDetail()
	return v
}

// ── ha.voter.unavailable (§4.3) ────────────────────────────────────────────

const condVoterUnavailable = "ha.voter.unavailable"

// voterUnavailableTTL is how long a member's abstention check is reused: it
// is an RPC per member, run from the lease holder's tick.
const voterUnavailableTTL = 30 * time.Second

type abstainCache struct {
	mu   sync.Mutex
	at   map[string]time.Time
	line map[string]string
}

// voterUnavailable lists every member of the adopted generation that is
// fenced, offline, in maintenance, removed or abstaining, with the command
// that removes it. There is no automatic shrink, by decision (§4.3): a member
// that is down still counts in every denominator, so each one here is fault
// tolerance the operator does not have.
func (s *Server) voterUnavailable(ctx context.Context) (map[string]string, error) {
	cfg, err := corrosion.AdoptedVoterConfig(ctx, s.db)
	if err != nil || !cfg.Explicit() {
		return nil, err
	}
	out := map[string]string{}
	for _, m := range cfg.Members {
		h, err := corrosion.GetHost(ctx, s.db, m.Name)
		if err != nil {
			return nil, err
		}
		switch {
		case h == nil:
			out[m.Name] = fmt.Sprintf("%s is removed but still a member of voter generation %d: `lv cluster voter rm %s`.",
				m.Name, cfg.Generation, m.Name)
		case !health.VotingEligible(h.State):
			out[m.Name] = fmt.Sprintf("%s is %s and still a member of voter generation %d, so every quorum counts it: "+
				"if it is gone for good `lv host rm --dead %s`, otherwise `lv cluster voter rm %s` to stop it voting.",
				m.Name, h.State, cfg.Generation, m.Name, m.Name)
		default:
			if line := s.abstention(ctx, cfg, m); line != "" {
				out[m.Name] = line
			}
		}
	}
	return out, nil
}

// abstention reports a member whose own incarnation no longer matches its
// entry (§3.11), cached for voterUnavailableTTL.
func (s *Server) abstention(ctx context.Context, cfg *corrosion.VoterConfig, m corrosion.VoterMember) string {
	c := &s.abstain
	c.mu.Lock()
	if c.at == nil {
		c.at, c.line = map[string]time.Time{}, map[string]string{}
	}
	if t, ok := c.at[m.Name]; ok && time.Since(t) < voterUnavailableTTL {
		line := c.line[m.Name]
		c.mu.Unlock()
		return line
	}
	c.mu.Unlock()
	cctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	line := ""
	if inc, err := s.remoteIncarnation(cctx, m.Name, cfg.Generation); err == nil && inc != m.Incarnation {
		line = fmt.Sprintf("%s abstains: its claim state is a different incarnation from the one it was admitted with "+
			"(re-imaged or reseeded?): `lv cluster voter rm %s` then `lv cluster voter add %s`.", m.Name, m.Name, m.Name)
	}
	c.mu.Lock()
	c.at[m.Name], c.line[m.Name] = time.Now(), line
	c.mu.Unlock()
	return line
}

func (s *Server) applyVoterUnavailable(ctx context.Context) {
	lines, err := s.voterUnavailable(ctx)
	if err != nil {
		return
	}
	var hosts []string
	for h := range lines {
		hosts = append(hosts, h)
	}
	s.applyClusterCondition(ctx, voterEvaluator, condVoterUnavailable, voterConditionSubject, lines, hosts,
		"voters the cluster counts but that cannot vote: ")
}
