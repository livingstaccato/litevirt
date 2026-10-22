package grpcapi

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fencessh"
)

// fenceSSHPeerTimeout bounds one peer's answer to a fanned-out status read.
const fenceSSHPeerTimeout = 10 * time.Second

// fenceSSHReevaluatePeerTimeout bounds one peer's answer to a fanned-out
// re-evaluation: its agent's own bound, and the status read after it.
const fenceSSHReevaluatePeerTimeout = fencessh.ReevaluateTimeout + fenceSSHPeerTimeout

// GetFenceSSHStatus is this host's view of managed fence SSH and, with
// fan_out, every other live host's own view (`lv doctor fence`). A diagnostic:
// nothing decides on it.
//
// With reevaluate (admin: each answering host logs in to its own sshd), each
// host answers only after one fresh sync of its agent that started after the
// request reached it (fencessh.Agent.Reevaluate), and sets
// evaluated_for_request when that sync proves its row. `lv host
// install-fence-ssh` confirms a host in seconds on it; an older host leaves it
// false, and the CLI then waits out fencessh.RowFreshAfter instead.
func (s *Server) GetFenceSSHStatus(ctx context.Context, req *pb.FenceSSHStatusRequest) (*pb.FenceSSHStatus, error) {
	if err := RequireRole(ctx, "viewer"); err != nil {
		return nil, err
	}
	reevaluate := req.GetReevaluate()
	if reevaluate {
		if err := RequireRole(ctx, "admin"); err != nil {
			return nil, err
		}
	}
	var hosts []corrosion.HostRecord
	if req.GetFanOut() {
		var err error
		if hosts, err = corrosion.ListHosts(ctx, s.db); err != nil {
			return nil, status.Errorf(codes.Unavailable, "list hosts: %v", err)
		}
	}
	out := &pb.FenceSSHStatus{GeneratedAt: time.Now().UTC().Format(time.RFC3339)}
	var mu sync.Mutex
	var wg sync.WaitGroup
	add := func(n *pb.FenceSSHNode) {
		mu.Lock()
		out.Nodes = append(out.Nodes, n)
		mu.Unlock()
	}
	// This host re-evaluates alongside its peers, not before them.
	wg.Add(1)
	go func() {
		defer wg.Done()
		if reevaluate {
			add(s.reevaluatedOwnFenceSSHNode(ctx))
		} else {
			add(s.ownFenceSSHNode(ctx))
		}
	}()
	for _, h := range hosts {
		if h.Name == s.hostName {
			continue
		}
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			add(s.peerFenceSSHNode(ctx, name, reevaluate))
		}(h.Name)
	}
	wg.Wait()
	sort.Slice(out.Nodes, func(i, j int) bool { return out.Nodes[i].Host < out.Nodes[j].Host })
	return out, nil
}

// reevaluatedOwnFenceSSHNode is this host's own view, read AFTER one fresh
// sync for this request (fencessh.Agent.Reevaluate). The order is the proof:
// evaluated_for_request vouches for the row returned beside it only because
// that row is read once the fresh evaluation has published it. Read first, a
// stale accepting row would come back marked proved. So the read lives here,
// after the evaluation, and nowhere else sets the two fields.
func (s *Server) reevaluatedOwnFenceSSHNode(ctx context.Context) *pb.FenceSSHNode {
	evaluated, why := false, "no fence ssh agent on this host"
	if s.fenceSSH != nil {
		if evaluated, why = s.fenceSSH.Reevaluate(ctx); !evaluated {
			slog.Info("fence ssh: a requested re-evaluation proved nothing", "why", why)
		}
	}
	n := s.ownFenceSSHNode(ctx)
	// Always set when asked, so the CLI can tell this build, whose
	// re-evaluation may prove nothing, from one that predates it.
	n.EvaluatedForRequest, n.ReevaluateOutcome = fenceSSHReevaluateOutcome(evaluated, why, n.GetError())
	return n
}

// ownFenceSSHNode is this host's own view.
func (s *Server) ownFenceSSHNode(ctx context.Context) *pb.FenceSSHNode {
	n := &pb.FenceSSHNode{Host: s.hostName, Reachable: true}
	if s.fenceSSH == nil {
		n.Error = "no fence ssh agent on this host"
		return n
	}
	n.Mode, n.LastError = s.fenceSSH.Mode(), s.fenceSSH.LastError()
	peers, err := s.fenceSSH.Status(ctx)
	if err != nil {
		n.Error = err.Error()
		return n
	}
	for _, p := range peers {
		pp := &pb.FenceSSHPeer{
			Host: p.Host, Row: p.Row, RowDetail: p.RowDetail, Accepting: p.Accepting, EverAccepting: p.EverAccepting,
			Generation: p.Generation, CertSerial: p.CertSerial, Address: p.Address, Path: p.Path, PathDetail: p.PathDetail,
		}
		if p.Probe != nil {
			pp.Probed, pp.ProbeOk, pp.ProbeDetail, pp.ProbedAt = true, p.Probe.OK, p.Probe.Detail, p.Probe.ProbedAt()
		}
		n.Peers = append(n.Peers, pp)
	}
	return n
}

// fenceSSHReevaluateOutcome is this host's evaluated_for_request and
// reevaluate_outcome: "proved" only for a proven evaluation and a status
// that reads, else a reason that is never empty.
func fenceSSHReevaluateOutcome(evaluated bool, why, statusErr string) (bool, string) {
	switch {
	case evaluated && statusErr == "":
		return true, "proved"
	case evaluated:
		return false, "its status could not be read: " + statusErr
	case why == "":
		return false, "its re-evaluation proved nothing"
	}
	return false, why
}

// peerFenceSSHNode asks host for its own view, re-evaluated when reevaluate
// says so. Only host's own answer sets evaluated_for_request: an older host
// does not know the field and leaves it false.
func (s *Server) peerFenceSSHNode(ctx context.Context, host string, reevaluate bool) *pb.FenceSSHNode {
	timeout := fenceSSHPeerTimeout
	if reevaluate {
		timeout = fenceSSHReevaluatePeerTimeout
	}
	pctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	c, closeConn, err := s.dialPeer(pctx, host)
	if err != nil {
		return &pb.FenceSSHNode{Host: host, Error: fmt.Sprintf("dial: %v", err)}
	}
	defer closeConn()
	resp, err := c.GetFenceSSHStatus(pctx, &pb.FenceSSHStatusRequest{Reevaluate: reevaluate})
	if err != nil {
		if status.Code(err) == codes.Unimplemented {
			return &pb.FenceSSHNode{Host: host, Reachable: true, Error: "its build predates managed fence ssh"}
		}
		return &pb.FenceSSHNode{Host: host, Error: err.Error()}
	}
	for _, n := range resp.GetNodes() {
		if n.GetHost() == host {
			return n
		}
	}
	return &pb.FenceSSHNode{Host: host, Reachable: true, Error: "it answered for another host"}
}

// The health condition a host raises for itself while its fence ssh row says
// its sshd accepted the managed fence key once and does not now.
const (
	fenceSSHEvaluator        = "fence_ssh"
	condFenceSSHNotAccepting = "fence_ssh_not_accepting"
)

// FenceSSHAccepting is the fence ssh agent's report of what this host just
// published (fencessh.Config.OnAccepting). While the row says it accepted the
// managed key before and does not now, peers still fence it over the managed
// key, but its sshd may refuse that login, so it raises
// fence_ssh_not_accepting (warning) for itself, and resolves it once it
// accepts again.
func (s *Server) FenceSSHAccepting(ctx context.Context, accepting, everAccepting bool, detail string) {
	raised := everAccepting && !accepting
	msg := ""
	if raised {
		msg = s.hostName + "'s sshd accepted the managed fence key before and does not now (" + detail +
			"); a peer's fence of it may fail. Run `lv host install-fence-ssh --host " + s.hostName +
			"` and check `lv doctor fence`"
	}
	s.setConditionOf(ctx, fenceSSHEvaluator, condFenceSSHNotAccepting, "host", s.hostName, []string{s.hostName},
		raised, corrosion.SeverityWarning, msg)
}
