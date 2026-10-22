package grpcapi

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// fenceSSHPeerTimeout bounds one peer's answer to a fanned-out status read.
const fenceSSHPeerTimeout = 10 * time.Second

// GetFenceSSHStatus is this host's view of managed fence SSH and, with
// fan_out, every other live host's own view (`lv doctor fence`). A diagnostic:
// nothing decides on it.
func (s *Server) GetFenceSSHStatus(ctx context.Context, req *pb.FenceSSHStatusRequest) (*pb.FenceSSHStatus, error) {
	if err := RequireRole(ctx, "viewer"); err != nil {
		return nil, err
	}
	out := &pb.FenceSSHStatus{GeneratedAt: time.Now().UTC().Format(time.RFC3339)}
	out.Nodes = append(out.Nodes, s.ownFenceSSHNode(ctx))
	if !req.GetFanOut() {
		return out, nil
	}
	hosts, err := corrosion.ListHosts(ctx, s.db)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "list hosts: %v", err)
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, h := range hosts {
		if h.Name == s.hostName {
			continue
		}
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			n := s.peerFenceSSHNode(ctx, name)
			mu.Lock()
			out.Nodes = append(out.Nodes, n)
			mu.Unlock()
		}(h.Name)
	}
	wg.Wait()
	sort.Slice(out.Nodes, func(i, j int) bool { return out.Nodes[i].Host < out.Nodes[j].Host })
	return out, nil
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

// peerFenceSSHNode asks host for its own view.
func (s *Server) peerFenceSSHNode(ctx context.Context, host string) *pb.FenceSSHNode {
	pctx, cancel := context.WithTimeout(ctx, fenceSSHPeerTimeout)
	defer cancel()
	c, closeConn, err := s.dialPeer(pctx, host)
	if err != nil {
		return &pb.FenceSSHNode{Host: host, Error: fmt.Sprintf("dial: %v", err)}
	}
	defer closeConn()
	resp, err := c.GetFenceSSHStatus(pctx, &pb.FenceSSHStatusRequest{})
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
