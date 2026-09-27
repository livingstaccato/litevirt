package fleet

// The anti-entropy meter counts, on the SERVING side of every node, how many
// anti-entropy RPCs it answered and how many response bytes it sent. It is how
// a scale scenario states what one anti-entropy pass costs the cluster without
// reaching into the pass itself: every peer the pass contacts is a call here,
// and every byte of every digest or dump it pulls is a byte here.
//
// Bytes are the marshalled size of each response message (proto.Size), which
// is what crosses the wire before framing and TLS.

import (
	"context"
	"sort"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
)

// aeMeteredMethods are the anti-entropy RPCs the meter counts.
var aeMeteredMethods = map[string]bool{
	"GetStateDigest":           true,
	"GetSensitiveStateDigest":  true,
	"GetStateDump":             true,
	"StreamStateDump":          true,
	"StreamTableDump":          true,
	"StreamSensitiveStateDump": true,
}

// AEMethodStats is what one method cost, summed over every node.
type AEMethodStats struct {
	Calls int
	Bytes int64
}

// aeMeter is one node's tally.
type aeMeter struct {
	mu      sync.Mutex
	methods map[string]*AEMethodStats
}

func (m *aeMeter) add(method string, calls int, bytes int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.methods == nil {
		m.methods = make(map[string]*AEMethodStats)
	}
	s := m.methods[method]
	if s == nil {
		s = &AEMethodStats{}
		m.methods[method] = s
	}
	s.Calls += calls
	s.Bytes += bytes
}

func (n *Node) aeMeterUnaryInterceptor(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	name := methodName(info.FullMethod)
	resp, err := handler(ctx, req)
	if aeMeteredMethods[name] {
		var size int64
		if msg, ok := resp.(proto.Message); ok && err == nil {
			size = int64(proto.Size(msg))
		}
		n.aeMeter.add(name, 1, size)
	}
	return resp, err
}

// meteredStream counts the bytes of every message the handler sends.
type meteredStream struct {
	grpc.ServerStream
	bytes int64
}

func (s *meteredStream) SendMsg(m any) error {
	if msg, ok := m.(proto.Message); ok {
		s.bytes += int64(proto.Size(msg))
	}
	return s.ServerStream.SendMsg(m)
}

func (n *Node) aeMeterStreamInterceptor(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	name := methodName(info.FullMethod)
	if !aeMeteredMethods[name] {
		return handler(srv, ss)
	}
	ms := &meteredStream{ServerStream: ss}
	err := handler(srv, ms)
	n.aeMeter.add(name, 1, ms.bytes)
	return err
}

// AEStats sums every node's anti-entropy tally, by method.
func (c *Cluster) AEStats() map[string]AEMethodStats {
	out := map[string]AEMethodStats{}
	for _, n := range c.Nodes {
		n.aeMeter.mu.Lock()
		for name, s := range n.aeMeter.methods {
			t := out[name]
			t.Calls += s.Calls
			t.Bytes += s.Bytes
			out[name] = t
		}
		n.aeMeter.mu.Unlock()
	}
	return out
}

// ResetAEStats zeroes every node's anti-entropy tally.
func (c *Cluster) ResetAEStats() {
	for _, n := range c.Nodes {
		n.aeMeter.mu.Lock()
		n.aeMeter.methods = nil
		n.aeMeter.mu.Unlock()
	}
}

// AEStatsTotal sums a tally across methods.
func AEStatsTotal(stats map[string]AEMethodStats) AEMethodStats {
	var t AEMethodStats
	for _, s := range stats {
		t.Calls += s.Calls
		t.Bytes += s.Bytes
	}
	return t
}

// AEStatsMethods returns a tally's method names, sorted.
func AEStatsMethods(stats map[string]AEMethodStats) []string {
	out := make([]string, 0, len(stats))
	for name := range stats {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}
