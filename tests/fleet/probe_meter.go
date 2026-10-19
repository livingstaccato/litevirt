package fleet

// The probe meter counts, on the SERVING side of every node, the health
// probes (Ready RPCs) it answered and the response bytes it sent: what one
// probe cycle costs the cluster, measured where the probes land rather than
// where the checker decides to send them. It sits behind the partition
// interceptor, so a probe the harness refused is not counted.

import (
	"context"
	"sync/atomic"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
)

type probeMeter struct {
	calls atomic.Int64
	bytes atomic.Int64
}

func (n *Node) probeMeterUnaryInterceptor(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	resp, err := handler(ctx, req)
	if methodName(info.FullMethod) == "Ready" {
		n.probeMeter.calls.Add(1)
		if msg, ok := resp.(proto.Message); ok && err == nil {
			n.probeMeter.bytes.Add(int64(proto.Size(msg)))
		}
	}
	return resp, err
}

// ProbeStats is the health probes every node answered, and their response
// bytes, since the last ResetProbeStats.
func (c *Cluster) ProbeStats() (calls, bytes int64) {
	for _, n := range c.Nodes {
		calls += n.probeMeter.calls.Load()
		bytes += n.probeMeter.bytes.Load()
	}
	return calls, bytes
}

// ResetProbeStats zeroes every node's probe tally.
func (c *Cluster) ResetProbeStats() {
	for _, n := range c.Nodes {
		n.probeMeter.calls.Store(0)
		n.probeMeter.bytes.Store(0)
	}
}
