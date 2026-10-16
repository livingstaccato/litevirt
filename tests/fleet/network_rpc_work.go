package fleet

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const networkCallKey = "fleet-network-call"

// networkCalls owns only outstanding fixture RPCs. A token is a private admission
// ticket, not authentication: existing TLS and authorization run before admission.
// Unknown, completed and client-sealed tickets all fail without creating records.
type networkCalls struct {
	mu         sync.Mutex
	calls      map[string]*networkCall
	idle       chan struct{}
	generation uint64
}
type networkCall struct {
	method, target                    string
	admitted, clientDone, handlerDone bool
}

func selectedNetworkRPC(method string) bool {
	switch methodName(method) {
	case "ApplyLB", "RefreshLB", "RemoveLB", "SyncVTEP":
		return true
	}
	return false
}
func (c *Cluster) networkRPCClient() grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoke grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		if !selectedNetworkRPC(method) {
			return invoke(ctx, method, req, reply, cc, opts...)
		}
		var entropy [32]byte
		if _, err := rand.Read(entropy[:]); err != nil {
			return err
		}
		token := hex.EncodeToString(entropy[:])
		r := &c.networkCalls
		r.mu.Lock()
		if r.calls == nil {
			r.calls = map[string]*networkCall{}
		}
		if len(r.calls) == 0 {
			r.idle = make(chan struct{})
		}
		call := &networkCall{method: method, target: cc.Target()}
		r.calls[token] = call
		r.generation++
		r.mu.Unlock()
		defer func() {
			r.mu.Lock()
			defer r.mu.Unlock()
			call.clientDone = true
			// Sealing and handler admission use the same lock: late entry either owns
			// this call already, or sees a missing ticket and cannot enter effects.
			if !call.admitted || call.handlerDone {
				r.remove(token)
			}
		}()
		md, _ := metadata.FromOutgoingContext(ctx)
		md = md.Copy()
		md.Set(networkCallKey, token)
		return invoke(metadata.NewOutgoingContext(ctx, md), method, req, reply, cc, opts...)
	}
}
func (r *networkCalls) remove(token string) {
	delete(r.calls, token)
	if len(r.calls) == 0 {
		close(r.idle)
	}
}
func (c *Cluster) networkRPCServer(n *Node) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if !selectedNetworkRPC(info.FullMethod) {
			return handler(ctx, req)
		}
		md, _ := metadata.FromIncomingContext(ctx)
		tokens := md.Get(networkCallKey)
		r := &c.networkCalls
		r.mu.Lock()
		var call *networkCall
		if len(tokens) == 1 {
			call = r.calls[tokens[0]]
		}
		if call == nil || call.admitted || call.clientDone || call.method != info.FullMethod || call.target != fmt.Sprintf("%s:%d", n.Address, n.Port) {
			r.mu.Unlock()
			return nil, status.Error(codes.Canceled, "fleet network RPC admission sealed or unknown")
		}
		call.admitted = true
		r.mu.Unlock()
		defer func() {
			r.mu.Lock()
			defer r.mu.Unlock()
			call.handlerDone = true
			if call.clientDone {
				r.remove(tokens[0])
			}
		}()
		// A causal child registers its server work before this handler returns. The
		// outgoing client may retire first; this admitted ownership remains until now.
		return handler(ctx, req)
	}
}
func (r *networkCalls) wait() uint64 {
	for {
		r.mu.Lock()
		if len(r.calls) == 0 {
			generation := r.generation
			r.mu.Unlock()
			return generation
		}
		idle := r.idle
		r.mu.Unlock()
		<-idle
	}
}
