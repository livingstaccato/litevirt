package fleet

import (
	"sync"
	"weak"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// A node's daemon on the network, for a scenario that kills it
// (fwliveCrash): every RPC from the node to a peer, and to the node from
// anyone, passes the node's life gate first, in the receiving node's
// partition interceptor.
//
//   - alive: the call goes on; one from the node is counted until its
//     handler returns (inFlightFrom);
//   - fenced: the call waits at the gate, with no answer and no error;
//   - dead: the call is refused Unavailable, as a dead host's connection is.
//
// Every node is alive unless a scenario fences it.

type lifeState int

const (
	lifeAlive lifeState = iota
	lifeFenced
	lifeDead
)

type nodeLife struct {
	mu       sync.Mutex
	state    lifeState
	changed  chan struct{}
	inflight int // calls from the node whose handlers are running
}

var nodeLives sync.Map // weak *Node → *nodeLife (a dead node's entry holds no node)

func (n *Node) life() *nodeLife {
	k := weak.Make(n)
	if l, ok := nodeLives.Load(k); ok {
		return l.(*nodeLife)
	}
	l, _ := nodeLives.LoadOrStore(k, &nodeLife{changed: make(chan struct{})})
	return l.(*nodeLife)
}

func (l *nodeLife) set(st lifeState) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.state = st
	close(l.changed)
	l.changed = make(chan struct{})
}

// fenceLife, killLife and reviveLife move n's gate.
func (n *Node) fenceLife()  { n.life().set(lifeFenced) }
func (n *Node) killLife()   { n.life().set(lifeDead) }
func (n *Node) reviveLife() { n.life().set(lifeAlive) }

// inFlightFrom is how many of n's calls a peer is still serving.
func (n *Node) inFlightFrom() int {
	l := n.life()
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.inflight
}

// nodeNamed is the cluster's node called name, or nil.
func (c *Cluster) nodeNamed(name string) *Node {
	for _, o := range c.Nodes {
		if o.Name == name {
			return o
		}
	}
	return nil
}

// lifeAdmit passes a call from caller (a certificate name) to n through both
// nodes' gates; done ends its count.
func (n *Node) lifeAdmit(caller string) (done func(), err error) {
	var from *Node
	if n.cluster != nil {
		from = n.cluster.nodeNamed(caller)
	}
	for {
		var wait chan struct{}
		for _, m := range []*Node{from, n} {
			if m == nil {
				continue
			}
			l := m.life()
			l.mu.Lock()
			st, ch := l.state, l.changed
			l.mu.Unlock()
			switch st {
			case lifeDead:
				return nil, status.Errorf(codes.Unavailable, "fleet: %s's daemon is dead", m.Name)
			case lifeFenced:
				wait = ch
			}
		}
		if wait == nil {
			break
		}
		<-wait
	}
	if from == nil || from == n {
		// Not a peer serving the node: its own handler is the node's.
		return func() {}, nil
	}
	l := from.life()
	l.mu.Lock()
	if l.state != lifeAlive {
		// Fenced between the look and the count: look again.
		l.mu.Unlock()
		return n.lifeAdmit(caller)
	}
	l.inflight++
	l.mu.Unlock()
	return func() {
		l.mu.Lock()
		l.inflight--
		l.mu.Unlock()
	}, nil
}
