package fleet

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/auth"
	"github.com/litevirt/litevirt/internal/automation/contract"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/grpcapi"
	automationv1 "github.com/livingstaccato/litevirt/api/gen/litevirt/automation/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// A second entry has its OWN actual Login and local credential provenance.
// This does not forward, replicate, or accept entry 0's bearer on another host.
func nativeOwnerSecondEntry(t *testing.T, c nativeOwnerClient) nativeOwnerClient {
	t.Helper()
	c.f.cluster.WaitConverged(t, convergeTimeout)
	n := c.f.cluster.Nodes[1]
	if e := auth.SeedBuiltinRoles(c.f.Context(), n.DB); e != nil {
		t.Fatal(e)
	}
	n.Server.SetAuthEngine(auth.NewEngine(n.DB))
	a := c.f.cluster.SelfClient(n)
	r, e := a.Login(c.f.Context(), &pb.LoginRequest{Username: nativeOwnerUsername, Password: "native-owner-password-0123456789", Realm: "local"})
	if e != nil || !strings.HasPrefix(r.GetToken(), grpcapi.SessionTokenPrefix) {
		t.Fatalf("second genuine local Login: %v", e)
	}
	p, e := corrosion.AutomationSessionPrincipal(c.f.Context(), n.DB, strings.TrimPrefix(r.GetToken(), grpcapi.SessionTokenPrefix))
	if e != nil || p == nil || p.UID != nativeOwnerPrincipalUID || p.ClusterUID != c.f.Head(t, 1).ClusterUID {
		t.Fatalf("second entry lacks real stable Login provenance: %+v %v", p, e)
	}
	return nativeOwnerClient{f: c.f, ctx: metadata.AppendToOutgoingContext(c.f.Context(), "authorization", "Bearer "+r.GetToken()), public: automationv1.NewAutomationClient(n.selfConn), owner: c.owner}
}

func TestAutomationOwnerSessionNativeConcurrentTargets(t *testing.T) {
	for _, same := range []bool{true, false} {
		name := "different-target"
		if same {
			name = "same-target"
		}
		t.Run(name, func(t *testing.T) {
			first := newNativeOwnerClient(t, false)
			second := nativeOwnerSecondEntry(t, first)
			if _, e := first.public.EnsureOwner(first.ctx, &automationv1.EnsureOwnerRequest{Owner: first.owner, RequestId: "concurrent-owner"}); e != nil {
				t.Fatal(e)
			}
			before := first.f.Head(t, 0)
			clients := []nativeOwnerClient{first, second}
			requests := []*automationv1.AcquireOwnerSessionRequest{{Owner: first.owner, RequestId: "concurrent-acquire", SessionId: "target-a"}, {Owner: first.owner, RequestId: "concurrent-acquire", SessionId: "target-a"}}
			if !same {
				requests[1].SessionId = "target-b"
			}
			type result struct {
				i        int
				response *automationv1.AcquireOwnerSessionResponse
				err      error
			}
			out := make(chan result, 2)
			entered := make(chan struct{}, 2)
			gate := make(chan struct{})
			done := make(chan struct{})
			var releaseOnce sync.Once
			release := func() { releaseOnce.Do(func() { close(gate) }) }
			ctx0, cancel0 := context.WithTimeout(first.ctx, 25*time.Second)
			ctx1, cancel1 := context.WithTimeout(second.ctx, 25*time.Second)
			contexts := []context.Context{ctx0, ctx1}
			for i, n := range first.f.cluster.Nodes[:2] {
				n.HookUnary("AcquireOwnerSession", func(ctx context.Context, req any, next grpc.UnaryHandler) (any, error) {
					select {
					case entered <- struct{}{}:
					case <-ctx.Done():
						return nil, ctx.Err()
					}
					select {
					case <-gate:
					case <-ctx.Done():
						return nil, ctx.Err()
					}
					return next(ctx, req)
				})
				go func(i int) {
					r, e := clients[i].public.AcquireOwnerSession(contexts[i], requests[i])
					out <- result{i, r, e}
				}(i)
			}
			var results [2]result
			go func() {
				for range 2 {
					r := <-out
					results[r.i] = r
				}
				close(done)
			}()
			t.Cleanup(func() {
				release()
				cancel0()
				cancel1()
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					t.Error("concurrent public calls did not terminate")
				}
			})
			for range 2 {
				select {
				case <-entered:
				case <-ctx0.Done():
					t.Fatal("both real authenticated entry calls did not arrive")
				}
			}
			release()
			select {
			case <-done:
			case <-ctx0.Done():
				t.Fatal("concurrent owner calls timed out")
			}
			// Contention can lose one bounded proposer attempt. Retrying after
			// both original calls terminate exercises durable receipt closure.
			for i := range results {
				if status.Code(results[i].err) == codes.Unavailable {
					results[i].response, results[i].err = clients[i].public.AcquireOwnerSession(clients[i].ctx, requests[i])
				}
			}
			successes := 0
			winner := -1
			for i, r := range results {
				if r.err == nil {
					successes++
					winner = i
				} else {
					nativeOwnerError(t, r.err, automationv1.ErrorCode_ERROR_CODE_IDEMPOTENCY_CONFLICT)
				}
			}
			want := 1
			if same {
				want = 2
			}
			if successes != want {
				t.Fatalf("concurrent results = %+v, want %d successes", results, want)
			}
			if same && !proto.Equal(results[0].response, results[1].response) {
				t.Fatal("same request/target returned different original responses")
			}
			first.f.Converge(t)
			first.assertSession(t, results[winner].response.GetSession(), requests[winner].SessionId, 1)
			first.assertDecision(t, results[winner].response.GetCursor(), "acquire_session", "concurrent-acquire", requests[winner].SessionId, 1)
			first.assertOwner(t, requests[winner].SessionId, 1)
			for _, n := range first.f.cluster.Nodes {
				for seq := before.Sequence + 1; seq <= first.f.Head(t, 0).Sequence; seq++ {
					rec, found, e := n.DB.AutomationRecord(first.f.Context(), seq)
					if e != nil || !found {
						t.Fatalf("history gap: %v", e)
					}
					d, e := contract.DecodeDecision(rec.Value.Automation.Envelope)
					if e != nil {
						t.Fatal(e)
					}
					if d.Command.RequestID == "concurrent-acquire" && !corrosion.SameOwnerTarget(d, requests[winner].SessionId) {
						t.Fatal("losing target entered certified history")
					}
				}
			}
		})
	}
}

func TestAutomationOwnerSessionNativeStaleFreshHandoff(t *testing.T) {
	c := newNativeOwnerClient(t, false)
	if _, e := c.public.EnsureOwner(c.ctx, &automationv1.EnsureOwnerRequest{Owner: c.owner, RequestId: "stale-owner"}); e != nil {
		t.Fatal(e)
	}
	a, e := c.public.AcquireOwnerSession(c.ctx, &automationv1.AcquireOwnerSessionRequest{Owner: c.owner, SessionId: "old-session", RequestId: "stale-acquire"})
	if e != nil {
		t.Fatal(e)
	}
	request := &automationv1.HandoffOwnerSessionRequest{Current: a.GetSession(), SuccessorSessionId: "new-session", RequestId: "first-handoff"}
	h, e := c.public.HandoffOwnerSession(c.ctx, request)
	if e != nil {
		t.Fatal(e)
	}
	before := c.f.Head(t, 0)
	stale := proto.Clone(request).(*automationv1.HandoffOwnerSessionRequest)
	stale.RequestId = "fresh-request-stale-session"
	stale.SuccessorSessionId = "must-not-activate"
	r, e := c.public.HandoffOwnerSession(c.ctx, stale)
	if e == nil || r != nil {
		t.Fatal("fresh request reused a fenced owner session")
	}
	// This requirement asserts the stable ownership conflict already produced
	// by the approved reducer; it does not invent a new public error enum.
	nativeOwnerError(t, e, automationv1.ErrorCode_ERROR_CODE_OWNERSHIP_CONFLICT)
	c.assertOwner(t, "new-session", 2)
	// A conditional conflict MAY have a certified negative receipt; no test
	// assumes that a refused reducer command cannot occupy a log slot.
	if first := h.GetCursor().GetAppliedSequence(); first != before.Sequence {
		t.Fatal("unexpected initial handoff cursor")
	}
	replay, e := c.public.HandoffOwnerSession(c.ctx, request)
	if e != nil || !proto.Equal(replay, h) {
		t.Fatalf("old successful receipt lost after fresh stale request: %+v %v", replay, e)
	}
}

func TestAutomationOwnerSessionNativeConcurrentMethods(t *testing.T) {
	c := newNativeOwnerClient(t, false)
	other := nativeOwnerSecondEntry(t, c)
	if _, e := c.public.EnsureOwner(c.ctx, &automationv1.EnsureOwnerRequest{Owner: c.owner, RequestId: "method-race-owner"}); e != nil {
		t.Fatal(e)
	}
	ensure := &automationv1.EnsureOwnerRequest{Owner: c.owner, RequestId: "same-request-two-methods"}
	acquire := &automationv1.AcquireOwnerSessionRequest{Owner: c.owner, RequestId: ensure.RequestId, SessionId: "method-race-target"}
	type result struct {
		kind   string
		cursor *automationv1.ReadCursor
		err    error
	}
	start := make(chan struct{})
	out := make(chan result, 2)
	joined := make(chan struct{})
	ctx0, cancel0 := context.WithTimeout(c.ctx, 25*time.Second)
	ctx1, cancel1 := context.WithTimeout(other.ctx, 25*time.Second)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		r, e := c.public.EnsureOwner(ctx0, ensure)
		out <- result{"ensure_owner", r.GetCursor(), e}
	}()
	go func() {
		defer wg.Done()
		<-start
		r, e := other.public.AcquireOwnerSession(ctx1, acquire)
		out <- result{"acquire_session", r.GetCursor(), e}
	}()
	go func() { wg.Wait(); close(joined) }()
	t.Cleanup(func() {
		cancel0()
		cancel1()
		select {
		case <-joined:
		case <-time.After(5 * time.Second):
			t.Error("method race calls did not join")
		}
	})
	close(start)
	results := []result{}
	for range 2 {
		select {
		case r := <-out:
			results = append(results, r)
		case <-ctx0.Done():
			t.Fatal("method race timed out")
		}
	}
	winner := -1
	success := 0
	for i := range results {
		r := &results[i]
		if status.Code(r.err) == codes.Unavailable {
			if r.kind == "ensure_owner" {
				reply, e := c.public.EnsureOwner(c.ctx, ensure)
				r.cursor, r.err = reply.GetCursor(), e
			} else {
				reply, e := other.public.AcquireOwnerSession(other.ctx, acquire)
				r.cursor, r.err = reply.GetCursor(), e
			}
		}
		if r.err == nil {
			success++
			winner = i
		} else {
			nativeOwnerError(t, r.err, automationv1.ErrorCode_ERROR_CODE_IDEMPOTENCY_CONFLICT)
		}
	}
	if success != 1 {
		t.Fatalf("cross-method request race produced %d winners: %+v", success, results)
	}
	c.f.Converge(t)
	target := ""
	var activation uint64
	if results[winner].kind == "acquire_session" {
		target = acquire.SessionId
		activation = 1
	}
	c.assertDecision(t, results[winner].cursor, results[winner].kind, ensure.RequestId, target, activation)
	c.assertOwner(t, target, activation)
}

func TestAutomationOwnerSessionNativeAfterCommitLostReply(t *testing.T) {
	c := newNativeOwnerClient(t, false)
	request := &automationv1.EnsureOwnerRequest{Owner: c.owner, RequestId: "committed-reply-lost"}
	committed := make(chan *automationv1.EnsureOwnerResponse, 1)
	c.f.cluster.Nodes[0].HookUnary("EnsureOwner", func(ctx context.Context, req any, next grpc.UnaryHandler) (any, error) {
		r, e := next(ctx, req)
		if e != nil {
			return r, e
		}
		committed <- proto.Clone(r.(*automationv1.EnsureOwnerResponse)).(*automationv1.EnsureOwnerResponse)
		return nil, status.Error(codes.Unavailable, "test: response lost after real handler completed")
	})
	if r, e := c.public.EnsureOwner(c.ctx, request); r != nil || status.Code(e) != codes.Unavailable {
		t.Fatalf("lost response fault not observed: %+v %v", r, e)
	}
	var original *automationv1.EnsureOwnerResponse
	select {
	case original = <-committed:
	default:
		t.Fatal("fault ran before a real committed result")
	}
	c.assertDecision(t, original.GetCursor(), "ensure_owner", request.RequestId, "", 0)
	r, e := c.public.EnsureOwner(c.ctx, request)
	if e != nil || !proto.Equal(r, original) {
		t.Fatalf("retry after actual committed lost response: %+v %v", r, e)
	}
}
