package fleet

import (
	"context"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/grpcapi"
	automationv1 "github.com/livingstaccato/litevirt/api/gen/litevirt/automation/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func TestAutomationOwnerSessionNativeAtomicRollback(t *testing.T) {
	c := newNativeOwnerClient(t, false)
	before := c.f.Head(t, 0)
	key, e := corrosion.AutomationClaimKey(before.Sequence + 1)
	if e != nil {
		t.Fatal(e)
	}
	restore, fired := c.f.cluster.Nodes[0].DB.FailAutomationValuedCommitForTest(key)
	restored := false
	t.Cleanup(func() {
		if !restored {
			restore()
		}
	})
	request := &automationv1.EnsureOwnerRequest{Owner: c.owner, RequestId: "native-atomic-rollback"}
	r, e := c.public.EnsureOwner(c.ctx, request)
	if e == nil || r != nil || !fired() {
		t.Fatalf("actual signed value FULL rollback not exercised: response=%+v error=%v fired=%v", r, e, fired())
	}
	nativeOwnerNoAccepted(t, c, before.Sequence+1)
	c.assertNoOwnerEffects(t, before, request.RequestId)
	restore()
	restored = true
	// Same genuine session and same request must now obtain real votes.
	r, e = c.public.EnsureOwner(c.ctx, request)
	if e != nil {
		t.Fatal(e)
	}
	c.assertDecision(t, r.GetCursor(), "ensure_owner", request.RequestId, "", 0)
}

func nativeOwnerExpiringLogin(t *testing.T, c nativeOwnerClient) (nativeOwnerClient, time.Time) {
	t.Helper()
	n := c.f.cluster.Nodes[0]
	// Existing daemon configuration surface, set with no concurrent Login/auth
	// calls. The real Login stamps its own actual expiry and stable provenance.
	n.Server.SetSessionTimeouts(time.Hour, 3*time.Second)
	r, e := c.f.cluster.SelfClient(n).Login(c.f.Context(), &pb.LoginRequest{Username: nativeOwnerUsername, Password: "native-owner-password-0123456789", Realm: "local"})
	if e != nil || !strings.HasPrefix(r.GetToken(), grpcapi.SessionTokenPrefix) {
		t.Fatalf("expiring real Login: %v", e)
	}
	expiry, e := time.Parse(time.RFC3339, r.GetExpiresAt())
	if e != nil || !time.Now().Before(expiry) {
		t.Fatalf("actual Login has no future expiry: %v", e)
	}
	c.ctx = metadata.AppendToOutgoingContext(c.f.Context(), "authorization", "Bearer "+r.GetToken())
	return c, expiry
}

func nativeOwnerWaitExpiry(t *testing.T, ctx context.Context, expiry time.Time) {
	t.Helper()
	timer := time.NewTimer(time.Until(expiry.Add(20 * time.Millisecond)))
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
		t.Fatal("expiry wait outlived request context")
	}
	if time.Now().Before(expiry) {
		t.Fatal("expiry clock precondition not reached")
	}
}

func TestAutomationOwnerSessionNativeActualBearerExpiry(t *testing.T) {
	for _, after := range []bool{false, true} {
		name := "authenticated-before-handler"
		if after {
			name = "after-native-full-commit"
		}
		t.Run(name, func(t *testing.T) {
			c, expiry := nativeOwnerExpiringLogin(t, newNativeOwnerClient(t, false))
			before := c.f.Head(t, 0)
			if after {
				release, result := nativeOwnerEnsureAt(t, c, "expiry-after-issuance", true)
				nativeOwnerWaitExpiry(t, c.f.Context(), expiry)
				release()
				r := nativeOwnerAwaitEnsure(t, result)
				if r.err != nil {
					t.Fatalf("real bearer expiry destroyed already authorized exact vote: %v", r.err)
				}
				c.assertDecision(t, r.response.GetCursor(), "ensure_owner", "expiry-after-issuance", "", 0)
				return
			}
			// Hold the public method AFTER the real auth interceptor, avoiding
			// the peer Prepare's 750ms timeout during an actual expiry wait.
			type expiryProof struct {
				entered, released time.Time
				handlerCalled     bool
				handlerErr        error
				failure           string
			}
			proofs := make(chan expiryProof, 1)
			c.f.cluster.Nodes[0].HookUnary("EnsureOwner", func(ctx context.Context, req any, next grpc.UnaryHandler) (any, error) {
				proof := expiryProof{entered: time.Now()}
				defer func() { proofs <- proof }()
				// An already expired/interceptor-refused call cannot reach this
				// point. Require a measurable live window, rather than assume
				// that Login's earlier future-expiry check still holds.
				if expiry.Sub(proof.entered) < 100*time.Millisecond {
					proof.failure = "authenticated hook entered without the required live expiry window"
					return nil, status.Error(codes.FailedPrecondition, "test: expiry entry precondition")
				}
				timer := time.NewTimer(time.Until(expiry.Add(20 * time.Millisecond)))
				defer timer.Stop()
				select {
				case <-timer.C:
				case <-ctx.Done():
					proof.failure = "authenticated call canceled before postexpiry handler release"
					return nil, ctx.Err()
				}
				proof.released = time.Now()
				if proof.released.Before(expiry) || ctx.Err() != nil {
					proof.failure = "handler release did not follow actual expiry on a live call"
					return nil, status.Error(codes.FailedPrecondition, "test: expiry release precondition")
				}
				proof.handlerCalled = true
				r, e := next(ctx, req)
				proof.handlerErr = e
				return r, e
			})
			r, e := c.public.EnsureOwner(c.ctx, &automationv1.EnsureOwnerRequest{Owner: c.owner, RequestId: "expiry-before-issuance"})
			var proof expiryProof
			select {
			case proof = <-proofs:
			default:
				t.Fatalf("CAUSAL_PRECONDITION_FAILED: auth refused before authenticated hook entry: %v", e)
			}
			if proof.failure != "" || !proof.entered.Before(expiry) || expiry.Sub(proof.entered) < 100*time.Millisecond || proof.released.Before(expiry) || !proof.handlerCalled {
				t.Fatalf("CAUSAL_PRECONDITION_FAILED: expiry trace failure=%q entered=%s expiry=%s released=%s handler_called=%v", proof.failure, proof.entered, expiry, proof.released, proof.handlerCalled)
			}
			if r != nil || status.Code(proof.handlerErr) != codes.Unavailable || status.Code(e) != codes.Unavailable {
				t.Fatalf("postexpiry real handler did not refuse native credential authority: response=%+v handler_error=%v public_error=%v", r, proof.handlerErr, e)
			}
			nativeOwnerError(t, e, automationv1.ErrorCode_ERROR_CODE_AUTHORITY_UNAVAILABLE)
			nativeOwnerNoAccepted(t, c, before.Sequence+1)
			c.assertNoOwnerEffects(t, before, "expiry-before-issuance")
		})
	}
}
