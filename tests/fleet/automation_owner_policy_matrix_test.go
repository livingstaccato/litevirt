package fleet

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/auth/policy"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/grpcapi"
	automationv1 "github.com/livingstaccato/litevirt/api/gen/litevirt/automation/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
)

type nativeOwnerEnsureResult struct {
	response      *automationv1.EnsureOwnerResponse
	err           error
	causalFailure string
}

// The before point requires BOTH remote Prepare handlers to be entered: the
// adapter and engine preflights have completed, but no Prepare majority can
// release phase two. The after point is the real entry's committed signed
// Accept, before any normal Accept fanout. Neither hook manufactures authority.
func nativeOwnerEnsureAt(t *testing.T, c nativeOwnerClient, request string, after bool) (func(), <-chan nativeOwnerEnsureResult) {
	t.Helper()
	ctx, cancel := context.WithTimeout(c.ctx, 20*time.Second)
	gate, arrived, finished := make(chan struct{}), make(chan struct{}, 2), make(chan struct{})
	result := make(chan nativeOwnerEnsureResult, 1)
	var once sync.Once
	var proofMu sync.Mutex
	gateContexts := []context.Context{}
	usablePromises := map[string]bool{}
	causalFailure := ""
	failCausal := func(reason string) {
		proofMu.Lock()
		if causalFailure == "" {
			causalFailure = reason
		}
		proofMu.Unlock()
	}
	release := func() {
		once.Do(func() {
			if !after {
				proofMu.Lock()
				if len(gateContexts) != 2 && causalFailure == "" {
					causalFailure = "both gated Prepare contexts were not established"
				}
				for _, call := range gateContexts {
					deadline, hasDeadline := call.Deadline()
					if call.Err() != nil || !hasDeadline || !time.Now().Before(deadline) {
						if causalFailure == "" {
							causalFailure = "gated Prepare expired before mutation completed and gate release"
						}
					}
				}
				proofMu.Unlock()
			}
			close(gate)
		})
	}
	wait := func(call context.Context) {
		select {
		case <-gate:
		case <-call.Done():
		}
	}
	key, err := corrosion.AutomationClaimKey(c.f.Head(t, 0).Sequence + 1)
	if err != nil {
		t.Fatal(err)
	}
	// Preserve the real fault/transport chain. Observe successful CLIENT-side
	// Prepare returns, not just server handler entry or a prepared SQL row.
	network := c.f.cluster.networkRPCClient()
	want := 2
	if after {
		want = 1
		var observed sync.Once
		c.f.cluster.Nodes[0].Server.SetClaimVoteObserverForTest(func(v grpcapi.ClaimVote) {
			if v.Phase == "accept" && v.Key == key {
				observed.Do(func() { arrived <- struct{}{}; wait(ctx) })
			}
		})
	} else {
		cfg, e := corrosion.AdoptedVoterConfig(c.f.Context(), c.f.cluster.Nodes[0].DB)
		if e != nil {
			t.Fatal(e)
		}
		incarnations := map[string]string{}
		for _, member := range cfg.Members {
			if member.Name != c.f.cluster.Nodes[0].Name {
				incarnations[member.Name] = member.Incarnation
			}
		}
		c.f.cluster.Nodes[0].Server.SetPeerUnaryInterceptor(func(call context.Context, method string, req, reply any, cc *grpc.ClientConn, invoke grpc.UnaryInvoker, opts ...grpc.CallOption) error {
			e := network(call, method, req, reply, cc, invoke, opts...)
			if methodName(method) != "PrepareRecoveryClaim" {
				return e
			}
			q, qok := req.(*pb.PrepareRecoveryClaimRequest)
			r, rok := reply.(*pb.PrepareRecoveryClaimResponse)
			if !qok || !rok || !proto.Equal(q.GetKey(), claimKeyPB(key)) || q.GetConfigGeneration() != cfg.Generation {
				failCausal("observed Prepare was not for the intended fresh owner slot/electorate")
				return e
			}
			if e != nil || call.Err() != nil || !r.GetPromised() || r.GetAcceptedValue() != nil || r.GetAcceptedBallot().GetRound() != 0 || !proto.Equal(r.GetPromisedBallot(), q.GetBallot()) || incarnations[r.GetVoter()] == "" || incarnations[r.GetVoter()] != r.GetVoterIncarnation() {
				failCausal(fmt.Sprintf("postmutation Prepare did not return a live usable fresh-slot promise: voter=%q rpc_error=%v context_error=%v", r.GetVoter(), e, call.Err()))
				return e
			}
			proofMu.Lock()
			usablePromises[r.GetVoter()] = true
			proofMu.Unlock()
			return e
		})
		for _, n := range c.f.cluster.Nodes[1:] {
			n.HookUnary("PrepareRecoveryClaim", func(call context.Context, req any, handler grpc.UnaryHandler) (any, error) {
				// HookUnary removes this hook before invoking it. Each of the
				// two peers can announce once; retry traffic runs its real handler.
				proofMu.Lock()
				gateContexts = append(gateContexts, call)
				proofMu.Unlock()
				select {
				case arrived <- struct{}{}:
				case <-call.Done():
					failCausal("Prepare expired before arrival handshake")
					return nil, call.Err()
				}
				select {
				case <-gate:
				case <-call.Done():
					failCausal("Prepare gate expired while mutation was in progress")
					return nil, call.Err()
				}
				if call.Err() != nil {
					failCausal("Prepare context canceled at gate release")
					return nil, call.Err()
				}
				return handler(call, req)
			})
		}
	}
	t.Cleanup(func() {
		release()
		cancel()
		select {
		case <-finished:
		case <-time.After(5 * time.Second):
			t.Error("owner call did not terminate after cancel/release")
		}
		c.f.cluster.Nodes[0].Server.SetClaimVoteObserverForTest(nil)
		if !after {
			c.f.cluster.Nodes[0].Server.SetPeerUnaryInterceptor(network)
		}
	})
	go func() {
		defer close(finished)
		r, e := c.public.EnsureOwner(ctx, &automationv1.EnsureOwnerRequest{Owner: c.owner, RequestId: request})
		proofMu.Lock()
		if !after && len(usablePromises) != 2 && causalFailure == "" {
			causalFailure = "postmutation proposer did not receive both live usable remote promises"
		}
		if !after && ctx.Err() != nil && causalFailure == "" {
			causalFailure = "outer owner request expired before native authorization result"
		}
		failure := causalFailure
		proofMu.Unlock()
		result <- nativeOwnerEnsureResult{response: r, err: e, causalFailure: failure}
	}()
	for i := 0; i < want; i++ {
		select {
		case <-arrived:
		case r := <-result:
			t.Fatalf("request returned before causal point: %v", r.err)
		case <-ctx.Done():
			t.Fatalf("causal point not reached: %v", ctx.Err())
		}
	}
	return release, result
}

func nativeOwnerAwaitEnsure(t *testing.T, result <-chan nativeOwnerEnsureResult) nativeOwnerEnsureResult {
	t.Helper()
	select {
	case r := <-result:
		if r.causalFailure != "" {
			t.Fatalf("CAUSAL_PRECONDITION_FAILED: %s", r.causalFailure)
		}
		return r
	case <-time.After(25 * time.Second):
		t.Fatal("owner call did not terminate")
	}
	return nativeOwnerEnsureResult{}
}

func nativeOwnerNoAccepted(t *testing.T, c nativeOwnerClient, sequence uint64) {
	t.Helper()
	key, err := corrosion.AutomationClaimKey(sequence)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range c.f.cluster.Nodes {
		s, _, err := n.DB.ClaimState(c.f.Context(), key)
		if err != nil || s.Accept != nil || s.Value != nil {
			t.Fatalf("%s left a valued vote after refusal: %+v %v", n.Name, s, err)
		}
	}
}

func nativeOwnerGrant(t *testing.T, c nativeOwnerClient, role, path, principal string, propagate bool) string {
	t.Helper()
	r, e := c.f.cluster.SelfClient(c.f.cluster.Nodes[0]).GrantRole(c.f.Context(), &pb.GrantRoleRequest{Role: role, Path: path, Principal: principal, Propagate: propagate})
	if e != nil || r.GetBinding().GetId() == "" {
		t.Fatalf("actual policy grant: %v", e)
	}
	return r.GetBinding().GetId()
}

func TestAutomationOwnerSessionNativeCurrentScopedRoles(t *testing.T) {
	for _, tc := range []struct {
		name, role, path, principal string
		verbs                       []string
		propagate, allowed          bool
	}{
		{"builtin-operator", "Operator", "/projects/" + nativeOwnerProject, "user:" + nativeOwnerUsername + "@local", nil, false, true},
		{"builtin-admin", "Admin", "/", "user:" + nativeOwnerUsername + "@local", nil, true, true},
		{"custom-exact", "OwnerOnly", "/projects/" + nativeOwnerProject, "user:" + nativeOwnerUsername + "@local", []string{"automation.owner.manage"}, false, true},
		{"custom-wildcard-group", "OwnerGroup", "/projects", "group:operator@local", []string{"automation.*"}, true, true},
		{"explicit-viewer", "Viewer", "/projects/" + nativeOwnerProject, "user:" + nativeOwnerUsername + "@local", nil, true, false},
		{"unrelated-scope-suppresses-fallback", "Operator", "/projects/unrelated", "user:" + nativeOwnerUsername + "@local", nil, true, false},
		{"nonpropagating-root-suppresses-fallback", "Operator", "/", "user:" + nativeOwnerUsername + "@local", nil, false, false},
		{"similar-prefix-is-not-scope", "Operator", "/projects/native-owner", "user:" + nativeOwnerUsername + "@local", nil, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newNativeOwnerClient(t, false)
			if tc.verbs != nil {
				if e := corrosion.InsertRole(c.f.Context(), c.f.cluster.Nodes[0].DB, corrosion.RoleRecord{Name: tc.role, Verbs: tc.verbs}); e != nil {
					t.Fatal(e)
				}
			}
			nativeOwnerGrant(t, c, tc.role, tc.path, tc.principal, tc.propagate)
			before := c.f.Head(t, 0)
			r, e := c.public.EnsureOwner(c.ctx, &automationv1.EnsureOwnerRequest{Owner: c.owner, RequestId: "scope-matrix"})
			if tc.allowed {
				if e != nil {
					t.Fatalf("current scoped role denied: %v", e)
				}
				c.assertDecision(t, r.GetCursor(), "ensure_owner", "scope-matrix", "", 0)
			} else {
				nativeOwnerError(t, e, automationv1.ErrorCode_ERROR_CODE_PERMISSION_DENIED)
				c.assertNoOwnerEffects(t, before, "scope-matrix")
				nativeOwnerNoAccepted(t, c, before.Sequence+1)
			}
		})
	}
}

func TestAutomationOwnerSessionNativeAuthorizationPoint(t *testing.T) {
	// Mutations use actual admin/session APIs and current durable policy. The
	// login-policy cases latch the EXISTING release feature on all real peers.
	// No session, issuance proof, voter acceptance, or allow flag is fabricated.
	mutations := []struct {
		name  string
		latch bool
		apply func(*testing.T, nativeOwnerClient)
	}{
		{"logout", false, func(t *testing.T, c nativeOwnerClient) {
			if _, e := c.f.cluster.SelfClient(c.f.cluster.Nodes[0]).Logout(c.ctx, &emptypb.Empty{}); e != nil {
				t.Fatal(e)
			}
		}},
		{"password-rotation", false, func(t *testing.T, c nativeOwnerClient) {
			if _, e := c.f.cluster.SelfClient(c.f.cluster.Nodes[0]).ChangePassword(c.f.Context(), &pb.ChangePasswordRequest{Username: nativeOwnerUsername, NewPassword: "rotated-password-0123456789"}); e != nil {
				t.Fatal(e)
			}
		}},
		// BASE has no role-change RPC. This negative input models an actual
		// replicated users.role update, preserving the real Login/lifetime and
		// reducing authority. It never creates a principal or allow record.
		{"current-role-demotion", false, func(t *testing.T, c nativeOwnerClient) {
			db := c.f.cluster.Nodes[0].DB
			if e := db.Execute(c.f.Context(), `UPDATE users SET role=?,updated_at=? WHERE username=? AND deleted_at IS NULL`, "viewer", db.NowTS(), nativeOwnerUsername); e != nil {
				t.Fatal(e)
			}
		}},
		{"disable-account", true, func(t *testing.T, c nativeOwnerClient) {
			b := true
			if _, e := c.f.cluster.SelfClient(c.f.cluster.Nodes[0]).SetUserAccount(c.f.Context(), &pb.SetUserAccountRequest{Username: nativeOwnerUsername, Disabled: &b}); e != nil {
				t.Fatal(e)
			}
		}},
		{"expire-account", true, func(t *testing.T, c nativeOwnerClient) {
			s := "2000-01-01T00:00:00Z"
			if _, e := c.f.cluster.SelfClient(c.f.cluster.Nodes[0]).SetUserAccount(c.f.Context(), &pb.SetUserAccountRequest{Username: nativeOwnerUsername, ExpiresAt: &s}); e != nil {
				t.Fatal(e)
			}
		}},
		{"explicit-binding-denial", false, func(t *testing.T, c nativeOwnerClient) {
			nativeOwnerGrant(t, c, "Viewer", "/projects/"+nativeOwnerProject, "user:"+nativeOwnerUsername+"@local", true)
		}},
		{"account-rebirth", false, func(t *testing.T, c nativeOwnerClient) {
			a := c.f.cluster.SelfClient(c.f.cluster.Nodes[0])
			if _, e := a.DeleteUser(c.f.Context(), &pb.DeleteUserRequest{Username: nativeOwnerUsername}); e != nil {
				t.Fatal(e)
			}
			if _, e := a.CreateUser(c.f.Context(), &pb.CreateUserRequest{Username: nativeOwnerUsername, Password: "reborn-password-0123456789", Role: "operator"}); e != nil {
				t.Fatal(e)
			}
		}},
		{"project-rebirth", false, func(t *testing.T, c nativeOwnerClient) {
			a := c.f.cluster.SelfClient(c.f.cluster.Nodes[0])
			if _, e := a.DeleteProject(c.f.Context(), &pb.DeleteProjectRequest{Name: nativeOwnerProject}); e != nil {
				t.Fatal(e)
			}
			if _, e := a.CreateProject(c.f.Context(), &pb.CreateProjectRequest{Name: nativeOwnerProject}); e != nil {
				t.Fatal(e)
			}
		}},
	}
	for _, mutation := range mutations {
		for _, after := range []bool{false, true} {
			name := mutation.name + "/before-native-commit"
			if after {
				name = mutation.name + "/after-native-commit"
			}
			t.Run(name, func(t *testing.T) {
				c := newNativeOwnerClient(t, false)
				if mutation.latch {
					latchLoginPolicy(t, c.f.cluster)
				}
				before := c.f.Head(t, 0)
				release, result := nativeOwnerEnsureAt(t, c, "authorization-point", after)
				if !after {
					nativeOwnerNoAccepted(t, c, before.Sequence+1)
				} else {
					key, _ := corrosion.AutomationClaimKey(before.Sequence + 1)
					s, found, e := c.f.cluster.Nodes[0].DB.ClaimState(c.f.Context(), key)
					if e != nil || !found || s.Accept == nil || s.Value == nil {
						t.Fatalf("after point lacks real committed signed vote: %+v %v", s, e)
					}
				}
				mutation.apply(t, c)
				release()
				r := nativeOwnerAwaitEnsure(t, result)
				if after || mutation.name == "password-rotation" {
					if r.err != nil {
						t.Fatalf("authorized same-principal value lost admission: %v", r.err)
					}
					c.assertDecision(t, r.response.GetCursor(), "ensure_owner", "authorization-point", "", 0)
					if mutation.name == "password-rotation" {
						// Design55/184 preserves access across authorized rotation.
						// Do the additional password checks AFTER releasing the
						// causal gate, so they cannot expire its Prepare contexts.
						nativeOwnerAssertPasswordRotation(t, c, r.response)
					}
				} else {
					if r.err == nil || r.response != nil {
						t.Fatalf("mutation before native authorization admitted: %+v", r.response)
					}
					if mutation.name == "explicit-binding-denial" || mutation.name == "current-role-demotion" {
						nativeOwnerError(t, r.err, automationv1.ErrorCode_ERROR_CODE_PERMISSION_DENIED)
					} else if status.Code(r.err) != codes.Unavailable {
						t.Fatalf("in-flight invalid credential/lifetime must be unavailable: %v", r.err)
					}
					c.assertNoOwnerEffects(t, before, "authorization-point")
					nativeOwnerNoAccepted(t, c, before.Sequence+1)
				}
			})
		}
	}
}

func nativeOwnerAssertPasswordRotation(t *testing.T, c nativeOwnerClient, original *automationv1.EnsureOwnerResponse) {
	t.Helper()
	entry := c.f.cluster.Nodes[0]
	legacy := c.f.cluster.SelfClient(entry)
	md, ok := metadata.FromOutgoingContext(c.ctx)
	bearers := md.Get("authorization")
	if !ok || len(bearers) != 1 || !strings.HasPrefix(bearers[0], "Bearer "+grpcapi.SessionTokenPrefix) {
		t.Fatal("rotation fixture lacks its original real Login bearer")
	}
	sessionID := strings.TrimPrefix(bearers[0], "Bearer "+grpcapi.SessionTokenPrefix)
	principal, e := corrosion.AutomationSessionPrincipal(c.f.Context(), entry.DB, sessionID)
	if e != nil || principal == nil || principal.UID != nativeOwnerPrincipalUID || principal.ClusterUID != c.f.Head(t, 0).ClusterUID {
		t.Fatalf("authorized rotation lost the original stable principal: %+v %v", principal, e)
	}
	who, e := legacy.Whoami(c.ctx, &emptypb.Empty{})
	if e != nil || who.GetUsername() != nativeOwnerUsername || who.GetRealm() != "local" || who.GetRole() != "operator" {
		t.Fatalf("original live bearer lost authentication after rotation: %+v %v", who, e)
	}
	request := &automationv1.EnsureOwnerRequest{Owner: c.owner, RequestId: "authorization-point"}
	replayed, e := c.public.EnsureOwner(c.ctx, request)
	if e != nil || !proto.Equal(replayed, original) {
		t.Fatalf("original bearer lost its exact owner result after rotation: %+v %v", replayed, e)
	}
	oldLogin, e := legacy.Login(c.f.Context(), &pb.LoginRequest{Username: nativeOwnerUsername, Password: "native-owner-password-0123456789", Realm: "local"})
	if status.Code(e) != codes.Unauthenticated || oldLogin != nil {
		t.Fatalf("replaced password was not refused by real Login: %v", e)
	}
	login, e := legacy.Login(c.f.Context(), &pb.LoginRequest{Username: nativeOwnerUsername, Password: "rotated-password-0123456789", Realm: "local"})
	if e != nil || !strings.HasPrefix(login.GetToken(), grpcapi.SessionTokenPrefix) {
		t.Fatalf("rotated password did not produce a real Login session: %v", e)
	}
	next, e := corrosion.AutomationSessionPrincipal(c.f.Context(), entry.DB, strings.TrimPrefix(login.GetToken(), grpcapi.SessionTokenPrefix))
	if e != nil || next == nil || next.UID != principal.UID || next.ClusterUID != principal.ClusterUID {
		t.Fatalf("new-password Login changed the stable principal: %+v %v", next, e)
	}
	ctx := metadata.AppendToOutgoingContext(c.f.Context(), "authorization", "Bearer "+login.GetToken())
	who, e = legacy.Whoami(ctx, &emptypb.Empty{})
	if e != nil || who.GetUsername() != nativeOwnerUsername || who.GetRealm() != "local" || who.GetRole() != "operator" {
		t.Fatalf("new-password bearer lacks real authentication: %+v %v", who, e)
	}
	replayed, e = c.public.EnsureOwner(ctx, request)
	if e != nil || !proto.Equal(replayed, original) {
		t.Fatalf("new-password bearer did not retain the exact owner result: %+v %v", replayed, e)
	}
	c.assertOwner(t, "", 0)
}

func TestAutomationOwnerSessionNativePolicyChangesAfterPreflight(t *testing.T) {
	c := newNativeOwnerClient(t, false)
	db := c.f.cluster.Nodes[0].DB
	if e := corrosion.InsertRole(c.f.Context(), db, corrosion.RoleRecord{Name: "MutableOwner", Verbs: []string{"automation.owner.manage"}}); e != nil {
		t.Fatal(e)
	}
	nativeOwnerGrant(t, c, "MutableOwner", "/projects/"+nativeOwnerProject, "user:"+nativeOwnerUsername+"@local", true)
	before := c.f.Head(t, 0)
	release, result := nativeOwnerEnsureAt(t, c, "role-edited-after-preflight", false)
	if e := corrosion.InsertRole(c.f.Context(), db, corrosion.RoleRecord{Name: "MutableOwner", Verbs: []string{"vm.read"}}); e != nil {
		t.Fatal(e)
	}
	release()
	r := nativeOwnerAwaitEnsure(t, result)
	nativeOwnerError(t, r.err, automationv1.ErrorCode_ERROR_CODE_PERMISSION_DENIED)
	c.assertNoOwnerEffects(t, before, "role-edited-after-preflight")
	nativeOwnerNoAccepted(t, c, before.Sequence+1)
}

// Both the cached auth engine and native FULL authorization use this matcher.
// The existing auth.TestContainerRootVerbIsNotCarriedBySuffixWildcards also
// checks the delegated-grant boundary after permissions.go delegates here.
func TestAutomationOwnerSessionNativePolicyMatcherContainerRootBoundary(t *testing.T) {
	for _, tc := range []struct {
		grant, verb string
		allowed     bool
	}{
		{"*.exec", "ctroot.exec", false},
		{"*.future", "ctroot.future", false},
		{"ct.*", "ctroot.exec", false},
		{"ctroot.*", "ctroot.exec", true},
		{"ctroot.exec", "ctroot.exec", true},
		{"*", "ctroot.exec", true},
		{"*.exec", "vm.exec", true},
	} {
		if got := policy.VerbMatches([]string{tc.grant}, tc.verb); got != tc.allowed {
			t.Errorf("grant %q matches %q = %v, want %v", tc.grant, tc.verb, got, tc.allowed)
		}
	}
}

func TestAutomationOwnerSessionNativeHeldProjectBinding(t *testing.T) {
	for _, afterPreflight := range []bool{false, true} {
		name := "before-preflight"
		if afterPreflight {
			name = "before-native-commit"
		}
		t.Run(name, func(t *testing.T) {
			f := NewAutomationFixture(t, 3)
			latchProjectIncarnation(t, f.cluster, nil, nil)
			seedRoles(t, f.cluster)
			// Delay only replicated state, leaving actual Prepare/Accept and
			// automation prefix RPCs live. The lagging node grants on a project
			// name with no row; it cannot see the creator's later first birth.
			for _, from := range f.cluster.Nodes {
				for _, to := range f.cluster.Nodes {
					if from != to {
						f.cluster.SetLinkFault(from, to, LinkFault{Block: true})
					}
				}
			}
			entry, lag := f.cluster.Nodes[0], f.cluster.Nodes[1]
			path, principal := "/projects/"+nativeOwnerProject, "group:operator@local"
			if p, e := corrosion.GetProject(f.Context(), lag.DB, nativeOwnerProject); e != nil || p != nil {
				t.Fatalf("lagging grant must precede the real first birth: %+v %v", p, e)
			}
			grant, e := f.cluster.SelfClient(lag).GrantRole(f.Context(), &pb.GrantRoleRequest{Role: "Operator", Path: path, Principal: principal, Propagate: true})
			if e != nil || grant.GetBinding().GetId() == "" {
				t.Fatalf("actual pre-birth group grant: %v", e)
			}
			id := grant.GetBinding().GetId()
			// This creates the project/account through their guarded owners,
			// enrolls their real lifetimes and obtains a genuine local Login.
			c := newNativeOwnerClientWithFixture(t, f, false)
			if bs, e := corrosion.ListBindingsForPrincipal(f.Context(), entry.DB, principal); e != nil || len(bs) != 0 {
				t.Fatalf("withheld pre-birth grant reached the creator: %+v %v", bs, e)
			}
			// A separate real native success proves this project's current
			// lifetime and session work before the delayed binding arrives.
			control := c
			control.owner = &automationv1.OwnerRef{ProjectUid: c.owner.ProjectUid, OwnerId: "held-project-positive-control"}
			positive, e := control.public.EnsureOwner(control.ctx, &automationv1.EnsureOwnerRequest{Owner: control.owner, RequestId: "held-project-positive-control"})
			if e != nil {
				t.Fatalf("real native positive control: %v", e)
			}
			control.assertDecision(t, positive.GetCursor(), "ensure_owner", "held-project-positive-control", "", 0)
			before := f.Head(t, 0)
			request := "held-project-binding"
			var release func()
			var result <-chan nativeOwnerEnsureResult
			if afterPreflight {
				release, result = nativeOwnerEnsureAt(t, c, request, false)
				nativeOwnerNoAccepted(t, c, before.Sequence+1)
			}
			f.cluster.SetLinkFault(lag, entry, LinkFault{})
			pumpMutations(t, f.cluster, lag, entry)
			binding, e := corrosion.GetRoleBinding(f.Context(), entry.DB, id)
			if e != nil || binding == nil || !binding.Held || binding.Role != "Operator" || binding.Principal != principal {
				t.Fatalf("real delayed grant must be held with permissive raw role intact: %+v %v", binding, e)
			}
			cached := engineOf(t, entry)
			if !cached.HasAnyBinding([]string{principal}) || cached.Allowed([]string{principal}, policy.OwnerManage, path) {
				t.Fatal("held binding must suppress fallback and grant nothing in current cached auth")
			}
			if afterPreflight {
				release()
				r := nativeOwnerAwaitEnsure(t, result)
				if r.response != nil {
					t.Fatal("native FULL authorization admitted a held binding")
				}
				nativeOwnerError(t, r.err, automationv1.ErrorCode_ERROR_CODE_PERMISSION_DENIED)
			} else {
				r, e := c.public.EnsureOwner(c.ctx, &automationv1.EnsureOwnerRequest{Owner: c.owner, RequestId: request})
				if r != nil {
					t.Fatal("preflight admitted a held binding")
				}
				nativeOwnerError(t, e, automationv1.ErrorCode_ERROR_CODE_PERMISSION_DENIED)
			}
			c.assertNoOwnerEffects(t, before, request)
			nativeOwnerNoAccepted(t, c, before.Sequence+1)
			// A genuine grant on the current incarnation restores access even
			// with the held row present; no credential/proof row is repaired.
			nativeOwnerGrant(t, c, "Operator", path, principal, true)
			current, e := c.public.EnsureOwner(c.ctx, &automationv1.EnsureOwnerRequest{Owner: c.owner, RequestId: request})
			if e != nil {
				t.Fatalf("current-incarnation grant did not authorize the real producer: %v", e)
			}
			c.assertDecision(t, current.GetCursor(), "ensure_owner", request, "", 0)
		})
	}
}
