package ui

import (
	"net/http"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// The host page of a held host (offline, fenced or suspect) offers "Confirm
// powered off", which is `lv host fence-confirm`: FenceHost with confirmed and
// confirm_manual_only, under the session's own authority, so the daemon
// authorizes (admin) and audits it as it does for the CLI. An active host
// offers no such button.
//
// Mutations: send FenceHost without ConfirmManualOnly — it would fence the
// host instead, red; show the button for an active host — red.
func TestUIFenceConfirm_CallsFenceConfirm(t *testing.T) {
	mock := newDefaultMock()
	mock.fenceHostResp = &pb.FenceResult{Method: "manual", Result: "manual-confirmed", Detail: "operator confirmation recorded"}
	s := newTestUIServer(t, mock)
	w := serveRequest(s, withAuth(mustReq(t, "POST", "/ui/hosts/host1/fence-confirm")))
	if w.Code != http.StatusOK {
		t.Fatalf("fence-confirm = %d: %s", w.Code, w.Body.String())
	}
	req := mock.lastFenceHostReq
	if req == nil || req.GetName() != "host1" || !req.GetConfirmed() || !req.GetConfirmManualOnly() {
		t.Fatalf("FenceHost request = %+v, want host1 confirmed and confirm_manual_only", req)
	}
	if msg, _ := renderedToast(t, w); !strings.Contains(msg, "host1 confirmed powered off") {
		t.Fatalf("toast %q", msg)
	}

	for _, tc := range []struct {
		state pb.HostState
		want  bool
	}{
		{pb.HostState_HOST_OFFLINE, true},
		{pb.HostState_HOST_FENCED, true},
		{pb.HostState_HOST_SUSPECT, true},
		{pb.HostState_HOST_ACTIVE, false},
	} {
		mock.inspectHostResp = &pb.Host{Name: "host1", State: tc.state}
		body := serveRequest(s, withAuth(mustReq(t, "GET", "/hosts/host1"))).Body.String()
		if got := strings.Contains(body, `hx-post="/ui/hosts/host1/fence-confirm"`); got != tc.want {
			t.Errorf("%s host page offers Confirm powered off: %v, want %v", tc.state, got, tc.want)
		}
	}
}

// A refusal (the host still answers, or the session is not admin) reaches the
// operator with the daemon's words.
func TestUIFenceConfirm_RefusalReachesTheUser(t *testing.T) {
	mock := newDefaultMock()
	mock.fenceHostErr = status.Error(codes.FailedPrecondition, "host1 still answers")
	s := newTestUIServer(t, mock)
	w := serveRequest(s, withAuth(mustReq(t, "POST", "/ui/hosts/host1/fence-confirm")))
	assertRefusalToast(t, "fence-confirm", w, http.StatusBadRequest, "host1 still answers")
}

// The health page flags the hosts fenced only over SSH and recommends ipmi
// or redfish; a BMC host and a host in maintenance are not named.
//
// Mutation: drop the section (SSHOnlyFencing unset) — red.
func TestUIHealth_FlagsSSHOnlyFencing(t *testing.T) {
	mock := newDefaultMock()
	mock.listHostsResp = &pb.ListHostsResponse{Hosts: []*pb.Host{
		{Name: "a", FenceStrategy: "best-effort"},
		{Name: "b", FenceStrategy: "ipmi"},
		{Name: "m", State: pb.HostState_HOST_MAINTENANCE},
	}}
	s := newTestUIServer(t, mock)
	body := serveRequest(s, withAuth(mustReq(t, "GET", "/health"))).Body.String()
	for _, want := range []string{`id="ssh-only-fencing"`, "1 host(s) fence only over SSH", `href="/hosts/a"`,
		"ipmi or redfish", "lv host fence-confirm"} {
		if !strings.Contains(body, want) {
			t.Fatalf("health page lacks %q", want)
		}
	}
	for _, not := range []string{`href="/hosts/b"`, `href="/hosts/m"`} {
		if strings.Contains(body, not) {
			t.Fatalf("health page names %s as SSH-only", not)
		}
	}
	mock.listHostsResp = &pb.ListHostsResponse{Hosts: []*pb.Host{{Name: "b", FenceStrategy: "redfish"}}}
	if body := serveRequest(s, withAuth(mustReq(t, "GET", "/health"))).Body.String(); strings.Contains(body, `id="ssh-only-fencing"`) {
		t.Fatal("an all-BMC cluster's health page flags SSH fencing")
	}
}

// The health page flags the hosts that trust a confirmed SSH power-off, in a
// section of their own.
//
// Mutation: drop the TrustSSHPoweroff data — red.
func TestUIHealth_FlagsTrustedSSHPoweroff(t *testing.T) {
	mock := newDefaultMock()
	mock.listHostsResp = &pb.ListHostsResponse{Hosts: []*pb.Host{
		{Name: "t", FenceStrategy: "ssh", Labels: map[string]string{"litevirt.trust_ssh_poweroff": "true"}},
		{Name: "u", FenceStrategy: "ipmi"},
	}}
	s := newTestUIServer(t, mock)
	body := serveRequest(s, withAuth(mustReq(t, "GET", "/health"))).Body.String()
	i := strings.Index(body, `id="trust-ssh-poweroff"`)
	if i < 0 || !strings.Contains(body[i:], "1 host(s) trust a confirmed SSH power-off") || !strings.Contains(body[i:], "runs them twice") {
		t.Fatal("health page does not flag the host trusting a confirmed SSH power-off")
	}
	mock.listHostsResp = &pb.ListHostsResponse{Hosts: []*pb.Host{{Name: "u", FenceStrategy: "ipmi"}}}
	if body := serveRequest(s, withAuth(mustReq(t, "GET", "/health"))).Body.String(); strings.Contains(body, `id="trust-ssh-poweroff"`) {
		t.Fatal("health page flags trust with no host trusting")
	}
}
