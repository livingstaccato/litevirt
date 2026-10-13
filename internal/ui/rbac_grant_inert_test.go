package ui

import (
	"net/url"
	"testing"
)

// O11: the UI grant form asks the daemon to refuse a bare user principal,
// which would be stored as a binding that never matches anyone.
func TestRBACGrant_AsksTheDaemonToRefuseAnInertPrincipal(t *testing.T) {
	mock := newDefaultMock()
	s := newTestUIServer(t, mock)
	serveRequest(s, authReq(t, "POST", "/ui/rbac/bindings", url.Values{
		"path": {"/"}, "role": {"operator"}, "principal": {"user:alice"},
	}))
	if got := mock.lastGrantRoleReq; got == nil || !got.RefuseInertPrincipal {
		t.Fatalf("GrantRole request %+v: want refuse_inert_principal", got)
	}
}
