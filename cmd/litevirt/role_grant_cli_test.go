package main

import (
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// O11: the CLI asks the daemon to refuse a bare user principal, which would
// be stored as a binding no caller ever matches.
func TestRoleGrant_AsksTheDaemonToRefuseAnInertPrincipal(t *testing.T) {
	m := newMockClient()
	if _, _, err := runCmd(t, m, "role", "grant", "Admin", "user:alice@local", "--path", "/"); err != nil {
		t.Fatalf("role grant: %v", err)
	}
	if m.lastGrantRoleReq == nil || !m.lastGrantRoleReq.RefuseInertPrincipal {
		t.Fatalf("GrantRole request %+v: want refuse_inert_principal", m.lastGrantRoleReq)
	}
}

// A daemon that predates refuse_inert_principal stores a bare principal
// anyway; the CLI says the binding it got back grants nothing.
func TestRoleGrant_WarnsWhenAnOlderDaemonStoredAnInertPrincipal(t *testing.T) {
	m := newMockClient()
	m.grantRoleResp = &pb.GrantRoleResponse{Binding: &pb.RoleBinding{Id: "b1", Path: "/", Role: "Admin", Principal: "user:alice"}}
	_, stderr, err := runCmd(t, m, "role", "grant", "Admin", "user:alice", "--path", "/")
	if err != nil {
		t.Fatalf("role grant: %v", err)
	}
	if !strings.Contains(stderr, "never match") || !strings.Contains(stderr, "user:alice@local") ||
		!strings.Contains(stderr, "lv role revoke b1") {
		t.Fatalf("stderr %q: want a warning naming the inert binding and the fix", stderr)
	}

	m.grantRoleResp = &pb.GrantRoleResponse{Binding: &pb.RoleBinding{Id: "b2", Path: "/", Role: "Admin", Principal: "user:alice@local"}}
	_, stderr, err = runCmd(t, m, "role", "grant", "Admin", "user:alice@local", "--path", "/")
	if err != nil {
		t.Fatalf("role grant: %v", err)
	}
	if strings.Contains(stderr, "never match") {
		t.Fatalf("a qualified binding drew the inert warning: %q", stderr)
	}
}

// The help no longer teaches the bare form.
func TestRoleGrant_HelpExamplesAreRealmQualified(t *testing.T) {
	cmd := newRoleGrantCmd()
	for _, line := range strings.Split(cmd.Long, "\n") {
		if strings.Contains(line, "lv role grant") && strings.Contains(line, "user:") &&
			!strings.Contains(line, "@local") && !strings.Contains(line, "@oidc:") && !strings.Contains(line, "@ldap:") {
			t.Errorf("help example uses a bare user principal: %q", line)
		}
	}
}
