package grpcapi

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// The full-state dump carries secret-bearing columns of replicated tables —
// hosts.ipmi_pass, users.password_hash, tokens.token_hash — because the repair
// representation must be byte-faithful. So the dump is peer-only: an operator or
// admin bearer, or a non-host client certificate, is refused, and a trusted peer
// still receives every one of those columns (colonelpanik/litevirt#268).
const (
	dumpIPMIPass     = "ipmi-secret-7f3a"
	dumpPasswordHash = "$2a$10$pw-hash-secret-91c2"
	dumpTokenHash    = "$2a$10$token-hash-secret-44be"
)

func seedDumpSecrets(t *testing.T, s *Server) {
	t.Helper()
	ctx := context.Background()
	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{
		Name: "bmc-host", Address: "10.0.0.20", State: "active",
	}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}
	// InsertHost does not write the BMC credentials; `lv host fence-config` does.
	if err := s.db.Execute(ctx,
		`UPDATE hosts SET fence_strategy = 'ipmi', ipmi_address = '10.0.1.20', ipmi_user = 'root', ipmi_pass = ?, updated_at = ? WHERE name = 'bmc-host'`,
		dumpIPMIPass, s.db.NowTS()); err != nil {
		t.Fatalf("set ipmi_pass: %v", err)
	}
	if err := corrosion.InsertUser(ctx, s.db, "alice", "operator", dumpPasswordHash); err != nil {
		t.Fatalf("InsertUser: %v", err)
	}
	if err := corrosion.InsertToken(ctx, s.db, corrosion.TokenRecord{
		ID: "tok-1", Username: "alice", Name: "ci", TokenHash: dumpTokenHash,
	}); err != nil {
		t.Fatalf("InsertToken: %v", err)
	}
}

func gunzipDump(t *testing.T, data []byte) []byte {
	t.Helper()
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("gzip: %v", err)
	}
	out, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("gunzip: %v", err)
	}
	return out
}

func assertDumpCarriesSecrets(t *testing.T, name string, data []byte) {
	t.Helper()
	plain := gunzipDump(t, data)
	for _, secret := range []string{dumpIPMIPass, dumpPasswordHash, dumpTokenHash} {
		if !bytes.Contains(plain, []byte(secret)) {
			t.Errorf("%s: peer dump is missing %q — repair must stay unredacted", name, secret)
		}
	}
}

func TestStateDump_PeerOnly(t *testing.T) {
	s := testServer(t)
	seedDumpSecrets(t, s)
	peerCtx := peerCtxFor(t, s, "peer-1")

	nonPeers := map[string]context.Context{
		"operator bearer": userCtx("op", "operator"),
		"admin bearer":    adminCtx(),
		// A bearerless lv-cli client certificate classifies as admin, but it is
		// not a cluster host and must not read the dump either.
		"client cert": lvCLICertCtx("lv-cli"),
	}
	for name, ctx := range nonPeers {
		if _, err := s.GetStateDump(ctx, &emptypb.Empty{}); status.Code(err) != codes.PermissionDenied {
			t.Errorf("GetStateDump %s: code = %v, want PermissionDenied (err=%v)", name, status.Code(err), err)
		}
		stream := &fakeDumpStream{ctx: ctx}
		if err := s.StreamStateDump(&emptypb.Empty{}, stream); status.Code(err) != codes.PermissionDenied {
			t.Errorf("StreamStateDump %s: code = %v, want PermissionDenied (err=%v)", name, status.Code(err), err)
		}
		if len(stream.chunks) != 0 {
			t.Errorf("StreamStateDump %s: sent %d chunks before refusing", name, len(stream.chunks))
		}
	}

	resp, err := s.GetStateDump(peerCtx, &emptypb.Empty{})
	if err != nil {
		t.Fatalf("GetStateDump peer: %v", err)
	}
	assertDumpCarriesSecrets(t, "GetStateDump", resp.GetData())

	stream := &fakeDumpStream{ctx: peerCtx}
	if err := s.StreamStateDump(&emptypb.Empty{}, stream); err != nil {
		t.Fatalf("StreamStateDump peer: %v", err)
	}
	var blob []byte
	for _, c := range stream.chunks {
		blob = append(blob, c.GetData()...)
	}
	assertDumpCarriesSecrets(t, "StreamStateDump", blob)
}

// lvCLICertCtx is a bearerless mTLS caller whose certificate is not a cluster
// host's (the distributable lv-cli cert): admin role, principal kind client.
func lvCLICertCtx(cn string) context.Context {
	ctx := context.WithValue(adminCtx(), ctxKeyAuthMethod, authMethodMTLS)
	ctx = context.WithValue(ctx, ctxKeyMTLSCommonName, cn)
	return context.WithValue(ctx, ctxKeyPrincipalKind, principalKindClient)
}

// unrowedPeerCtx is the trusted cluster peer node-1 with no hosts row yet —
// trusted on its ServerAuth host certificate alone, as during bootstrap — so a
// test can authenticate as a peer without adding a row to the state it dumps.
func unrowedPeerCtx() context.Context {
	ctx := context.WithValue(hostCertCtx(), ctxKeyUsername, "admin")
	ctx = context.WithValue(ctx, ctxKeyRole, "admin")
	ctx = context.WithValue(ctx, ctxKeyAuthMethod, authMethodMTLS)
	ctx = context.WithValue(ctx, ctxKeyMTLSCommonName, "node-1")
	return context.WithValue(ctx, ctxKeyPrincipalKind, principalKindPeer)
}
