package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/pki"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

type hostRemoveTestClient struct {
	pb.LiteVirtClient
	publishErr error
	calls      []string
	voters     []string // members of the adopted voter generation
	removeReq  *pb.RemoveHostRequest
	removeResp *pb.RemoveHostResponse
	// preflightErr is PreflightRemoveHost's answer; preflightReq the request.
	preflightErr error
	preflightReq *pb.RemoveHostRequest
	// removeErrs are RemoveHost's answers, one per call, before it succeeds.
	removeErrs []error
	planVoter  bool
	// goneAfterRemove lists no host once RemoveHost has been called.
	goneAfterRemove bool
	// hostState and hostAddr are node-9's listed state and address.
	hostState pb.HostState
	hostAddr  string
}

func (c *hostRemoveTestClient) PlanDeadHostRemoval(_ context.Context, req *pb.PlanDeadHostRemovalRequest, _ ...grpc.CallOption) (*pb.PlanDeadHostRemovalResponse, error) {
	return &pb.PlanDeadHostRemovalResponse{Host: req.GetName(), Fenced: true, FenceDetail: "ipmi power off", Voter: c.planVoter}, nil
}

func (c *hostRemoveTestClient) PreflightRemoveHost(_ context.Context, req *pb.RemoveHostRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	c.preflightReq = req
	if c.preflightErr != nil {
		return nil, c.preflightErr
	}
	return &emptypb.Empty{}, nil
}

func (c *hostRemoveTestClient) GetVoterConfig(context.Context, *pb.GetVoterConfigRequest, ...grpc.CallOption) (*pb.GetVoterConfigResponse, error) {
	resp := &pb.GetVoterConfigResponse{AdoptedGeneration: 4, Explicit: len(c.voters) > 0}
	for _, v := range c.voters {
		resp.Members = append(resp.Members, &pb.VoterMemberStatus{Name: v})
	}
	return resp, nil
}

func (c *hostRemoveTestClient) ListHosts(context.Context, *pb.ListHostsRequest, ...grpc.CallOption) (*pb.ListHostsResponse, error) {
	if c.goneAfterRemove && countCalls(c.calls, "remove") > 0 {
		return &pb.ListHostsResponse{}, nil
	}
	return &pb.ListHostsResponse{Hosts: []*pb.Host{{Name: "node-9", CertSerial: "a1b2c3", State: c.hostState, Address: c.hostAddr}}}, nil
}

func (c *hostRemoveTestClient) PublishCRL(context.Context, *pb.PublishCRLRequest, ...grpc.CallOption) (*pb.PublishCRLResponse, error) {
	c.calls = append(c.calls, "publish")
	if c.publishErr != nil {
		return nil, c.publishErr
	}
	return &pb.PublishCRLResponse{Version: 47}, nil
}

func (c *hostRemoveTestClient) RetireAuditKey(context.Context, *pb.RetireAuditKeyRequest, ...grpc.CallOption) (*pb.RetireAuditKeyResponse, error) {
	c.calls = append(c.calls, "retire")
	return nil, errors.New(`rpc error: code = FailedPrecondition desc = host "node-9" has no live audit signing certificate: it either never published one or its key is already retired, so there is nothing to retire`)
}

func (c *hostRemoveTestClient) RemoveHost(_ context.Context, req *pb.RemoveHostRequest, _ ...grpc.CallOption) (*pb.RemoveHostResponse, error) {
	c.calls = append(c.calls, "remove")
	c.removeReq = req
	if len(c.removeErrs) > 0 {
		err := c.removeErrs[0]
		c.removeErrs = c.removeErrs[1:]
		if err != nil {
			return nil, err
		}
	}
	if c.removeResp != nil {
		return c.removeResp, nil
	}
	return &pb.RemoveHostResponse{}, nil
}

// Removing a host tombstones its row and nothing else. The certificate it holds
// still chains to the cluster CA, so peer trust — which now falls back to the
// certificate for a host it has no row for — depends entirely on that tombstone
// reaching every node. A node that never receives it keeps accepting a peer the
// operator decommissioned, and nothing says so.
//
// The CRL is the second, independent mechanism, and every piece of it already
// existed: pki.AppendToCRL, a crl.pem the daemon re-reads on mtime change, and a
// health check that publishes each node's CRL version and warns on a mismatch.
// Nothing called them.

func TestRevokeHostCert_AddsTheSerialToTheCRL(t *testing.T) {
	dir := t.TempDir()
	if err := pki.GenerateCA(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key")); err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	if err := revokeHostCert(dir, "node-9", "a1b2c3"); err != nil {
		t.Fatalf("revokeHostCert: %v", err)
	}
	serials, err := pki.LoadCRL(filepath.Join(dir, "crl.pem"))
	if err != nil {
		t.Fatalf("LoadCRL: %v", err)
	}
	found := false
	for _, s := range serials {
		if strings.EqualFold(s, "a1b2c3") {
			found = true
		}
	}
	if !found {
		t.Fatalf("the removed host's serial is not in the CRL (%v)\n"+
			"removal then rests solely on the tombstone reaching every node, and a node "+
			"that misses it keeps accepting a decommissioned peer", serials)
	}

	// Revoking again must not fail or duplicate — `lv host rm` is re-runnable.
	if err := revokeHostCert(dir, "node-9", "a1b2c3"); err != nil {
		t.Fatalf("second revoke: %v", err)
	}
	if again, _ := pki.LoadCRL(filepath.Join(dir, "crl.pem")); len(again) != len(serials) {
		t.Errorf("re-revoking duplicated the entry: %v -> %v", serials, again)
	}
}

func TestHostRemove_DoesNotTombstoneBeforeRevocationPublishes(t *testing.T) {
	configDir := t.TempDir()
	t.Setenv("LV_CONFIG_DIR", configDir)
	pkiDir := filepath.Join(configDir, "pki")
	if err := os.MkdirAll(pkiDir, 0o700); err != nil {
		t.Fatalf("mkdir pki: %v", err)
	}
	if err := pki.GenerateCA(filepath.Join(pkiDir, "ca.crt"), filepath.Join(pkiDir, "ca.key")); err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	client := &hostRemoveTestClient{publishErr: errors.New("cluster unavailable")}
	if err := HostRemove(context.Background(), client, "node-9", false); err == nil {
		t.Fatal("publish failure reported a successful removal")
	}
	if got := strings.Join(client.calls, ","); got != "publish" {
		t.Fatalf("calls = %q, want publish only; RemoveHost ran before revocation was durable", got)
	}
}

func TestHostRemove_PublishesBeforeTombstoning(t *testing.T) {
	configDir := t.TempDir()
	t.Setenv("LV_CONFIG_DIR", configDir)
	pkiDir := filepath.Join(configDir, "pki")
	if err := os.MkdirAll(pkiDir, 0o700); err != nil {
		t.Fatalf("mkdir pki: %v", err)
	}
	if err := pki.GenerateCA(filepath.Join(pkiDir, "ca.crt"), filepath.Join(pkiDir, "ca.key")); err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	client := &hostRemoveTestClient{}
	if err := HostRemove(context.Background(), client, "node-9", false); err != nil {
		t.Fatalf("HostRemove: %v", err)
	}
	if got := strings.Join(client.calls, ","); got != "publish,retire,remove" {
		t.Fatalf("calls = %q, want publish,retire,remove", got)
	}
}

// TestRevokeHostCert_WithoutTheCAKeySaysSo — `lv host rm` may be run from a node
// that holds no CA private key. That cannot silently skip revocation.
func TestRevokeHostCert_WithoutTheCAKeySaysSo(t *testing.T) {
	dir := t.TempDir()
	if err := pki.GenerateCA(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key")); err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	if err := os.Remove(filepath.Join(dir, "ca.key")); err != nil {
		t.Fatalf("remove ca.key: %v", err)
	}
	err := revokeHostCert(dir, "node-9", "a1b2c3")
	if err == nil {
		t.Fatal("revocation without the CA private key reported success")
	}
	// The bare signing failure already errors, so the explicit check only earns its
	// place by saying WHICH machine can do this — otherwise the operator is told a
	// file is missing without being told where the one that matters lives.
	if !strings.Contains(err.Error(), "lv host init") {
		t.Errorf("the error does not point at the machine holding the CA: %v", err)
	}
}

func TestRevokeHostCert_NoSerialRefusesAnUnrevokableRemoval(t *testing.T) {
	dir := t.TempDir()
	if err := pki.GenerateCA(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key")); err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	for _, serial := range []string{"", "unknown"} {
		if err := revokeHostCert(dir, "node-9", serial); err == nil {
			t.Errorf("serial %q allowed a removal whose certificate cannot be revoked", serial)
		}
	}
}

// ── audit signing contract on removal ───────────────────────────────────────
//
// The 2026-08-01 lab found node-4 re-admitted with its OLD audit signing
// certificate still published and unretired: its fresh daemon would not sign
// (new key, closed-out world) and every row it wrote was reported as
// tampering on every node. `lv host rm` runs where the cluster CA lives — the
// only place a retirement can be signed — so removal must close the contract.

type hostRemoveAuditTestClient struct {
	hostRemoveTestClient
	retireErr error
}

func (c *hostRemoveAuditTestClient) RetireAuditKey(context.Context, *pb.RetireAuditKeyRequest, ...grpc.CallOption) (*pb.RetireAuditKeyResponse, error) {
	c.calls = append(c.calls, "retire")
	return nil, c.retireErr
}

func TestHostRemove_ClosesAuditContractBeforeRemoval(t *testing.T) {
	dir := t.TempDir()
	if err := pki.GenerateCA(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key")); err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	t.Setenv("LV_CONFIG_DIR", filepath.Dir(dir))
	if err := os.Rename(dir, filepath.Join(filepath.Dir(dir), "pki")); err != nil {
		t.Fatalf("stage pki dir: %v", err)
	}

	// The common case for a host that never signed: retirement reports there
	// is nothing to retire. Removal must attempt it and then proceed.
	c := &hostRemoveAuditTestClient{retireErr: errors.New(
		`rpc error: code = FailedPrecondition desc = host "node-9" has no live audit signing certificate: it either never published one or its key is already retired, so there is nothing to retire`)}
	if err := HostRemove(context.Background(), c, "node-9", false); err != nil {
		t.Fatalf("HostRemove with nothing to retire must succeed: %v", err)
	}
	retireIdx, removeIdx := -1, -1
	for i, call := range c.calls {
		switch call {
		case "retire":
			if retireIdx < 0 {
				retireIdx = i
			}
		case "remove":
			removeIdx = i
		}
	}
	if retireIdx < 0 {
		t.Fatal("HostRemove never attempted to close the audit signing contract")
	}
	if removeIdx < retireIdx {
		t.Fatal("audit contract must be probed before the host row is removed")
	}
}

func TestHostRemove_AuditRetirementFailureDoesNotBlockRemoval(t *testing.T) {
	dir := t.TempDir()
	if err := pki.GenerateCA(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key")); err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	t.Setenv("LV_CONFIG_DIR", filepath.Dir(dir))
	if err := os.Rename(dir, filepath.Join(filepath.Dir(dir), "pki")); err != nil {
		t.Fatalf("stage pki dir: %v", err)
	}

	// A lagging replica (or any transient fault) must not wedge removal: the
	// CRL revocation above is the security boundary; the contract can still be
	// closed afterwards with `lv host retire-audit-key`.
	c := &hostRemoveAuditTestClient{retireErr: errors.New("rpc error: code = Unavailable desc = replica lags")}
	if err := HostRemove(context.Background(), c, "node-9", false); err != nil {
		t.Fatalf("HostRemove must warn, not fail, when retirement errs: %v", err)
	}
	found := false
	for _, call := range c.calls {
		if call == "remove" {
			found = true
		}
	}
	if !found {
		t.Fatal("removal did not proceed after a retirement failure")
	}
}

// TestHostRemove_RefusesAVoterBeforeRevoking: `lv host rm` of a current voter
// is refused, naming `lv cluster voter rm` — and refused BEFORE the
// certificate is revoked, because the daemon's own refusal would come after a
// revocation nothing undoes, leaving a voter that can no longer sign.
//
// Mutation: drop the refuseVoterRemoval call — the CRL is published first.
func TestHostRemove_RefusesAVoterBeforeRevoking(t *testing.T) {
	configDir := t.TempDir()
	t.Setenv("LV_CONFIG_DIR", configDir)
	pkiDir := filepath.Join(configDir, "pki")
	if err := os.MkdirAll(pkiDir, 0o700); err != nil {
		t.Fatalf("mkdir pki: %v", err)
	}
	if err := pki.GenerateCA(filepath.Join(pkiDir, "ca.crt"), filepath.Join(pkiDir, "ca.key")); err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	client := &hostRemoveTestClient{voters: []string{"node-1", "node-9"}}
	err := HostRemove(context.Background(), client, "node-9", false)
	if err == nil || !strings.Contains(err.Error(), "lv cluster voter rm node-9") {
		t.Fatalf("removing a voter was not refused with the way forward: %v", err)
	}
	if len(client.calls) != 0 {
		t.Fatalf("calls = %v; nothing may run before the voter check", client.calls)
	}
	if _, err := os.Stat(filepath.Join(pkiDir, "crl.pem")); err == nil {
		t.Fatal("the voter's certificate was revoked before the refusal")
	}
}

// R-I2, R-M5: `lv host rm` asks the daemon to remove only the serial it
// revoked, and prints what was removed — or, from a daemon too old to say,
// the line it always printed.
func TestHostRemove_RemovesOnlyTheRevokedSerialAndSaysSo(t *testing.T) {
	configDir := t.TempDir()
	t.Setenv("LV_CONFIG_DIR", configDir)
	pkiDir := filepath.Join(configDir, "pki")
	if err := os.MkdirAll(pkiDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := pki.GenerateCA(filepath.Join(pkiDir, "ca.crt"), filepath.Join(pkiDir, "ca.key")); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		resp *pb.RemoveHostResponse
		want string
	}{
		{&pb.RemoveHostResponse{CertSerial: "a1b2c3", Incarnation: 2}, "Host node-9 removed (incarnation 2, serial a1b2c3)."},
		{nil, "Host node-9 removed from cluster."},
	} {
		client := &hostRemoveTestClient{removeResp: tc.resp}
		out := captureStdout(t, func() {
			if err := HostRemove(context.Background(), client, "node-9", false); err != nil {
				t.Fatalf("HostRemove: %v", err)
			}
		})
		if client.removeReq.GetExpectedCertSerial() != "a1b2c3" {
			t.Errorf("RemoveHost asked to remove serial %q, want the revoked a1b2c3", client.removeReq.GetExpectedCertSerial())
		}
		if !strings.Contains(out, tc.want) {
			t.Errorf("printed %q, want %q", out, tc.want)
		}
	}
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = old }()
	fn()
	w.Close()
	b, _ := io.ReadAll(r)
	return string(b)
}

// Lab test 26, F5: a removal the daemon would refuse is refused before the
// certificate is revoked, so the member is not cut off from its peers while
// its row stays live. A daemon from before the check (Unimplemented) is not
// asked again.
func TestHostRemove_ARefusedRemovalRevokesNothing(t *testing.T) {
	setup := func(t *testing.T) string {
		configDir := t.TempDir()
		t.Setenv("LV_CONFIG_DIR", configDir)
		pkiDir := filepath.Join(configDir, "pki")
		if err := os.MkdirAll(pkiDir, 0o700); err != nil {
			t.Fatalf("mkdir pki: %v", err)
		}
		if err := pki.GenerateCA(filepath.Join(pkiDir, "ca.crt"), filepath.Join(pkiDir, "ca.key")); err != nil {
			t.Fatalf("GenerateCA: %v", err)
		}
		return pkiDir
	}
	revoked := func(t *testing.T, pkiDir string) bool {
		serials, err := pki.LoadCRL(filepath.Join(pkiDir, "crl.pem"))
		if err != nil {
			return false
		}
		for _, s := range serials {
			if strings.EqualFold(s, "a1b2c3") {
				return true
			}
		}
		return false
	}
	for _, dead := range []bool{false, true} {
		pkiDir := setup(t)
		client := &hostRemoveTestClient{preflightErr: status.Error(codes.Unavailable, "no peer completed the pull")}
		var err error
		if dead {
			err = revokeAndPublishOnly(client)
		} else {
			err = HostRemove(context.Background(), client, "node-9", true)
		}
		if err == nil || !strings.Contains(err.Error(), "no peer completed the pull") {
			t.Errorf("dead=%v: a refused preflight returned %v, want the refusal", dead, err)
		}
		if len(client.calls) != 0 || revoked(t, pkiDir) {
			t.Errorf("dead=%v: calls %v, revoked %v; want nothing revoked, published or removed", dead, client.calls, revoked(t, pkiDir))
		}
		if r := client.preflightReq; r == nil || r.GetExpectedCertSerial() != "a1b2c3" || r.GetDead() != dead || r.GetForce() == dead {
			t.Errorf("dead=%v: preflight request %v, want the removal's own request with the serial", dead, r)
		}
	}
	pkiDir := setup(t)
	client := &hostRemoveTestClient{preflightErr: status.Error(codes.Unimplemented, "unknown method")}
	if err := HostRemove(context.Background(), client, "node-9", false); err != nil || !revoked(t, pkiDir) {
		t.Errorf("against a daemon without the preflight: %v (revoked %v), want the removal as before", err, revoked(t, pkiDir))
	}
}

func revokeAndPublishOnly(c *hostRemoveTestClient) error {
	_, _, err := revokeAndPublish(context.Background(), c, &pb.RemoveHostRequest{Name: "node-9", Dead: true})
	return err
}

// rmTestPKI stages a CA under a fresh LV_CONFIG_DIR and returns its pki dir.
func rmTestPKI(t *testing.T) string {
	t.Helper()
	configDir := t.TempDir()
	t.Setenv("LV_CONFIG_DIR", configDir)
	pkiDir := filepath.Join(configDir, "pki")
	if err := os.MkdirAll(pkiDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := pki.GenerateCA(filepath.Join(pkiDir, "ca.crt"), filepath.Join(pkiDir, "ca.key")); err != nil {
		t.Fatal(err)
	}
	return pkiDir
}

func countCalls(calls []string, name string) int {
	n := 0
	for _, c := range calls {
		if c == name {
			n++
		}
	}
	return n
}

// Re-review m-3(a): once the certificate is revoked and the CRL published, a
// RemoveHost that fails Unavailable (a voter's link flapped between the
// preflight and the removal) is retried, a bounded number of times; a refusal
// of another kind is not; and a removal that still fails names the exact
// command to re-run.
//
// Mutations: call RemoveHost once (no retry) — "transient" fails; retry every
// code — "refused" sees more than one RemoveHost; drop the re-run line —
// "persistent" fails.
func TestHostRemove_RetriesTheRemovalAfterTheRevocation(t *testing.T) {
	old := removeRetryBackoff
	removeRetryBackoff = []time.Duration{0, 0}
	t.Cleanup(func() { removeRetryBackoff = old })
	unavailable := status.Error(codes.Unavailable, "no peer completed the pull")
	for _, dead := range []bool{false, true} {
		run := func(c *hostRemoveTestClient) error {
			if dead {
				return HostRemoveDead(context.Background(), c, "node-9", false)
			}
			return HostRemove(context.Background(), c, "node-9", true)
		}
		rerun := "lv host rm --force node-9"
		if dead {
			rerun = "lv host rm --dead node-9"
		}
		t.Run(fmt.Sprintf("transient dead=%v", dead), func(t *testing.T) {
			rmTestPKI(t)
			c := &hostRemoveTestClient{removeErrs: []error{unavailable, unavailable}}
			if err := run(c); err != nil {
				t.Fatalf("a removal that succeeds on its third attempt: %v", err)
			}
			if n := countCalls(c.calls, "remove"); n != 3 {
				t.Errorf("RemoveHost called %d times, want 3", n)
			}
		})
		t.Run(fmt.Sprintf("persistent dead=%v", dead), func(t *testing.T) {
			rmTestPKI(t)
			c := &hostRemoveTestClient{removeErrs: []error{unavailable, unavailable, unavailable, unavailable}}
			err := run(c)
			if err == nil || !strings.Contains(err.Error(), rerun) {
				t.Errorf("a removal that never succeeds: %v, want the re-run command %q", err, rerun)
			}
			if n := countCalls(c.calls, "remove"); n != 3 {
				t.Errorf("RemoveHost called %d times, want 3", n)
			}
		})
		t.Run(fmt.Sprintf("refused dead=%v", dead), func(t *testing.T) {
			rmTestPKI(t)
			c := &hostRemoveTestClient{removeErrs: []error{status.Error(codes.FailedPrecondition, "host has VMs")}}
			if err := run(c); err == nil {
				t.Fatal("a refused removal reported success")
			}
			if n := countCalls(c.calls, "remove"); n != 1 {
				t.Errorf("RemoveHost called %d times for a FailedPrecondition, want 1", n)
			}
		})
	}
}

// eqts final check m-C: a retried RemoveHost whose earlier attempt removed
// the host but lost its reply is answered NotFound. The removal completed, so
// the command reports success; a NotFound on the first attempt is still an
// error, since nothing this command did removed the host.
//
// Mutations: treat NotFound as a refusal on every attempt — "reply lost"
// fails; on every attempt as success — "first attempt" passes a removal
// this command never made; skip the ListHosts check — "still listed"
// reports a live host removed.
func TestHostRemove_ARetryAfterALostReplyIsTheRemoval(t *testing.T) {
	old := removeRetryBackoff
	removeRetryBackoff = []time.Duration{0, 0}
	t.Cleanup(func() { removeRetryBackoff = old })
	unavailable := status.Error(codes.Unavailable, "context deadline exceeded")
	notFound := status.Error(codes.NotFound, `host "node-9" not found`)
	for _, dead := range []bool{false, true} {
		run := func(c *hostRemoveTestClient) error {
			if dead {
				return HostRemoveDead(context.Background(), c, "node-9", false)
			}
			return HostRemove(context.Background(), c, "node-9", false)
		}
		t.Run(fmt.Sprintf("reply lost dead=%v", dead), func(t *testing.T) {
			rmTestPKI(t)
			c := &hostRemoveTestClient{removeErrs: []error{unavailable, notFound}, goneAfterRemove: true}
			if err := run(c); err != nil {
				t.Errorf("a removal whose first reply was lost: %v", err)
			}
		})
		// fd review I2: the daemon also answers NotFound when it could not
		// read the row. A host still listed is not removed.
		t.Run(fmt.Sprintf("still listed dead=%v", dead), func(t *testing.T) {
			rmTestPKI(t)
			c := &hostRemoveTestClient{removeErrs: []error{unavailable, notFound}}
			err := run(c)
			if err == nil || !strings.Contains(err.Error(), "the certificate is revoked; run") {
				t.Errorf("a NotFound for a host still listed = %v, want the rerun", err)
			}
		})
		t.Run(fmt.Sprintf("first attempt dead=%v", dead), func(t *testing.T) {
			rmTestPKI(t)
			c := &hostRemoveTestClient{removeErrs: []error{notFound}}
			if err := run(c); err == nil {
				t.Error("a NotFound on the first attempt reported success")
			}
		})
	}
}

// Re-review n-3: `lv host rm --dead --dry-run` asks the daemon whether it
// would make the removal, so the dry run does not report a plan the removal
// would refuse; it still revokes, publishes and removes nothing.
//
// Mutation: return before the preflight in the dry-run branch — the refusal
// is not reported and no preflight request is seen.
func TestHostRemoveDead_TheDryRunRunsThePreflight(t *testing.T) {
	pkiDir := rmTestPKI(t)
	c := &hostRemoveTestClient{preflightErr: status.Error(codes.Unavailable, "no peer completed the pull")}
	err := HostRemoveDead(context.Background(), c, "node-9", true)
	if err == nil || !strings.Contains(err.Error(), "no peer completed the pull") {
		t.Errorf("a dry run the removal would refuse: %v, want the refusal", err)
	}
	if r := c.preflightReq; r == nil || !r.GetDead() || r.GetExpectedCertSerial() != "a1b2c3" {
		t.Errorf("preflight request %v, want the dead removal's own request with the serial", r)
	}
	if len(c.calls) != 0 {
		t.Errorf("calls = %v; a dry run changes nothing", c.calls)
	}
	if _, err := os.Stat(filepath.Join(pkiDir, "crl.pem")); err == nil {
		t.Error("a dry run revoked the certificate")
	}
	ok := &hostRemoveTestClient{}
	if err := HostRemoveDead(context.Background(), ok, "node-9", true); err != nil || ok.preflightReq == nil || len(ok.calls) != 0 {
		t.Errorf("a dry run the removal would make: %v (preflight %v, calls %v)", err, ok.preflightReq, ok.calls)
	}
	// A voter: the daemon refuses to remove a voter's host until the real
	// run has removed the vote, so the dry run does not ask.
	voter := &hostRemoveTestClient{planVoter: true, preflightErr: status.Error(codes.FailedPrecondition, "node-9 is a member of voter generation 1")}
	if err := HostRemoveDead(context.Background(), voter, "node-9", true); err != nil || voter.preflightReq != nil || len(voter.calls) != 0 {
		t.Errorf("a voter's dry run: %v (preflight %v, calls %v), want no preflight and no change", err, voter.preflightReq, voter.calls)
	}
}

// fd re-review N-m3: an add stranded after its admission leaves the admitted
// pair staged on the host for a rerun. When the operator removes the joining
// host instead, `lv host rm` removes that staged pair (only the one of the
// serial it revoked), best-effort: a host it cannot reach does not fail the
// removal. Nothing is attempted for a host that is not joining.
//
// Mutation: never call the cleanup — "joining" sees no call; call it for
// every host — "active" sees one.
func TestHostRemove_RemovesAStrandedAddsStagedPair(t *testing.T) {
	type call struct{ addr, serial string }
	for _, tc := range []struct {
		name  string
		state pb.HostState
		fail  error
		want  int
	}{
		{"joining", pb.HostState_HOST_JOINING, nil, 1},
		{"joining unreachable", pb.HostState_HOST_JOINING, errors.New("no route to host"), 1},
		{"active", pb.HostState_HOST_ACTIVE, nil, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rmTestPKI(t)
			var calls []call
			old := removeStagedAdmission
			removeStagedAdmission = func(addr, serial string) error {
				calls = append(calls, call{addr, serial})
				return tc.fail
			}
			t.Cleanup(func() { removeStagedAdmission = old })
			c := &hostRemoveTestClient{hostState: tc.state, hostAddr: "10.0.0.9"}
			// A failed cleanup is an unfinished removal, reported as one
			// (TestHostRemove_AJoiningHostsFailedCleanupNamesItsFinish).
			if err := HostRemove(context.Background(), c, "node-9", false); (err != nil) != (tc.fail != nil) {
				t.Fatalf("removal: %v", err)
			}
			if len(calls) != tc.want {
				t.Fatalf("staged-pair cleanup called %d times, want %d", len(calls), tc.want)
			}
			if tc.want == 1 && (calls[0].addr != "10.0.0.9" || calls[0].serial != "a1b2c3") {
				t.Errorf("cleanup asked for %+v, want 10.0.0.9 and the revoked serial", calls[0])
			}
		})
	}
}

// fd re-review 2 N2-m2, Codex cand30 I2: the cleanup deletes only what the
// add admitted with the revoked serial staged: the files tagged with it, and
// an earlier release's untagged pair only when its certificate is that
// serial. Another attempt's staged files on the machine, and the machine's
// installed identity, are not touched, which is also what makes a dial to a
// reused address harmless.
//
// Codex 612c78ba N-M1: a symlinked config's staged copy, beside its target,
// goes too.
//
// Mutations: delete untagged staged files whatever their serial — "another
// serial" loses the legacy pair; drop the key check — "the revoked
// certificate beside another key" loses the other key; delete every attempt's tagged files — the
// other attempt's pair goes; leave the resolved config — its stage is left.
func TestRemoveStagedPair_OnlyTheRevokedSerial(t *testing.T) {
	dir := t.TempDir()
	if err := pki.GenerateCA(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key")); err != nil {
		t.Fatal(err)
	}
	mint := func(name string) ([]byte, []byte, string) {
		crt, key := filepath.Join(dir, name+".crt"), filepath.Join(dir, name+".key")
		if err := pki.GenerateHostCert(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"), crt, key, "node-9", nil); err != nil {
			t.Fatal(err)
		}
		c, _ := os.ReadFile(crt)
		k, _ := os.ReadFile(key)
		serial, _ := pki.CertSerial(crt)
		return c, k, strings.ToLower(serial)
	}
	revokedCrt, revokedKey, revoked := mint("revoked")
	otherCrt, otherKey, other := mint("other")
	for _, tc := range []struct {
		name string
		// legacy is the untagged pair an earlier release staged, if any.
		legacy, legacyKey []byte
		legacyGone        bool
	}{
		{"tagged", nil, nil, false},
		{"the revoked serial untagged", revokedCrt, revokedKey, true},
		{"another serial untagged", otherCrt, otherKey, false},
		// Codex ec8 I2: the certificate claimed before an older add staged a
		// new pair, the key after: not one pair, so nothing goes.
		{"the revoked certificate beside another key", revokedCrt, otherKey, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pkiDir := t.TempDir()
			r := &LocalAddTarget{Root: t.TempDir(), PKIDir: pkiDir}
			put := func(path string, b []byte) {
				t.Helper()
				if err := os.MkdirAll(filepath.Dir(r.Path(path)), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(r.Path(path), b, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			crt, key := filepath.Join(remotePKIDir, "host.crt"), filepath.Join(remotePKIDir, "host.key")
			put(crt, otherCrt) // the machine's installed identity
			put(key, otherKey)
			// The config is a symlink: an add stages it beside its target.
			target := "/srv/litevirt/node.yaml"
			put(target, []byte("host_name: node-9\n"))
			if err := os.MkdirAll(filepath.Dir(r.Path(remoteConfig)), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(r.Path(target), r.Path(remoteConfig)); err != nil {
				t.Fatal(err)
			}
			staged := append(addStagedTargets(), target)
			// Two attempts admitted with the revoked serial (a rerun's), and
			// one with another.
			for _, p := range staged {
				put(addStagedPath(p, revoked+"-0a"), []byte("revoked attempt"))
				put(addStagedPath(p, revoked+"-0b"), []byte("revoked rerun"))
				put(addStagedPath(p, other+"-0c"), []byte("other attempt"))
			}
			put(addStagedPath(crt, revoked+"-0a"), revokedCrt)
			put(addStagedPath(key, revoked+"-0a"), revokedKey)
			if tc.legacy != nil {
				put(legacyStagedPath(crt), tc.legacy)
				put(legacyStagedPath(key), tc.legacyKey)
			}
			if err := removeStagedPair(r, strings.ToUpper(revoked)); err != nil {
				t.Fatal(err)
			}
			exists := func(path string) bool { _, err := os.Stat(r.Path(path)); return err == nil }
			for _, p := range staged {
				for _, n := range []string{"-0a", "-0b"} {
					if exists(addStagedPath(p, revoked+n)) {
						t.Errorf("the revoked admission's %s (attempt %s) is left staged", p, n)
					}
				}
				if !exists(addStagedPath(p, other+"-0c")) {
					t.Errorf("another admission's staged %s was removed", p)
				}
			}
			if !exists(crt) || !exists(key) || !exists(target) {
				t.Error("the machine's installed identity or config was removed")
			}
			if tc.legacy != nil && (exists(legacyStagedPath(crt)) == tc.legacyGone || exists(legacyStagedPath(key)) == tc.legacyGone) {
				t.Errorf("the untagged staged pair: crt left %v, key left %v, want removed %v",
					exists(legacyStagedPath(crt)), exists(legacyStagedPath(key)), tc.legacyGone)
			}
		})
	}
}

// Codex 6c258 I1: removal's cleanup read the install record of the revoked
// serial and then removed the file by name, without the add lock: a re-add
// that installed and wrote its own record in between lost it, and a second
// add of the machine under another name could install over it. The record is
// removed only under the lock, re-read there, and only those bytes.
//
// Mutations: remove by name after the first read — "a re-add wrote its record
// meanwhile" loses it; remove without the lock — "an add holds the machine"
// loses it.
func TestRemoveInstalledMarker_OnlyTheRecordOfTheRevokedInstall(t *testing.T) {
	const revoked = "0a0a"
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, r *LocalAddTarget) func()
		left  string
	}{
		{"the revoked install", nil, ""},
		{"another install", func(t *testing.T, r *LocalAddTarget) func() {
			writeMarker(t, r, "node-9 0b0b 1 bb\n")
			return func() {}
		}, "node-9 0b0b 1 bb\n"},
		{"a re-add wrote its record meanwhile", func(t *testing.T, r *LocalAddTarget) func() {
			old := afterMarkerRead
			afterMarkerRead = func() { writeMarker(t, r, "node-9 0b0b 2 bb\n") }
			return func() { afterMarkerRead = old }
		}, "node-9 0b0b 2 bb\n"},
		{"an add holds the machine", func(t *testing.T, r *LocalAddTarget) func() {
			old := addLockWait
			addLockWait = 1
			release := holdAddLock(t, r)
			return func() { release(); addLockWait = old }
		}, "node-9 0a0a 1 aa\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			r := &LocalAddTarget{Root: root, PKIDir: filepath.Join(root, "etc", "litevirt", "pki")}
			writeMarker(t, r, "node-9 "+revoked+" 1 aa\n")
			if tc.setup != nil {
				defer tc.setup(t, r)()
			}
			err := releaseInstallRecord(r, revoked, releaseRemoved)
			if tc.name == "an add holds the machine" && err == nil {
				t.Error("removal while an add holds the machine reported success")
			}
			got, rerr := os.ReadFile(r.Path(addInstalledMarker))
			if tc.left == "" {
				if !os.IsNotExist(rerr) {
					t.Errorf("the revoked install's record is left: %q", got)
				}
				return
			}
			if string(got) != tc.left {
				t.Errorf("record = %q, want %q kept", got, tc.left)
			}
		})
	}
}

func writeMarker(t *testing.T, r *LocalAddTarget, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(r.Path(addInstalledMarker)), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(r.Path(addInstalledMarker), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// Codex 446f3a39 I1: removal's cleanup checked the install record under the
// lock and then sent the removal as a command of its own. Delayed past its
// ten-second connection, that command ran after the lock was gone and after
// a re-add had installed and written its record, and removed it. The check
// and the removal are one command now, run by the process that holds the
// lock: the late command finds the re-add's record and leaves it.
//
// Mutation: remove the record by name in the command — the re-add's record
// is lost.
func TestRemoveInstalledMarker_ALateRemovalLeavesAReaddsRecord(t *testing.T) {
	root := t.TempDir()
	local := &LocalAddTarget{Root: root, PKIDir: filepath.Join(root, "etc", "litevirt", "pki")}
	r := &deferringTarget{LocalAddTarget: local, kind: "unstage"}
	writeMarker(t, local, "node-9 0a0a 1 aa\n")
	_ = releaseInstallRecord(r, "0a0a", releaseRemoved)
	if len(r.deferred) == 0 {
		t.Fatal("the removal issued no command")
	}
	// The connection and its lock are gone; a re-add installs and records.
	writeMarker(t, local, "node-9 0b0b 2 bb installed\n")
	r.runDeferred(t)
	got, err := os.ReadFile(local.Path(addInstalledMarker))
	if err != nil || string(got) != "node-9 0b0b 2 bb installed\n" {
		t.Errorf("the re-add's record = %q, %v; want it kept", got, err)
	}
}
