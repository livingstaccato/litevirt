package grpcapi

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

const testRedfishPass = "rf-bmc-s3cret"

func redfishRequest() *pb.ConfigureHostRequest {
	return &pb.ConfigureHostRequest{
		Name: "h", FenceStrategy: "redfish",
		RedfishEndpoint: "https://10.0.1.1:8000", RedfishUser: "admin", RedfishPass: testRedfishPass,
		RedfishSystemId: "node-1", RedfishAuth: "basic",
	}
}

func redfishTestServer(t *testing.T) *Server {
	t.Helper()
	s := testServerR2(t)
	if err := corrosion.InsertHost(adminCtx(), s.db, corrosion.HostRecord{Name: "h", Address: "10.0.0.1", State: "active"}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}
	return s
}

func redfishRows(t *testing.T, s *Server) int {
	t.Helper()
	rows, err := s.db.Query(adminCtx(), `SELECT 1 AS one FROM host_fence_redfish`)
	if err != nil {
		t.Fatal(err)
	}
	return len(rows)
}

// TestConfigureHost_RedfishGatedOnReleaseFeature: a 'redfish' fence strategy
// and the Redfish row are the release feature redfish_fence. A previous-release
// peer cannot decode the row and reads the strategy as best-effort SSH, so
// until every host runs this build both are refused — with nothing written —
// while every setting the previous release had still works.
func TestConfigureHost_RedfishGatedOnReleaseFeature(t *testing.T) {
	s := redfishTestServer(t) // no release-feature gate wired: fail closed
	ctx := adminCtx()
	for name, req := range map[string]*pb.ConfigureHostRequest{
		"strategy+settings": redfishRequest(),
		"settings-only":     {Name: "h", RedfishEndpoint: "https://10.0.1.1", RedfishUser: "a", RedfishPass: "b"},
	} {
		_, err := s.ConfigureHost(ctx, req)
		if status.Code(err) != codes.FailedPrecondition ||
			!strings.Contains(err.Error(), "the cluster upgrade must finish first (redfish_fence needs "+capabilities.ReleaseToken+")") {
			t.Errorf("%s: want the release refusal naming redfish_fence, got %v", name, err)
		}
	}
	refusal := status.Error(codes.FailedPrecondition, "the cluster upgrade must finish first (redfish_fence needs "+capabilities.ReleaseToken+"): x")
	s.SetReleaseFeatureGate(fakeFeatureGate{err: refusal})
	if _, err := s.ConfigureHost(ctx, redfishRequest()); !errors.Is(err, refusal) {
		t.Errorf("want the gate's refusal unchanged, got %v", err)
	}
	if h, _ := corrosion.GetHost(ctx, s.db, "h"); h == nil || h.FenceStrategy == "redfish" || h.Redfish.Configured() {
		t.Fatalf("a refused redfish config was written: %+v", h)
	}
	if n := redfishRows(t, s); n != 0 {
		t.Fatalf("a refused redfish config left %d row(s)", n)
	}
	// What the previous release does is not refused: other strategies, other
	// settings, and a --clear-redfish of a host that has no Redfish settings.
	for _, req := range []*pb.ConfigureHostRequest{
		{Name: "h", FenceStrategy: "ssh"},
		{Name: "h", Role: "worker", Region: "eu"},
		{Name: "h", ClearRedfish: true},
	} {
		if _, err := s.ConfigureHost(ctx, req); err != nil {
			t.Errorf("ConfigureHost(%v) with the gate closed: %v", req, err)
		}
	}
	if n := redfishRows(t, s); n != 0 {
		t.Errorf("a clear with nothing to clear wrote %d row(s)", n)
	}
}

// TestConfigureHost_RedfishSettingsLiveOnTheSensitiveLane: through the gate,
// the settings land in host_fence_redfish, every fence reads them from there,
// and the password is nowhere on the hosts row or in the reply.
func TestConfigureHost_RedfishSettingsLiveOnTheSensitiveLane(t *testing.T) {
	s := redfishTestServer(t)
	s.SetReleaseFeatureGate(fakeFeatureGate{t: t, grant: true})
	ctx := adminCtx()
	out, err := s.ConfigureHost(ctx, redfishRequest())
	if err != nil {
		t.Fatalf("ConfigureHost: %v", err)
	}
	if out.FenceStrategy != "redfish" || out.RedfishEndpoint != "https://10.0.1.1:8000" ||
		out.RedfishSystemId != "node-1" || out.RedfishAuth != "basic" {
		t.Errorf("reply = %+v", out)
	}
	if strings.Contains(out.String(), testRedfishPass) {
		t.Errorf("the reply carries the Redfish password")
	}
	h, err := corrosion.GetHost(ctx, s.db, "h")
	if err != nil || h == nil {
		t.Fatalf("GetHost: %v", err)
	}
	if h.Redfish.Pass != testRedfishPass || h.Redfish.User != "admin" || h.Redfish.Endpoint != "https://10.0.1.1:8000" {
		t.Errorf("stored Redfish = %+v", h.Redfish)
	}
	rows, err := s.db.Query(ctx, `SELECT * FROM hosts WHERE name = 'h'`)
	if err != nil || len(rows) != 1 {
		t.Fatal(err)
	}
	for _, col := range rows[0].Columns {
		if strings.Contains(rows[0].String(col), testRedfishPass) {
			t.Errorf("hosts.%s carries the Redfish password", col)
		}
	}

	// A later request naming one field keeps the others.
	if _, err := s.ConfigureHost(ctx, &pb.ConfigureHostRequest{Name: "h", RedfishPass: "rotated"}); err != nil {
		t.Fatalf("rotate the password: %v", err)
	}
	h, _ = corrosion.GetHost(ctx, s.db, "h")
	if h.Redfish.Pass != "rotated" || h.Redfish.Endpoint != "https://10.0.1.1:8000" || h.Redfish.SystemID != "node-1" ||
		h.Redfish.Auth != "basic" || h.FenceStrategy != "redfish" {
		t.Errorf("after a password-only update: strategy %q, %+v", h.FenceStrategy, h.Redfish)
	}
}

// TestConfigureHost_RedfishRefusals: a configuration a fence could not use is
// refused when it is set, never discovered in an outage.
func TestConfigureHost_RedfishRefusals(t *testing.T) {
	ctx := adminCtx()
	cases := map[string]struct {
		req  *pb.ConfigureHostRequest
		code codes.Code
	}{
		"http":           {&pb.ConfigureHostRequest{Name: "h", RedfishEndpoint: "http://10.0.1.1", RedfishUser: "a", RedfishPass: "b"}, codes.InvalidArgument},
		"auth":           {&pb.ConfigureHostRequest{Name: "h", RedfishEndpoint: "https://10.0.1.1", RedfishAuth: "digest"}, codes.InvalidArgument},
		"bad-ca":         {&pb.ConfigureHostRequest{Name: "h", RedfishEndpoint: "https://10.0.1.1", RedfishCaPem: "nope"}, codes.InvalidArgument},
		"no-endpoint":    {&pb.ConfigureHostRequest{Name: "h", RedfishUser: "a"}, codes.InvalidArgument},
		"strategy-bare":  {&pb.ConfigureHostRequest{Name: "h", FenceStrategy: "redfish"}, codes.FailedPrecondition},
		"strategy-nopw":  {&pb.ConfigureHostRequest{Name: "h", FenceStrategy: "redfish", RedfishEndpoint: "https://10.0.1.1", RedfishUser: "a"}, codes.FailedPrecondition},
		"clear-and-set":  {&pb.ConfigureHostRequest{Name: "h", ClearRedfish: true, RedfishUser: "a"}, codes.InvalidArgument},
		"unknown-method": {&pb.ConfigureHostRequest{Name: "h", FenceStrategy: "drac"}, codes.InvalidArgument},
	}
	for name, tc := range cases {
		s := redfishTestServer(t)
		s.SetReleaseFeatureGate(fakeFeatureGate{t: t, grant: true})
		if _, err := s.ConfigureHost(ctx, tc.req); status.Code(err) != tc.code {
			t.Errorf("%s: got %v, want %s", name, err, tc.code)
		}
		if n := redfishRows(t, s); n != 0 {
			t.Errorf("%s: a refused request wrote %d row(s)", name, n)
		}
	}
}

// TestConfigureHost_ClearRedfish: --clear-redfish tombstones the row, and is
// refused while the host would be left fencing by redfish with nothing to
// authenticate with.
func TestConfigureHost_ClearRedfish(t *testing.T) {
	s := redfishTestServer(t)
	s.SetReleaseFeatureGate(fakeFeatureGate{t: t, grant: true})
	ctx := adminCtx()
	if _, err := s.ConfigureHost(ctx, redfishRequest()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConfigureHost(ctx, &pb.ConfigureHostRequest{Name: "h", ClearRedfish: true}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("clear on a redfish-fenced host: got %v, want FailedPrecondition", err)
	}
	out, err := s.ConfigureHost(ctx, &pb.ConfigureHostRequest{Name: "h", FenceStrategy: "ssh", ClearRedfish: true})
	if err != nil {
		t.Fatalf("clear with another strategy: %v", err)
	}
	if out.RedfishEndpoint != "" || out.FenceStrategy != "ssh" {
		t.Errorf("reply after clear = %+v", out)
	}
	h, _ := corrosion.GetHost(ctx, s.db, "h")
	if h.Redfish.Configured() || h.Redfish.Pass != "" {
		t.Errorf("after clear the host still has %+v", h.Redfish)
	}
	rows, err := s.db.Query(ctx, `SELECT password, deleted_at FROM host_fence_redfish WHERE host_name = 'h'`)
	if err != nil || len(rows) != 1 || rows[0].String("password") != "" || rows[0].String("deleted_at") == "" {
		t.Errorf("redfish row after clear: %v %v", rows, err)
	}
}

// The row's writer takes redfish_fence's grant: without one it writes nothing.
func TestHostFenceRedfishStatement_NeedsTheGrant(t *testing.T) {
	if _, err := hostFenceRedfishStatement(capabilities.FeatureGrant{}, "h", nil, "ts"); !errors.Is(err, capabilities.ErrNoFeatureGrant) {
		t.Errorf("zero grant: %v, want ErrNoFeatureGrant", err)
	}
	g := capabilities.GrantForTest(t, capabilities.FeatureVMLimits)
	if _, err := hostFenceRedfishStatement(g, "h", nil, "ts"); !errors.Is(err, capabilities.ErrNoFeatureGrant) {
		t.Errorf("another feature's grant: %v, want ErrNoFeatureGrant", err)
	}
}

// A 'redfish' fence strategy on its own is redfish_fence's data too: a host
// whose Redfish settings already exist, switched back to redfish, goes through
// the gate, and a refusing gate (a node quarantined, say) leaves its strategy
// as it was.
func TestConfigureHost_RedfishStrategyAloneIsGated(t *testing.T) {
	s := redfishTestServer(t)
	s.SetReleaseFeatureGate(fakeFeatureGate{t: t, grant: true})
	ctx := adminCtx()
	if _, err := s.ConfigureHost(ctx, redfishRequest()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConfigureHost(ctx, &pb.ConfigureHostRequest{Name: "h", FenceStrategy: "ssh"}); err != nil {
		t.Fatalf("switch to ssh: %v", err)
	}
	refusal := status.Error(codes.FailedPrecondition, "the cluster upgrade must finish first (redfish_fence needs "+capabilities.ReleaseToken+"): x")
	s.SetReleaseFeatureGate(fakeFeatureGate{err: refusal})
	if _, err := s.ConfigureHost(ctx, &pb.ConfigureHostRequest{Name: "h", FenceStrategy: "redfish"}); !errors.Is(err, refusal) {
		t.Fatalf("strategy-only redfish with a refusing gate: %v, want the gate's refusal", err)
	}
	if h, _ := corrosion.GetHost(ctx, s.db, "h"); h == nil || h.FenceStrategy != "ssh" {
		t.Errorf("a refused strategy change was written: %+v", h)
	}
}

// The system id and the CA bundle can each be unset on its own (an empty field
// means "leave alone", so it needs its own flag), keeping every other setting,
// and the host keeps fencing by redfish throughout.
func TestConfigureHost_RedfishUnsetOneSetting(t *testing.T) {
	s := redfishTestServer(t)
	s.SetReleaseFeatureGate(fakeFeatureGate{t: t, grant: true})
	ctx := adminCtx()
	req := redfishRequest()
	req.RedfishCaPem = testCAPEM(t)
	out, err := s.ConfigureHost(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if !out.RedfishCaConfigured || out.RedfishSystemId != "node-1" {
		t.Fatalf("reply = %+v", out)
	}
	if out, err = s.ConfigureHost(ctx, &pb.ConfigureHostRequest{Name: "h", ClearRedfishSystemId: true}); err != nil {
		t.Fatalf("unset system id: %v", err)
	}
	h, _ := corrosion.GetHost(ctx, s.db, "h")
	if h.Redfish.SystemID != "" || h.Redfish.CACert == "" || h.Redfish.Pass != testRedfishPass || h.FenceStrategy != "redfish" {
		t.Errorf("after unsetting the system id: %s %+v", h.FenceStrategy, h.Redfish)
	}
	if out, err = s.ConfigureHost(ctx, &pb.ConfigureHostRequest{Name: "h", ClearRedfishCa: true}); err != nil {
		t.Fatalf("unset CA: %v", err)
	}
	if out.RedfishCaConfigured {
		t.Error("reply still reports a CA bundle")
	}
	h, _ = corrosion.GetHost(ctx, s.db, "h")
	if h.Redfish.CACert != "" || h.Redfish.Endpoint != "https://10.0.1.1:8000" || h.Redfish.Auth != "basic" || h.Redfish.Pass != testRedfishPass {
		t.Errorf("after unsetting the CA: %+v", h.Redfish)
	}
	for _, bad := range []*pb.ConfigureHostRequest{
		{Name: "h", ClearRedfishSystemId: true, RedfishSystemId: "x"},
		{Name: "h", ClearRedfishCa: true, RedfishCaPem: req.RedfishCaPem},
		{Name: "h", ClearRedfish: true, ClearRedfishCa: true, FenceStrategy: "ssh"},
	} {
		if _, err := s.ConfigureHost(ctx, bad); status.Code(err) != codes.InvalidArgument {
			t.Errorf("%v: got %v, want InvalidArgument", bad, err)
		}
	}
}

// testCAPEM is a PEM certificate for a CA bundle setting.
func testCAPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "bmc-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}
