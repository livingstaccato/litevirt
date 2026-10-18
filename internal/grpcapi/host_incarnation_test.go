package grpcapi

import (
	"context"
	"errors"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fence"
	"github.com/litevirt/litevirt/internal/health"
)

// The incarnation counter's operator side (host_incarnation.go). Test numbers
// are the design's (eqts-report.md, section 7).

// incServer is a seeded, caught-up server holding a peer and host-x's
// tombstone at incarnation n (0 or 1), last admitted with serial "01old".
func incServer(t *testing.T, n int) *Server {
	t.Helper()
	ctx := context.Background()
	s := testServer(t)
	for _, h := range []string{s.hostName, "peer-host"} {
		if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{Name: h, Address: "10.0.0.1", State: "active", CertSerial: "s-" + h}); err != nil {
			t.Fatal(err)
		}
	}
	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{Name: "host-x", Address: "10.0.0.9", State: "active", CertSerial: "01old"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.DB().Exec(`UPDATE hosts SET incarnation = ? WHERE name = 'host-x'`, n); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.DeleteHost(ctx, s.db, "host-x"); err != nil {
		t.Fatal(err)
	}
	s.db.MarkAuditSeededForTests()
	s.db.MarkReplicaCaughtUpForTests("peer-host")
	return s
}

func incOf(t *testing.T, s *Server, name string) (int64, bool) {
	t.Helper()
	n, _, _, deleted, found, err := corrosion.HostIncarnationOf(context.Background(), s.db, name)
	if err != nil || !found {
		t.Fatalf("read %s: found=%v err=%v", name, found, err)
	}
	return n, deleted
}

// unavailableFeatureGate is a release gate whose feature is not available.
type unavailableFeatureGate struct{ err error }

func (g unavailableFeatureGate) WithFeature(context.Context, capabilities.Feature,
	func(context.Context, capabilities.FeatureGrant) error) error {
	return g.err
}
func (g unavailableFeatureGate) FeatureAvailable(capabilities.Feature) bool { return false }

// Test 1 (C1): the re-admit statement follows the tombstone, never the grant.
func TestAdmitHost_ShapeFollowsTheTombstone(t *testing.T) {
	t.Run("tombstone at 0, feature unavailable: legacy", func(t *testing.T) {
		s := incServer(t, 0)
		s.SetReleaseFeatureGate(unavailableFeatureGate{})
		resp, err := admit(s, "host-x")
		if err != nil {
			t.Fatal(err)
		}
		if n, deleted := incOf(t, s, "host-x"); n != 0 || deleted {
			t.Errorf("row = (%d, deleted %v), want live at 0", n, deleted)
		}
		// Lab test 26, F1: the response says why no incarnation was issued.
		if why := resp.GetIncarnationNotIssued(); !strings.Contains(why, "host_incarnation") {
			t.Errorf("incarnation_not_issued = %q, want the reason naming host_incarnation", why)
		}
	})
	t.Run("tombstone at 0, feature available: V2 at 1", func(t *testing.T) {
		s := incServer(t, 0)
		s.SetReleaseFeatureGate(&scriptedFeatureGate{t: t})
		if _, err := admit(s, "host-x"); err != nil {
			t.Fatal(err)
		}
		if n, deleted := incOf(t, s, "host-x"); n != 1 || deleted {
			t.Errorf("row = (%d, deleted %v), want live at 1", n, deleted)
		}
	})
	t.Run("tombstone at 1, latch not durable: refused", func(t *testing.T) {
		s := incServer(t, 1)
		s.SetReleaseFeatureGate(unavailableFeatureGate{err: status.Error(codes.FailedPrecondition, "release not latched")})
		_, err := admit(s, "host-x")
		if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "release not latched") {
			t.Errorf("admission over a counted tombstone without the feature = %v, want the gate's refusal passed through", err)
		}
		if n, deleted := incOf(t, s, "host-x"); n != 1 || !deleted {
			t.Errorf("row = (%d, deleted %v), want the tombstone at 1 untouched", n, deleted)
		}
	})
	t.Run("tombstone at 1, no gate at all: refused", func(t *testing.T) {
		s := incServer(t, 1)
		s.SetReleaseFeatureGate(nil)
		if _, err := admit(s, "host-x"); err == nil {
			t.Error("admitted over a counted tombstone with no release gate")
		}
		if _, deleted := incOf(t, s, "host-x"); !deleted {
			t.Error("the tombstone was re-admitted by the legacy statement")
		}
	})
	t.Run("tombstone at 0, the gate is Unavailable: the legacy statement, and the response says why (I-5)", func(t *testing.T) {
		s := incServer(t, 0)
		g := &scriptedFeatureGate{t: t, fn: func(context.Context, int) error {
			return status.Error(codes.Unavailable, "not yet acknowledged by node-9 — retry")
		}}
		s.SetReleaseFeatureGate(g)
		resp, err := admit(s, "host-x")
		if err != nil {
			t.Fatalf("admission = %v, want the legacy fallback", err)
		}
		if !strings.Contains(resp.GetIncarnationNotIssued(), "not yet acknowledged by node-9") {
			t.Errorf("incarnation_not_issued = %q, want the gate's reason", resp.GetIncarnationNotIssued())
		}
		if n, deleted := incOf(t, s, "host-x"); n != 0 || deleted {
			t.Errorf("row = (%d, deleted %v), want live at 0", n, deleted)
		}
	})
	t.Run("tombstone at 1, the gate is Unavailable: refused, never downgraded, message passed through", func(t *testing.T) {
		s := incServer(t, 1)
		g := &scriptedFeatureGate{t: t, fn: func(context.Context, int) error {
			return status.Error(codes.Unavailable, "not yet acknowledged by node-9 — retry")
		}}
		s.SetReleaseFeatureGate(g)
		_, err := admit(s, "host-x")
		if status.Code(err) != codes.Unavailable || !strings.Contains(err.Error(), "not yet acknowledged by node-9") ||
			strings.Contains(err.Error(), "finished the upgrade") {
			t.Errorf("admission = %v, want Unavailable with the gate's message", err)
		}
		if _, deleted := incOf(t, s, "host-x"); !deleted {
			t.Error("a failed grant downgraded to the legacy re-admission over a counted tombstone")
		}
	})
	t.Run("tombstone at 1 with the grant: V2 at 2", func(t *testing.T) {
		s := incServer(t, 1)
		s.SetReleaseFeatureGate(&scriptedFeatureGate{t: t})
		if _, err := admit(s, "host-x"); err != nil {
			t.Fatal(err)
		}
		if n, deleted := incOf(t, s, "host-x"); n != 2 || deleted {
			t.Errorf("row = (%d, deleted %v), want live at 2", n, deleted)
		}
	})
}

// Lab test 26, F2: a re-admission that would issue an incarnation, made by a
// previous release's lv (it names no release it installs), is refused with
// the commands that bring the host in; the tombstone is left alone. Over a
// tombstone at 0 with the feature unavailable it is the previous release's
// re-admission, which that build keeps, and is not refused.
func TestAdmitHost_APreviousReleaseLvIsNotGivenAnIncarnation(t *testing.T) {
	for _, n := range []int{0, 1} {
		s := incServer(t, n)
		s.SetReleaseFeatureGate(&scriptedFeatureGate{t: t})
		_, err := admitFrom(s, "host-x", false)
		if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "lv host upgrade host-x") ||
			!strings.Contains(err.Error(), "this release's CLI") {
			t.Errorf("tombstone at %d: admission from a previous release's lv = %v, want FailedPrecondition naming the fix", n, err)
		}
		if got, deleted := incOf(t, s, "host-x"); got != int64(n) || !deleted {
			t.Errorf("tombstone at %d: row = (%d, deleted %v), want the tombstone untouched", n, got, deleted)
		}
	}
	s := incServer(t, 0)
	s.SetReleaseFeatureGate(unavailableFeatureGate{})
	if _, err := admitFrom(s, "host-x", false); err != nil {
		t.Errorf("a previous-release re-admission at 0 before the feature: %v, want the legacy admission", err)
	}
}

// quorumGate is a gate whose quorum a test sets, counted with or without the
// target as excluded says.
type quorumGate struct {
	flipExecGate
	full, excluding health.QuorumState
}

func (g *quorumGate) QuorumProof(context.Context) (health.QuorumState, int, int) { return g.full, 1, 2 }
func (g *quorumGate) QuorumProofExcluding(context.Context, string) (health.QuorumState, int, int) {
	return g.excluding, 1, 2
}

// fakePuller is the anti-entropy a currency pull goes through.
type fakePuller struct {
	err      error
	pulls    int
	pull     func()
	excluded []string
}

func (p *fakePuller) RunOnce(context.Context) bool { return true }
func (p *fakePuller) PullTableNow(_ context.Context, _, exclude string) (string, []string, error) {
	p.pulls++
	p.excluded = append(p.excluded, exclude)
	if p.pull != nil {
		p.pull()
	}
	if p.err != nil {
		return "", nil, p.err
	}
	return "peer-host", nil, nil
}

// Test 16 (I3, R-I1, R-I2, R-M1, R-M2): the operator's hosts writes.
func TestOperatorHostsWrites_RefuseWhenNotCaughtUp(t *testing.T) {
	ctx := context.Background()
	lagging := func(t *testing.T) *Server {
		s := testServer(t)
		for _, h := range []string{s.hostName, "peer-host", "host-y"} {
			if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{Name: h, Address: "10.0.0.1", State: "active", CertSerial: "s-" + h}); err != nil {
				t.Fatal(err)
			}
		}
		s.SetHostWriteCurrencyCheck(true)
		s.db.MarkReplicaStale("test: lagging")
		return s
	}
	s := lagging(t)
	ratio := 2.0
	for name, call := range map[string]func() error{
		"RemoveHost": func() error {
			_, err := s.RemoveHost(adminCtx(), &pb.RemoveHostRequest{Name: "host-y", Force: true})
			return err
		},
		"ConfigureHost": func() error {
			_, err := s.ConfigureHost(adminCtx(), &pb.ConfigureHostRequest{Name: "host-y", CpuOvercommit: &ratio})
			return err
		},
		"SetHostLabels": func() error {
			_, err := s.SetHostLabels(adminCtx(), &pb.SetHostLabelsRequest{Name: "host-y", Labels: map[string]string{"k": "v"}})
			return err
		},
		"UndrainHost": func() error {
			_, err := s.UndrainHost(adminCtx(), &pb.UndrainHostRequest{Name: "host-y"})
			return err
		},
		"IsolateHost": func() error {
			_, err := s.IsolateHost(adminCtx(), &pb.IsolateHostRequest{Name: "host-y"})
			return err
		},
	} {
		if err := call(); status.Code(err) != codes.Unavailable || !strings.Contains(err.Error(), "caught up") {
			t.Errorf("%s on a lagging node = %v, want the caught-up refusal", name, err)
		}
	}
	if _, deleted := incOf(t, s, "host-y"); deleted {
		t.Error("a lagging node removed host-y")
	}

	t.Run("FenceHost is exempt and names what it fenced through", func(t *testing.T) {
		s := lagging(t)
		s.SetFenceExecutor(func(context.Context, fence.HostConfig) fence.Result {
			return fence.Result{Success: true, Method: "ssh", Detail: "powered off"}
		})
		res, err := s.FenceHost(adminCtx(), &pb.FenceHostRequest{Name: "host-y", Confirmed: true})
		if err != nil {
			t.Fatalf("FenceHost on a lagging node: %v", err)
		}
		if !strings.Contains(res.GetDetail(), "incarnation 0") || !strings.Contains(res.GetDetail(), "serial s-host-y") {
			t.Errorf("fence detail %q does not name the incarnation and serial", res.GetDetail())
		}
	})

	t.Run("RemoveHost reports what it removed, and only the serial the CLI revoked", func(t *testing.T) {
		s := incServer(t, 0)
		if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{Name: "host-z", Address: "10.0.0.5", State: "active", CertSerial: "zz01"}); err != nil {
			t.Fatal(err)
		}
		_, err := s.RemoveHost(adminCtx(), &pb.RemoveHostRequest{Name: "host-z", Force: true, ExpectedCertSerial: "other"})
		if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "run `lv host rm` again") {
			t.Errorf("removal of another serial = %v, want FailedPrecondition", err)
		}
		resp, err := s.RemoveHost(adminCtx(), &pb.RemoveHostRequest{Name: "host-z", Force: true, ExpectedCertSerial: "ZZ01"})
		if err != nil {
			t.Fatal(err)
		}
		if resp.GetCertSerial() != "zz01" || resp.GetIncarnation() != 0 {
			t.Errorf("RemoveHost = %+v, want serial zz01 at incarnation 0", resp)
		}
		// An empty expected serial (an older CLI) is not checked.
		if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{Name: "host-w", Address: "10.0.0.6", State: "active", CertSerial: "ww01"}); err != nil {
			t.Fatal(err)
		}
		if _, err := s.RemoveHost(adminCtx(), &pb.RemoveHostRequest{Name: "host-w", Force: true}); err != nil {
			t.Errorf("a removal with no expected serial: %v", err)
		}
	})

	t.Run("a re-admission landing between the CLI's read and the removal is refused", func(t *testing.T) {
		s := incServer(t, 0)
		if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{Name: "host-z", Address: "10.0.0.5", State: "active", CertSerial: "zz01"}); err != nil {
			t.Fatal(err)
		}
		// The currency pull brings a re-admission of host-z under a new serial.
		s.SetAntiEntropy(&fakePuller{pull: func() {
			s.db.DB().Exec(`UPDATE hosts SET cert_serial = 'zz02', incarnation = 1 WHERE name = 'host-z'`)
		}})
		_, err := s.RemoveHost(adminCtx(), &pb.RemoveHostRequest{Name: "host-z", Force: true, ExpectedCertSerial: "zz01"})
		if status.Code(err) != codes.FailedPrecondition {
			t.Errorf("removal after a re-admission landed = %v, want FailedPrecondition", err)
		}
		if _, deleted := incOf(t, s, "host-z"); deleted {
			t.Error("the new machine was removed under the old machine's revocation")
		}
	})

	t.Run("a failed currency pull refuses", func(t *testing.T) {
		s := incServer(t, 0)
		s.SetReleaseFeatureGate(&scriptedFeatureGate{t: t})
		p := &fakePuller{err: errors.New("no peer answered")}
		s.SetAntiEntropy(p)
		if _, err := admit(s, "host-x"); status.Code(err) != codes.Unavailable {
			t.Errorf("AdmitHost with a failed pull = %v, want Unavailable", err)
		}
		if _, err := s.RemoveHost(adminCtx(), &pb.RemoveHostRequest{Name: "peer-host", Force: true}); status.Code(err) != codes.Unavailable {
			t.Errorf("RemoveHost with a failed pull = %v, want Unavailable", err)
		}
		if p.pulls != 2 {
			t.Errorf("pulls = %d, want one per decision", p.pulls)
		}
		if strings.Join(p.excluded, ",") != "host-x,peer-host" {
			t.Errorf("pulls excluded %v, want the target of each decision", p.excluded)
		}
	})

	t.Run("quorum", func(t *testing.T) {
		for _, st := range []health.QuorumState{health.QuorumNo, health.QuorumUnknown} {
			s := incServer(t, 0)
			s.SetReleaseFeatureGate(&scriptedFeatureGate{t: t})
			s.SetGate(&quorumGate{full: st, excluding: st})
			_, err := admit(s, "host-x")
			if status.Code(err) != codes.Unavailable || !strings.Contains(err.Error(), "voter") {
				t.Errorf("%v: AdmitHost (V2) = %v, want the quorum refusal", st, err)
			}
			_, err = s.RemoveHost(adminCtx(), &pb.RemoveHostRequest{Name: "peer-host", Force: true})
			if status.Code(err) != codes.Unavailable || !strings.Contains(err.Error(), "voter") {
				t.Errorf("%v: RemoveHost = %v, want the quorum refusal", st, err)
			}
		}
		// The target does not vote on its own removal: a two-node cluster
		// with its other node down can still remove it.
		s := incServer(t, 0)
		s.SetGate(&quorumGate{full: health.QuorumNo, excluding: health.QuorumYes})
		if _, err := s.RemoveHost(adminCtx(), &pb.RemoveHostRequest{Name: "peer-host", Force: true}); err != nil {
			t.Errorf("removal of the only other voter, counted without it: %v", err)
		}
		// A first admission issues no number and is not gated.
		s = incServer(t, 0)
		s.SetGate(&quorumGate{full: health.QuorumNo, excluding: health.QuorumNo})
		// At its own address: host-x is admitted below at admit's.
		if _, err := admitAt(s, "brand-new", "10.0.0.8"); err != nil {
			t.Errorf("a first admission under no quorum: %v", err)
		}
		// Nor a re-admission before the feature.
		s.SetReleaseFeatureGate(unavailableFeatureGate{})
		if _, err := admit(s, "host-x"); err != nil {
			t.Errorf("a legacy re-admission under no quorum: %v", err)
		}
	})

	t.Run("a cluster of one is its own majority", func(t *testing.T) {
		s := testServer(t)
		if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{Name: s.hostName, Address: "10.0.0.1", State: "active", CertSerial: "me"}); err != nil {
			t.Fatal(err)
		}
		if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{Name: "host-x", Address: "10.0.0.9", State: "active", CertSerial: "01old"}); err != nil {
			t.Fatal(err)
		}
		if _, err := s.db.DB().Exec(`UPDATE hosts SET deleted_at = updated_at WHERE name = 'host-x'`); err != nil {
			t.Fatal(err)
		}
		s.db.MarkAuditSeededForTests()
		s.SetReleaseFeatureGate(&scriptedFeatureGate{t: t})
		s.SetGate(&quorumGate{full: health.QuorumUnknown, excluding: health.QuorumUnknown})
		if _, err := admit(s, "host-x"); err != nil {
			t.Errorf("a cluster of one re-adding a host: %v", err)
		}
	})
}
