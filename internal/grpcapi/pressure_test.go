package grpcapi

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pressure"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"
)

// fakePressure is a fixed sampler report.
type fakePressure struct{ rep pressure.Report }

func (f *fakePressure) Report() pressure.Report { return f.rep }

func degradedReport(level pressure.Level) pressure.Report {
	since := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	return pressure.Report{
		Level: level, Since: since, TimeToFull: 90 * time.Minute,
		Resources: []pressure.ResourceReport{
			{Name: "data_dir.space", Level: level, Since: since, Free: 6, Total: 100, Unit: "bytes", FreePct: 6, TimeToFull: 90 * time.Minute},
			{Name: "fds.daemon", Level: pressure.OK, Since: since, Free: 900, Total: 1000, Unit: "fds", FreePct: 90},
		},
	}
}

// Pressure is orthogonal to readiness: a critical host still answers
// ready=true, so it keeps its weight in every peer's quorum. The level and the
// pressured resources go to any caller; the per-resource detail only to a
// host certificate, as not_ready_reason does.
func TestReady_PressureNeverMakesAHostUnready(t *testing.T) {
	s := testServer(t)
	insertReadyHost(t, s, "test-host")
	s.SetPressureSource(&fakePressure{rep: degradedReport(pressure.Critical)})

	resp, err := s.Ready(hostCertCtx(), &pb.ReadyRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if !resp.GetReady() {
		t.Fatalf("a critical host answered ready=false (%q): pressure must never cost a host its quorum weight", resp.GetNotReadyReason())
	}
	p := resp.GetPressure()
	if p.GetLevel() != "critical" || len(p.GetResources()) != 1 || p.GetResources()[0] != "data_dir.space" {
		t.Fatalf("pressure %+v, want critical on data_dir.space", p)
	}
	if p.GetTimeToFullSec() != 5400 || p.GetSince() != "2026-10-21T12:00:00Z" {
		t.Fatalf("pressure %+v, want time_to_full 5400 and since 12:00", p)
	}
	if len(p.GetDetail()) != 2 {
		t.Fatalf("host-cert caller: %d detail rows, want 2", len(p.GetDetail()))
	}

	resp, err = s.Ready(context.Background(), &pb.ReadyRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetPressure().GetLevel() != "critical" {
		t.Fatalf("operator caller: level %q, want critical (the level is not withheld)", resp.GetPressure().GetLevel())
	}
	if len(resp.GetPressure().GetDetail()) != 0 {
		t.Fatal("operator caller: detail disclosed, want it withheld (paths and sizes)")
	}
}

func TestReady_NoSamplerAnswersNoPressure(t *testing.T) {
	s := testServer(t)
	insertReadyHost(t, s, "test-host")
	resp, _ := s.Ready(context.Background(), &pb.ReadyRequest{})
	if resp.Pressure != nil {
		t.Fatalf("pressure %+v with no sampler, want absent", resp.Pressure)
	}
}

func TestPeerReady_RecordsThePeersPressure(t *testing.T) {
	s := serverWithPeerReady(t, readyClient{resp: &pb.ReadyResponse{HostName: "host-b", Ready: true,
		Pressure: &pb.HostPressure{Level: "degrade", Resources: []string{"pool.default.space"}}}})
	if v := s.PeerPressure("host-b"); v.Answered || v.Level() != "unknown" {
		t.Fatalf("before any probe: %+v level %q, want unanswered and unknown", v, v.Level())
	}
	ready, _, err := s.PeerReady(context.Background(), "host-b", "127.0.0.1:1")
	if err != nil || !ready {
		t.Fatalf("PeerReady = %v, %v", ready, err)
	}
	v := s.PeerPressure("host-b")
	if !v.Answered || v.Level() != "degrade" || v.Asked.IsZero() {
		t.Fatalf("after the probe: %+v level %q, want answered degrade", v, v.Level())
	}
}

// A peer on a build that predates the field (or with pressure off) answers
// without it, and an even older one answers Unimplemented. Both are unknown,
// never ok.
func TestPeerReady_NoPressureFieldIsUnknown(t *testing.T) {
	for name, c := range map[string]readyClient{
		"nil field":     {resp: &pb.ReadyResponse{HostName: "host-b", Ready: true}},
		"unimplemented": {err: status.Error(codes.Unimplemented, "unknown method Ready")},
	} {
		s := serverWithPeerReady(t, c)
		if _, _, err := s.PeerReady(context.Background(), "host-b", "127.0.0.1:1"); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		v := s.PeerPressure("host-b")
		if !v.Answered || v.Level() != "unknown" {
			t.Errorf("%s: %+v level %q, want answered and unknown", name, v, v.Level())
		}
	}
	// A probe that did not arrive leaves the last answer standing.
	s := serverWithPeerReady(t, readyClient{resp: &pb.ReadyResponse{HostName: "host-b", Ready: true, Pressure: &pb.HostPressure{Level: "warn"}}})
	s.PeerReady(context.Background(), "host-b", "127.0.0.1:1")
	s.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) {
		return readyClient{err: status.Error(codes.Unavailable, "down")}, func() {}, nil
	}
	s.PeerReady(context.Background(), "host-b", "127.0.0.1:1")
	if l := s.PeerPressure("host-b").Level(); l != "warn" {
		t.Fatalf("after an unreachable probe: %q, want the last answer (warn)", l)
	}
}

// oldReadyResponseType is ReadyResponse as a build before field 8 knows it.
func oldReadyResponseType(t *testing.T) protoreflect.MessageType {
	t.Helper()
	fdp := protodesc.ToFileDescriptorProto(pb.File_litevirt_v1_service_proto)
	var found bool
	for _, m := range fdp.MessageType {
		if m.GetName() != "ReadyResponse" {
			continue
		}
		var keep []*descriptorpb.FieldDescriptorProto
		for _, f := range m.Field {
			if f.GetNumber() != 8 {
				keep = append(keep, f)
			}
		}
		m.Field, found = keep, true
	}
	if !found {
		t.Fatal("no ReadyResponse in service.proto")
	}
	// Imports resolve from the global registry; the edited file itself is
	// built standalone, not registered.
	fd, err := protodesc.NewFile(fdp, protoregistry.GlobalFiles)
	if err != nil {
		t.Fatalf("build the old descriptor: %v", err)
	}
	return dynamicpb.NewMessageType(fd.Messages().ByName("ReadyResponse"))
}

// An old peer decodes a new answer: the verdict and every field it knows
// survive, and the pressure it does not know is skipped.
func TestReadyResponse_AnOldDecoderIgnoresPressure(t *testing.T) {
	b, err := proto.Marshal(&pb.ReadyResponse{HostName: "host-b", Ready: true, PartitionPause: true, HaKnown: true,
		Pressure: &pb.HostPressure{Level: "critical", Resources: []string{"data_dir.space"}}})
	if err != nil {
		t.Fatal(err)
	}
	mt := oldReadyResponseType(t)
	if mt.Descriptor().Fields().ByNumber(8) != nil {
		t.Fatal("the old type still has field 8")
	}
	old := mt.New().Interface()
	if err := proto.Unmarshal(b, old); err != nil {
		t.Fatalf("an old decoder refused the new answer: %v", err)
	}
	fields := old.ProtoReflect().Descriptor().Fields()
	get := func(name string) protoreflect.Value {
		return old.ProtoReflect().Get(fields.ByName(protoreflect.Name(name)))
	}
	if get("host_name").String() != "host-b" || !get("ready").Bool() || !get("partition_pause").Bool() || !get("ha_known").Bool() {
		t.Fatalf("old decode lost known fields: %v", old)
	}
}

func pressureCond(t *testing.T, s *Server, host string) (corrosion.HealthCondition, bool) {
	t.Helper()
	c, ok, err := corrosion.GetHealthCondition(context.Background(), s.db, PressureEvaluator, CondHostPressure, "host", host)
	if err != nil {
		t.Fatal(err)
	}
	return c, ok
}

// The lease holder writes host.pressure for every host from what it knows:
// its own sampler for itself, each peer's latest probe answer for the peer.
// It resolves it at ok and when a host answers with no pressure; a host it has
// no answer from is left as it is.
func TestPressureHealthTick_RaisesAndResolves(t *testing.T) {
	ctx := context.Background()
	src := &fakePressure{rep: degradedReport(pressure.Degrade)}
	resp := &pb.ReadyResponse{HostName: "host-b", Ready: true, Pressure: &pb.HostPressure{Level: "critical", Resources: []string{"data_dir.space"}}}
	c := readyClient{resp: resp}
	s := serverWithPeerReady(t, c)
	insertReadyHost(t, s, "test-host")
	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{Name: "host-b", Address: "10.0.0.2", SSHUser: "root", State: "active"}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{Name: "host-c", Address: "10.0.0.3", SSHUser: "root", State: "active"}); err != nil {
		t.Fatal(err)
	}
	s.SetPressureSource(src)
	s.PeerReady(ctx, "host-b", "127.0.0.1:1")
	// host-c was pressured when a previous lease holder last heard from it,
	// and this node has heard nothing since: its condition is left standing.
	if err := corrosion.UpsertHealthCondition(ctx, s.db, corrosion.HealthCondition{Evaluator: PressureEvaluator,
		Code: CondHostPressure, SubjectKind: "host", SubjectID: "host-c", Lifecycle: corrosion.ConditionConfirmed,
		Severity: corrosion.SeverityWarning, Reporter: "host-b"}); err != nil {
		t.Fatal(err)
	}

	s.PressureHealthTick(ctx)
	if c, _ := pressureCond(t, s, "host-c"); c.Lifecycle != corrosion.ConditionConfirmed || c.Reporter != "host-b" {
		t.Fatalf("host-c, never answered this run: %+v, want its condition untouched", c)
	}
	self, ok := pressureCond(t, s, "test-host")
	if !ok || self.Lifecycle != corrosion.ConditionObserved || self.Severity != corrosion.SeverityWarning {
		t.Fatalf("self at degrade: %+v (found %v), want observed warning", self, ok)
	}
	var ev map[string]any
	if err := json.Unmarshal([]byte(self.Evidence), &ev); err != nil || ev["level"] != "degrade" || ev["time_to_full_sec"] != float64(5400) {
		t.Fatalf("self evidence %s (%v)", self.Evidence, err)
	}
	peer, ok := pressureCond(t, s, "host-b")
	if !ok || peer.Severity != corrosion.SeverityCritical {
		t.Fatalf("host-b at critical: %+v (found %v), want critical", peer, ok)
	}

	// Unchanged: confirmed once, then no write per tick.
	s.PressureHealthTick(ctx)
	self, _ = pressureCond(t, s, "test-host")
	if self.Lifecycle != corrosion.ConditionConfirmed {
		t.Fatalf("second tick: %s, want confirmed", self.Lifecycle)
	}
	before := mutationCount(t, s)
	for i := 0; i < 5; i++ {
		s.PressureHealthTick(ctx)
	}
	if after := mutationCount(t, s); after != before {
		t.Fatalf("five unchanged ticks wrote %d rows, want none", after-before)
	}

	// Back to ok, and a peer that answers without pressure: both resolved.
	src.rep = pressure.Report{Level: pressure.OK}
	c.resp = &pb.ReadyResponse{HostName: "host-b", Ready: true}
	s.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) { return c, func() {}, nil }
	s.PeerReady(ctx, "host-b", "127.0.0.1:1")
	s.PressureHealthTick(ctx)
	for _, h := range []string{"test-host", "host-b"} {
		if c, _ := pressureCond(t, s, h); c.Lifecycle != corrosion.ConditionResolved {
			t.Errorf("%s: %s, want resolved", h, c.Lifecycle)
		}
	}
}

func mutationCount(t *testing.T, s *Server) int {
	t.Helper()
	rows, err := s.db.Query(context.Background(), `SELECT COUNT(*) AS n FROM mutation_log`)
	if err != nil {
		t.Fatal(err)
	}
	return int(rows[0].Int("n"))
}

// lv host inspect shows the host's pressure: its own sampler for the
// answering daemon, the probe answer for a peer, unknown for a host that never
// said.
func TestInspectHost_ShowsPressure(t *testing.T) {
	ctx := adminCtx()
	s := serverWithPeerReady(t, readyClient{resp: &pb.ReadyResponse{HostName: "host-b", Ready: true,
		Pressure: &pb.HostPressure{Level: "warn", Resources: []string{"data_dir.inodes"}}}})
	insertReadyHost(t, s, "test-host")
	for _, h := range []string{"host-b", "host-c"} {
		if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{Name: h, Address: "10.0.0.9", SSHUser: "root", State: "active"}); err != nil {
			t.Fatal(err)
		}
	}
	s.SetPressureSource(&fakePressure{rep: degradedReport(pressure.Degrade)})
	s.PeerReady(context.Background(), "host-b", "127.0.0.1:1")

	for host, want := range map[string]string{"test-host": "degrade", "host-b": "warn", "host-c": "unknown"} {
		h, err := s.InspectHost(ctx, &pb.InspectHostRequest{Name: host})
		if err != nil {
			t.Fatal(err)
		}
		if got := h.GetPressure().GetLevel(); got != want {
			t.Errorf("%s: pressure level %q, want %q", host, got, want)
		}
		if host == "host-b" && h.GetPressureObservedAt() == "" {
			t.Errorf("host-b: no pressure_observed_at")
		}
	}
	h, _ := s.InspectHost(ctx, &pb.InspectHostRequest{Name: "test-host"})
	if len(h.GetPressure().GetDetail()) != 2 {
		t.Errorf("self: %d detail rows, want 2", len(h.GetPressure().GetDetail()))
	}
}

// G1: an answer from another host than the one dialled (an address re-used
// by a different daemon) says nothing about this host's pressure, whatever it
// carries.
func TestPeerReady_AnotherHostsPressureIsNotRecorded(t *testing.T) {
	s := serverWithPeerReady(t, readyClient{resp: &pb.ReadyResponse{HostName: "host-x", Ready: true,
		Pressure: &pb.HostPressure{Level: "critical", Resources: []string{"data_dir.space"}}}})
	s.PeerReady(context.Background(), "host-b", "127.0.0.1:1")
	if l := s.PeerPressure("host-b").Level(); l != PressureUnknown {
		t.Fatalf("host-x answered for host-b: host-b's pressure %q, want unknown", l)
	}
}

// G2: two probes of one host can be in flight at once; the answer to the one
// sent LATER is kept, whichever arrives last.
func TestPeerPressure_TheLaterProbeWins(t *testing.T) {
	s := testServer(t)
	now := time.Now()
	s.peerPressure.record("host-b", now, &pb.HostPressure{Level: "warn"})
	s.peerPressure.record("host-b", now.Add(-time.Second), &pb.HostPressure{Level: "critical"})
	if l := s.PeerPressure("host-b").Level(); l != "warn" {
		t.Fatalf("an earlier probe's late answer replaced the later one: %q, want warn", l)
	}
}

// The probe answer says when its sampler last sampled, and whether its levels
// are stale.
func TestReady_PressureCarriesSampledAtAndStale(t *testing.T) {
	s := testServer(t)
	insertReadyHost(t, s, "test-host")
	rep := degradedReport(pressure.Warn)
	rep.SampledAt = time.Date(2026, 10, 21, 12, 5, 0, 0, time.UTC)
	rep.Stale = true
	s.SetPressureSource(&fakePressure{rep: rep})
	resp, _ := s.Ready(context.Background(), &pb.ReadyRequest{})
	if p := resp.GetPressure(); p.GetSampledAt() != "2026-10-21T12:05:00Z" || !p.GetStale() {
		t.Fatalf("pressure %+v, want sampled_at 12:05 and stale", p)
	}
}

// G4: a host removed from the cluster has its open condition resolved.
func TestPressureHealthTick_ResolvesARemovedHost(t *testing.T) {
	ctx := context.Background()
	s := serverWithPeerReady(t, readyClient{resp: &pb.ReadyResponse{HostName: "host-b", Ready: true,
		Pressure: &pb.HostPressure{Level: "degrade", Resources: []string{"data_dir.space"}}}})
	insertReadyHost(t, s, "test-host")
	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{Name: "host-b", Address: "10.0.0.2", SSHUser: "root", State: "active"}); err != nil {
		t.Fatal(err)
	}
	s.PeerReady(ctx, "host-b", "127.0.0.1:1")
	s.PressureHealthTick(ctx)
	if c, ok := pressureCond(t, s, "host-b"); !ok || c.Lifecycle == corrosion.ConditionResolved {
		t.Fatalf("setup: host-b condition %+v (found %v), want open", c, ok)
	}
	if err := corrosion.DeleteHost(ctx, s.db, "host-b"); err != nil {
		t.Fatal(err)
	}
	s.PressureHealthTick(ctx)
	c, _ := pressureCond(t, s, "host-b")
	if c.Lifecycle != corrosion.ConditionResolved || !strings.Contains(c.Evidence, "removed") {
		t.Fatalf("after host-b was removed: %+v, want resolved as removed", c)
	}
}

// N1: an answer older than pressureAnswerMaxAge (a host that stopped
// answering: down, cut off, in maintenance) is not re-asserted as current:
// its condition is left exactly as it was, last_seen included.
func TestPressureHealthTick_AnOldAnswerIsNotRefreshed(t *testing.T) {
	ctx := context.Background()
	s := testServer(t)
	insertReadyHost(t, s, "test-host")
	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{Name: "host-b", Address: "10.0.0.2", SSHUser: "root", State: "active"}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpsertHealthCondition(ctx, s.db, corrosion.HealthCondition{Evaluator: PressureEvaluator,
		Code: CondHostPressure, SubjectKind: "host", SubjectID: "host-b", Lifecycle: corrosion.ConditionConfirmed,
		Severity: corrosion.SeverityWarning, LastSeen: "2026-10-21T10:00:00Z", Reporter: "host-c"}); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-time.Hour)
	for name, p := range map[string]*pb.HostPressure{
		"still pressured": {Level: "degrade", Resources: []string{"data_dir.space"}},
		"ok":              {Level: "ok"},
	} {
		s.peerPressure.m = nil
		s.peerPressure.record("host-b", old, p)
		s.PressureHealthTick(ctx)
		c, _ := pressureCond(t, s, "host-b")
		if c.LastSeen != "2026-10-21T10:00:00Z" || c.Reporter != "host-c" || c.Lifecycle != corrosion.ConditionConfirmed {
			t.Fatalf("%s, answered an hour ago: %+v, want the row untouched", name, c)
		}
	}
	// A fresh answer is acted on.
	s.peerPressure.record("host-b", time.Now(), &pb.HostPressure{Level: "ok"})
	s.PressureHealthTick(ctx)
	if c, _ := pressureCond(t, s, "host-b"); c.Lifecycle != corrosion.ConditionResolved {
		t.Fatalf("a fresh ok answer: %s, want resolved", c.Lifecycle)
	}
}
