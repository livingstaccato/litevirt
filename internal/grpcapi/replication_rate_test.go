package grpcapi

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pbsstore"
)

// rateGate is a release gate that refuses the features in closed, fails the
// write of the features in writeFails after its entry check passed (a token
// latched whose first use cannot be acknowledged), and counts every question
// asked about each feature.
type rateGate struct {
	t          testing.TB
	mu         sync.Mutex
	closed     map[capabilities.Feature]bool
	writeFails map[capabilities.Feature]error
	asks       map[capabilities.Feature]int
}

func (g *rateGate) ask(f capabilities.Feature) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.asks == nil {
		g.asks = map[capabilities.Feature]int{}
	}
	g.asks[f]++
}

func (g *rateGate) asked(f capabilities.Feature) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.asks[f]
}

func (g *rateGate) refusal(f capabilities.Feature) error {
	return status.Errorf(codes.FailedPrecondition, "the cluster upgrade must finish first (%s needs %s)", f, capabilities.ReleaseToken)
}

func (g *rateGate) WithFeature(ctx context.Context, f capabilities.Feature,
	write func(context.Context, capabilities.FeatureGrant) error) error {
	g.ask(f)
	if g.closed[f] {
		return g.refusal(f)
	}
	if err := g.writeFails[f]; err != nil {
		return err
	}
	return write(ctx, capabilities.GrantForTest(g.t, f))
}

func (g *rateGate) FeatureAvailable(f capabilities.Feature) bool {
	g.ask(f)
	return !g.closed[f]
}

func (g *rateGate) FeatureRefusal(_ context.Context, f capabilities.Feature) error {
	g.ask(f)
	if g.closed[f] {
		return g.refusal(f)
	}
	return nil
}

// rateServer is a server with VM web1 on this host, pool dr here, the
// cluster-policy table writable and gate g wired.
func rateServer(t *testing.T, g *rateGate) *Server {
	t.Helper()
	s := testServer(t)
	ctx := context.Background()
	s.db.SetClusterPolicyGate(func() bool { return true })
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "web1", HostName: s.hostName, State: "stopped"}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpsertStoragePool(ctx, s.db, corrosion.StoragePoolRecord{
		HostName: s.hostName, Name: "dr", Driver: "local", State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	g.t = t
	s.SetReleaseFeatureGate(g)
	return s
}

func i64(v int64) *int64 { return &v }

func vmRateReq(cron string, bw *int64) *pb.CreateReplicationScheduleRequest {
	return &pb.CreateReplicationScheduleRequest{
		Scope: "vm", VmName: "web1", TargetPool: "dr", TargetHost: "test-host", Cron: cron, Enabled: true,
		BwlimitBytesPerSec: bw,
	}
}

// storedRate is the raw value of a schedule row's rate record, and whether a
// record exists at all.
func storedRate(t *testing.T, s *Server, schedule, repo string) (string, bool) {
	t.Helper()
	rows, err := s.db.Query(context.Background(), `SELECT value FROM cluster_policies WHERE key = ?`,
		corrosion.ReplicationRateKey(schedule, repo))
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) == 0 {
		return "", false
	}
	return rows[0].String("value"), true
}

func scheduleRows(t *testing.T, s *Server) []corrosion.BackupScheduleRecord {
	t.Helper()
	rows, err := corrosion.ListBackupSchedules(context.Background(), s.db)
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

// A rate the release gate refuses creates no schedule, for a VM and for a
// container: an unlimited schedule the operator did not ask for is never left
// behind.
//
// Mutation: run the fail-fast after the upsert — the VM row exists.
func TestReplicationRate_RefusedRateCreatesNoSchedule(t *testing.T) {
	g := &rateGate{closed: map[capabilities.Feature]bool{capabilities.FeatureReplicationRate: true}}
	s := rateServer(t, g)
	_, err := s.CreateReplicationSchedule(adminCtx(), vmRateReq("0 * * * *", i64(50<<20)))
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), string(capabilities.FeatureReplicationRate)) {
		t.Fatalf("vm: %v, want FailedPrecondition naming %s", err, capabilities.FeatureReplicationRate)
	}
	if rows := scheduleRows(t, s); len(rows) != 0 {
		t.Fatalf("a refused rate left a schedule: %+v", rows)
	}

	seedActiveHost(t, s, "host-b", true)
	seedCTRow(t, s, "test-host", "web", "_default", "image-recreate")
	s.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) {
		return &replicaPeer{}, func() {}, nil
	}
	req := ctSchedReq("web", "host-b", "dr")
	req.BwlimitBytesPerSec = i64(50 << 20)
	if _, err := s.CreateReplicationSchedule(adminCtx(), req); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("container: %v, want FailedPrecondition", err)
	}
	if rows := scheduleRows(t, s); len(rows) != 0 {
		t.Fatalf("a refused rate left a container schedule: %+v", rows)
	}
	if g.asked(capabilities.FeatureContainerReplication) != 0 {
		t.Errorf("the container schedule's own gate was run although its rate was refused")
	}
}

// bwlimit is optional: unset keeps the stored rate, 0 clears it, a value
// below the minimum is refused before anything is written. List and the
// create's answer carry the rate.
//
// Mutations: treat an unset field as 0 — the re-add clears; drop the minimum
// check — 1000 B/s is stored.
func TestReplicationRate_OptionalSemantics(t *testing.T) {
	s := rateServer(t, &rateGate{})
	ctx := adminCtx()
	got, err := s.CreateReplicationSchedule(ctx, vmRateReq("0 * * * *", i64(8<<20)))
	if err != nil || got.GetBwlimitBytesPerSec() != 8<<20 {
		t.Fatalf("create with 8MiB: %v, answer rate %d", err, got.GetBwlimitBytesPerSec())
	}
	if got, err := s.CreateReplicationSchedule(ctx, vmRateReq("5 * * * *", nil)); err != nil || got.GetBwlimitBytesPerSec() != 8<<20 {
		t.Fatalf("re-add without bwlimit: %v, answer rate %d, want the stored 8MiB", err, got.GetBwlimitBytesPerSec())
	}
	if v, _ := storedRate(t, s, "web1", "dr"); v != "8388608" {
		t.Fatalf("re-add without bwlimit changed the stored rate to %q", v)
	}
	list, err := s.ListReplicationSchedules(ctx, &pb.ListReplicationSchedulesRequest{})
	if err != nil || len(list.Schedules) != 1 || list.Schedules[0].BwlimitBytesPerSec != 8<<20 {
		t.Fatalf("list: %v %+v, want one schedule at 8MiB", err, list)
	}

	for _, bad := range []int64{1000, pbsstore.MinRate - 1, -1} {
		if _, err := s.CreateReplicationSchedule(ctx, vmRateReq("9 * * * *", i64(bad))); status.Code(err) != codes.InvalidArgument {
			t.Errorf("bwlimit %d: %v, want InvalidArgument", bad, err)
		}
	}
	if rows := scheduleRows(t, s); len(rows) != 1 || rows[0].Cron != "5 * * * *" {
		t.Fatalf("a refused bwlimit changed the schedule: %+v", rows)
	}

	if got, err := s.CreateReplicationSchedule(ctx, vmRateReq("5 * * * *", i64(0))); err != nil || got.GetBwlimitBytesPerSec() != 0 {
		t.Fatalf("bwlimit 0: %v, answer rate %d", err, got.GetBwlimitBytesPerSec())
	}
	if v, ok := storedRate(t, s, "web1", "dr"); !ok || v != "" {
		t.Fatalf("bwlimit 0 left %q (record %v), want a cleared record", v, ok)
	}
	list, _ = s.ListReplicationSchedules(ctx, &pb.ListReplicationSchedulesRequest{})
	if list.Schedules[0].BwlimitBytesPerSec != 0 {
		t.Fatalf("list after clear: %d", list.Schedules[0].BwlimitBytesPerSec)
	}
}

// A schedule with no rate, and a 0 for a schedule that never had one, never
// ask the replication_rate gate and write no rate record: the feature is used
// only when someone sets a rate.
//
// Mutation: run the fail-fast whenever the field is present — the 0 asks.
func TestReplicationRate_CreateWithoutRateNeverAsksTheGate(t *testing.T) {
	g := &rateGate{}
	s := rateServer(t, g)
	for _, bw := range []*int64{nil, i64(0)} {
		if _, err := s.CreateReplicationSchedule(adminCtx(), vmRateReq("0 * * * *", bw)); err != nil {
			t.Fatal(err)
		}
	}
	if n := g.asked(capabilities.FeatureReplicationRate); n != 0 {
		t.Fatalf("the replication_rate gate was asked %d times", n)
	}
	if _, ok := storedRate(t, s, "web1", "dr"); ok {
		t.Fatal("a rate record was written for a schedule with no rate")
	}
}

// The rate is written after the schedule. When that write fails, the schedule
// stands without a limit and the error says so, and how to set it again.
func TestReplicationRate_RateWriteFailureSaysTheScheduleIsUnlimited(t *testing.T) {
	g := &rateGate{writeFails: map[capabilities.Feature]error{
		capabilities.FeatureReplicationRate: status.Error(codes.Unavailable, "could not confirm replication_rate with every host"),
	}}
	s := rateServer(t, g)
	_, err := s.CreateReplicationSchedule(adminCtx(), vmRateReq("0 * * * *", i64(8<<20)))
	if err == nil || !strings.Contains(err.Error(), "without a bandwidth limit") ||
		!strings.Contains(err.Error(), "lv replication schedule add") || !strings.Contains(err.Error(), "could not confirm") {
		t.Fatalf("err = %v, want it to say the schedule exists without a limit, name the command and keep the cause", err)
	}
	if status.Code(err) != codes.Unavailable {
		t.Errorf("code = %v, want the gate's Unavailable", status.Code(err))
	}
	if rows := scheduleRows(t, s); len(rows) != 1 {
		t.Fatalf("schedule rows = %+v, want the schedule", rows)
	}
}

// Every path that deletes a schedule row goes through deleteScheduleRow, which
// clears the row's rate when one is stored, and only then: a delete never
// performs a first use and never writes a record for a schedule that had none.
//
// Mutation: clear unconditionally — the no-rate cases write a record and ask
// the gate.
func TestReplicationRate_EveryScheduleDeleteClearsItsRate(t *testing.T) {
	type deleter struct {
		name           string
		schedule, repo string
		seed           func(t *testing.T, s *Server)
		del            func(s *Server) error
	}
	vmRow := func(repo, typ string) func(t *testing.T, s *Server) {
		return func(t *testing.T, s *Server) {
			if err := corrosion.UpsertBackupSchedule(context.Background(), s.db, corrosion.BackupScheduleRecord{
				VMName: "web1", Repo: repo, Cron: "0 * * * *", Enabled: true, Type: typ, TargetPool: repo,
			}); err != nil {
				t.Fatal(err)
			}
		}
	}
	cases := []deleter{
		{"DeleteReplicationSchedule", "web1", "dr", vmRow("dr", "replication"), func(s *Server) error {
			_, err := s.DeleteReplicationSchedule(adminCtx(), &pb.DeleteReplicationScheduleRequest{VmName: "web1", TargetPool: "dr"})
			return err
		}},
		{"deleteContainerReplicationSchedule", corrosion.ContainerScheduleKey("_default", "web"), "dr", func(t *testing.T, s *Server) {
			putCTSchedule(t, s, corrosion.BackupScheduleRecord{
				VMName: corrosion.ContainerScheduleKey("_default", "web"), ProjectName: "_default", Scope: "container",
				Repo: "dr", Cron: "0 * * * *", Enabled: true, Type: "replication", TargetPool: "dr", TargetHost: "host-b",
			})
		}, func(s *Server) error {
			_, err := s.DeleteReplicationSchedule(adminCtx(), &pb.DeleteReplicationScheduleRequest{VmName: "web", Scope: "container", TargetPool: "dr"})
			return err
		}},
		{"DeleteBackupSchedule", "web1", "main", vmRow("main", "backup"), func(s *Server) error {
			_, err := s.DeleteBackupSchedule(adminCtx(), &pb.DeleteBackupScheduleRequest{VmName: "web1", Repo: "main"})
			return err
		}},
		{"syncComposeBackupSchedule", "web1", "main", vmRow("main", "backup"), func(s *Server) error {
			return s.syncComposeBackupSchedule(adminCtx(), "web1", &compose.VMDef{})
		}},
	}
	for _, tc := range cases {
		for _, withRate := range []bool{true, false} {
			g := &rateGate{}
			s := rateServer(t, g)
			tc.seed(t, s)
			if withRate {
				if err := corrosion.SetReplicationRate(context.Background(), s.db,
					capabilities.GrantForTest(t, capabilities.FeatureReplicationRate), tc.schedule, tc.repo, 4<<20, "alice"); err != nil {
					t.Fatal(err)
				}
			}
			if err := tc.del(s); err != nil {
				t.Fatalf("%s (rate %v): %v", tc.name, withRate, err)
			}
			for _, r := range scheduleRows(t, s) {
				if r.VMName == tc.schedule && r.Repo == tc.repo {
					t.Fatalf("%s: the schedule row was not deleted", tc.name)
				}
			}
			v, ok := storedRate(t, s, tc.schedule, tc.repo)
			switch {
			case withRate && (!ok || v != ""):
				t.Errorf("%s: the stored rate is %q (record %v) after the delete, want cleared", tc.name, v, ok)
			case !withRate && ok:
				t.Errorf("%s: a delete of a schedule with no rate wrote a rate record %q", tc.name, v)
			case !withRate && g.asked(capabilities.FeatureReplicationRate) != 0:
				t.Errorf("%s: a delete of a schedule with no rate asked the replication_rate gate", tc.name)
			}
		}
	}
}

// deleteScheduleRow is the only non-test caller of
// corrosion.DeleteBackupSchedule, so no path deletes a schedule row and leaves
// its rate for a later schedule of the same name to inherit.
//
// Mutation: call corrosion.DeleteBackupSchedule directly from one of the four
// handlers — this test names it.
func TestReplicationRate_DeleteBackupScheduleHasOneCaller(t *testing.T) {
	root := filepath.Join("..", "..")
	fset := token.NewFileSet()
	var callers []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if rel == "gen" || rel == ".git" || rel == "vendor" || strings.HasPrefix(rel, ".claude") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(rel, ".go") || strings.HasSuffix(rel, "_test.go") {
			return nil
		}
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return perr
		}
		callers = append(callers, deleteScheduleCallers(fset, f, rel)...)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"internal/grpcapi:deleteScheduleRow"}
	if strings.Join(callers, ",") != strings.Join(want, ",") {
		t.Fatalf("callers of corrosion.DeleteBackupSchedule = %v, want only %v: delete schedule rows through Server.deleteScheduleRow", callers, want)
	}
}

// deleteScheduleCallers lists "<dir>:<func>" for every call of
// corrosion.DeleteBackupSchedule in f (DeleteBackupSchedule unqualified inside
// package corrosion).
func deleteScheduleCallers(fset *token.FileSet, f *ast.File, rel string) []string {
	var out []string
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Body == nil {
			continue
		}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			switch fn := call.Fun.(type) {
			case *ast.SelectorExpr:
				if x, ok := fn.X.(*ast.Ident); ok && x.Name == "corrosion" && fn.Sel.Name == "DeleteBackupSchedule" {
					out = append(out, filepath.ToSlash(filepath.Dir(rel))+":"+fd.Name.Name)
				}
			case *ast.Ident:
				if f.Name.Name == "corrosion" && fn.Name == "DeleteBackupSchedule" {
					out = append(out, filepath.ToSlash(filepath.Dir(rel))+":"+fd.Name.Name)
				}
			}
			return true
		})
	}
	return out
}

// The guard has teeth: a direct call in a handler is found.
func TestReplicationRate_DeleteGuardFindsADirectCall(t *testing.T) {
	src := `package grpcapi
func (s *Server) DeleteBackupSchedule() { _ = corrosion.DeleteBackupSchedule(ctx, s.db, k, r) }
func (s *Server) deleteScheduleRow() { _ = corrosion.DeleteBackupSchedule(ctx, s.db, k, r) }`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "x.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	got := deleteScheduleCallers(fset, f, "internal/grpcapi/x.go")
	if len(got) != 2 || got[0] != "internal/grpcapi:DeleteBackupSchedule" {
		t.Fatalf("callers = %v", got)
	}
}
