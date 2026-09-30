package main

import (
	"context"
	"io"
	"net"
	"regexp"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/grpcapi"
)

// `lv sg create/rm/rule-add/rule-rm` used to open the host's database in the
// CLI process and write it there, past the daemon's authorization and with no
// audit row (colonelpanik/litevirt#182). These tests put the commands in front
// of a REAL daemon, through a real gRPC connection and the daemon's own auth
// interceptor, so the caller an audit row names is decided the way production
// decides it: from the bearer token. The daemon's database is an in-memory one
// the CLI process has no path to, so a command that still wrote directly would
// leave the daemon's tables untouched and fail here.

const sgCLIToken = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// sgCLIDaemon registers srv behind a bufconn listener and points withClient at
// it, carrying the bearer token for token (empty = none).
func sgCLIDaemon(t *testing.T, srv pb.LiteVirtServer, interceptor grpc.UnaryServerInterceptor, token string) {
	t.Helper()
	listener := bufconn.Listen(1024 * 1024)
	var opts []grpc.ServerOption
	if interceptor != nil {
		opts = append(opts, grpc.UnaryInterceptor(interceptor))
	}
	gs := grpc.NewServer(opts...)
	pb.RegisterLiteVirtServer(gs, srv)
	go func() { _ = gs.Serve(listener) }()
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	client := pb.NewLiteVirtClient(conn)
	orig := withClient
	withClient = func(ctx context.Context, fn func(context.Context, pb.LiteVirtClient) error) error {
		if token != "" {
			ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token)
		}
		return fn(ctx, client)
	}
	t.Cleanup(func() {
		withClient = orig
		_ = conn.Close()
		gs.Stop()
		_ = listener.Close()
	})
}

// sgCLIRealDaemon starts a real grpcapi server whose one user has the given
// legacy role, and returns its database.
func sgCLIRealDaemon(t *testing.T, user, role string) *corrosion.Client {
	t.Helper()
	ctx := context.Background()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(sgCLIToken), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("GenerateFromPassword: %v", err)
	}
	if err := corrosion.InsertUser(ctx, db, user, role, string(hash)); err != nil {
		t.Fatalf("InsertUser: %v", err)
	}
	if err := corrosion.InsertToken(ctx, db, corrosion.TokenRecord{
		ID: "cli-token", Username: user, Name: "cli", TokenHash: string(hash),
	}); err != nil {
		t.Fatalf("InsertToken: %v", err)
	}
	service := grpcapi.NewServerForTests(grpcapi.TestServerOpts{HostName: "test-host", DataDir: t.TempDir(), DB: db})
	sgCLIDaemon(t, service, service.UnaryAuthInterceptor, sgCLIToken)
	return db
}

func runSGCLI(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := newSGCmd()
	cmd.SetArgs(args)
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	var err error
	out := captureStdout(t, func() { err = cmd.Execute() })
	return out, err
}

type sgCLIAuditRow struct {
	user, target, detail, result string
}

func sgCLIAudit(t *testing.T, db *corrosion.Client, action string) []sgCLIAuditRow {
	t.Helper()
	rows, err := db.Query(context.Background(),
		`SELECT username, target, detail, result FROM audit_log WHERE action = ? ORDER BY seq, timestamp`, action)
	if err != nil {
		t.Fatalf("query audit_log: %v", err)
	}
	out := make([]sgCLIAuditRow, len(rows))
	for i, r := range rows {
		out[i] = sgCLIAuditRow{r.String("username"), r.String("target"), r.String("detail"), r.String("result")}
	}
	return out
}

func wantSGCLIAudit(t *testing.T, db *corrosion.Client, action, user, target, detail string) {
	t.Helper()
	rows := sgCLIAudit(t, db, action)
	if len(rows) == 0 {
		t.Fatalf("%s: the CLI changed a security group and the daemon's audit log has no row for it", action)
	}
	got := rows[len(rows)-1]
	want := sgCLIAuditRow{user, target, detail, "ok"}
	if got != want {
		t.Errorf("%s audit row = %+v\n                 want %+v", action, got, want)
	}
}

func mustMatch(t *testing.T, out, pattern string) string {
	t.Helper()
	m := regexp.MustCompile(pattern).FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("output %q does not match %q", out, pattern)
	}
	return m[1]
}

func TestSGCLI_WritesGoThroughTheDaemonAndAreAudited(t *testing.T) {
	db := sgCLIRealDaemon(t, "carol", "operator")
	ctx := context.Background()

	out, err := runSGCLI(t, "create", "web", "--stack", "shop")
	if err != nil {
		t.Fatalf("lv sg create: %v", err)
	}
	sgID := mustMatch(t, out, `^Created security group "web" \(id=(\S+)\)\n$`)
	if sg, err := corrosion.GetSecurityGroup(ctx, db, sgID); err != nil || sg == nil || sg.StackName != "shop" {
		t.Fatalf("the daemon holds no group %s with stack shop (got %+v, err %v)", sgID, sg, err)
	}
	wantSGCLIAudit(t, db, "sg.add", "carol", "web", "before=none after={name=web stack=shop rules=[]}")

	out, err = runSGCLI(t, "rule-add", sgID, "--proto", "tcp", "--port", "443", "--cidr", "10.0.0.0/8", "--priority", "20")
	if err != nil {
		t.Fatalf("lv sg rule-add: %v", err)
	}
	ruleID := mustMatch(t, out, `^Added rule (\S+)\n$`)
	rule := "{sg=" + sgID + " ingress tcp port=443 cidr=10.0.0.0/8 accept priority=20}"
	wantSGCLIAudit(t, db, "sg.rule.add", "carol", sgID, "before=none after="+rule)
	if got, err := corrosion.GetSGRule(ctx, db, ruleID); err != nil || got == nil {
		t.Fatalf("the daemon holds no rule %s (err %v)", ruleID, err)
	}

	out, err = runSGCLI(t, "rule-rm", ruleID)
	if err != nil {
		t.Fatalf("lv sg rule-rm: %v", err)
	}
	if out != "Removed rule "+ruleID+"\n" {
		t.Errorf("rule-rm output = %q", out)
	}
	wantSGCLIAudit(t, db, "sg.rule.rm", "carol", ruleID, "before="+rule+" after=none")

	if _, err := runSGCLI(t, "rule-add", sgID, "--direction", "egress", "--proto", "udp", "--port", "53", "--action", "drop"); err != nil {
		t.Fatalf("lv sg rule-add (egress): %v", err)
	}
	out, err = runSGCLI(t, "rm", sgID)
	if err != nil {
		t.Fatalf("lv sg rm: %v", err)
	}
	if out != "Deleted security group "+sgID+"\n" {
		t.Errorf("rm output = %q", out)
	}
	wantSGCLIAudit(t, db, "sg.rm", "carol", sgID,
		"before={name=web stack=shop rules=[{sg="+sgID+" egress udp port=53 cidr=any drop priority=100}]} after=none")
	if sg, err := corrosion.GetSecurityGroup(ctx, db, sgID); err != nil || sg != nil {
		t.Errorf("group %s still live after lv sg rm (got %+v, err %v)", sgID, sg, err)
	}
}

func TestSGCLI_ViewerIsRefused(t *testing.T) {
	db := sgCLIRealDaemon(t, "victor", "viewer")
	ctx := context.Background()
	if err := corrosion.InsertSecurityGroup(ctx, db, corrosion.SecurityGroup{ID: "sg-1", Name: "web"}); err != nil {
		t.Fatalf("InsertSecurityGroup: %v", err)
	}
	if err := corrosion.InsertSGRule(ctx, db, corrosion.SGRule{ID: "r-1", SGID: "sg-1", Direction: "ingress"}); err != nil {
		t.Fatalf("InsertSGRule: %v", err)
	}

	for _, args := range [][]string{
		{"create", "evil"},
		{"rule-add", "sg-1", "--port", "22"},
		{"rule-rm", "r-1"},
		{"rm", "sg-1"},
	} {
		out, err := runSGCLI(t, args...)
		if status.Code(err) != codes.PermissionDenied {
			t.Errorf("lv sg %v as viewer: err = %v, want PermissionDenied", args, err)
		}
		if out != "" {
			t.Errorf("lv sg %v as viewer printed %q; a refused change must not claim success", args, out)
		}
	}
	sgs, _ := corrosion.ListSecurityGroups(ctx, db, "")
	if len(sgs) != 1 || sgs[0].ID != "sg-1" {
		t.Errorf("groups after refused commands = %+v, want only sg-1", sgs)
	}
	rules, _ := corrosion.ListSGRules(ctx, db, "sg-1")
	if len(rules) != 1 || rules[0].ID != "r-1" {
		t.Errorf("rules after refused commands = %+v, want only r-1", rules)
	}
}

// A new CLI talking to a daemon that predates these RPCs gets Unimplemented. It
// must say so plainly, and it must not fall back to writing the database.
func TestSGCLI_OldDaemonGetsAClearError(t *testing.T) {
	sgCLIDaemon(t, pb.UnimplementedLiteVirtServer{}, nil, "")
	for _, args := range [][]string{
		{"create", "web"},
		{"rm", "sg-1"},
		{"rule-add", "sg-1"},
		{"rule-rm", "r-1"},
	} {
		out, err := runSGCLI(t, args...)
		if err == nil {
			t.Fatalf("lv sg %v against an old daemon succeeded", args)
		}
		msg := err.Error()
		if !strings.Contains(msg, "upgrade litevirtd") || !strings.Contains(msg, "lv sg "+args[0]) {
			t.Errorf("lv sg %v against an old daemon: error %q does not name the command and say to upgrade", args, msg)
		}
		if out != "" {
			t.Errorf("lv sg %v against an old daemon printed %q", args, out)
		}
	}
}
