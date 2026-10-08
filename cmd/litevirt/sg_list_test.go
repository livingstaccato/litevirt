package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/cli"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/grpcapi"
)

// `lv sg ls` and `lv sg rule-ls` used to open the host's database in the CLI
// process, so they answered whoever could run the binary on a node with every
// group and rule in the cluster, whatever credential the CLI carried: a token
// scoped to one project included. They now read through ListSecurityGroups, the
// RPC the web UI reads through, so the daemon decides what the caller may see.
// The local database is read only when the daemon cannot answer at all
// (Unavailable) or predates the RPC (Unimplemented) — never on a refusal.

// noLocalDB makes any read of the local database fail the test.
func noLocalDB(t *testing.T) {
	t.Helper()
	orig := openClusterDB
	openClusterDB = func() (*corrosion.Client, error) {
		t.Errorf("the command opened the local database instead of asking the daemon")
		return nil, errors.New("local database not available in this test")
	}
	t.Cleanup(func() { openClusterDB = orig })
}

// localDB points the CLI's local-database read at a fresh test database seeded
// by seed. Each open gets its own, because the command closes what it opens.
func localDB(t *testing.T, seed func(*testing.T, *corrosion.Client)) {
	t.Helper()
	orig := openClusterDB
	openClusterDB = func() (*corrosion.Client, error) {
		db := corrosion.NewTestClientT(t)
		if err := corrosion.InitSchema(context.Background(), db); err != nil {
			t.Fatalf("InitSchema: %v", err)
		}
		seed(t, db)
		return db, nil
	}
	t.Cleanup(func() { openClusterDB = orig })
}

func seedSGListing(t *testing.T, db *corrosion.Client) {
	t.Helper()
	ctx := context.Background()
	for _, g := range []corrosion.SecurityGroup{
		{ID: "sg-web", Name: "web", CreatedAt: "2026-10-01T00:00:00Z"},
		{ID: "sg-db", Name: "db", StackName: "shop", CreatedAt: "2026-10-02T00:00:00Z"},
	} {
		if err := corrosion.InsertSecurityGroup(ctx, db, g); err != nil {
			t.Fatalf("InsertSecurityGroup(%s): %v", g.ID, err)
		}
	}
	for _, r := range []corrosion.SGRule{
		{ID: "r-web", SGID: "sg-web", Direction: "ingress", Proto: "tcp", PortRange: "443", CIDR: "0.0.0.0/0", Priority: 10},
		{ID: "r-db", SGID: "sg-db", Direction: "ingress", Proto: "tcp", PortRange: "5432", CIDR: "10.9.0.0/16", Priority: 20},
	} {
		if err := corrosion.InsertSGRule(ctx, db, r); err != nil {
			t.Fatalf("InsertSGRule(%s): %v", r.ID, err)
		}
	}
}

func runSGCLIErr(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	cmd := newSGCmd()
	cmd.SetArgs(args)
	var eb bytes.Buffer
	cmd.SetOut(&eb)
	cmd.SetErr(&eb)
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	stdout = captureStdout(t, func() { err = cmd.Execute() })
	return stdout, eb.String(), err
}

func TestSGCLI_ListingsReadThroughTheDaemon(t *testing.T) {
	db := sgCLIRealDaemon(t, "olga", "operator")
	seedSGListing(t, db)
	noLocalDB(t)

	out, err := runSGCLI(t, "ls")
	if err != nil {
		t.Fatalf("lv sg ls: %v", err)
	}
	for _, want := range []string{"sg-web", "web", "2026-10-01T00:00:00Z", "sg-db", "shop"} {
		if !strings.Contains(out, want) {
			t.Errorf("lv sg ls output lacks %q:\n%s", want, out)
		}
	}

	out, err = runSGCLI(t, "ls", "--stack", "shop")
	if err != nil {
		t.Fatalf("lv sg ls --stack shop: %v", err)
	}
	if !strings.Contains(out, "sg-db") || strings.Contains(out, "sg-web") {
		t.Errorf("lv sg ls --stack shop = %q, want sg-db only", out)
	}

	out, err = runSGCLI(t, "rule-ls", "sg-db")
	if err != nil {
		t.Fatalf("lv sg rule-ls: %v", err)
	}
	for _, want := range []string{"r-db", "5432", "10.9.0.0/16", "20"} {
		if !strings.Contains(out, want) {
			t.Errorf("lv sg rule-ls sg-db output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "r-web") {
		t.Errorf("lv sg rule-ls sg-db listed another group's rule:\n%s", out)
	}
}

// sgCLIScopedDaemon starts a real daemon whose one user is an admin holding a
// token scoped to /projects/teamA.
func sgCLIScopedDaemon(t *testing.T) *corrosion.Client {
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
	if err := corrosion.InsertUser(ctx, db, "ada", "admin", string(hash)); err != nil {
		t.Fatalf("InsertUser: %v", err)
	}
	if err := corrosion.InsertToken(ctx, db, corrosion.TokenRecord{
		ID: "cli-token", Username: "ada", Name: "cli", TokenHash: string(hash),
		ScopePaths: []string{"/projects/teamA"},
	}); err != nil {
		t.Fatalf("InsertToken: %v", err)
	}
	service := grpcapi.NewServerForTests(grpcapi.TestServerOpts{HostName: "test-host", DataDir: t.TempDir(), DB: db})
	sgCLIDaemon(t, service, service.UnaryAuthInterceptor, sgCLIToken)
	return db
}

// A refusal is the daemon's answer: the command reports it, prints nothing, and
// does not go and read the database itself.
func TestSGCLI_ListingsHonourTheDaemonsRefusal(t *testing.T) {
	db := sgCLIScopedDaemon(t)
	seedSGListing(t, db)
	noLocalDB(t)

	for _, args := range [][]string{{"ls"}, {"rule-ls", "sg-db"}} {
		out, err := runSGCLI(t, args...)
		if status.Code(err) != codes.PermissionDenied {
			t.Errorf("lv sg %v with a project-scoped token: err = %v, want PermissionDenied", args, err)
		}
		for _, secret := range []string{"sg-web", "web", "5432", "10.9.0.0/16"} {
			if strings.Contains(out, secret) {
				t.Errorf("lv sg %v with a project-scoped token printed %q:\n%s", args, secret, out)
			}
		}
	}
}

// unavailableSGServer answers ListSecurityGroups as a daemon that is down.
type unavailableSGServer struct{ pb.UnimplementedLiteVirtServer }

func (unavailableSGServer) ListSecurityGroups(context.Context, *pb.ListSecurityGroupsRequest) (*pb.ListSecurityGroupsResponse, error) {
	return nil, status.Error(codes.Unavailable, "connection refused")
}

// A daemon that predates ListSecurityGroups, or one that is down, cannot answer;
// on a node the listings then read the local database as they always did, and
// say so on stderr, rather than refusing a listing that used to work.
func TestSGCLI_ListingsFallBackOnlyWhenTheDaemonCannotAnswer(t *testing.T) {
	for name, srv := range map[string]pb.LiteVirtServer{
		"old daemon (Unimplemented)": pb.UnimplementedLiteVirtServer{},
		"daemon down (Unavailable)":  unavailableSGServer{},
	} {
		t.Run(name, func(t *testing.T) {
			sgCLIDaemon(t, srv, nil, "")
			localDB(t, seedSGListing)

			out, stderr, err := runSGCLIErr(t, "ls")
			if err != nil {
				t.Fatalf("lv sg ls: %v", err)
			}
			if !strings.Contains(out, "sg-web") || !strings.Contains(out, "sg-db") {
				t.Errorf("lv sg ls fell back but listed %q", out)
			}
			if !strings.Contains(stderr, "local database") {
				t.Errorf("lv sg ls read the local database without saying so; stderr = %q", stderr)
			}

			out, _, err = runSGCLIErr(t, "rule-ls", "sg-web")
			if err != nil {
				t.Fatalf("lv sg rule-ls: %v", err)
			}
			if !strings.Contains(out, "r-web") || strings.Contains(out, "r-db") {
				t.Errorf("lv sg rule-ls sg-web fell back and listed %q, want r-web only", out)
			}
		})
	}
}

// When the CLI has no credentials to connect with at all — no LV_HOST, no
// readable PKI bundle — no daemon ever saw the request, so nothing refused it.
// On a node the listings then read the local database, as they always did
// before they went through the daemon: only someone who can already read that
// file gets anything from it.
func TestSGCLI_ListingsFallBackWhenTheCLICannotConnect(t *testing.T) {
	origConnect := cli.Connect
	cli.Connect = func(context.Context) (pb.LiteVirtClient, func(), error) {
		return nil, nil, errors.New("load local TLS config from /etc/litevirt/pki: permission denied")
	}
	t.Cleanup(func() { cli.Connect = origConnect })
	localDB(t, seedSGListing)

	out, stderr, err := runSGCLIErr(t, "ls")
	if err != nil {
		t.Fatalf("lv sg ls with no credentials on a node: %v", err)
	}
	if !strings.Contains(out, "sg-web") || !strings.Contains(out, "sg-db") {
		t.Errorf("lv sg ls fell back but listed %q", out)
	}
	if !strings.Contains(stderr, "local database") {
		t.Errorf("lv sg ls read the local database without saying so; stderr = %q", stderr)
	}
	out, _, err = runSGCLIErr(t, "rule-ls", "sg-db")
	if err != nil {
		t.Fatalf("lv sg rule-ls with no credentials on a node: %v", err)
	}
	if !strings.Contains(out, "r-db") || strings.Contains(out, "r-web") {
		t.Errorf("lv sg rule-ls sg-db fell back and listed %q, want r-db only", out)
	}
}

// Off a node, with no credentials, neither path can answer; the error names
// why the CLI could not reach a daemon, not only that the local read failed.
func TestSGCLI_ListingsWithNoDaemonAndNoLocalDatabaseSayWhy(t *testing.T) {
	origConnect := cli.Connect
	cli.Connect = func(context.Context) (pb.LiteVirtClient, func(), error) {
		return nil, nil, errors.New("LV_HOST not set")
	}
	t.Cleanup(func() { cli.Connect = origConnect })
	origDB := openClusterDB
	openClusterDB = func() (*corrosion.Client, error) { return nil, errors.New("must run on a litevirt node") }
	t.Cleanup(func() { openClusterDB = origDB })

	_, _, err := runSGCLIErr(t, "ls")
	if err == nil || !strings.Contains(err.Error(), "LV_HOST not set") || !strings.Contains(err.Error(), "must run on a litevirt node") {
		t.Errorf("lv sg ls with neither a daemon nor a local database: err = %v, want both reasons", err)
	}
}
