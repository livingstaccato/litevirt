package main

import (
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func row(host, issuer string, notAfter time.Time, fps ...string) *pb.MigrationTLSHostStatus {
	r := &pb.MigrationTLSHostStatus{Host: host, Provisioned: true, CertIssuerFingerprint: issuer,
		CertNotAfter: timestamppb.New(notAfter)}
	for _, fp := range fps {
		r.TrustedCas = append(r.TrustedCas, &pb.MigrationTLSCA{Fingerprint: fp, NotAfter: timestamppb.New(notAfter)})
	}
	return r
}

func TestMigrationTLSProblems_HealthyClusterHasNone(t *testing.T) {
	now := time.Now()
	far := now.Add(365 * 24 * time.Hour)
	if p := migrationTLSProblems([]*pb.MigrationTLSHostStatus{row("a", "x", far, "x"), row("b", "x", far, "x")}, false, now); len(p) != 0 {
		t.Fatalf("problems = %v; want none", p)
	}
}

// Each line names the host and the condition. Mutations, one per case:
// drop the error check / the validation check / the expiry check / the
// plaintext check / the CA-set comparison — that case's want goes missing.
func TestMigrationTLSProblems_FlagsEachCondition(t *testing.T) {
	now := time.Now()
	far, soon := now.Add(365*24*time.Hour), now.Add(30*24*time.Hour)
	plain := row("e", "x", far, "x")
	plain.AllowUnencryptedStorage = true
	invalid := row("d", "x", far, "x")
	invalid.ValidationError = "torn"
	rows := []*pb.MigrationTLSHostStatus{
		row("a", "x", far, "x"),
		{Host: "b", Error: "unreachable: boom"},
		row("c", "x", soon, "x"),
		invalid,
		plain,
		row("f", "y", far, "x", "y"),
	}
	got := strings.Join(migrationTLSProblems(rows, false, now), "\n")
	for _, want := range []string{"b: unreachable: boom", "c: host certificate expires", "d: torn", "e: falls back to plaintext", "f: trusts a different CA set"} {
		if !strings.Contains(got, want) {
			t.Errorf("problems missing %q:\n%s", want, got)
		}
	}
}

// Review focus 5: run away from the operator machine mid-rotation, a CA-set
// mismatch is reported, with the hint that a rotation may be running.
// Mid-rotation on the operator machine (rotating=true), it is not a problem.
//
// Mutation: drop the rotating check — the rotating case reports a mismatch.
func TestMigrationTLSProblems_CASetMismatchDuringARotation(t *testing.T) {
	now := time.Now()
	far := now.Add(365 * 24 * time.Hour)
	rows := []*pb.MigrationTLSHostStatus{row("a", "x", far, "x"), row("b", "x", far, "x", "y")}
	if p := migrationTLSProblems(rows, true, now); len(p) != 0 {
		t.Errorf("rotating: problems = %v; want none", p)
	}
	got := strings.Join(migrationTLSProblems(rows, false, now), "\n")
	if !strings.Contains(got, "rotate-migration-ca") {
		t.Errorf("not rotating: %q does not mention that a rotation may be running", got)
	}
}
