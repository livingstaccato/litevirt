package grpcapi

import (
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Mid-rotation, an updated host and one not yet updated hold different CA
// files. The refusal stays a refusal, and names the rotation, so the operator
// waits for its phase instead of reissuing credentials, which
// `lv host install-migration-tls` refuses while a rotation runs.
//
// Mutation: drop the rotation sentence from migrationCAMismatch — red.
func TestMigrationCAMismatch_NamesARunningRotation(t *testing.T) {
	if err := migrationCAMismatch("vm", "a", "x", "b", "x"); err != nil {
		t.Fatalf("one CA set refused: %v", err)
	}
	err := migrationCAMismatch("vm", "a", "old+new", "b", "old")
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("err = %v; want FailedPrecondition", err)
	}
	for _, want := range []string{"`lv host rotate-migration-ca`", "`lv host install-migration-tls --reissue`"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal %q does not name %s", err, want)
		}
	}
}

// An incomplete set is usually a credential push still in flight, not a
// damaged set: the refusal names both remedies, letting the push finish (or
// re-running it) and reissuing, so an operator does not reissue over a push.
//
// Mutation: drop the incomplete-set sentence — red.
func TestUnusableMigrationCredentialsRefusal_NamesBothRemedies(t *testing.T) {
	err := unusableMigrationCredentialsRefusal("vm", "node-2",
		"migration-TLS credentials are unusable: incomplete set, missing host.key (a credential push may be in progress)")
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("err = %v; want FailedPrecondition", err)
	}
	for _, want := range []string{"node-2", "incomplete", "let it finish", "re-run `lv host install-migration-tls`",
		"`lv host install-migration-tls --reissue`"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal %q does not say %q", err, want)
		}
	}
}
