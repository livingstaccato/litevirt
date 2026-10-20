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
	if err := migrationCAMismatch("vm", "a", "x", nil, "b", "x", nil); err != nil {
		t.Fatalf("one CA set refused: %v", err)
	}
	err := migrationCAMismatch("vm", "a", "old+new", nil, "b", "old", nil)
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

// The refusal names each host's CA fingerprints, the ones lv doctor
// migration-tls lists, not the digest of a two-CA set that appears nowhere
// else. A target whose build reports only the digest is shown by it, marked.
//
// Mutation: print the set digests instead of the lists — red.
func TestMigrationCAMismatch_NamesTheRealCAFingerprints(t *testing.T) {
	err := migrationCAMismatch("vm", "a", "digest-a", []string{"6cee35be", "5eda7fef"}, "b", "digest-b", []string{"6cee35be"})
	for _, want := range []string{"a: 6cee35be, 5eda7fef", "b: 6cee35be"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal %q does not list %q", err, want)
		}
	}
	if strings.Contains(err.Error(), "digest-a") || strings.Contains(err.Error(), "digest-b") {
		t.Errorf("refusal %q quotes a set digest although both hosts listed their CAs", err)
	}
	err = migrationCAMismatch("vm", "a", "digest-a", []string{"6cee35be"}, "b", "digest-b", nil)
	if !strings.Contains(err.Error(), "b: digest-b (") {
		t.Errorf("older target: refusal %q; want its digest, marked as one", err)
	}
}
