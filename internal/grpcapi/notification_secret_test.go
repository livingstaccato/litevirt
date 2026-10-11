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
)

const webhookSecret = `{"url":"https://hooks.example.com/services/T000/B000/sUp3rS3cr3t"}`

func seedNotificationTarget(t *testing.T, s *Server) {
	t.Helper()
	if err := corrosion.InsertNotificationTarget(adminCtx(), s.db, corrosion.NotificationTarget{
		ID: "tgt1", Name: "ops-webhook", Type: "webhook", Config: webhookSecret, Enabled: true,
	}); err != nil {
		t.Fatalf("InsertNotificationTarget: %v", err)
	}
}

// TestListNotificationTargets_ViewerDoesNotSeeTheSecret is the #200 regression.
//
// The RPC is gated at "viewer" and returned NotificationTarget.Config verbatim.
// That config IS the credential — a webhook/Slack URL is a bearer secret — and
// notification_targets sits in corrosion's sensitiveTableNames precisely
// because it "must never enter the operator-readable state dump". Handing it to
// every viewer over the API contradicted that.
func TestListNotificationTargets_ViewerDoesNotSeeTheSecret(t *testing.T) {
	s := testServer(t)
	seedNotificationTarget(t, s)

	resp, err := s.ListNotificationTargets(viewerCtx(), &pb.ListNotificationTargetsRequest{})
	if err != nil {
		t.Fatalf("a viewer should still be able to LIST targets: %v", err)
	}
	if len(resp.Targets) != 1 {
		t.Fatalf("got %d targets, want 1", len(resp.Targets))
	}
	got := resp.Targets[0]
	if strings.Contains(got.Config, "sUp3rS3cr3t") {
		t.Errorf("viewer received the webhook secret: config = %q", got.Config)
	}
	// The rest of the row stays visible: a viewer may see THAT a target exists.
	if got.Name != "ops-webhook" || got.Type != "webhook" || !got.Enabled {
		t.Errorf("redaction ate the non-secret fields: %+v", got)
	}
}

// An operator is who the config is for, and must still get it — otherwise
// `lv notify target ls` stops being able to show what it is configured to call.
func TestListNotificationTargets_OperatorStillSeesTheConfig(t *testing.T) {
	s := testServer(t)
	seedNotificationTarget(t, s)

	for _, role := range []string{"operator", "admin"} {
		resp, err := s.ListNotificationTargets(userCtx("u", role), &pb.ListNotificationTargetsRequest{})
		if err != nil {
			t.Fatalf("%s list: %v", role, err)
		}
		if len(resp.Targets) != 1 {
			t.Fatalf("%s: got %d targets, want 1", role, len(resp.Targets))
		}
		if resp.Targets[0].Config != webhookSecret {
			t.Errorf("%s did not receive the real config: %q", role, resp.Targets[0].Config)
		}
	}
}

const emailSecret = `{"host":"smtp.example.com","from":"lv@example.com","to":["ops@example.com"],"username":"u","password":"sm7pPassw0rd"}`

// An SMTP password is never handed back by the list RPC, to any role — an
// operator included, since managing a target never needs to read it back.
func TestListNotificationTargets_EmailPasswordMaskedForEveryRole(t *testing.T) {
	s := testServer(t)
	if err := corrosion.InsertNotificationTarget(adminCtx(), s.db, corrosion.NotificationTarget{
		ID: "tgt-mail", Name: "ops-mail", Type: "email", Config: emailSecret, Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{"viewer", "operator", "admin"} {
		resp, err := s.ListNotificationTargets(userCtx("u", role), &pb.ListNotificationTargetsRequest{})
		if err != nil {
			t.Fatalf("%s list: %v", role, err)
		}
		if strings.Contains(resp.Targets[0].Config, "sm7pPassw0rd") {
			t.Errorf("%s received the SMTP password: %q", role, resp.Targets[0].Config)
		}
	}
	// operator still sees the non-secret routing config.
	resp, _ := s.ListNotificationTargets(userCtx("u", "operator"), &pb.ListNotificationTargetsRequest{})
	if !strings.Contains(resp.Targets[0].Config, "smtp.example.com") || !strings.Contains(resp.Targets[0].Config, "ops@example.com") {
		t.Errorf("operator lost the non-secret config: %q", resp.Targets[0].Config)
	}
}

// openEmailFeature wires a release-feature gate that grants (the release token
// has latched), so a create reaches the writer with its FeatureGrant.
func openEmailFeature(t *testing.T, s *Server) {
	t.Helper()
	s.SetReleaseFeatureGate(fakeFeatureGate{t: t, grant: true})
}

func TestCreateNotificationTarget_EmailValidated(t *testing.T) {
	s := testServer(t)
	openEmailFeature(t, s)
	_, err := s.CreateNotificationTarget(adminCtx(), &pb.CreateNotificationTargetRequest{Name: "m", Type: "email", Config: `{"host":"h"}`, Enabled: true})
	if err == nil {
		t.Fatal("invalid email config accepted")
	}
	if _, err := s.CreateNotificationTarget(adminCtx(), &pb.CreateNotificationTargetRequest{Name: "m", Type: "email", Config: emailSecret, Enabled: true}); err != nil {
		t.Fatalf("valid email config rejected: %v", err)
	}
}

// I-2: the create response must not echo the password.
func TestCreateNotificationTarget_ResponseMasksPassword(t *testing.T) {
	s := testServer(t)
	openEmailFeature(t, s)
	pt, err := s.CreateNotificationTarget(adminCtx(), &pb.CreateNotificationTargetRequest{Name: "m", Type: "email", Config: emailSecret, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(pt.Config, "sm7pPassw0rd") {
		t.Errorf("create response echoed the password: %s", pt.Config)
	}
	// ...but the stored row still has it, or sending would break.
	rows, _ := corrosion.ListNotificationTargets(adminCtx(), s.db)
	if len(rows) != 1 || !strings.Contains(rows[0].Config, "sm7pPassw0rd") {
		t.Errorf("stored config lost the password: %+v", rows)
	}
}

// I-1: a differently-cased key is stored canonically and masked on list.
func TestCreateNotificationTarget_MixedCasePasswordCanonicalAndMasked(t *testing.T) {
	s := testServer(t)
	openEmailFeature(t, s)
	cfg := `{"Host":"smtp.example.com","From":"lv@example.com","To":["ops@example.com"],"Username":"u","Password":"MixedCasePw"}`
	if _, err := s.CreateNotificationTarget(adminCtx(), &pb.CreateNotificationTargetRequest{Name: "m", Type: "email", Config: cfg, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	rows, _ := corrosion.ListNotificationTargets(adminCtx(), s.db)
	if strings.Contains(rows[0].Config, `"Password"`) || !strings.Contains(rows[0].Config, `"password"`) {
		t.Errorf("stored config not canonical: %s", rows[0].Config)
	}
	for _, role := range []string{"viewer", "operator", "admin"} {
		resp, _ := s.ListNotificationTargets(userCtx("u", role), &pb.ListNotificationTargetsRequest{})
		if strings.Contains(resp.Targets[0].Config, "MixedCasePw") {
			t.Errorf("%s saw the password: %s", role, resp.Targets[0].Config)
		}
	}
}

// Rolling upgrade: an email target with a password is refused until the release
// token has latched; one without a password is never gated.
func TestCreateNotificationTarget_EmailPasswordGatedOnReleaseFeature(t *testing.T) {
	s := testServer(t) // no release-feature gate wired: fail closed
	_, err := s.CreateNotificationTarget(adminCtx(), &pb.CreateNotificationTargetRequest{Name: "m", Type: "email", Config: emailSecret, Enabled: true})
	if status.Code(err) != codes.FailedPrecondition ||
		!strings.Contains(err.Error(), "the cluster upgrade must finish first (email_target_secret needs "+capabilities.ReleaseToken+")") {
		t.Fatalf("want the release refusal naming the feature and token, got %v", err)
	}
	refusal := status.Error(codes.FailedPrecondition, "the cluster upgrade must finish first (email_target_secret needs "+capabilities.ReleaseToken+"): x")
	s.SetReleaseFeatureGate(fakeFeatureGate{err: refusal})
	if _, err := s.CreateNotificationTarget(adminCtx(), &pb.CreateNotificationTargetRequest{Name: "m", Type: "email", Config: emailSecret, Enabled: true}); !errors.Is(err, refusal) {
		t.Fatalf("want the gate's refusal unchanged, got %v", err)
	}
	if rows, _ := corrosion.ListNotificationTargets(adminCtx(), s.db); len(rows) != 0 {
		t.Fatalf("a refused create left %d rows", len(rows))
	}
	nopw := `{"host":"smtp.example.com","from":"lv@example.com","to":["ops@example.com"]}`
	if _, err := s.CreateNotificationTarget(adminCtx(), &pb.CreateNotificationTargetRequest{Name: "m2", Type: "email", Config: nopw, Enabled: true}); err != nil {
		t.Fatalf("passwordless email target refused: %v", err)
	}
	if _, err := s.CreateNotificationTarget(adminCtx(), &pb.CreateNotificationTargetRequest{Name: "w", Type: "webhook", Config: `{"url":"http://x"}`, Enabled: true}); err != nil {
		t.Fatalf("webhook target refused: %v", err)
	}
	openEmailFeature(t, s)
	if _, err := s.CreateNotificationTarget(adminCtx(), &pb.CreateNotificationTargetRequest{Name: "m", Type: "email", Config: emailSecret, Enabled: true}); err != nil {
		t.Fatalf("create through an open gate: %v", err)
	}
}

// The writer refuses a call that did not come through the gate.
func TestInsertEmailTargetWithSecret_RefusesWithoutGrant(t *testing.T) {
	s := testServer(t)
	err := corrosion.InsertEmailTargetWithSecret(context.Background(), s.db, capabilities.FeatureGrant{},
		corrosion.NotificationTarget{ID: "x", Name: "x", Type: "email", Config: emailSecret, Enabled: true})
	if !errors.Is(err, capabilities.ErrNoFeatureGrant) {
		t.Fatalf("want ErrNoFeatureGrant, got %v", err)
	}
}

// N-5: an unknown key is refused with InvalidArgument naming it.
func TestCreateNotificationTarget_EmailUnknownKeyRejectedByName(t *testing.T) {
	s := testServer(t)
	openEmailFeature(t, s)
	cfg := `{"host":"h","from":"a@b.c","to":["x@y.z"],"passwrd":"typo"}`
	_, err := s.CreateNotificationTarget(adminCtx(), &pb.CreateNotificationTargetRequest{Name: "m", Type: "email", Config: cfg, Enabled: true})
	if err == nil || status.Code(err) != codes.InvalidArgument || !strings.Contains(err.Error(), "passwrd") {
		t.Fatalf("want InvalidArgument naming the key, got %v", err)
	}
}
