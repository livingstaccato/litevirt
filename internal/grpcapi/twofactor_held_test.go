package grpcapi

import (
	"context"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// heldCarolServer: s's node u had not latched user_incarnation_v1 when it
// enrolled "old-phone" for a carol node a has since deleted and re-created;
// once u adopts the re-create, the factor is held.
func heldCarolServer(t *testing.T) *Server {
	t.Helper()
	ctx := context.Background()
	s := testServer(t)
	a, u := corrosion.NewTestClientT(t), s.db
	if err := corrosion.InitSchema(ctx, a); err != nil {
		t.Fatal(err)
	}
	uOn := false
	a.SetUserIncarnationGate(func() bool { return true })
	u.SetUserIncarnationGate(func() bool { return uOn })
	for _, c := range []*corrosion.Client{a, u} {
		c.SetCredentialsSplitGate(func() bool { return true })
	}
	sync := func(from, to *corrosion.Client) {
		t.Helper()
		if err := to.MergeStateBytesLWW(from.DumpStateBytes()); err != nil {
			t.Fatal(err)
		}
		if err := to.MergeSensitiveStateBytesLWW(from.DumpSensitiveStateBytes()); err != nil {
			t.Fatal(err)
		}
	}
	if err := corrosion.InsertUser(ctx, a, "carol", "operator", "hash-old"); err != nil {
		t.Fatal(err)
	}
	sync(a, u)
	if err := corrosion.DeleteUser(ctx, a, "carol"); err != nil {
		t.Fatal(err)
	}
	pw, _ := bcrypt.GenerateFromPassword([]byte("new-carol-pw"), bcrypt.MinCost)
	if err := corrosion.InsertUser(ctx, a, "carol", "operator", string(pw)); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertUser2FA(ctx, u, corrosion.User2FARecord{Username: "carol", Method: "totp", Secret: "JBSWY3DPEHPK3PXP", Label: "old-phone"}); err != nil {
		t.Fatal(err)
	}
	uOn = true
	sync(a, u)
	return s
}

// Re-review 5, M1, at the API: a correct password with only held factors is
// refused (FailedPrecondition) naming the two recovery commands; the factor
// is listed marked "(held)" and counts as enrolled; and the admin removes it
// by the label it is listed under.
//
// Mutations: the held factor left out of ListTwoFactors — red; left out of
// hasSecondFactor — red; the suffix not stripped on disable — red.
func TestTwoFactor_AHeldFactorIsListedCountedAndRemovable(t *testing.T) {
	ctx := context.Background()
	s := heldCarolServer(t)
	_, err := s.Login(ctx, &pb.LoginRequest{Username: "carol", Password: "new-carol-pw"})
	if status.Code(err) != codes.FailedPrecondition ||
		!strings.Contains(err.Error(), "lv 2fa disable --user carol --method totp --label") ||
		!strings.Contains(err.Error(), "lv 2fa enroll-code carol") {
		t.Errorf("login = %v; want FailedPrecondition naming both recovery commands", err)
	}
	if has, err := s.hasSecondFactor(ctx, "carol"); err != nil || !has {
		t.Errorf("hasSecondFactor = %v (err %v): an enrollment-only session could enroll beside the held factor", has, err)
	}
	ls, err := s.ListTwoFactors(adminCtx(), &pb.ListTwoFactorsRequest{Username: "carol"})
	if err != nil {
		t.Fatal(err)
	}
	if len(ls.Factors) != 1 || ls.Factors[0].Label != "old-phone"+HeldFactorLabelSuffix {
		t.Fatalf("listed = %+v, want old-phone marked held", ls.Factors)
	}
	if _, err := s.DisableTwoFactor(adminCtx(), &pb.DisableTwoFactorRequest{Username: "carol", Method: "totp", Label: ls.Factors[0].Label}); err != nil {
		t.Fatal(err)
	}
	if held, _ := corrosion.ListHeldUser2FA(ctx, s.db, "carol"); len(held) != 0 {
		t.Errorf("after the admin's disable: held = %+v", held)
	}
}
