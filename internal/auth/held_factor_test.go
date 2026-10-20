package auth

// Re-review 5, M1 (R5-1): a factor that a node which had not latched
// user_incarnation_v1 enrolled for a deleted account is held once the
// re-create reaches it: never accepted, and the account's login fails closed
// until an admin removes it.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"

	"github.com/litevirt/litevirt/internal/corrosion"
)

const heldOld, heldNew = "JBSWY3DPEHPK3PXP", "KRSXG5CTMVRXEZLU"

// heldCarol builds R5-1 up to the new carol's own enrolment and returns a,
// the latched node that took the held factor from u.
func heldCarol(t *testing.T) *corrosion.Client {
	t.Helper()
	ctx := context.Background()
	a, u := corrosion.NewTestClientT(t), corrosion.NewTestClientT(t)
	uOn := false
	a.SetUserIncarnationGate(func() bool { return true })
	u.SetUserIncarnationGate(func() bool { return uOn })
	for _, c := range []*corrosion.Client{a, u} {
		if err := corrosion.InitSchema(ctx, c); err != nil {
			t.Fatal(err)
		}
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
	pw, err := bcrypt.GenerateFromPassword([]byte("new-carol-pw"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertUser(ctx, a, "carol", "operator", string(pw)); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertUser2FA(ctx, u, corrosion.User2FARecord{Username: "carol", Method: "totp", Secret: heldOld, Label: "old-phone"}); err != nil {
		t.Fatal(err)
	}
	uOn = true
	sync(a, u)
	sync(u, a)
	return a
}

func codeFor(t *testing.T, secret string) string {
	t.Helper()
	c, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// R5-1, committed: the deleted holder's code alone does not pass the
// re-created carol's second factor, before or after she enrols her own.
//
// Red on 0476319bb: VerifyTOTP(old code) = true. Mutation: no hold — red.
func TestHeldFactor_AStaleUntaggedFactorAloneDoesNotPassTheNewAccount(t *testing.T) {
	ctx := context.Background()
	a := heldCarol(t)
	if ok, err := VerifyTOTP(ctx, a, "carol", codeFor(t, heldOld)); err != nil || ok {
		t.Errorf("before her enrolment: VerifyTOTP(the deleted holder's code) = %v (err %v), want false", ok, err)
	}
	if err := corrosion.InsertUser2FA(ctx, a, corrosion.User2FARecord{Username: "carol", Method: "totp", Secret: heldNew, Label: "phone"}); err != nil {
		t.Fatal(err)
	}
	if ok, err := VerifyTOTP(ctx, a, "carol", codeFor(t, heldOld)); err != nil || ok {
		t.Errorf("after her enrolment: VerifyTOTP(the deleted holder's code) = %v (err %v), want false", ok, err)
	}
	if ok, err := VerifyTOTP(ctx, a, "carol", codeFor(t, heldNew)); err != nil || !ok {
		t.Errorf("after her enrolment: VerifyTOTP(her own code) = %v (err %v), want true", ok, err)
	}
	p, err := NewLocalRealm(a).Authenticate(ctx, Credentials{Username: "carol", Password: "new-carol-pw"})
	if err != nil || p == nil || !p.Requires2FA {
		t.Errorf("after her enrolment: login = %+v (err %v), want a second-factor challenge", p, err)
	}
}

// With only held factors the login is refused on a correct password, never
// password-only, and the refusal names the two recovery commands.
//
// Red on 0476319bb (no hold; the stale factor is active). Mutation: held
// factors ignored by LocalRealm — red (a password-only login).
func TestHeldFactor_OnlyHeldFactorsRefuseTheLogin(t *testing.T) {
	ctx := context.Background()
	a := heldCarol(t)
	p, err := NewLocalRealm(a).Authenticate(ctx, Credentials{Username: "carol", Password: "new-carol-pw"})
	if !errors.Is(err, ErrSecondFactorHeld) {
		t.Fatalf("login = %+v, err %v; want ErrSecondFactorHeld", p, err)
	}
	for _, want := range []string{"lv 2fa disable --user carol --method totp --label", "lv 2fa enroll-code carol"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal %q does not name %q", err, want)
		}
	}
	if _, err := NewLocalRealm(a).Authenticate(ctx, Credentials{Username: "carol", Password: "wrong"}); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("a wrong password: err %v, want ErrInvalidCredentials (the hold is told only to the password's holder)", err)
	}
}
