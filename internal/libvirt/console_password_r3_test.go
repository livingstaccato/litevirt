package libvirt

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A QEMU whose password display asks for no password at all (it offers
// security type None) does not ENFORCE one: "unable", so the host sets no
// VNC passwords and reports console_password_v1 in not_enforcing, rather than
// believing its consoles are protected.
//
// Mutation "probe uses Authenticate (accepts None)" — red.
func TestProbeVNCPassword_NoAuthOfferedIsUnable(t *testing.T) {
	withProbe(t, &fakeProbeQEMU{offerNone: true}, false)
	r, proven := probeVNCPassword(context.Background())
	if r == "" || proven {
		t.Fatalf("a display offering no authentication: reason %q, proven %v; want unable", r, proven)
	}
	if !strings.Contains(r, "does not enforce") {
		t.Errorf("reason %q does not say the password is not enforced", r)
	}
}

// On a FIPS kernel the backstop strips passwords only after a start failure
// about the console — QEMU's message is about its -vnc/-spice option, or
// names VNC, SPICE or a password — never after an unrelated one (a disk that
// will not open), which must stand as it is with the passwords kept.
//
// Mutation "FIPS fallback on any start failure" — red.
func TestStart_FIPSFallbackOnlyForAConsoleFailure(t *testing.T) {
	old := fipsEnabledPath
	t.Cleanup(func() { fipsEnabledPath = old })
	f := filepath.Join(t.TempDir(), "fips_enabled")
	_ = os.WriteFile(f, []byte("1\n"), 0o644)
	fipsEnabledPath = f

	unrelated := errors.New("internal error: qemu unexpectedly closed the monitor: qemu-system-x86_64: " +
		"-blockdev {\"driver\":\"file\",\"filename\":\"/pool/web-root.qcow2\"}: Could not open '/pool/web-root.qcow2': Permission denied")
	m := &startModel{inactive: passworded, failFirst: unrelated}
	called := false
	if err := startWithConsoleBackstop(m, StartGuard{}, "web", PolicySet, func(string) { called = true }); err == nil {
		t.Fatal("an unrelated start failure on a FIPS kernel was retried into success")
	}
	if !HasConsolePassword(m.inactive) || called || m.starts != 1 {
		t.Errorf("unrelated failure on FIPS: password kept %v, host marked %v, starts %d; want kept, unmarked, 1",
			HasConsolePassword(m.inactive), called, m.starts)
	}

	console := errors.New("internal error: qemu unexpectedly closed the monitor: qemu-system-x86_64: " +
		"-spice port=5930,addr=127.0.0.1,password-secret=graphics-spice0-secret0: some message no one has seen")
	m = &startModel{inactive: passworded, failFirst: console}
	if err := startWithConsoleBackstop(m, StartGuard{}, "web", PolicySet, nil); err != nil {
		t.Fatalf("a console start failure on a FIPS kernel: %v", err)
	}
	if HasConsolePassword(m.inactive) {
		t.Error("a console start failure on a FIPS kernel kept the passwords")
	}
}
