package libvirt

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// The refusal matcher reads only QEMU's own message, after the option it
// echoes: a domain name or a path that contains "vnc" or "des" is not a
// console password refusal.
//
// Mutation "match the whole error text" — red.
func TestIsConsolePasswordRefusal_AnchoredToQEMUsMessage(t *testing.T) {
	for _, msg := range []string{
		// A LUKS cipher error on a VM called vnc-lab: "vnc" only in the name.
		"internal error: qemu unexpectedly closed the monitor: qemu-system-x86_64: -blockdev {\"driver\":\"luks\",\"node-name\":\"vnc-lab-disk\"}: Cipher algorithm 'aes-256-xts' not supported",
		// A bind failure whose socket path names a domain called des-vm.
		"internal error: qemu-system-x86_64: -vnc unix:/var/lib/libvirt/qemu/domain-3-des-vm/vnc.sock,password=on: Failed to bind socket: Address in use",
		// libvirt's own text with no QEMU message at all.
		"internal error: domain vnc-des-fips failed to start",
	} {
		if IsConsolePasswordRefusal(errors.New(msg)) {
			t.Errorf("taken for a console password refusal: %q", msg)
		}
	}
}

// Before the latch litevirt has set no password; an operator's on an imported
// domain is left alone, and that start fails as it always did.
//
// Mutation "backstop runs under PolicyLeave" — red.
func TestStart_BackstopLeavesAnOperatorPasswordBeforeTheLatch(t *testing.T) {
	m := &startModel{inactive: passworded, refuse: true}
	called := false
	if err := startWithConsoleBackstop(m, StartGuard{}, "web", PolicyLeave, func(string) { called = true }); err == nil {
		t.Fatal("the start succeeded: the operator's password was stripped before the latch")
	}
	if !HasConsolePassword(m.inactive) || called || m.starts != 1 {
		t.Errorf("under PolicyLeave: password kept %v, host marked %v, starts %d; want kept, unmarked, 1",
			HasConsolePassword(m.inactive), called, m.starts)
	}
}

// On a FIPS-mode kernel a failed start of a passworded domain is retried
// without the passwords even when QEMU's message matches nothing known: the
// message is QEMU's to change (10.2.1 has neither known one).
//
// Mutation "no fips_enabled fallback" — red.
func TestStart_BackstopFallsBackOnTheFIPSKernel(t *testing.T) {
	old := fipsEnabledPath
	t.Cleanup(func() { fipsEnabledPath = old })
	f := filepath.Join(t.TempDir(), "fips_enabled")
	_ = os.WriteFile(f, []byte("1\n"), 0o644)
	fipsEnabledPath = f

	m := &startModel{inactive: passworded}
	unknown := errors.New("internal error: qemu unexpectedly closed the monitor: qemu-system-x86_64: some message no one has seen")
	m.failFirst = unknown
	var reason string
	if err := startWithConsoleBackstop(m, StartGuard{}, "web", PolicySet, func(r string) { reason = r }); err != nil {
		t.Fatalf("start on a FIPS kernel with an unrecognised refusal: %v", err)
	}
	if HasConsolePassword(m.inactive) || reason == "" || m.starts != 2 {
		t.Errorf("password kept %v, reason %q, starts %d; want stripped, marked, 2", HasConsolePassword(m.inactive), reason, m.starts)
	}

	// Not on a FIPS kernel: the same unknown failure stands.
	_ = os.WriteFile(f, []byte("0\n"), 0o644)
	m = &startModel{inactive: passworded, failFirst: unknown}
	if err := startWithConsoleBackstop(m, StartGuard{}, "web", PolicySet, nil); err == nil || !HasConsolePassword(m.inactive) {
		t.Errorf("an unknown failure off FIPS was retried without the password (err %v)", err)
	}
}
