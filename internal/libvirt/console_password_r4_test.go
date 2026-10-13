package libvirt

import (
	"bytes"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func captureSlog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(old) })
	return &buf
}

func withFIPS(t *testing.T, on bool) {
	t.Helper()
	old := fipsEnabledPath
	t.Cleanup(func() { fipsEnabledPath = old })
	f := filepath.Join(t.TempDir(), "fips_enabled")
	v := "0\n"
	if on {
		v = "1\n"
	}
	_ = os.WriteFile(f, []byte(v), 0o644)
	fipsEnabledPath = f
}

// Lab-2 F2: the backstop's log says what actually matched. A console-option
// failure on a FIPS kernel (the drill's was a VNC port collision) is not "QEMU
// refused the console password"; only a message that says so is.
//
// Mutation "one message for both" — red.
func TestStart_BackstopLogSaysWhatMatched(t *testing.T) {
	withFIPS(t, true)
	buf := captureSlog(t)
	collision := errors.New("internal error: qemu unexpectedly closed the monitor: qemu-system-x86_64: " +
		"-vnc 127.0.0.1:0,password=on: Failed to find an available port: Address already in use")
	m := &startModel{inactive: passworded, failFirst: collision}
	_ = startWithConsoleBackstop(m, StartGuard{}, "web", PolicySet, nil)
	log := buf.String()
	if strings.Contains(log, "refused the console password") {
		t.Errorf("a port collision was logged as a password refusal:\n%s", log)
	}
	if !strings.Contains(log, "console option failed on a FIPS-mode host") {
		t.Errorf("the log does not say a console option failed on a FIPS host:\n%s", log)
	}

	buf.Reset()
	refusal := errors.New("internal error: qemu-system-x86_64: -vnc unix:/x,password=on: Cipher backend does not support DES algorithm")
	m = &startModel{inactive: passworded, failFirst: refusal}
	_ = startWithConsoleBackstop(m, StartGuard{}, "web", PolicySet, nil)
	if !strings.Contains(buf.String(), "QEMU refused the console password") {
		t.Errorf("a real refusal was not logged as one:\n%s", buf.String())
	}
}

// Lab-2 F1: on a FIPS-mode kernel SPICE cannot connect at all (spice-server
// makes an RSA-1024 key per link, which FIPS refuses), so the host says so.
//
// Mutation "no SPICE check" — red.
func TestSpiceUnusableReason_FIPS(t *testing.T) {
	withFIPS(t, true)
	if r := SpiceUnusableReason(); !strings.Contains(r, "SPICE") || !strings.Contains(r, "FIPS") {
		t.Fatalf("SpiceUnusableReason on a FIPS kernel = %q, want it to name SPICE and FIPS", r)
	}
	withFIPS(t, false)
	if r := SpiceUnusableReason(); r != "" {
		t.Fatalf("SpiceUnusableReason off FIPS = %q, want none", r)
	}
}
