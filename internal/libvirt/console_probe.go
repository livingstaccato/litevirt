package libvirt

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// VNC password probe (docs/ui.md "Console passwords").
//
// VNC authentication is DES. A QEMU whose crypto backend has no DES — every
// FIPS-mode host — refuses a -vnc ...,password=on display, and with it the
// whole guest start. So the daemon asks its own QEMU once at startup, and a
// host that cannot do it sets no VNC passwords (SPICE keeps its own): its
// consoles stay open, and it says so in PingResponse.not_enforcing. The start
// backstop (startWithConsoleBackstop) covers anything the probe gets wrong.

// vncProbeRunner runs QEMU with args and stdin and returns its stderr and
// error. A variable so the tests run without a QEMU.
var vncProbeRunner = func(ctx context.Context, bin string, args []string, stdin string) (string, error) {
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Stdin = strings.NewReader(stdin)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	cmd.Stdout = nil
	err := cmd.Run()
	return stderr.String(), err
}

// vncProbeBinary finds this host's QEMU system emulator, "" when it has none.
var vncProbeBinary = func() string {
	arch := map[string]string{"amd64": "x86_64", "arm64": "aarch64"}[runtime.GOARCH]
	for _, c := range []string{"/usr/libexec/qemu-kvm", "qemu-system-" + arch} {
		if c == "qemu-system-" {
			continue
		}
		if p, err := exec.LookPath(c); err == nil {
			return p
		}
	}
	return ""
}

// fipsEnabledPath is the kernel's FIPS switch. A variable for the tests.
var fipsEnabledPath = "/proc/sys/crypto/fips_enabled"

func fipsEnabled() bool {
	b, err := os.ReadFile(fipsEnabledPath)
	return err == nil && strings.TrimSpace(string(b)) == "1"
}

// ProbeVNCPassword reports why this host's QEMU cannot do VNC password
// authentication, "" when it can. It starts QEMU with no machine and a
// password-protected VNC display on a private unix socket, and quits it over
// QMP. A QEMU that refuses the display cannot; one that starts can. When
// there is no QEMU to ask, the kernel's FIPS switch decides. An inconclusive
// probe (QEMU failed for another reason) counts as "can": the start backstop
// still catches a refusal.
func ProbeVNCPassword(ctx context.Context) string {
	bin := vncProbeBinary()
	if bin == "" {
		if fipsEnabled() {
			return "the kernel is in FIPS mode (no QEMU found to ask)"
		}
		return ""
	}
	dir, err := os.MkdirTemp("", "lv-vncprobe-")
	if err != nil {
		return ""
	}
	defer os.RemoveAll(dir)
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	args := []string{
		"-machine", "none", "-nodefaults", "-no-user-config", "-display", "none", "-S",
		"-vnc", "unix:" + filepath.Join(dir, "vnc.sock") + ",password=on",
		"-qmp", "stdio",
	}
	stderr, err := vncProbeRunner(ctx, bin, args, `{"execute":"qmp_capabilities"}`+"\n"+`{"execute":"quit"}`+"\n")
	if err == nil {
		return ""
	}
	if IsConsolePasswordRefusal(errors.New(stderr)) {
		return fmt.Sprintf("%s refuses VNC password authentication: %s", filepath.Base(bin), firstLine(stderr))
	}
	if fipsEnabled() {
		return fmt.Sprintf("the kernel is in FIPS mode and the QEMU probe failed: %s", firstLine(stderr))
	}
	return ""
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return s
}
