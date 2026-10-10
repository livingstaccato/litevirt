//go:build linux

package filerestore

import (
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

// The test binary doubles as the restore VM's trampoline (the litevirt
// binary's `__file-restore-exec`) and as an escaped qemu (`__escape-probe`),
// so the launch tests run the real exec stage, Landlock included.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case TrampolineArg:
			RunTrampoline(os.Args[2:])
			return
		case escapeProbeArg:
			escapeProbe(os.Args[2:])
			return
		}
	}
	os.Exit(m.Run())
}

const escapeProbeArg = "__escape-probe"

// escapeProbe is what an escaped restore qemu would try, run in its place:
// read a world-readable file outside its allowlist, connect to a TCP
// listener and to an abstract unix socket — and, as a control, read a file
// it is allowed. It writes one line per attempt to out and exits 1 (the VM
// never comes up).
//
//	__escape-probe <out> <secret> <tcp addr> <abstract name> <allowed file>
func escapeProbe(args []string) {
	if len(args) != 5 {
		os.Exit(2)
	}
	out, secret, tcp, abstract, allowed := args[0], args[1], args[2], args[3], args[4]
	res := func(err error) string {
		if err == nil {
			return "ok"
		}
		return "refused: " + err.Error()
	}
	var b strings.Builder
	_, err := os.ReadFile(secret)
	fmt.Fprintf(&b, "read=%s\n", res(err))
	c, err := net.DialTimeout("tcp", tcp, 2*time.Second)
	if err == nil {
		c.Close()
	}
	fmt.Fprintf(&b, "tcp=%s\n", res(err))
	c, err = net.DialTimeout("unix", "@"+abstract, 2*time.Second)
	if err == nil {
		c.Close()
	}
	fmt.Fprintf(&b, "abstract=%s\n", res(err))
	_, err = os.ReadFile(allowed)
	fmt.Fprintf(&b, "allowed=%s\n", res(err))
	_ = os.WriteFile(out, []byte(b.String()), 0o644)
	os.Exit(1)
}
