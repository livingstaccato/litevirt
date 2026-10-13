// Fleet scenarios for console passwords, lab-2 findings: a FIPS host's SPICE
// is reported unusable (F1), and a migration that strips the VNC password says
// so on the source (F3).
package fleet

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	lv "github.com/litevirt/litevirt/internal/libvirt"
)

// lockedBuffer is a log sink the fleet's goroutines can write while a test
// reads it.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func captureLogs(t *testing.T) *lockedBuffer {
	t.Helper()
	buf := &lockedBuffer{}
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(buf, nil)))
	t.Cleanup(func() { slog.SetDefault(old) })
	return buf
}

// TestFleet_ConsolePassword_SpiceUnusableOnAFIPSHostIsReported (lab-2 F1):
// on a FIPS host no SPICE client can connect, with or without a password.
// GetSpiceInfo, entered on another host, says so in its warning; nothing is
// refused (the info, password included, still comes back).
//
// Mutation "no warning" — red.
func TestFleet_ConsolePassword_SpiceUnusableOnAFIPSHostIsReported(t *testing.T) {
	c := consoleCluster(t)
	relay, fips := c.Nodes[0], c.Nodes[1]
	fips.Virt.SetSpiceUnusable("the kernel is in FIPS mode: spice-server makes an RSA-1024 key for every SPICE link")
	createConsoleVM(t, c, relay, "desk", fips.Name, true)
	resp, err := c.SelfClient(relay).GetSpiceInfo(context.Background(), &pb.GetSpiceInfoRequest{VmName: "desk"})
	if err != nil {
		t.Fatalf("GetSpiceInfo refused on a host where SPICE cannot connect: %v", err)
	}
	if !strings.Contains(resp.GetWarning(), "FIPS") {
		t.Errorf("GetSpiceInfo warning = %q, want it to say SPICE cannot connect on a FIPS host", resp.GetWarning())
	}
	if resp.GetPort() == 0 || resp.GetPassword() == "" {
		t.Errorf("the connection info was not returned in full: %+v", resp)
	}
}

// TestFleet_ConsolePassword_AStripMigrationIsLoggedOnTheSource (lab-2 F3):
// the source logs that the guest moves without its VNC password, with
// strip_vnc_password=true, naming the VM and the target.
//
// Mutation "no strip log" — red.
func TestFleet_ConsolePassword_AStripMigrationIsLoggedOnTheSource(t *testing.T) {
	logs := captureLogs(t)
	c := consoleCluster(t)
	src, dst := c.Nodes[0], c.Nodes[1]
	createConsoleVM(t, c, src, "desk", src.Name, false)
	dst.Virt.SetVNCPasswordUnavailable("fips")
	src.Virt.OnMigrateToTarget = func(name, _ string, p lv.MigrateParams) error {
		dst.Virt.LandMigrated(p.DestXML)
		return src.Virt.UndefineDomain(name, false)
	}
	if err := migrateAt(t, c, src, "desk", dst.Name); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	var line string
	for _, l := range strings.Split(logs.String(), "\n") {
		if strings.Contains(l, "strip_vnc_password=true") {
			line = l
		}
	}
	if line == "" || !strings.Contains(line, "vm=desk") || !strings.Contains(line, "target="+dst.Name) {
		t.Fatalf("no source log naming the VM, the target and strip_vnc_password=true; last match %q", line)
	}
}
