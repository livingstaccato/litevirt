package grpcapi

import (
	"errors"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// UpdateVM's regenerate reads the current definition for what only it holds
// (a journaled device's alias). A read that fails still regenerates, as it
// always has, but says so with the VM's name instead of dropping it silently.
//
// Mutation: discard the read's error without logging — the warning test goes
// red.
func TestUpdateVM_RegenerateLogsAnUnreadableDefinition(t *testing.T) {
	s := reconfigServer(t)
	ctx := adminCtx()
	insertTestVMWithSpec(t, ctx, s.db, "dumpfail", "test-host", "stopped",
		seedSpecJSON(t, &pb.VMSpec{Name: "dumpfail", Cpu: 2, MemoryMib: 2048, Machine: "pc"}))
	if err := s.virt.DefineDomain(`<domain type='kvm'><name>dumpfail</name><devices></devices></domain>`); err != nil {
		t.Fatalf("seed domain: %v", err)
	}
	s.virt.(*libvirtfake.Fake).FailDumpXMLInactive = func(string) error { return errors.New("connection reset by peer") }
	logs := captureSlog(t)

	if _, err := s.UpdateVM(ctx, &pb.UpdateVMRequest{Name: "dumpfail", Machine: "q35"}); err != nil {
		t.Fatalf("UpdateVM must still regenerate when the definition cannot be read: %v", err)
	}
	var line string
	for _, l := range strings.Split(logs.String(), "\n") {
		if strings.Contains(l, "level=WARN") && strings.Contains(l, "connection reset by peer") {
			line = l
		}
	}
	if line == "" || !strings.Contains(line, "vm=dumpfail") {
		t.Fatalf("no warning naming the VM and the read error:\n%s", logs.String())
	}
}
