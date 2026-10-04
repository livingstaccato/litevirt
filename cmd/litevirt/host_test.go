package main

import (
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

func TestNewHostConfigCmd(t *testing.T) {
	cmd := newHostConfigCmd()

	if cmd.Use != "config <host>" {
		t.Errorf("Use = %q, want %q", cmd.Use, "config <host>")
	}
	if cmd.Short == "" {
		t.Error("Short should not be empty")
	}

	expectedFlags := []string{
		"fence-strategy",
		"ipmi-address",
		"ipmi-user",
		"ipmi-pass",
		"watchdog-dev",
	}
	for _, name := range expectedFlags {
		if cmd.Flags().Lookup(name) == nil {
			t.Errorf("expected flag %q not found", name)
		}
	}
}

// --clear-ipmi is the only way to remove a host's IPMI settings (an empty
// --ipmi-* flag means "leave alone"), and asking to set and clear them at once
// is refused before anything is sent.
func TestHostConfig_ClearIPMIFlag(t *testing.T) {
	cmd := newHostConfigCmd()
	f := cmd.Flags().Lookup("clear-ipmi")
	if f == nil || f.DefValue != "false" {
		t.Fatalf("clear-ipmi flag = %+v, want a bool defaulting to false", f)
	}
	for _, other := range []string{"ipmi-address", "ipmi-user", "ipmi-pass"} {
		cmd := newHostConfigCmd()
		cmd.SetArgs([]string{"h", "--clear-ipmi", "--" + other, "x"})
		cmd.SilenceUsage, cmd.SilenceErrors = true, true
		err := cmd.Execute()
		if err == nil || !strings.Contains(err.Error(), "clear-ipmi") {
			t.Errorf("--clear-ipmi with --%s: err = %v, want a flag-conflict error", other, err)
		}
	}
}

// A server that predates clear_ipmi ignores the field and answers with the
// host unchanged; the CLI must not report that as a clear.
func TestHostConfig_ClearIPMIUnhonouredIsAnError(t *testing.T) {
	if err := checkIPMICleared(&pb.Host{Name: "h", IpmiAddress: "10.0.1.1"}); err == nil {
		t.Error("a host still carrying an IPMI address after --clear-ipmi must be an error")
	}
	if err := checkIPMICleared(&pb.Host{Name: "h"}); err != nil {
		t.Errorf("cleared host: %v", err)
	}
}
