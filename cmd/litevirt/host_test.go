package main

import (
	"os"
	"path/filepath"
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

// A server that predates the Redfish fields ignores them and answers with the
// host unchanged; the CLI must not report that as configured, or as cleared.
func TestHostConfig_RedfishUnhonouredIsAnError(t *testing.T) {
	set := &pb.ConfigureHostRequest{Name: "h", RedfishEndpoint: "https://10.0.1.1"}
	if err := checkRedfishApplied(&pb.Host{Name: "h"}, set); err == nil {
		t.Error("a host with no Redfish endpoint after --redfish-endpoint must be an error")
	}
	if err := checkRedfishApplied(&pb.Host{Name: "h", RedfishEndpoint: "https://10.0.1.1"}, set); err != nil {
		t.Errorf("configured host: %v", err)
	}
	clear := &pb.ConfigureHostRequest{Name: "h", ClearRedfish: true}
	if err := checkRedfishApplied(&pb.Host{Name: "h", RedfishEndpoint: "https://10.0.1.1"}, clear); err == nil {
		t.Error("a host still carrying a Redfish endpoint after --clear-redfish must be an error")
	}
	if err := checkRedfishApplied(&pb.Host{Name: "h"}, clear); err != nil {
		t.Errorf("cleared host: %v", err)
	}
	for _, other := range []string{"redfish-endpoint", "redfish-pass", "redfish-ca-file"} {
		cmd := newHostConfigCmd()
		cmd.SetArgs([]string{"h", "--clear-redfish", "--" + other, "x"})
		cmd.SilenceUsage, cmd.SilenceErrors = true, true
		if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "clear-redfish") {
			t.Errorf("--clear-redfish with --%s: err = %v, want a flag-conflict error", other, err)
		}
	}
}

// The BMC password can come from a file or stdin, keeping it out of argv.
func TestReadSecretFile(t *testing.T) {
	f := filepath.Join(t.TempDir(), "pw")
	if err := os.WriteFile(f, []byte("s3cret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := readSecretFile(nil, f); err != nil || got != "s3cret" {
		t.Errorf("file: %q %v", got, err)
	}
	if got, err := readSecretFile(strings.NewReader("from-stdin\r\n"), "-"); err != nil || got != "from-stdin" {
		t.Errorf("stdin: %q %v", got, err)
	}
	if _, err := readSecretFile(strings.NewReader("\n"), "-"); err == nil {
		t.Error("an empty secret was accepted")
	}
	for _, pair := range [][]string{{"--redfish-pass", "x", "--redfish-pass-file", f}, {"--clear-redfish-ca", "--redfish-ca-file", f}} {
		cmd := newHostConfigCmd()
		cmd.SetArgs(append([]string{"h"}, pair...))
		cmd.SilenceUsage, cmd.SilenceErrors = true, true
		if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "none of the others") && !strings.Contains(err.Error(), "if any flags in the group") {
			t.Errorf("%v: err = %v, want a flag-conflict error", pair, err)
		}
	}
	if err := checkRedfishApplied(&pb.Host{Name: "h", RedfishSystemId: "1"}, &pb.ConfigureHostRequest{ClearRedfishSystemId: true}); err == nil {
		t.Error("an unhonoured system-id unset must be an error")
	}
	if err := checkRedfishApplied(&pb.Host{Name: "h", RedfishCaConfigured: true}, &pb.ConfigureHostRequest{ClearRedfishCa: true}); err == nil {
		t.Error("an unhonoured CA unset must be an error")
	}
}
