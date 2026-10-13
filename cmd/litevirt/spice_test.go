package main

import (
	"bytes"
	"os"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// `lv spice --launch` hands remote-viewer a 0600 connection file carrying the
// console's password, never the password on argv (where every local user
// could read it from /proc).
//
// Mutation "launch with the URI + password on argv" — red.
func TestSpiceLaunch_PasswordInA0600FileNotArgv(t *testing.T) {
	resp := &pb.GetSpiceInfoResponse{Host: "10.0.0.5", Port: 5930, Uri: "spice://10.0.0.5:5930",
		Password: "Spice24CharPasswordAbcde"}
	path, err := writeSpiceVV(t.TempDir(), "desk", resp)
	if err != nil {
		t.Fatalf("writeSpiceVV: %v", err)
	}
	args := spiceLaunchArgs(path)
	for _, a := range args {
		if strings.Contains(a, resp.Password) {
			t.Fatalf("the password is on remote-viewer's argv: %v", args)
		}
	}
	if len(args) != 1 || args[0] != path {
		t.Fatalf("remote-viewer args = %v, want just the connection file", args)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("connection file mode %v, want 0600", fi.Mode().Perm())
	}
	b, _ := os.ReadFile(path)
	for _, want := range []string{"[virt-viewer]", "type=spice", "host=10.0.0.5", "port=5930",
		"password=Spice24CharPasswordAbcde", "delete-this-file=1"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("connection file missing %q:\n%s", want, b)
		}
	}
}

// A host where SPICE cannot connect (a FIPS-mode kernel) is named in the
// output; the info is still printed.
//
// Mutation "warning not printed" — red.
func TestSpiceInfo_PrintsTheHostsWarning(t *testing.T) {
	var b bytes.Buffer
	printSpiceInfo(&b, "desk", &pb.GetSpiceInfoResponse{Host: "h", Port: 5930, Uri: "spice://h:5930",
		Warning: "the kernel is in FIPS mode: no SPICE client can connect"}, false)
	if !strings.Contains(b.String(), "Warning:") || !strings.Contains(b.String(), "FIPS") || !strings.Contains(b.String(), "Port: 5930") {
		t.Errorf("lv spice output lacks the warning or the info:\n%s", b.String())
	}
}

// The password is printed only on request.
//
// Mutation "always print the password" — red.
func TestSpiceInfo_PasswordOnlyWithShowPassword(t *testing.T) {
	resp := &pb.GetSpiceInfoResponse{Host: "10.0.0.5", Port: 5930, Uri: "spice://10.0.0.5:5930",
		Password: "Spice24CharPasswordAbcde"}
	var hidden, shown bytes.Buffer
	printSpiceInfo(&hidden, "desk", resp, false)
	printSpiceInfo(&shown, "desk", resp, true)
	if strings.Contains(hidden.String(), resp.Password) {
		t.Errorf("the password is printed without --show-password:\n%s", hidden.String())
	}
	if !strings.Contains(hidden.String(), "--show-password") {
		t.Errorf("the output does not say how to get the password:\n%s", hidden.String())
	}
	if !strings.Contains(shown.String(), "Password: "+resp.Password) {
		t.Errorf("--show-password does not print it:\n%s", shown.String())
	}
	var none bytes.Buffer
	printSpiceInfo(&none, "desk", &pb.GetSpiceInfoResponse{Host: "h", Port: 1, Uri: "spice://h:1"}, true)
	if strings.Contains(none.String(), "Password") {
		t.Errorf("a console with no password prints a Password line:\n%s", none.String())
	}
}
