package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"google.golang.org/grpc"
)

type captureConfigureHost struct {
	pb.LiteVirtClient
	req *pb.ConfigureHostRequest
}

func (c *captureConfigureHost) ConfigureHost(_ context.Context, in *pb.ConfigureHostRequest, _ ...grpc.CallOption) (*pb.Host, error) {
	c.req = in
	return &pb.Host{Name: in.GetName()}, nil
}

// runHostConfig runs `lv host config` with stdin, returning what reached
// ConfigureHost and what was written to stderr.
func runHostConfig(t *testing.T, stdin string, args ...string) (*pb.ConfigureHostRequest, string, error) {
	t.Helper()
	spy := &captureConfigureHost{}
	orig := withClient
	withClient = func(ctx context.Context, fn func(context.Context, pb.LiteVirtClient) error) error {
		return fn(ctx, spy)
	}
	t.Cleanup(func() { withClient = orig })
	cmd := newHostConfigCmd()
	cmd.SetArgs(args)
	cmd.SetIn(strings.NewReader(stdin))
	var stderr bytes.Buffer
	cmd.SetErr(&stderr)
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	var err error
	captureStdout(t, func() { err = cmd.ExecuteContext(context.Background()) })
	return spy.req, stderr.String(), err
}

// Lab 4 finding 5: `lv host config` took the IPMI password only on argv,
// where `ps` on the machine running lv shows it to every user. It now reads
// it from a file or stdin (--ipmi-pass-file, as --redfish-pass-file does);
// --ipmi-pass still works and warns that it is visible.
//
// Mutations: drop the --ipmi-pass-file read — "file" and "stdin" send no
// password; drop the warning — "argv" prints none.
func TestHostConfig_IPMIPassKeptOutOfArgv(t *testing.T) {
	f := filepath.Join(t.TempDir(), "pw")
	if err := os.WriteFile(f, []byte("from-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, stdin string
		args        []string
		want        string
		warns       bool
	}{
		{"file", "", []string{"node-1", "--ipmi-pass-file", f}, "from-file", false},
		{"stdin", "from-stdin\n", []string{"node-1", "--ipmi-pass-file", "-"}, "from-stdin", false},
		{"argv", "", []string{"node-1", "--ipmi-pass", "on-argv"}, "on-argv", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, stderr, err := runHostConfig(t, tc.stdin, tc.args...)
			if err != nil {
				t.Fatal(err)
			}
			if req.GetIpmiPass() != tc.want {
				t.Errorf("sent ipmi_pass %q, want %q", req.GetIpmiPass(), tc.want)
			}
			warned := strings.Contains(stderr, "--ipmi-pass is visible") && strings.Contains(stderr, "process list")
			if warned != tc.warns {
				t.Errorf("stderr = %q, want the visibility warning: %v", stderr, tc.warns)
			}
			if strings.Contains(stderr, tc.want) {
				t.Errorf("stderr shows the password: %q", stderr)
			}
		})
	}
	t.Run("empty stdin", func(t *testing.T) {
		if req, _, err := runHostConfig(t, "\n", "node-1", "--ipmi-pass-file", "-"); err == nil || req != nil {
			t.Fatalf("an empty password was sent: %v, %v", req, err)
		}
	})
	// Review minor: a password file its group or other users can read is
	// warned of (it is still used); a 0600 file and stdin are not.
	t.Run("group- or world-readable file", func(t *testing.T) {
		for _, flag := range []string{"--ipmi-pass-file", "--redfish-pass-file"} {
			for mode, warns := range map[os.FileMode]bool{0o600: false, 0o640: true, 0o644: true, 0o400: false} {
				p := filepath.Join(t.TempDir(), "pw")
				if err := os.WriteFile(p, []byte("pw\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(p, mode); err != nil {
					t.Fatal(err)
				}
				_, stderr, _ := runHostConfig(t, "", "node-1", flag, p)
				if got := strings.Contains(stderr, "readable by its group or other users"); got != warns {
					t.Errorf("%s at %04o: warned %v, want %v (%q)", flag, mode, got, warns, stderr)
				}
			}
		}
		if _, stderr, _ := runHostConfig(t, "pw\n", "node-1", "--ipmi-pass-file", "-"); strings.Contains(stderr, "readable") {
			t.Errorf("stdin warned of a file mode: %q", stderr)
		}
	})
	for _, pair := range [][]string{{"--ipmi-pass", "x", "--ipmi-pass-file", f}, {"--clear-ipmi", "--ipmi-pass-file", f}} {
		if req, _, err := runHostConfig(t, "", append([]string{"node-1"}, pair...)...); err == nil || req != nil {
			t.Errorf("%v: err = %v, want a flag conflict and nothing sent", pair, err)
		}
	}
}
