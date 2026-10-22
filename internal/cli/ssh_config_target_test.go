package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/pki"
	"github.com/litevirt/litevirt/internal/ssh"
	"google.golang.org/grpc"
)

type listHostsOnly struct{ pb.LiteVirtClient }

func (listHostsOnly) ListHosts(context.Context, *pb.ListHostsRequest, ...grpc.CallOption) (*pb.ListHostsResponse, error) {
	return &pb.ListHostsResponse{}, nil
}

// sshAliasEnv gives the test a HOME whose ssh config defines `labnode`, a CA
// the add/rotate paths need, and a lookupHost recording what it was asked.
func sshAliasEnv(t *testing.T, hostName string) (asked *[]string) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SSH_AUTH_SOCK", "")
	cfgDir := filepath.Join(home, "lvcfg")
	t.Setenv("LV_CONFIG_DIR", cfgDir)
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := "Host labnode\n  HostName " + hostName + "\n  User deploy\n  Port 1\n"
	if err := os.WriteFile(filepath.Join(home, ".ssh", "config"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	pkiDir := filepath.Join(cfgDir, "pki")
	if err := os.MkdirAll(pkiDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := pki.GenerateCA(filepath.Join(pkiDir, "ca.crt"), filepath.Join(pkiDir, "ca.key")); err != nil {
		t.Fatal(err)
	}
	var seen []string
	old := lookupHost
	lookupHost = func(h string) ([]string, error) {
		seen = append(seen, h)
		return []string{"10.9.9.9"}, nil
	}
	t.Cleanup(func() { lookupHost = old })
	return &seen
}

type provisioner struct {
	name string
	run  func() error
}

func provisioners() []provisioner {
	return []provisioner{
		{"init", func() error { return HostInit(context.Background(), "labnode", "node-9", false) }},
		{"add", func() error {
			return HostAdd(context.Background(), listHostsOnly{}, "labnode", "node-9", []string{"10.0.0.1:7946"})
		}},
		{"rotate-audit-key", func() error { return HostRotateAuditKey(context.Background(), "node-9", "labnode") }},
	}
}

// An alias that exists only in ~/.ssh/config must get past the address step:
// the old DNS lookup of "labnode" failed before ssh was ever tried.
func TestProvision_AliasOnlyInSSHConfig(t *testing.T) {
	for _, p := range provisioners() {
		t.Run(p.name, func(t *testing.T) {
			asked := sshAliasEnv(t, "127.0.0.1")
			lookupHost = func(h string) ([]string, error) { *asked = append(*asked, h); return nil, os.ErrNotExist }
			err := p.run()
			if err != nil && strings.Contains(err.Error(), "resolve host") {
				t.Fatalf("%s resolved the alias through DNS instead of ssh config: %v", p.name, err)
			}
		})
	}
}

// When the alias DNS-resolves somewhere else, the address step must use the
// config's HostName, the machine the dial reaches, not the alias.
func TestProvision_UsesHostNameForAddressStep(t *testing.T) {
	for _, p := range provisioners() {
		t.Run(p.name, func(t *testing.T) {
			asked := sshAliasEnv(t, "node.lab.test")
			_ = p.run()
			for _, h := range *asked {
				if h == "labnode" {
					t.Fatalf("%s looked up the alias %q in DNS; asked %v", p.name, h, *asked)
				}
			}
			if len(*asked) == 0 || (*asked)[0] != "node.lab.test" {
				t.Fatalf("%s did not look up the ssh config HostName; asked %v", p.name, *asked)
			}
		})
	}
}

func TestRefuseInitOfAClusterMember_UsesHostName(t *testing.T) {
	asked := sshAliasEnv(t, "node.lab.test")
	_ = RefuseInitOfAClusterMember(context.Background(), "labnode", false)
	if len(*asked) == 0 || (*asked)[0] != "node.lab.test" {
		t.Fatalf("asked %v, want the ssh config HostName first", *asked)
	}
}

// `lv host init` looks at the ssh config once: the cluster-member check and
// the init both take the already-resolved target, so a config that answers
// differently on a second run cannot split the SAN from the dial.
func TestHostInit_ResolvesTheSSHConfigOnce(t *testing.T) {
	_ = sshAliasEnv(t, "127.0.0.1")
	counter := filepath.Join(t.TempDir(), "runs")
	home := os.Getenv("HOME")
	cfg := "Match exec \"echo x >> " + counter + "\"\n  Port 1\nHost labnode\n  HostName 127.0.0.1\n  User deploy\n  Port 1\n"
	if err := os.WriteFile(filepath.Join(home, ".ssh", "config"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	rt, err := ssh.Resolve("labnode")
	if err != nil {
		t.Fatal(err)
	}
	_ = RefuseInitOfAClusterMemberResolved(context.Background(), "labnode", rt, false)
	_ = HostInitResolved(context.Background(), "labnode", rt, "node-9", false)
	b, _ := os.ReadFile(counter)
	if n := strings.Count(string(b), "x"); n != 1 {
		t.Fatalf("ssh -G ran %d times for one init, want 1", n)
	}
}
