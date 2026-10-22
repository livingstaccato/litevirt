package fence

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func opts(args []string) map[string]string {
	m := map[string]string{}
	for i := 0; i+1 < len(args); i++ {
		if args[i] == "-o" {
			k, v, _ := strings.Cut(args[i+1], "=")
			if _, ok := m[k]; !ok {
				m[k] = v
			}
		}
	}
	return m
}

// TestSSHArgs_Managed: the managed fence uses no configuration of root's, its
// own key and no agent, the pinned key and nothing else, binds to its own
// certificate address, and cannot be proxied, forwarded or multiplexed.
func TestSSHArgs_Managed(t *testing.T) {
	h := HostConfig{Name: "node-x", Address: "10.77.0.3", SSHUser: "admin", SSHPort: 2222, SSH: SSHFence{
		Path: SSHPathManaged, KnownHosts: []byte("litevirt-fence.6e6f64652d78 ssh-ed25519 AAAA\n"),
		HostKeyAlias: "litevirt-fence.6e6f64652d78", IdentityFile: "/etc/litevirt/ssh/fence_ed25519",
		BindAddress: "10.77.0.2", User: "root", Request: "litevirt-fence v1 poweroff 6e6f64652d78",
	}}
	target, args, cleanup, err := sshArgs(context.Background(), h, h.SSH.Request)
	defer cleanup()
	if err != nil {
		t.Fatal(err)
	}
	if target != "root@10.77.0.3" {
		t.Errorf("target = %q: the managed path logs in as root whatever ssh_user says", target)
	}
	if args[0] != "-F" || args[1] != "/dev/null" || !slices.Contains(args, "/etc/litevirt/ssh/fence_ed25519") {
		t.Errorf("args = %q: want -F /dev/null first and -i the fence key", args)
	}
	o := opts(args)
	for k, want := range map[string]string{
		"StrictHostKeyChecking": "yes", "IdentitiesOnly": "yes", "IdentityAgent": "none",
		"HostKeyAlias": "litevirt-fence.6e6f64652d78", "GlobalKnownHostsFile": "/dev/null", "ProxyCommand": "none",
		"ProxyJump": "none", "ControlMaster": "no", "ControlPath": "none", "ForwardAgent": "no",
		"ClearAllForwardings": "yes", "BindAddress": "10.77.0.2", "BatchMode": "yes", "UpdateHostKeys": "no",
		"PasswordAuthentication": "no",
	} {
		if o[k] != want {
			t.Errorf("-o %s=%q, want %q", k, o[k], want)
		}
	}
	kh, err := os.ReadFile(o["UserKnownHostsFile"])
	if err != nil || string(kh) != string(h.SSH.KnownHosts) {
		t.Errorf("UserKnownHostsFile %q holds %q (%v), want the pinned keys", o["UserKnownHostsFile"], kh, err)
	}
	if args[len(args)-1] != h.SSH.Request || !slices.Contains(args, "2222") {
		t.Errorf("args end %q: want the request last, on ssh_port", args[len(args)-3:])
	}
	cleanup()
	if _, err := os.Stat(o["UserKnownHostsFile"]); !os.IsNotExist(err) {
		t.Errorf("the pinned known_hosts outlived the fence: %v", err)
	}
}

// TestSSHArgs_PinnedKeepsRootsIdentity: the pinned legacy path changes only
// the host-key check; root's configuration still supplies the identity.
func TestSSHArgs_PinnedKeepsRootsIdentity(t *testing.T) {
	h := HostConfig{Name: "node-x", Address: "10.77.0.3", SSH: SSHFence{Path: SSHPathPinned,
		KnownHosts: []byte("a ssh-ed25519 AAAA\n"), HostKeyAlias: "a"}}
	target, args, cleanup, err := sshArgs(context.Background(), h, sshPowerOffCommand)
	defer cleanup()
	if err != nil {
		t.Fatal(err)
	}
	o := opts(args)
	if target != "root@10.77.0.3" || o["StrictHostKeyChecking"] != "yes" || o["HostKeyAlias"] != "a" ||
		o["KnownHostsCommand"] != "none" || o["GlobalKnownHostsFile"] != "/dev/null" ||
		slices.Contains(args, "-F") || slices.Contains(args, "-i") {
		t.Fatalf("pinned args = %q", args)
	}
}

// TestSSHArgs_LegacyIsUnchanged: with no row the command is the one the base
// build ran, byte for byte.
func TestSSHArgs_LegacyIsUnchanged(t *testing.T) {
	_, args, cleanup, err := sshArgs(context.Background(), HostConfig{Address: "10.0.0.9"}, sshPowerOffCommand)
	defer cleanup()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"-o", "StrictHostKeyChecking=no", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
		"-o", "ServerAliveInterval=2", "-o", "ServerAliveCountMax=3", "-p", "22", "root@10.0.0.9", sshPowerOffCommand}
	if !slices.Equal(args, want) {
		t.Fatalf("legacy args = %q, want %q", args, want)
	}
}

// TestFenceSSH_RefusalDialsNothing: a refused path fails the fence without
// running ssh; a lenient fence keeps best-effort's contract.
func TestFenceSSH_RefusalDialsNothing(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "ran")
	fake := filepath.Join(dir, "ssh")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\necho ran >> "+log+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	defer OverrideSSHBinaryForTest(fake)()
	h := HostConfig{Name: "node-x", Address: "10.0.0.9", SSH: SSHFence{Refusal: "row does not verify"}}
	r := fenceSSH(context.Background(), h, false)
	if r.Success || !strings.Contains(r.Detail, "row does not verify") {
		t.Fatalf("strict = %+v", r)
	}
	if lr := fenceSSH(context.Background(), h, true); !lr.Success || lr.Method != "best-effort-ssh" {
		t.Fatalf("lenient = %+v", lr)
	}
	if _, err := os.Stat(log); !os.IsNotExist(err) {
		t.Fatal("a refused fence ran ssh")
	}
}
