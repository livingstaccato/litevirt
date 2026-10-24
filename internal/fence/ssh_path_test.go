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
		"PasswordAuthentication": "no", "VerifyHostKeyDNS": "no",
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
// the host-key check; root's configuration still supplies the identity. It
// never rides a master connection root's configuration multiplexes over (a
// mux session checks no host key) or takes a key from SSHFP or a
// KnownHostsCommand.
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
		o["ControlMaster"] != "no" || o["ControlPath"] != "none" || o["VerifyHostKeyDNS"] != "no" ||
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
	want := []string{"-o", "StrictHostKeyChecking=no", "-o", "BatchMode=yes", "-o", "LogLevel=ERROR", "-o", "ConnectTimeout=10",
		"-o", "ServerAliveInterval=2", "-o", "ServerAliveCountMax=3", "-p", "22", "root@10.0.0.9", sshPowerOffCommand}
	if !slices.Equal(args, want) {
		t.Fatalf("legacy args = %q, want %q", args, want)
	}
}

// TestFenceSSH_RefusalDialsNothing: a refused path fails the fence without
// running ssh, under every strategy. A lenient (best-effort) fence fails too:
// its assumed success is for an attempt that may have landed, and a refused
// one was never made. Both name the ways out.
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
	if r.Success || r.Method != "ssh" || !strings.Contains(r.Detail, "row does not verify") {
		t.Fatalf("strict = %+v", r)
	}
	lr := fenceSSH(context.Background(), h, true)
	if lr.Success || lr.Method != "best-effort-ssh" || !strings.Contains(lr.Detail, "row does not verify") {
		t.Fatalf("lenient = %+v, want a failure", lr)
	}
	for _, res := range []Result{r, lr} {
		if res.LogResult() != LogPartial || Assurance(res.Method, res.LogResult()) != AssuranceFailed {
			t.Fatalf("%+v is recorded %s/%s, want partial/failed", res, res.LogResult(), Assurance(res.Method, res.LogResult()))
		}
		for _, want := range []string{"lv host fence-confirm node-x", "ipmi or redfish", "does not count as a fence"} {
			if !strings.Contains(res.Detail, want) {
				t.Fatalf("detail %q does not name %q", res.Detail, want)
			}
		}
	}
	for _, strategy := range []string{"", "best-effort", "ssh"} {
		h := h
		h.FenceStrategy = strategy
		if er := Execute(context.Background(), h); er.Success {
			t.Fatalf("Execute under %q of a refused path = %+v, want a failure", strategy, er)
		}
	}
	// A path that cannot start (a pinned path with no pin) is not attempted
	// either.
	unstarted := HostConfig{Name: "node-x", Address: "10.0.0.9", SSH: SSHFence{Path: SSHPathPinned}}
	if ur := fenceSSH(context.Background(), unstarted, true); ur.Success || !strings.Contains(ur.Detail, "could not start") {
		t.Fatalf("lenient fence that could not start = %+v, want a failure", ur)
	}
	if _, err := os.Stat(log); !os.IsNotExist(err) {
		t.Fatal("a refused fence ran ssh")
	}
}

// TestFenceSSH_PinnedOnAClientWithoutKnownHostsCommand: OpenSSH before 8.5
// (EL8's 8.0, Debian 11's 8.4) rejects KnownHostsCommand as an unknown option
// and exits 255 before it dials. Passing it there failed every pinned fence:
// a strict fence never fenced, a best-effort one reported success with the
// host still running. Such a client has no KnownHostsCommand for root's config
// to set, so the option is left out and the fence powers the host off.
func TestFenceSSH_PinnedOnAClientWithoutKnownHostsCommand(t *testing.T) {
	h := fakeSSH(t, fakeRemote{forceWorks: true, sysrqWritable: true, preKnownHostsCommand: true})
	cfg := sshHost()
	cfg.SSH = SSHFence{Path: SSHPathPinned, KnownHosts: []byte("a ssh-ed25519 AAAA\n"), HostKeyAlias: "a"}

	r := Execute(fenceCtx(t), cfg)

	if got := h.state(t); got != "off" {
		t.Errorf("host state = %q after a pinned fence on a pre-8.5 client, want off; detail=%q", got, r.Detail)
	}
	if !r.Success {
		t.Errorf("Success=false for a host that was powered off; detail=%q", r.Detail)
	}
}

// TestSSHArgs_PinnedKeepsKnownHostsCommandWhereSupported: a client that
// accepts the option still gets it, so root's config cannot add keys to the
// pin.
func TestSSHArgs_PinnedKeepsKnownHostsCommandWhereSupported(t *testing.T) {
	fakeSSH(t, fakeRemote{forceWorks: true, sysrqWritable: true})
	h := HostConfig{Name: "node-x", Address: "10.77.0.3", SSH: SSHFence{Path: SSHPathPinned,
		KnownHosts: []byte("a ssh-ed25519 AAAA\n"), HostKeyAlias: "a"}}
	_, args, cleanup, err := sshArgs(context.Background(), h, sshPowerOffCommand)
	defer cleanup()
	if err != nil {
		t.Fatal(err)
	}
	if o := opts(args); o["KnownHostsCommand"] != "none" || o["StrictHostKeyChecking"] != "yes" {
		t.Fatalf("pinned args = %q", args)
	}
}
