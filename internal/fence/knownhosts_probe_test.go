package fence

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func pinnedArgs(t *testing.T) []string {
	t.Helper()
	h := HostConfig{Name: "node-x", Address: "10.77.0.3", SSH: SSHFence{Path: SSHPathPinned,
		KnownHosts: []byte("a ssh-ed25519 AAAA\n"), HostKeyAlias: "a"}}
	_, args, cleanup, err := sshArgs(context.Background(), h, sshPowerOffCommand)
	t.Cleanup(cleanup)
	if err != nil {
		t.Fatal(err)
	}
	return args
}

// A probe that fails for any reason other than the client rejecting
// KnownHostsCommand by name keeps the option: the pin is never loosened on a
// guess. Here `ssh -G` exits 255 with a "Bad configuration option" about
// another option, and a resolver error.
//
// Mutation: knownHostsCommandSupported's final `return true` → false: red.
func TestSSHArgs_PinnedKeepsKnownHostsCommandWhenTheProbeFails(t *testing.T) {
	fakeSSH(t, fakeRemote{forceWorks: true, sysrqWritable: true, probe: "fails"})
	if o := opts(pinnedArgs(t)); o["KnownHostsCommand"] != "none" {
		t.Fatalf("a failed probe dropped KnownHostsCommand=none: %v", o)
	}
}

// A probe that never answers is cut off at its timeout, even when a child of
// the client holds its output open, and keeps the option.
//
// Mutations: the final `return true` → false: red; no cmd.WaitDelay: red
// (the probe waits out the child, 30 s).
func TestSSHArgs_PinnedKeepsKnownHostsCommandWhenTheProbeHangs(t *testing.T) {
	fakeSSH(t, fakeRemote{forceWorks: true, sysrqWritable: true, probe: "hangs"})
	prev := knownHostsProbeTimeout
	knownHostsProbeTimeout = 300 * time.Millisecond
	t.Cleanup(func() { knownHostsProbeTimeout = prev })

	start := time.Now()
	args := pinnedArgs(t)
	if took := time.Since(start); took > 10*time.Second {
		t.Errorf("a hung probe held the fence for %v, want about its %v timeout", took, knownHostsProbeTimeout)
	}
	if o := opts(args); o["KnownHostsCommand"] != "none" {
		t.Fatalf("a hung probe dropped KnownHostsCommand=none: %v", o)
	}
}

// The answer is cached for the client binary as it is: an in-place upgrade to
// OpenSSH 8.5 or later (a package manager renames a new file over the old one;
// a hand copy rewrites it) is probed again, and the option comes back without
// a restart.
//
// Mutation: cache by path alone: red.
func TestKnownHostsCommandSupported_ReprobesAClientThatChanged(t *testing.T) {
	for _, how := range []string{"rename", "rewrite"} {
		t.Run(how, func(t *testing.T) {
			fakeSSH(t, fakeRemote{forceWorks: true, sysrqWritable: true, preKnownHostsCommand: true})
			bin, err := exec.LookPath("ssh")
			if err != nil {
				t.Fatal(err)
			}
			if knownHostsCommandSupported(context.Background(), "ssh") {
				t.Fatal("a pre-8.5 client was taken to support KnownHostsCommand")
			}
			upgraded := []byte("#!/bin/sh\n# OpenSSH 9.6: accepts KnownHostsCommand\ncase \"$1\" in -G) exit 0 ;; esac\nexit 0\n")
			switch how {
			case "rename":
				tmp := filepath.Join(filepath.Dir(bin), ".ssh.new")
				if err := os.WriteFile(tmp, upgraded, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(tmp, bin); err != nil {
					t.Fatal(err)
				}
			case "rewrite":
				if err := os.WriteFile(bin, upgraded, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			if !knownHostsCommandSupported(context.Background(), "ssh") {
				t.Fatal("the upgraded client is still taken to lack KnownHostsCommand: the old answer was kept")
			}
		})
	}
}
