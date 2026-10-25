package ssh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
)

// execSSHD is an SSH server that runs each exec request under sh as sshd
// does without a PTY: the command leads a session of its own, its stdin is
// the channel's (EOF when the client closes it), and nothing signals it
// when the channel closes.
func execSSHD(t *testing.T) *Client { t.Helper(); return execSSHDPath(t, "") }

// execSSHDPath is execSSHD with each command's PATH set to path ("" keeps
// the test's environment).
func execSSHDPath(t *testing.T, path string) *Client {
	t.Helper()
	_, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(sk)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ssh.ServerConfig{NoClientAuth: true}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				_, chans, reqs, err := ssh.NewServerConn(c, cfg)
				if err != nil {
					c.Close()
					return
				}
				go ssh.DiscardRequests(reqs)
				for nc := range chans {
					if nc.ChannelType() != "session" {
						nc.Reject(ssh.UnknownChannelType, "no")
						continue
					}
					ch, creqs, err := nc.Accept()
					if err != nil {
						continue
					}
					go serveExec(ch, creqs, path)
				}
			}()
		}
	}()
	conn, err := ssh.Dial("tcp", ln.Addr().String(), &ssh.ClientConfig{
		User: "root", HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return &Client{conn: conn, addr: ln.Addr().String()}
}

func serveExec(ch ssh.Channel, reqs <-chan *ssh.Request, path string) {
	defer ch.Close()
	for req := range reqs {
		if req.Type != "exec" || len(req.Payload) < 4 {
			req.Reply(false, nil)
			continue
		}
		n := binary.BigEndian.Uint32(req.Payload)
		cmd := exec.Command("sh", "-c", string(req.Payload[4:4+n]))
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		if path != "" {
			cmd.Env = []string{"PATH=" + path}
		}
		// stdin through a pipe this server does not wait on, as sshd's.
		pr, pw, err := os.Pipe()
		if err != nil {
			req.Reply(false, nil)
			return
		}
		cmd.Stdin, cmd.Stdout, cmd.Stderr = pr, ch, ch.Stderr()
		req.Reply(true, nil)
		if err := cmd.Start(); err != nil {
			pr.Close()
			pw.Close()
			return
		}
		pr.Close()
		go func() { _, _ = io.Copy(pw, ch); pw.Close() }()
		status := 0
		var ee *exec.ExitError
		if err := cmd.Wait(); errors.As(err, &ee) {
			status = ee.ExitCode()
			if status < 0 {
				status = 128 + int(ee.Sys().(syscall.WaitStatus).Signal())
			}
		}
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], uint32(status))
		_, _ = ch.SendRequest("exit-status", false, b[:])
		return
	}
}

// A command that ends by itself answers as RunOutput's would: its stdout,
// and its exit status. The wrapper neither waits for the session's stdin
// nor changes the status.
func TestRunOutputContext_AnswersLikeRunOutput(t *testing.T) {
	c := execSSHD(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	start := time.Now()
	out, err := c.RunOutputContext(ctx, `echo "it's here"; exit 3`)
	if string(out) != "it's here\n" {
		t.Errorf("output %q", out)
	}
	var ee *ssh.ExitError
	if !errors.As(err, &ee) || ee.ExitStatus() != 3 {
		t.Errorf("err %v, want exit status 3", err)
	}
	if out, err := c.RunOutputContext(ctx, `echo ok`); err != nil || string(out) != "ok\n" {
		t.Errorf("%q, %v", out, err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("took %v", d)
	}
}

// When the context ends, the command and everything it started on the
// remote are killed, not merely abandoned: a channel closed under a non-PTY
// command does not signal it.
//
// Mutation: run cmd unwrapped (killOnStdinEOF returns cmd) — the stdin EOF
// and the closed session leave the shell, its pipeline and the background
// sleep running, red.
func TestRunOutputContext_DeadlineKillsTheRemoteGroup(t *testing.T) {
	assertDeadlineKillsTheRemoteGroup(t, execSSHD(t), treeCmd)
}

// treeCmd is a command with a background child and a pipeline, all in its
// own process group; it records its shell's pid in the file it is given.
func treeCmd(marker string) string {
	return `sleep 30 & echo $$ > '` + marker + `'; sleep 30 | cat`
}

// escapingCmd runs, under coreutils timeout, a child that ignores SIGTERM.
// timeout without --foreground calls setpgid(0, 0), so the child and timeout
// leave the command's process group (staying in its session), and a kill of
// that group misses them (the rc8 lab drill 3 leftover). It records the
// child's pid.
func escapingCmd(marker string) string {
	return `sleep 30 & timeout 30 sh -c 'trap "" TERM; echo $$ > '"'` + marker + `'"'; exec sleep 30'`
}

// A child that moved to a process group of its own is still in the
// command's session, and the whole session is killed.
//
// Mutation: kill only the command's process group in the watcher — timeout
// and its TERM-ignoring child run on, red.
func TestRunOutputContext_DeadlineKillsTheSession(t *testing.T) {
	if _, err := exec.LookPath("timeout"); err != nil {
		t.Skip("no timeout(1)")
	}
	assertDeadlineKillsTheRemoteGroup(t, execSSHD(t), escapingCmd)
}

// On a machine with no setsid, the command stays in the group sshd gave the
// wrapper, and that whole group is killed, not only the command's shell.
//
// Mutation: kill only the command's shell on that branch (g=$p) — the
// background sleep and the pipeline outlive it, red.
func TestRunOutputContext_NoSetsidKillsTheWholeTree(t *testing.T) {
	bin := t.TempDir()
	for _, tool := range []string{"sh", "sleep", "cat"} {
		p, err := exec.LookPath(tool)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(p, filepath.Join(bin, tool)); err != nil {
			t.Fatal(err)
		}
	}
	c := execSSHDPath(t, bin)
	if out, err := c.RunOutputContext(context.Background(), `command -v setsid || echo none`); err != nil || string(out) != "none\n" {
		t.Fatalf("the fake machine must have no setsid: %q, %v", out, err)
	}
	assertDeadlineKillsTheRemoteGroup(t, c, treeCmd)
}

// With no setsid, a child that left the command's process group is still in
// the session sshd gave the wrapper, and that session is killed.
//
// Mutation: kill only the wrapper's process group on that branch — timeout
// and its child run on, red.
func TestRunOutputContext_NoSetsidKillsTheSession(t *testing.T) {
	bin := t.TempDir()
	for _, tool := range []string{"sh", "sleep", "cat", "timeout"} {
		p, err := exec.LookPath(tool)
		if err != nil {
			t.Skip(err)
		}
		if err := os.Symlink(p, filepath.Join(bin, tool)); err != nil {
			t.Fatal(err)
		}
	}
	c := execSSHDPath(t, bin)
	if out, err := c.RunOutputContext(context.Background(), `command -v setsid || echo none`); err != nil || string(out) != "none\n" {
		t.Fatalf("the fake machine must have no setsid: %q, %v", out, err)
	}
	assertDeadlineKillsTheRemoteGroup(t, c, escapingCmd)
}

func assertDeadlineKillsTheRemoteGroup(t *testing.T, c *Client, cmd func(marker string) string) {
	t.Helper()
	marker := filepath.Join(t.TempDir(), "pid")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	start := time.Now()
	done := make(chan error, 1)
	go func() {
		_, err := c.RunOutputContext(ctx, cmd(marker))
		done <- err
	}()
	pid, pgid, sid := 0, 0, 0
	for time.Since(start) < 10*time.Second {
		if b, err := os.ReadFile(marker); err == nil && strings.HasSuffix(string(b), "\n") {
			if pid, err = strconv.Atoi(strings.TrimSpace(string(b))); err != nil {
				t.Fatal(err)
			}
			if pgid, err = syscall.Getpgid(pid); err != nil {
				t.Fatalf("the command (pid %d) is already gone: %v", pid, err)
			}
			if sid, err = unix.Getsid(pid); err != nil {
				t.Fatalf("the command (pid %d) is already gone: %v", pid, err)
			}
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	var err error
	select {
	case err = <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("RunOutputContext was not bounded by its context")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err %v, want the context's deadline", err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("took %v", d)
	}
	if pid == 0 {
		t.Fatal("the command never ran")
	}
	if own, _ := unix.Getsid(0); pgid == syscall.Getpgrp() || sid == own {
		t.Fatalf("the command ran in the test's own process group (%d) or session (%d)", pgid, sid)
	}
	if live := liveIn(t, pgid, sid, pid); len(live) > 0 {
		t.Fatalf("after RunOutputContext returned, still running: %v", live)
	}
}

// liveIn lists the processes, other than zombies, in process group pgid or
// session sid or with pid, polling briefly so a killed process has time to
// exit.
func liveIn(t *testing.T, pgid, sid, pid int) []string {
	t.Helper()
	if _, err := os.Stat("/proc/self/stat"); err != nil {
		t.Skip("no /proc to read process groups from")
	}
	var live []string
	for deadline := time.Now().Add(2 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		live = live[:0]
		stats, _ := filepath.Glob("/proc/[0-9]*/stat")
		for _, statPath := range stats {
			b, err := os.ReadFile(statPath)
			if err != nil {
				continue
			}
			s := string(b)
			k := strings.LastIndexByte(s, ')')
			if k < 0 {
				continue
			}
			fs := strings.Fields(s[k+1:]) // state, ppid, pgrp, session, ...
			if len(fs) < 4 || fs[0] == "Z" {
				continue
			}
			p, _ := strconv.Atoi(strings.Fields(s)[0])
			g, _ := strconv.Atoi(fs[2])
			sess, _ := strconv.Atoi(fs[3])
			if g == pgid || sess == sid || p == pid {
				live = append(live, s[:k+1])
			}
		}
		if len(live) == 0 || time.Now().After(deadline) {
			return live
		}
	}
}
