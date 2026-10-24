package ssh

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	cryptossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
)

func enrollmentSocketPair(t *testing.T) (*net.UnixConn, *net.UnixConn) {
	t.Helper()
	dir, err := os.MkdirTemp("", "ens-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(dir, "s"), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	client, err := net.DialUnix("unix", nil, ln.Addr().(*net.UnixAddr))
	if err != nil {
		t.Fatal(err)
	}
	peer, err := ln.AcceptUnix()
	if err != nil {
		client.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close(); peer.Close() })
	return client, peer
}

// Cancellation must interrupt the actual blocked socket write and join it.
func TestEnrollmentDiagnosticsCancellationJoinsBlockedWrite(t *testing.T) {
	conn, peer := enrollmentSocketPair(t)
	if err := conn.SetWriteBuffer(4096); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	diagnostics, err := NewEnrollmentDiagnostics(ctx, conn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { peer.Close(); diagnostics.Close() }()
	started := make(chan struct{})
	finished := make(chan error, 1)
	go func() { close(started); _, err := diagnostics.Write(bytes.Repeat([]byte{'x'}, 8<<20)); finished <- err }()
	<-started
	select {
	case err := <-finished:
		t.Fatalf("fixture did not block actual diagnostic socket: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	cancel()
	select {
	case err := <-finished:
		if err == nil {
			t.Fatal("cancelled diagnostic write succeeded")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("diagnostic write did not join")
	}
	if err := peer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(io.Discard, peer); err != nil {
		t.Fatalf("owned diagnostic peer did not observe EOF: %v", err)
	}
	if _, err := diagnostics.Write([]byte("later")); err == nil {
		t.Fatal("closed diagnostic sink accepted new write")
	}
}

// Removing the handshake's agent-owner Close must fail this test: a real agent
// observes EOF after authentication, while the authenticated SSH client lives.
func TestEnrollmentAuthenticationReleasesAgentAfterHandshake(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	authorized, err := cryptossh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	keyring := agent.NewKeyring()
	if err := keyring.Add(agent.AddedKey{PrivateKey: key}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "agent")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	t.Setenv("SSH_AUTH_SOCK", path)
	agentAccepted := make(chan net.Conn, 1)
	agentDone := make(chan error, 1)
	var agentConn net.Conn
	agentJoined := false
	t.Cleanup(func() {
		listener.Close()
		if agentConn == nil {
			select {
			case agentConn = <-agentAccepted:
			default:
			}
		}
		if agentConn != nil {
			agentConn.Close()
		}
		if !agentJoined {
			select {
			case <-agentDone:
			case <-time.After(3 * time.Second):
				t.Error("owned agent did not join")
			}
		}
	})
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			agentDone <- err
			return
		}
		agentAccepted <- conn
		defer conn.Close()
		agentDone <- agent.ServeAgent(keyring, conn)
	}()

	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	_, hostKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostSigner, err := cryptossh.NewSignerFromKey(hostKey)
	if err != nil {
		t.Fatal(err)
	}
	serverConfig := &cryptossh.ServerConfig{PublicKeyCallback: func(meta cryptossh.ConnMetadata, offered cryptossh.PublicKey) (*cryptossh.Permissions, error) {
		if meta.User() != "deploy" || string(offered.Marshal()) != string(authorized.Marshal()) {
			return nil, fmt.Errorf("unexpected authentication")
		}
		return nil, nil
	}}
	serverConfig.AddHostKey(hostSigner)
	serverAccepted := make(chan net.Conn, 1)
	serverDone := make(chan error, 1)
	go func() {
		conn, err := tcp.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		serverAccepted <- conn
		defer conn.Close()
		server, channels, requests, err := cryptossh.NewServerConn(conn, serverConfig)
		if err != nil {
			serverDone <- err
			return
		}
		requestsDone := make(chan struct{})
		go func() {
			cryptossh.DiscardRequests(requests)
			close(requestsDone)
		}()
		for channel := range channels {
			channel.Reject(cryptossh.Prohibited, "no sessions in authentication test")
		}
		server.Close()
		<-requestsDone
		serverDone <- nil
	}()
	var client *Client
	var serverConn net.Conn
	defer func() {
		listener.Close()
		tcp.Close()
		if client != nil {
			client.Close()
		}
		if serverConn == nil {
			select {
			case serverConn = <-serverAccepted:
			default:
			}
		}
		if serverConn != nil {
			serverConn.Close()
		}
		select {
		case <-serverDone:
		case <-time.After(3 * time.Second):
			t.Error("owned SSH server did not join")
		}
	}()
	known := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(known, []byte(knownhosts.Line([]string{tcp.Addr().String()}, hostSigner.PublicKey())+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	host, port, err := net.SplitHostPort(tcp.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	target := &Target{user: "deploy", host: host, port: port, cfg: &resolved{Hostname: host, Port: port, KnownHosts: []string{known}, StrictYes: true}}
	var dialErr error
	client, dialErr = NewClientResolved(target)
	select {
	case agentConn = <-agentAccepted:
	case <-time.After(3 * time.Second):
		t.Fatal("agent connection not accepted")
	}
	select {
	case serverConn = <-serverAccepted:
	case <-time.After(3 * time.Second):
		agentConn.Close()
		t.Fatal("SSH connection not accepted")
	}
	if dialErr != nil {
		t.Fatalf("authentication failed: %v", dialErr)
	}
	select {
	case err := <-agentDone:
		agentJoined = true
		if err != nil && !errors.Is(err, io.EOF) {
			t.Fatalf("agent close: %v", err)
		}
	case <-time.After(750 * time.Millisecond):
		agentConn.Close()
		select {
		case <-agentDone:
			agentJoined = true
		case <-time.After(3 * time.Second):
			t.Fatal("owned agent did not join after forced closure")
		}
		t.Fatal("ENROLLMENT_AGENT_CONNECTION_RETAINED_AFTER_AUTHENTICATION")
	}
}

// A socket waiting for the first agent reply must count against the existing
// connect budget, rather than holding authentication outside that budget.
func TestEnrollmentAuthenticationBudgetInterruptsAgentList(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	listener, err := net.Listen("unix", filepath.Join(t.TempDir(), "agent"))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSH_AUTH_SOCK", listener.Addr().String())
	accepted := make(chan net.Conn, 1)
	requested := make(chan struct{})
	peerDone := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			peerDone <- err
			return
		}
		accepted <- conn
		defer conn.Close()
		var request [5]byte
		if _, err := io.ReadFull(conn, request[:]); err != nil {
			peerDone <- err
			return
		}
		close(requested)
		var extra [1]byte
		_, err = conn.Read(extra[:])
		peerDone <- err
	}()
	result := make(chan error, 1)
	go func() {
		client, err := NewClientTimeout("deploy@127.0.0.1:1", 150*time.Millisecond)
		if client != nil {
			client.Close()
		}
		result <- err
	}()
	var conn net.Conn
	joined, peerJoined := false, false
	defer func() {
		listener.Close()
		if conn == nil {
			select {
			case conn = <-accepted:
			default:
			}
		}
		if conn != nil {
			conn.Close()
		}
		if !joined {
			select {
			case <-result:
			case <-time.After(3 * time.Second):
				t.Error("owned authentication call did not join")
			}
		}
		if !peerJoined {
			select {
			case <-peerDone:
			case <-time.After(3 * time.Second):
				t.Error("owned agent peer did not join")
			}
		}
	}()
	select {
	case conn = <-accepted:
	case <-time.After(3 * time.Second):
		t.Fatal("agent connection not accepted")
	}
	select {
	case <-requested:
	case <-time.After(3 * time.Second):
		t.Fatal("agent List was not requested")
	}
	select {
	case err := <-result:
		joined = true
		if err == nil {
			t.Fatal("stalled authentication succeeded")
		}
	case <-time.After(750 * time.Millisecond):
		t.Fatal("ENROLLMENT_AGENT_LIST_IGNORED_CONNECT_BUDGET")
	}
	select {
	case err := <-peerDone:
		peerJoined = true
		if !errors.Is(err, io.EOF) {
			t.Fatalf("agent connection was not closed: %v", err)
		}
	case <-time.After(750 * time.Millisecond):
		t.Fatal("agent connection remained open after authentication timeout")
	}
}

// This real SSH fixture owns its listener, accepted connection, session workers,
// shell process groups and diagnostic reader. It executes only test commands as
// this test's unprivileged user, never enrollment or service-control helpers.
type enrollmentFixtureControl struct {
	mode     string
	observed chan struct{}
	terminal chan struct{}
	once     sync.Once
	opens    atomic.Int32
	written  atomic.Int32
}

func (c *enrollmentFixtureControl) observe() { c.once.Do(func() { close(c.observed) }) }

func enrollmentCarrierFixture(t *testing.T) (*EnrollmentClient, func() string) {
	client, diagnostic, err := enrollmentCarrierFixtureAttempt(t, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	return client, diagnostic
}

func enrollmentCarrierFixtureAttempt(t *testing.T, drain bool, dial func(*Target, *EnrollmentDiagnostics) (*EnrollmentClient, error), controls ...*enrollmentFixtureControl) (*EnrollmentClient, func() string, error) {
	var control *enrollmentFixtureControl
	if len(controls) > 0 {
		control = controls[0]
	}
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SSH_AUTH_SOCK", "")
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	private, err := cryptossh.MarshalPrivateKey(key, "test")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(home, ".ssh"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".ssh", "id_ed25519"), pem.EncodeToMemory(private), 0600); err != nil {
		t.Fatal(err)
	}
	authorized, err := cryptossh.NewPublicKey(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	_, hostKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostSigner, err := cryptossh.NewSignerFromKey(hostKey)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	fixtureCtx, fixtureCancel := context.WithCancel(context.Background())
	accepted := make(chan net.Conn, 1)
	serverDone := make(chan error, 1)
	var client *EnrollmentClient
	var peer net.Conn
	var diagConn, diagPeer *net.UnixConn
	diagDone := make(chan string, 1)
	var diagnostic string
	joinedDiag := true
	t.Cleanup(func() {
		fixtureCancel()
		if diagPeer != nil {
			diagPeer.Close()
		}
		if client != nil {
			client.Close()
		}
		if diagConn != nil {
			diagConn.Close()
		}
		ln.Close()
		if peer == nil {
			select {
			case peer = <-accepted:
			default:
			}
		}
		if peer != nil {
			peer.Close()
		}
		select {
		case <-serverDone:
		case <-time.After(3 * time.Second):
			t.Error("SSH fixture did not join")
		}
		if !joinedDiag {
			select {
			case <-diagDone:
			case <-time.After(3 * time.Second):
				t.Error("diagnostic fixture did not join")
			}
		}
	})
	go func() {
		if control != nil {
			defer close(control.terminal)
		}
		conn, err := ln.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		accepted <- conn
		defer conn.Close()
		cfg := &cryptossh.ServerConfig{PublicKeyCallback: func(meta cryptossh.ConnMetadata, key cryptossh.PublicKey) (*cryptossh.Permissions, error) {
			if meta.User() != "deploy" || !bytes.Equal(key.Marshal(), authorized.Marshal()) {
				return nil, fmt.Errorf("authentication refused")
			}
			return nil, nil
		}}
		cfg.AddHostKey(hostSigner)
		server, chans, reqs, err := cryptossh.NewServerConn(conn, cfg)
		if err != nil {
			serverDone <- err
			return
		}
		var workers sync.WaitGroup
		workers.Add(1)
		go func() { defer workers.Done(); cryptossh.DiscardRequests(reqs) }()
		for incoming := range chans {
			if incoming.ChannelType() != "session" {
				incoming.Reject(cryptossh.Prohibited, "only sessions")
				continue
			}
			if control != nil {
				control.opens.Add(1)
				if control.mode == "open" {
					control.observe()
					_ = server.Wait()
					break
				}
			}
			channel, requests, err := incoming.Accept()
			if err != nil {
				continue
			}
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer channel.Close()
				for request := range requests {
					if request.Type != "exec" {
						request.Reply(false, nil)
						continue
					}
					var payload struct{ Command string }
					if err := cryptossh.Unmarshal(request.Payload, &payload); err != nil {
						request.Reply(false, nil)
						return
					}
					if control != nil && control.mode == "ack" {
						control.observe()
						_, _ = io.Copy(io.Discard, channel)
						return
					}
					if err := request.Reply(true, nil); err != nil {
						return
					}
					if control != nil && control.mode == "missing-exit" {
						control.observe()
						frame := []byte("LVNENR01\x00\x00\x00\x02\x30\x00")
						n, err := channel.Write(frame)
						if err == nil {
							control.written.Store(int32(n))
						}
						return
					}
					cmd := exec.CommandContext(fixtureCtx, "/bin/sh", "-c", payload.Command)
					cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
					cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
					cmd.WaitDelay = time.Second
					cmd.Stdin, cmd.Stdout, cmd.Stderr = channel, channel, channel.Stderr()
					err := cmd.Run()
					if cmd.Process != nil {
						syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
					}
					status := uint32(0)
					if err != nil {
						status = 1
					}
					channel.SendRequest("exit-status", false, cryptossh.Marshal(struct{ Status uint32 }{status}))
					return
				}
			}()
		}
		server.Close()
		workers.Wait()
		serverDone <- nil
	}()
	diagConn, diagPeer = enrollmentSocketPair(t)
	if err := diagConn.SetWriteBuffer(4096); err != nil {
		t.Fatal(err)
	}
	if drain {
		joinedDiag = false
		go func() {
			var b bytes.Buffer
			_, _ = io.Copy(&b, io.LimitReader(diagPeer, 1<<20))
			diagDone <- b.String()
		}()
	}

	known := filepath.Join(home, "known_hosts")
	if err := os.WriteFile(known, []byte(knownhosts.Line([]string{ln.Addr().String()}, hostSigner.PublicKey())+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	host, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	diagnostics, err := NewEnrollmentDiagnostics(context.Background(), diagConn)
	if err != nil {
		t.Fatal(err)
	}
	if dial == nil {
		dial = func(target *Target, d *EnrollmentDiagnostics) (*EnrollmentClient, error) {
			return NewEnrollmentClient(context.Background(), target, d)
		}
	}
	client, err = dial(&Target{user: "deploy", host: host, port: port, cfg: &resolved{Hostname: host, Port: port, KnownHosts: []string{known}, StrictYes: true}}, diagnostics)
	return client, func() string {
		if !joinedDiag {
			client.Close()
			diagnostic = <-diagDone
			joinedDiag = true
		}
		return diagnostic
	}, err
}

func TestEnrollmentCarrierIOAndBounds(t *testing.T) {
	for _, tc := range []struct {
		name, command string
		native        bool
		wantLen       int
		wantErr       bool
	}{
		{"stdin-and-diagnostics", "cat; printf diagnostic >&2", false, 6, false},
		{"nonzero-with-bytes", "printf fake; exit 7", true, 0, true},
		{"probe-exact", "/usr/bin/head -c 16384 /dev/zero", false, 16384, false},
		{"probe-overflow", "/usr/bin/head -c 16385 /dev/zero", false, 0, true},
		{"native-exact", "/usr/bin/head -c 16396 /dev/zero", true, 16396, false},
		{"native-overflow", "/usr/bin/head -c 16397 /dev/zero", true, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, diagnostic := enrollmentCarrierFixture(t)
			var got []byte
			var err error
			if tc.native {
				got, err = client.RunWithInputOutput(context.Background(), tc.command, nil)
			} else if tc.name == "stdin-and-diagnostics" {
				got, err = client.RunWithInputOutput(context.Background(), tc.command, []byte("secret"))
			} else {
				got, err = client.RunOutput(context.Background(), tc.command)
			}
			if (err != nil) != tc.wantErr {
				t.Fatalf("error=%v want error=%v", err, tc.wantErr)
			}
			if !tc.wantErr && len(got) != tc.wantLen {
				t.Fatalf("output length=%d want%d", len(got), tc.wantLen)
			}
			if tc.name == "stdin-and-diagnostics" {
				if string(got) != "secret" {
					t.Fatalf("stdin bytes changed")
				}
				if diagnostic() != "diagnostic" {
					t.Fatal("stderr contaminated or lost")
				}
			}
		})
	}
}

func TestEnrollmentCarrierCopiesExecutableWithMode(t *testing.T) {
	client, _ := enrollmentCarrierFixture(t)
	local := filepath.Join(t.TempDir(), "local")
	remote := filepath.Join(t.TempDir(), "remote")
	body := bytes.Repeat([]byte("binary"), 10000)
	if err := os.WriteFile(local, body, 0600); err != nil {
		t.Fatal(err)
	}
	if err := client.CopyFileMode(context.Background(), local, remote, 0700); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(remote)
	if err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(remote)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, body) || st.Mode().Perm() != 0700 {
		t.Fatal("copied executable bytes or mode changed")
	}
	link := filepath.Join(t.TempDir(), "local-link")
	if err := os.Symlink(local, link); err != nil {
		t.Fatal(err)
	}
	linkRemote := filepath.Join(t.TempDir(), "link-copy")
	if err := client.CopyFileMode(context.Background(), link, linkRemote, 0700); err != nil {
		t.Fatal(err)
	}
	linkBytes, err := os.ReadFile(linkRemote)
	if err != nil || !bytes.Equal(linkBytes, body) {
		t.Fatalf("regular symlink copy changed: %v", err)
	}
	oversize := filepath.Join(t.TempDir(), "oversize")
	f, err := os.Create(oversize)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate((512 << 20) + 1); err != nil {
		f.Close()
		t.Fatal(err)
	}
	f.Close()
	absent := filepath.Join(t.TempDir(), "must-not-create")
	if err := client.CopyFileMode(context.Background(), oversize, absent, 0700); err == nil {
		t.Fatal("oversize executable accepted")
	}
	if _, err := os.Stat(absent); !os.IsNotExist(err) {
		t.Fatal("oversize executable started a remote write")
	}
}

func enrollmentWaitForFile(t *testing.T, path, want string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		body, err := os.ReadFile(path)
		if err == nil {
			if string(body) != want {
				t.Fatalf("unexpected fixture marker %q", body)
			}
			return
		}
		if !os.IsNotExist(err) {
			t.Fatal(err)
		}
		if time.Now().After(deadline) {
			t.Fatalf("real remote fixture did not publish %s", path)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestEnrollmentCarrierCancellationJoinsStalledCommand(t *testing.T) {
	client, _ := enrollmentCarrierFixture(t)
	started := filepath.Join(t.TempDir(), "started")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := client.RunWithInputOutput(ctx, "printf started > "+ShellQuote(started)+"; /bin/sleep 30", bytes.Repeat([]byte{'x'}, 8<<20))
		done <- err
	}()
	enrollmentWaitForFile(t, started, "started")
	select {
	case err := <-done:
		t.Fatalf("stalled remote command returned before cancellation: %v", err)
	default:
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled command succeeded")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("owned SSH operation did not join")
	}
	if _, err := client.RunOutput(context.Background(), "printf later"); err == nil {
		t.Fatal("cancelled carrier remained usable")
	}
}

func TestEnrollmentRejectsUnadmittedDiagnostics(t *testing.T) {
	for _, tc := range []string{"connect", "resolve"} {
		t.Run(tc, func(t *testing.T) {
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Fatalf("ENROLLMENT_UNADMITTED_DIAGNOSTICS_PANICKED: %v", recovered)
				}
			}()
			diagnostics := &EnrollmentDiagnostics{}
			if tc == "connect" {
				if _, err := NewEnrollmentClient(context.Background(), nil, diagnostics); err == nil {
					t.Fatal("unadmitted diagnostics accepted")
				}
			} else {
				if _, err := ResolveContext(context.Background(), "fixture.invalid", diagnostics); err == nil {
					t.Fatal("unadmitted diagnostics accepted")
				}
			}
		})
	}
}

func TestEnrollmentCarrierCancellationInterruptsBlockedDiagnostics(t *testing.T) {
	client, _, err := enrollmentCarrierFixtureAttempt(t, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := client.RunOutput(ctx, "/usr/bin/head -c 8388608 /dev/zero >&2"); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled stderr operation succeeded")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("actual blocked stderr writer did not join")
	}
}

type enrollmentPausedAgent struct {
	agent.Agent
	listPause int
	signPause bool
	calls     int
	entered   chan struct{}
	release   chan struct{}
}

func (a *enrollmentPausedAgent) List() ([]*agent.Key, error) {
	a.calls++
	if a.calls == a.listPause {
		close(a.entered)
		<-a.release
	}
	return a.Agent.List()
}
func (a *enrollmentPausedAgent) Sign(key cryptossh.PublicKey, data []byte) (*cryptossh.Signature, error) {
	if a.signPause {
		close(a.entered)
		<-a.release
	}
	return a.Agent.Sign(key, data)
}

func TestEnrollmentCarrierCancellationInterruptsPrivateAgent(t *testing.T) {
	for _, tc := range []struct {
		name string
		list int
		sign bool
	}{{"discovery", 1, false}, {"signers", 2, false}, {"signature", 0, true}} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := enrollmentCarrierFixtureAttempt(t, true, func(target *Target, diagnostics *EnrollmentDiagnostics) (*EnrollmentClient, error) {
				pemBytes, err := os.ReadFile(filepath.Join(os.Getenv("HOME"), ".ssh", "id_ed25519"))
				if err != nil {
					t.Fatal(err)
				}
				key, err := cryptossh.ParseRawPrivateKey(pemBytes)
				if err != nil {
					t.Fatal(err)
				}
				keyring := agent.NewKeyring()
				if err := keyring.Add(agent.AddedKey{PrivateKey: key}); err != nil {
					t.Fatal(err)
				}
				paused := &enrollmentPausedAgent{Agent: keyring, listPause: tc.list, signPause: tc.sign, entered: make(chan struct{}), release: make(chan struct{})}
				dir, err := os.MkdirTemp("", "ena-")
				if err != nil {
					t.Fatal(err)
				}
				defer os.RemoveAll(dir)
				ln, err := net.Listen("unix", filepath.Join(dir, "s"))
				if err != nil {
					t.Fatal(err)
				}
				defer ln.Close()
				t.Setenv("SSH_AUTH_SOCK", ln.Addr().String())
				accepted := make(chan net.Conn, 1)
				agentDone := make(chan error, 1)
				go func() {
					conn, err := ln.Accept()
					if err != nil {
						agentDone <- err
						return
					}
					accepted <- conn
					defer conn.Close()
					agentDone <- agent.ServeAgent(paused, conn)
				}()
				var peer net.Conn
				released, joined := false, false
				defer func() {
					ln.Close()
					if !released {
						close(paused.release)
					}
					if peer == nil {
						select {
						case peer = <-accepted:
						default:
						}
					}
					if peer != nil {
						peer.Close()
					}
					if !joined {
						select {
						case <-agentDone:
						case <-time.After(3 * time.Second):
							t.Error("owned private agent did not join")
						}
					}
				}()
				ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
				defer cancel()
				client, dialErr := NewEnrollmentClient(ctx, target, diagnostics)
				select {
				case <-paused.entered:
				default:
					t.Error("required real agent request was not reached")
				}
				close(paused.release)
				released = true
				select {
				case <-agentDone:
					joined = true
				case <-time.After(time.Second):
					t.Error("cancelled owned agent socket remained live")
				}
				if client != nil {
					client.Close()
					t.Error("paused agent authentication succeeded")
				}
				return client, dialErr
			})
			if err == nil {
				t.Fatal("private agent ignored cancellation")
			}
		})
	}
}

func TestEnrollmentCarrierCancelIsNotRemoteNoEffect(t *testing.T) {
	client, _ := enrollmentCarrierFixture(t)
	dir := t.TempDir()
	started := filepath.Join(dir, "started")
	allow := filepath.Join(dir, "allow")
	marker := filepath.Join(dir, "remote-effect")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	command := "printf started > " + ShellQuote(started) + "; while [ ! -f " + ShellQuote(allow) + " ]; do /bin/sleep .01; done; printf committed > " + ShellQuote(marker)
	go func() { _, err := client.RunOutput(ctx, command); done <- err }()
	enrollmentWaitForFile(t, started, "started")
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled transport returned success")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("cancelled transport did not join")
	}
	if err := os.WriteFile(allow, []byte("allow"), 0600); err != nil {
		t.Fatal(err)
	}
	enrollmentWaitForFile(t, marker, "committed")
}

func TestEnrollmentCopyReaderRejectsGrowingInput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "growing")
	if err := os.WriteFile(path, []byte("abc"), 0600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	interrupted := false
	reader := &enrollmentCopyReader{source: file, remaining: 3, interrupt: func() { interrupted = true }}
	first := make([]byte, 3)
	if _, err := io.ReadFull(reader, first); err != nil {
		t.Fatal(err)
	}
	appendFile, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := appendFile.WriteString("d"); err != nil {
		appendFile.Close()
		t.Fatal(err)
	}
	appendFile.Close()
	var extra [1]byte
	n, err := reader.Read(extra[:])
	if n != 0 || !errors.Is(err, errEnrollmentExecutable) || !interrupted {
		t.Fatalf("growth accepted: n%d err%v interrupted%v", n, err, interrupted)
	}
}

func TestEnrollmentCarrierHandshakeCancellationJoinsConnection(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan net.Conn, 1)
	done := make(chan error, 1)
	go func() {
		peer, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		accepted <- peer
		defer peer.Close()
		_, err = io.Copy(io.Discard, peer)
		done <- err
	}()
	var peer net.Conn
	joined := false
	defer func() {
		ln.Close()
		if peer == nil {
			select {
			case peer = <-accepted:
			default:
			}
		}
		if peer != nil {
			peer.Close()
		}
		if !joined {
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Error("silent SSH peer did not join")
			}
		}
	}()
	diagnosticConn, diagnosticPeer := enrollmentSocketPair(t)
	defer diagnosticPeer.Close()
	diagnostics, err := NewEnrollmentDiagnostics(context.Background(), diagnosticConn)
	if err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SSH_AUTH_SOCK", "")
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	private, err := cryptossh.MarshalPrivateKey(key, "test")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(home, ".ssh"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".ssh", "id_ed25519"), pem.EncodeToMemory(private), 0600); err != nil {
		t.Fatal(err)
	}
	host, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	client, err := NewEnrollmentClient(ctx, &Target{user: "deploy", host: host, port: port, cfg: &resolved{Hostname: host, Port: port}}, diagnostics)
	if client != nil {
		client.Close()
	}
	if err == nil {
		t.Fatal("silent SSH handshake succeeded")
	}
	select {
	case peer = <-accepted:
	case <-time.After(time.Second):
		t.Fatal("real TCP connection was not made")
	}
	select {
	case err := <-done:
		joined = true
		if err != nil {
			t.Fatalf("silent peer did not observe connection close: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled actual SSH handshake did not close connection")
	}
}

func TestEnrollmentCopyRejectsFIFOWithoutRemoteEffect(t *testing.T) {
	for _, cancelled := range []bool{false, true} {
		t.Run(fmt.Sprint(cancelled), func(t *testing.T) {
			control := &enrollmentFixtureControl{observed: make(chan struct{}), terminal: make(chan struct{})}
			client, _, err := enrollmentCarrierFixtureAttempt(t, true, nil, control)
			if err != nil {
				t.Fatal(err)
			}
			fifo := filepath.Join(t.TempDir(), "executable")
			if err := syscall.Mkfifo(fifo, 0600); err != nil {
				t.Fatal(err)
			}
			remoteDir := t.TempDir()
			remote := filepath.Join(remoteDir, "must-not-write")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if cancelled {
				cancel()
			}
			done := make(chan error, 1)
			go func() { done <- client.CopyFileMode(ctx, fifo, remote, 0700) }()
			blocked := false
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("FIFO admitted as executable")
				}
			case <-time.After(250 * time.Millisecond):
				blocked = true
				cancel()
				// Explicit failed-run cleanup: a nonblocking writer releases the
				// old blocking read-open. This is never a passing cancellation path.
				deadline := time.Now().Add(3 * time.Second)
				for {
					fd, err := syscall.Open(fifo, syscall.O_WRONLY|syscall.O_NONBLOCK, 0)
					if err == nil {
						syscall.Close(fd)
						break
					}
					if !errors.Is(err, syscall.ENXIO) || time.Now().After(deadline) {
						t.Fatalf("failed FIFO cleanup: %v", err)
					}
					time.Sleep(10 * time.Millisecond)
				}
				select {
				case <-done:
				case <-time.After(3 * time.Second):
					t.Fatal("blocked FIFO copy did not join after failed-run writer cleanup")
				}
			}
			entries, err := os.ReadDir(remoteDir)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 0 || control.opens.Load() != 0 {
				t.Fatal("nonregular admission started a remote write/session")
			}
			if blocked {
				t.Fatal("ENROLLMENT_COPY_FIFO_BLOCKED_BEFORE_ADMISSION")
			}
		})
	}
}

func TestEnrollmentCarrierSessionStageBoundaries(t *testing.T) {
	for _, mode := range []string{"open", "ack", "missing-exit"} {
		t.Run(mode, func(t *testing.T) {
			control := &enrollmentFixtureControl{mode: mode, observed: make(chan struct{}), terminal: make(chan struct{})}
			client, _, err := enrollmentCarrierFixtureAttempt(t, true, nil, control)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			type result struct {
				body []byte
				err  error
			}
			done := make(chan result, 1)
			go func() { body, err := client.RunWithInputOutput(ctx, "fixture", nil); done <- result{body, err} }()
			select {
			case <-control.observed:
			case <-time.After(3 * time.Second):
				t.Fatal("actual transport stage was not reached")
			}
			if mode != "missing-exit" {
				select {
				case <-done:
					t.Fatal("withheld acknowledgement unexpectedly completed")
				default:
				}
				cancel()
			}
			var got result
			select {
			case got = <-done:
			case <-time.After(3 * time.Second):
				t.Fatal("owned transport stage did not join")
			}
			if got.err == nil || len(got.body) != 0 {
				t.Fatalf("unconfirmed result accepted: bytes=%d error=%v", len(got.body), got.err)
			}
			if mode == "missing-exit" {
				var missing *cryptossh.ExitMissingError
				if !errors.As(got.err, &missing) || control.written.Load() != 14 {
					t.Fatalf("missing-exit cut not exercised: bytes%d err%v", control.written.Load(), got.err)
				}
			}
			select {
			case <-control.terminal:
			case <-time.After(3 * time.Second):
				t.Fatal("actual SSH fixture work did not join")
			}
		})
	}
}
