package ssh

import (
	"bytes"
	"context"
	"fmt"
	"os"

	"errors"
	"golang.org/x/crypto/ssh"
	"io"
	"net"
	"sync"
	"syscall"
	"time"
)

// EnrollmentDiagnostics owns one connected Unix stream socket. Its concrete
// resource admission deliberately excludes arbitrary, potentially blocking
// io.Writer implementations. Ownership transfers even if admission fails.
type EnrollmentDiagnostics struct {
	conn          *net.UnixConn
	ctx           context.Context
	deadline      time.Time
	mu            sync.Mutex
	closed        bool
	writers       sync.WaitGroup
	stopInterrupt func()
}

func NewEnrollmentDiagnostics(ctx context.Context, conn *net.UnixConn) (*EnrollmentDiagnostics, error) {
	if conn == nil {
		return nil, errors.New("nil enrollment diagnostic socket")
	}
	refuse := func(err error) (*EnrollmentDiagnostics, error) { conn.Close(); return nil, err }
	if ctx == nil {
		return refuse(errors.New("nil enrollment context"))
	}
	if err := ctx.Err(); err != nil {
		return refuse(err)
	}
	if conn.RemoteAddr() == nil || conn.LocalAddr().Network() != "unix" || conn.RemoteAddr().Network() != "unix" {
		return refuse(errors.New("enrollment diagnostics requires a connected Unix stream socket"))
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(10 * time.Minute)
	}
	if err := conn.SetWriteDeadline(deadline); err != nil {
		return refuse(err)
	}
	d := &EnrollmentDiagnostics{conn: conn, ctx: ctx, deadline: deadline}
	d.stopInterrupt = interruptOnCancellation(ctx, d.interrupt)
	return d, nil
}

func (d *EnrollmentDiagnostics) admitted() error {
	if d == nil || d.conn == nil || d.ctx == nil || d.stopInterrupt == nil {
		return errors.New("unadmitted enrollment diagnostics")
	}
	d.mu.Lock()
	closed := d.closed
	d.mu.Unlock()
	if closed {
		return net.ErrClosed
	}
	return nil
}

func (d *EnrollmentDiagnostics) interrupt() {
	if d == nil {
		return
	}
	d.mu.Lock()
	d.closed = true
	d.mu.Unlock()
	if d.conn != nil {
		d.conn.Close()
	}
}

func (d *EnrollmentDiagnostics) Write(p []byte) (int, error) {
	if err := d.admitted(); err != nil {
		return 0, err
	}
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return 0, net.ErrClosed
	}
	if err := d.ctx.Err(); err != nil {
		d.mu.Unlock()
		return 0, err
	}
	d.writers.Add(1)
	d.mu.Unlock()
	defer d.writers.Done()
	return d.conn.Write(p)
}

func (d *EnrollmentDiagnostics) Close() error {
	if d == nil {
		return nil
	}
	d.interrupt()
	if d.stopInterrupt != nil {
		d.stopInterrupt()
	}
	d.writers.Wait()
	return nil
}

var _ io.Writer = (*EnrollmentDiagnostics)(nil)

const enrollmentInvocationLimit = 10 * time.Minute
const enrollmentConnectLimit = 10 * time.Second
const enrollmentProbeLimit = 16 << 10
const enrollmentResponseLimit = 12 + (16 << 10)
const enrollmentInputLimit = 12 + (12 << 20)
const enrollmentExecutableLimit = 512 << 20

var errEnrollmentOutput = errors.New("enrollment stdout exceeds bound")
var errEnrollmentExecutable = errors.New("enrollment executable exceeds bound")

// EnrollmentClient is a dormant enrollment-only transport. Returned bytes are
// opaque and never assert reservation, completion, rollback or remote no-effect.
// The caller must validate the already-selected native response codec separately.
type EnrollmentClient struct {
	conn          *ssh.Client
	raw           net.Conn
	diagnostics   *EnrollmentDiagnostics
	ctx           context.Context
	cancel        context.CancelFunc
	stopInterrupt func()
	mu            sync.Mutex
	closed, busy  bool
	operations    sync.WaitGroup
}

// NewEnrollmentClient takes ownership of diagnostics on entry, even on failure.
// Target is already resolved; it is never independently re-resolved here.
func NewEnrollmentClient(parent context.Context, target *Target, diagnostics *EnrollmentDiagnostics) (*EnrollmentClient, error) {
	if diagnostics == nil {
		return nil, errors.New("nil enrollment diagnostics")
	}
	ready := false
	defer func() {
		if !ready {
			diagnostics.Close()
		}
	}()
	if err := diagnostics.admitted(); err != nil {
		return nil, err
	}
	if parent == nil {
		return nil, errors.New("nil enrollment context")
	}
	if err := parent.Err(); err != nil {
		return nil, err
	}
	if target == nil || target.cfg == nil {
		return nil, errors.New("nil enrollment target")
	}
	deadline := time.Now().Add(enrollmentInvocationLimit)
	if diagnostics.deadline.Before(deadline) {
		deadline = diagnostics.deadline
	}
	ctx, cancel := context.WithDeadline(parent, deadline)
	defer func() {
		if !ready {
			cancel()
		}
	}()
	addr := net.JoinHostPort(target.cfg.Hostname, target.port)
	dialCtx, dialCancel := context.WithTimeout(ctx, enrollmentConnectLimit)
	raw, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", addr)
	dialCancel()
	if err != nil {
		return nil, fmt.Errorf("enrollment TCP connect: %w", err)
	}
	defer func() {
		if !ready {
			raw.Close()
		}
	}()
	handshakeCtx, handshakeCancel := context.WithTimeout(ctx, enrollmentConnectLimit)
	stopHandshake := interruptOnCancellation(handshakeCtx, func() { raw.Close(); diagnostics.interrupt() })
	defer func() { stopHandshake(); handshakeCancel() }()
	deadline, _ = handshakeCtx.Deadline()
	if err := raw.SetDeadline(deadline); err != nil {
		return nil, err
	}
	if err := diagnostics.conn.SetWriteDeadline(deadline); err != nil {
		return nil, err
	}
	auth, err := authMethodsForContext(handshakeCtx, target.cfg)
	if err != nil {
		return nil, fmt.Errorf("enrollment SSH authentication: %w", err)
	}
	defer auth.Close()
	warning := func(format string, args ...any) error {
		_, err := fmt.Fprintf(diagnostics, format, args...)
		return err
	}
	config, err := clientConfigWithWarning(target.user, auth.methods, target.cfg, addr, warning)
	if err != nil {
		return nil, fmt.Errorf("enrollment SSH host key: %w", err)
	}
	connection, chans, requests, err := ssh.NewClientConn(raw, addr, config)
	if err != nil {
		return nil, fmt.Errorf("enrollment SSH handshake: %w", err)
	}
	stopHandshake()
	auth.Close()
	deadline, _ = ctx.Deadline()
	if err := raw.SetDeadline(deadline); err != nil {
		connection.Close()
		return nil, err
	}
	if err := diagnostics.conn.SetWriteDeadline(deadline); err != nil {
		connection.Close()
		return nil, err
	}
	client := &EnrollmentClient{conn: ssh.NewClient(connection, chans, requests), raw: raw, diagnostics: diagnostics, ctx: ctx, cancel: cancel}
	client.stopInterrupt = interruptOnCancellation(ctx, client.interrupt)
	if err := ctx.Err(); err != nil {
		client.Close()
		return nil, err
	}
	ready = true
	return client, nil
}

func (c *EnrollmentClient) interrupt() {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	c.cancel()
	c.raw.Close()
	c.conn.Close()
	c.diagnostics.interrupt()
}

func (c *EnrollmentClient) Close() error {
	c.interrupt()
	c.stopInterrupt()
	c.operations.Wait()
	c.conn.Wait()
	return c.diagnostics.Close()
}

func (c *EnrollmentClient) RunWithInputOutput(ctx context.Context, command string, input []byte) ([]byte, error) {
	if len(input) > enrollmentInputLimit {
		return nil, errors.New("enrollment input exceeds bound")
	}
	return c.run(ctx, command, bytes.NewReader(bytes.Clone(input)), enrollmentResponseLimit)
}

func (c *EnrollmentClient) RunOutput(ctx context.Context, command string) ([]byte, error) {
	return c.run(ctx, command, nil, enrollmentProbeLimit)
}
func (c *EnrollmentClient) Run(ctx context.Context, command string) error {
	_, err := c.run(ctx, command, nil, 0)
	return err
}

// run serializes this attempt's operations. A failed operation closes the
// attempt; no implicit retry/reconnect can erase unknown remote effects.
func (c *EnrollmentClient) run(ctx context.Context, command string, input io.Reader, limit int64) (output []byte, resultErr error) {
	if ctx == nil {
		return nil, errors.New("nil enrollment operation context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c.mu.Lock()
	if c.closed || c.busy {
		c.mu.Unlock()
		return nil, errors.New("enrollment transport closed or already in use")
	}
	c.busy = true
	c.operations.Add(1)
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		c.busy = false
		c.mu.Unlock()
		c.operations.Done()
		if resultErr != nil {
			c.Close()
		}
	}()
	stop := interruptOnCancellation(ctx, c.interrupt)
	defer stop()
	deadline, _ := c.ctx.Deadline()
	if earlier, ok := ctx.Deadline(); ok && earlier.Before(deadline) {
		deadline = earlier
	}
	if err := c.raw.SetDeadline(deadline); err != nil {
		return nil, err
	}
	if err := c.diagnostics.conn.SetWriteDeadline(deadline); err != nil {
		return nil, err
	}
	session, err := c.conn.NewSession()
	if err != nil {
		return nil, err
	}
	defer session.Close()
	stdout, err := session.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderr, err := session.StderrPipe()
	if err != nil {
		return nil, err
	}
	session.Stdin = input
	type captured struct {
		bytes []byte
		err   error
	}
	outDone := make(chan captured, 1)
	errDone := make(chan error, 1)
	go func() {
		b, err := io.ReadAll(io.LimitReader(stdout, limit+1))
		if int64(len(b)) > limit {
			err = errEnrollmentOutput
		}
		if err != nil {
			c.interrupt()
		}
		outDone <- captured{b, err}
	}()
	go func() {
		_, err := io.Copy(c.diagnostics, stderr)
		if err != nil {
			c.interrupt()
		}
		errDone <- err
	}()
	commandErr := session.Start(command)
	if commandErr == nil {
		commandErr = session.Wait()
	} else {
		c.interrupt()
		session.Close()
	}
	if commandErr != nil {
		c.interrupt()
	}
	out := <-outDone
	diagnosticErr := <-errDone
	if err := errors.Join(commandErr, out.err, diagnosticErr, ctx.Err(), c.ctx.Err()); err != nil {
		return nil, fmt.Errorf("enrollment transport result unknown: %w", err)
	}
	return out.bytes, nil
}

type enrollmentCopyReader struct {
	source    io.Reader
	remaining int64
	interrupt func()
}

func (r *enrollmentCopyReader) Read(p []byte) (int, error) {
	if r.remaining == 0 {
		var extra [1]byte
		n, err := r.source.Read(extra[:])
		if n != 0 {
			r.interrupt()
			return 0, errEnrollmentExecutable
		}
		return 0, err
	}
	if int64(len(p)) > r.remaining {
		p = p[:r.remaining]
	}
	n, err := r.source.Read(p)
	r.remaining -= int64(n)
	return n, err
}

func (c *EnrollmentClient) CopyFileMode(ctx context.Context, localPath, remotePath string, mode os.FileMode) error {
	if ctx == nil {
		return errors.New("nil enrollment copy context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	file, err := os.OpenFile(localPath, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer file.Close()
	st, err := file.Stat()
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() {
		return errors.New("enrollment executable is not a regular file")
	}
	if st.Size() > enrollmentExecutableLimit {
		return errEnrollmentExecutable
	}
	reader := &enrollmentCopyReader{source: file, remaining: enrollmentExecutableLimit, interrupt: c.interrupt}
	_, err = c.run(ctx, writeFileCmd(remotePath, mode), reader, 0)
	return err
}
