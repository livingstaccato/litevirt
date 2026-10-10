package filerestore

import (
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

// Client talks to the agent in a restore VM. One request at a time.
// Every answer goes through the sanitizers before it is returned.
type Client struct {
	mu     sync.Mutex
	rw     io.ReadWriteCloser
	c      *lineConn
	broken atomic.Bool
	// opTimeout bounds one list/volumes round trip (not a tar, which is
	// bounded by its limits and the caller's context).
	opTimeout time.Duration
}

// ErrClientBroken means an earlier request left the connection out of step
// (a cut-short archive); the session has to be replaced.
var ErrClientBroken = errors.New("restore VM connection is no longer usable")

// NewClient wraps an established connection to the agent.
func NewClient(rw io.ReadWriteCloser) *Client {
	return &Client{rw: rw, c: newLineConn(rw), opTimeout: 60 * time.Second}
}

type deadliner interface{ SetDeadline(time.Time) error }

func (c *Client) setDeadline(d time.Duration) {
	if dl, ok := c.rw.(deadliner); ok {
		if d > 0 {
			_ = dl.SetDeadline(time.Now().Add(d))
		} else {
			_ = dl.SetDeadline(time.Time{})
		}
	}
}

func (c *Client) roundTrip(req Request) (Response, error) {
	if c.broken.Load() {
		return Response{}, ErrClientBroken
	}
	c.setDeadline(c.opTimeout)
	defer c.setDeadline(0)
	if err := c.c.send(req); err != nil {
		c.broken.Store(true)
		return Response{}, fmt.Errorf("restore VM: %w", err)
	}
	var resp Response
	if err := c.c.recv(&resp); err != nil {
		c.broken.Store(true)
		return Response{}, fmt.Errorf("restore VM: %w", err)
	}
	return resp, nil
}

// Volumes lists the filesystems the agent mounted.
func (c *Client) Volumes() ([]Volume, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	resp, err := c.roundTrip(Request{Op: OpVolumes})
	if err != nil {
		return nil, err
	}
	if resp.Error != "" {
		return nil, errors.New(agentErr(resp.Error))
	}
	return SanitizeVolumes(resp.Volumes), nil
}

// List lists directory p ("/" lists the volumes).
func (c *Client) List(p string) (entries []Entry, truncated bool, skipped int, err error) {
	clean, err := CleanArchivePath(p)
	if err != nil {
		return nil, false, 0, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	resp, err := c.roundTrip(Request{Op: OpList, Path: clean})
	if err != nil {
		return nil, false, 0, err
	}
	if resp.Error != "" {
		return nil, false, 0, errors.New(agentErr(resp.Error))
	}
	entries, skipped = SanitizeEntries(resp.Entries)
	return entries, resp.Truncated, skipped, nil
}

// Tar writes a sanitized archive of paths to dst. Unless it returns nil the
// client is spent: the agent's archive was not read to its end.
func (c *Client) Tar(dst io.Writer, paths []string, lim TarLimits) (TarStats, error) {
	sels, err := SelectionNames(paths)
	if err != nil {
		return TarStats{}, err
	}
	clean := make([]string, len(sels))
	for i, s := range sels {
		clean[i] = "/" + s
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.broken.Load() {
		return TarStats{}, ErrClientBroken
	}
	if err := c.c.send(Request{Op: OpTar, Paths: clean, MaxBytes: lim.MaxBytes, MaxEntries: lim.MaxEntries}); err != nil {
		c.broken.Store(true)
		return TarStats{}, fmt.Errorf("restore VM: %w", err)
	}
	c.setDeadline(c.opTimeout)
	var resp Response
	if err := c.c.recv(&resp); err != nil {
		c.broken.Store(true)
		return TarStats{}, fmt.Errorf("restore VM: %w", err)
	}
	c.setDeadline(0)
	if resp.Error != "" {
		return TarStats{}, errors.New(agentErr(resp.Error))
	}
	// The archive may be large, so there is no deadline on the whole of it,
	// but a stall is bounded: every read must make progress within
	// opTimeout, or the agent is taken as hung.
	st, err := SanitizeTar(dst, &progressReader{r: c.c.r, touch: func() { c.setDeadline(c.opTimeout) }}, sels, lim)
	c.setDeadline(0)
	if err != nil {
		c.broken.Store(true)
	}
	return st, err
}

// progressReader refreshes the connection deadline before each read.
type progressReader struct {
	r     io.Reader
	touch func()
}

func (p *progressReader) Read(b []byte) (int, error) {
	p.touch()
	return p.r.Read(b)
}

// Shutdown asks the agent to power the VM off. With a request in flight it
// does nothing (the caller is about to kill the VM, which ends that request).
func (c *Client) Shutdown() error {
	if !c.mu.TryLock() {
		return ErrClientBroken
	}
	defer c.mu.Unlock()
	if c.broken.Load() {
		return ErrClientBroken
	}
	c.setDeadline(5 * time.Second)
	_ = c.c.send(Request{Op: OpShutdown})
	var resp Response
	return c.c.recv(&resp)
}

// Broken reports whether the connection is out of step and the session
// must be replaced.
func (c *Client) Broken() bool { return c.broken.Load() }

// Close closes the connection.
func (c *Client) Close() error { return c.rw.Close() }

// agentErr bounds and de-controls an error string from the agent before it
// reaches a caller.
func agentErr(s string) string {
	if len(s) > 512 {
		s = s[:512]
	}
	b := []rune{}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			r = '?'
		}
		b = append(b, r)
	}
	return "restore VM: " + string(b)
}
