package filerestore

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/litevirt/litevirt/internal/filerestore/wire"
)

// Client talks to the agent in a restore VM. One request at a time.
// Every answer goes through the sanitizers before it is returned.
type Client struct {
	mu     sync.Mutex
	rw     io.ReadWriteCloser
	c      *wire.LineConn
	broken atomic.Bool
	// streaming: while an extraction is read, each read off the connection
	// first pushes the deadline out (progress, not total time, is bounded).
	streaming atomic.Bool
	// opTimeout bounds one round trip, and how long an extraction may go
	// without progress.
	opTimeout time.Duration
}

// ErrClientBroken means an earlier request left the connection out of step
// (a cut-short extraction); the session has to be replaced.
var ErrClientBroken = errors.New("restore VM connection is no longer usable")

// ErrWrongVM means the agent did not answer with the session's nonce: the
// vsock CID reached some other VM.
var ErrWrongVM = errors.New("the vsock peer is not this session's restore VM")

// NewClient wraps an established connection to the agent.
func NewClient(rw io.ReadWriteCloser) *Client {
	c := &Client{rw: rw, opTimeout: 60 * time.Second}
	c.c = wire.NewLineConn(touchRW{c})
	return c
}

// touchRW is the connection as the line reader sees it.
type touchRW struct{ c *Client }

func (t touchRW) Read(b []byte) (int, error) {
	if t.c.streaming.Load() {
		t.c.setDeadline(t.c.opTimeout)
	}
	return t.c.rw.Read(b)
}

func (t touchRW) Write(b []byte) (int, error) { return t.c.rw.Write(b) }

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

func (c *Client) roundTrip(req wire.Request) (wire.Response, error) {
	if c.broken.Load() {
		return wire.Response{}, ErrClientBroken
	}
	c.setDeadline(c.opTimeout)
	defer c.setDeadline(0)
	if err := c.c.Send(req); err != nil {
		c.broken.Store(true)
		return wire.Response{}, fmt.Errorf("restore VM: %w", err)
	}
	var resp wire.Response
	if err := c.c.Recv(&resp); err != nil {
		c.broken.Store(true)
		return wire.Response{}, fmt.Errorf("restore VM: %w", err)
	}
	return resp, nil
}

// Hello checks the agent is the one this session booted: it must answer
// with nonce, which only the session's VM is given. Until it has, nothing
// else is sent. timeout bounds the wait (0: the client's own).
func (c *Client) Hello(nonce string, timeout time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	saved := c.opTimeout
	if timeout > 0 {
		c.opTimeout = timeout
	}
	resp, err := c.roundTrip(wire.Request{Op: wire.OpHello})
	c.opTimeout = saved
	if err != nil {
		return err
	}
	if nonce == "" || resp.Nonce != nonce {
		c.broken.Store(true)
		return ErrWrongVM
	}
	return nil
}

// Volumes lists the filesystems the agent mounted.
func (c *Client) Volumes() ([]Volume, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	resp, err := c.roundTrip(wire.Request{Op: wire.OpVolumes})
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
	if c.broken.Load() {
		return nil, false, 0, ErrClientBroken
	}
	c.setDeadline(c.opTimeout)
	defer c.setDeadline(0)
	if err := c.c.Send(wire.Request{Op: wire.OpList, Path: clean}); err != nil {
		c.broken.Store(true)
		return nil, false, 0, fmt.Errorf("restore VM: %w", err)
	}
	line, err := wire.ReadLine(c.c.R, wire.MaxResponseLine)
	if err != nil {
		c.broken.Store(true)
		return nil, false, 0, fmt.Errorf("restore VM: %w", err)
	}
	resp, err := decodeListResponse(line)
	if err != nil {
		return nil, false, 0, fmt.Errorf("restore VM: %w", err)
	}
	if resp.Error != "" {
		return nil, false, 0, errors.New(agentErr(resp.Error))
	}
	entries, skipped = SanitizeEntries(resp.Entries)
	return entries, resp.Truncated, skipped, nil
}

// decodeListResponse decodes a listing reply entry by entry, keeping at
// most MaxListEntries: what a hostile agent packs into the (bounded) line
// beyond that is skipped while decoding, never materialized.
func decodeListResponse(line []byte) (wire.Response, error) {
	var resp wire.Response
	dec := json.NewDecoder(bytes.NewReader(line))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return resp, fmt.Errorf("malformed listing")
	}
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return resp, err
		}
		key, _ := kt.(string)
		switch key {
		case "error":
			if err := dec.Decode(&resp.Error); err != nil {
				return resp, err
			}
		case "truncated":
			if err := dec.Decode(&resp.Truncated); err != nil {
				return resp, err
			}
		case "entries":
			t, err := dec.Token()
			if err != nil {
				return resp, err
			}
			if t == nil {
				continue // null
			}
			if t != json.Delim('[') {
				return resp, fmt.Errorf("malformed listing")
			}
			for dec.More() {
				if len(resp.Entries) >= wire.MaxListEntries {
					var skip json.RawMessage
					if err := dec.Decode(&skip); err != nil {
						return resp, err
					}
					resp.Truncated = true
					continue
				}
				var e wire.Entry
				if err := dec.Decode(&e); err != nil {
					return resp, err
				}
				resp.Entries = append(resp.Entries, e)
			}
			if _, err := dec.Token(); err != nil {
				return resp, err
			}
		default:
			var skip json.RawMessage
			if err := dec.Decode(&skip); err != nil {
				return resp, err
			}
		}
	}
	return resp, nil
}

// Tar writes a sanitized tar archive of paths to dst. Unless it returns nil
// the client is spent: the agent's stream was not read to its end.
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
	resp, err := c.roundTrip(wire.Request{Op: wire.OpTar, Paths: clean, MaxBytes: lim.MaxBytes, MaxEntries: lim.MaxEntries})
	if err != nil {
		return TarStats{}, err
	}
	if resp.Error != "" {
		return TarStats{}, errors.New(agentErr(resp.Error))
	}
	// The stream may be large, so there is no deadline on the whole of it,
	// but a stall is bounded: every read must make progress within
	// opTimeout, or the agent is taken as hung. (The caller bounds the
	// whole extraction's wall time.)
	c.setDeadline(c.opTimeout)
	c.streaming.Store(true)
	st, err := SanitizeStream(dst, c.c.R, sels, lim)
	c.streaming.Store(false)
	c.setDeadline(0)
	if err != nil {
		c.broken.Store(true)
	}
	return st, err
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
	_ = c.c.Send(wire.Request{Op: wire.OpShutdown})
	var resp wire.Response
	return c.c.Recv(&resp)
}

// Broken reports whether the connection is out of step and the session
// must be replaced.
func (c *Client) Broken() bool { return c.broken.Load() }

// Close closes the connection.
func (c *Client) Close() error { return c.rw.Close() }

// agentErr bounds and escapes an error string from the agent before it
// reaches a caller.
func agentErr(s string) string {
	return "restore VM: " + wire.EscapeBounded(s, 512)
}
