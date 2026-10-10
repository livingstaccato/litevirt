package filerestore

import (
	"bytes"
	"errors"
	"net"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/filerestore/wire"
)

// fakeAgentConn answers each request with resp(req) on an in-memory pipe.
func fakeAgentConn(t *testing.T, resp func(c *wire.LineConn, guest net.Conn, req wire.Request) bool) *Client {
	t.Helper()
	host, guest := net.Pipe()
	go func() {
		defer guest.Close()
		c := wire.NewLineConn(guest)
		for {
			var req wire.Request
			if err := c.Recv(&req); err != nil {
				return
			}
			if !resp(c, guest, req) {
				return
			}
		}
	}()
	cl := NewClient(host)
	t.Cleanup(func() { cl.Close() })
	return cl
}

// An agent that stops sending mid-extraction does not hold the host
// forever: each read must make progress within the client's timeout.
func TestClient_StalledAgentTimesOut(t *testing.T) {
	cl := fakeAgentConn(t, func(c *wire.LineConn, guest net.Conn, req wire.Request) bool {
		_ = c.Send(wire.Response{})
		_, _ = guest.Write([]byte(`{"n":"vda1/x","t":"fi`)) // half a record, then nothing
		time.Sleep(time.Hour)
		return false
	})
	cl.opTimeout = 300 * time.Millisecond
	done := make(chan error, 1)
	go func() {
		var out bytes.Buffer
		_, err := cl.Tar(&out, []string{"/vda1/x"}, TarLimits{})
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil || !cl.Broken() {
			t.Fatalf("a stalled stream: err=%v broken=%v", err, cl.Broken())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Tar blocked on a stalled agent")
	}
}

// m-1: an agent that does not know the session's nonce — another VM on the
// same vsock CID — is refused before anything else is sent.
func TestClient_HelloNonce(t *testing.T) {
	var got []string
	cl := fakeAgentConn(t, func(c *wire.LineConn, _ net.Conn, req wire.Request) bool {
		got = append(got, req.Op)
		_ = c.Send(wire.Response{Nonce: "someone-else"})
		return true
	})
	if err := cl.Hello("mine", 0); !errors.Is(err, ErrWrongVM) {
		t.Fatalf("a wrong nonce: %v, want ErrWrongVM", err)
	}
	if _, err := cl.Volumes(); err == nil {
		t.Fatal("the client kept talking to the wrong VM")
	}
	if len(got) != 1 {
		t.Fatalf("requests sent: %v, want only the hello", got)
	}
	ok := fakeAgentConn(t, func(c *wire.LineConn, _ net.Conn, req wire.Request) bool {
		_ = c.Send(wire.Response{Nonce: "mine"})
		return true
	})
	if err := ok.Hello("mine", 0); err != nil {
		t.Fatalf("the right nonce: %v", err)
	}
}

// m-2: an agent error is bounded and escaped before it reaches a caller.
func TestClient_AgentErrorsAreEscaped(t *testing.T) {
	cl := fakeAgentConn(t, func(c *wire.LineConn, _ net.Conn, req wire.Request) bool {
		_ = c.Send(wire.Response{Error: "boom\x1b[2J\u009b31m‮gnp.exe" + strings.Repeat("x", 2000)})
		return true
	})
	_, err := cl.Volumes()
	if err == nil {
		t.Fatal("no error")
	}
	msg := err.Error()
	if strings.ContainsAny(msg, "\x1b\u009b‮") || len(msg) > 700 {
		t.Fatalf("agent error not escaped/bounded: %q (%d bytes)", msg[:80], len(msg))
	}
}

// N-4: a listing reply packed with entries past the cap is not materialized
// before the cap applies.
func TestClient_ListingDecodedWithinTheCap(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"entries":[`)
	for b.Len() < wire.MaxResponseLine-100 {
		b.WriteString(`{},`)
	}
	b.WriteString(`{}]}`)
	line := []byte(b.String() + "\n")
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	resp, err := decodeListResponse(line)
	runtime.ReadMemStats(&after)
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Entries) != wire.MaxListEntries || !resp.Truncated {
		t.Fatalf("kept %d entries truncated=%v", len(resp.Entries), resp.Truncated)
	}
	// ~2.8M empty objects would be ~200-400 MB as []Entry.
	if alloc := after.TotalAlloc - before.TotalAlloc; alloc > 96<<20 {
		t.Fatalf("decoding a capped listing allocated %d MB", alloc>>20)
	}
}
