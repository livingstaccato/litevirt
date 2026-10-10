package agent

import (
	"bytes"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/litevirt/litevirt/internal/filerestore/wire"
)

// The idle watchdog sees activity on every request and on every entry an
// extraction streams, so a long extraction does not power the VM off under
// the host.
func TestServer_TouchesOnRequestsAndWhileStreaming(t *testing.T) {
	root := t.TempDir()
	for _, n := range []string{"a", "b", "c"} {
		if err := os.WriteFile(filepath.Join(root, n), []byte(n), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	srv := NewServer(map[string]Volume{"vda1": NewDirVolume(root, "ext4")}, "n")
	var touches atomic.Int64
	srv.touch = func() { touches.Add(1) }
	host, guest := net.Pipe()
	go func() { _, _ = srv.ServeConn(guest); guest.Close() }()
	defer host.Close()
	c := wire.NewLineConn(host)
	_ = c.Send(wire.Request{Op: wire.OpHello})
	var resp wire.Response
	_ = c.Recv(&resp)
	afterHello := touches.Load()
	if afterHello < 1 {
		t.Fatal("a request did not touch the watchdog")
	}
	_ = c.Send(wire.Request{Op: wire.OpTar, Paths: []string{"/vda1"}})
	_ = c.Recv(&resp)
	for {
		rec, err := wire.ReadRecord(c.R)
		if err != nil {
			t.Fatal(err)
		}
		if rec.End {
			break
		}
		if rec.Size > 0 {
			buf := make([]byte, rec.Size)
			if _, err := c.R.Read(buf); err != nil {
				t.Fatal(err)
			}
			_ = bytes.TrimSpace(buf)
		}
	}
	// The request, then one per entry: vda1/, a, b, c.
	if got := touches.Load() - afterHello; got < 5 {
		t.Fatalf("an extraction of 4 entries touched the watchdog %d times", got)
	}
}
