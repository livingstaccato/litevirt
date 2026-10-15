package libvirt

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	golibvirt "github.com/digitalocean/go-libvirt"
)

const (
	defaultSocket = "/var/run/libvirt/libvirt-sock"

	// reconnectInterval is how often the client checks its connection to libvirtd.
	reconnectInterval = 5 * time.Second
	// reconnectMaxBackoff caps the retry delay when libvirtd is down.
	reconnectMaxBackoff = 30 * time.Second
)

// DomainEventCallback is called when a domain lifecycle event is received.
// Reason values are libvirt-specific (e.g. 0=booted, 1=migrated for Started).
type DomainEventCallback func(domainName string, event DomainEventType, detail int)

// DomainEventType represents a libvirt domain lifecycle event.
type DomainEventType int

const (
	DomainEventStarted  DomainEventType = 0
	DomainEventStopped  DomainEventType = 1
	DomainEventCrashed  DomainEventType = 2
	DomainEventShutdown DomainEventType = 3
)

// Client wraps a go-libvirt connection for VM lifecycle operations.
// It automatically reconnects if the connection to libvirtd drops (#42)
// and supports domain event callbacks for immediate VM death detection (#44).
type Client struct {
	mu   sync.RWMutex
	virt *golibvirt.Libvirt

	// Domain event callback registered by the daemon.
	eventCallback DomainEventCallback

	// The start guard (start_guard.go).
	startGuard StartGuard
	guardSet   bool
	guardReady chan struct{} // RequireStartGuard; closed once a guard is set
	guardWait  time.Duration
	guardNeeds func(name string) bool // RequireStartGuard's scope; nil = every start
	readyOnce  sync.Once

	// consolePolicy decides whether DefineDomain gives a domain's consoles
	// passwords (SetConsolePasswordPolicy, console_password.go).
	consolePolicy atomic.Pointer[func() ConsolePolicy]
	// vncUnavailable is why this host's QEMU cannot do VNC password
	// authentication ("" = it can): ProbeVNCPassword or a refused start.
	vncUnavailable atomic.Pointer[string]
	// vncProbed is closed once the startup probe has answered
	// (MarkVNCProbed); nil on a client built without NewClient.
	vncProbed     chan struct{}
	vncProbedOnce sync.Once

	// stateReader asks for domain states on connections of its own
	// (state_reader.go); made on first use. secureReader is the same on the
	// read-write socket, for the reads a read-only connection is refused.
	stateReaderMu sync.Mutex
	stateReader   *StateReader
	secureReader  *StateReader

	// conn is the socket under virt, closed by Close when the connection
	// does not close in time. connMu guards it (not mu, which a call that
	// libvirt does not answer can hold).
	connMu sync.Mutex
	conn   net.Conn
}

// clientCloseTimeout bounds how long Close waits for the daemon's connection
// to close: go-libvirt's Disconnect asks libvirtd first, and a connection
// libvirtd stopped reading (max_client_requests calls it does not answer)
// never answers, which would hold the daemon's shutdown short of closing its
// database. A variable for the tests.
var clientCloseTimeout = time.Second

// NewClient connects to the local libvirtd daemon.
func NewClient() (*Client, error) {
	return newClientOn(defaultSocket)
}

func newClientOn(socket string) (*Client, error) {
	virt, conn, err := dialLibvirt(socket)
	if err != nil {
		return nil, err
	}
	return &Client{virt: virt, conn: conn, vncProbed: make(chan struct{})}, nil
}

func dialLibvirt(socket string) (*golibvirt.Libvirt, net.Conn, error) {
	conn, err := net.DialTimeout("unix", socket, 5*time.Second)
	if err != nil {
		return nil, nil, fmt.Errorf("connect to libvirtd: %w", err)
	}

	virt := golibvirt.New(conn)
	if err := virt.Connect(); err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("libvirt handshake: %w", err)
	}
	return virt, conn, nil
}

// Reconnect re-establishes the libvirt connection. Used after libvirtd restarts (#42).
func (c *Client) Reconnect() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Disconnect old connection (best-effort, it may already be dead).
	if c.virt != nil {
		c.virt.Disconnect() //nolint:errcheck
	}

	virt, conn, err := dialLibvirt(defaultSocket)
	if err != nil {
		return err
	}
	c.virt = virt
	c.connMu.Lock()
	c.conn = conn
	c.connMu.Unlock()
	slog.Info("libvirt: reconnected to libvirtd")
	return nil
}

// StartReconnectLoop monitors the libvirt connection and automatically
// reconnects if libvirtd restarts (#42). Also registers domain event
// callbacks on each reconnect (#44). Blocks until ctx is cancelled.
func (c *Client) StartReconnectLoop(ctx context.Context) {
	ticker := time.NewTicker(reconnectInterval)
	defer ticker.Stop()

	backoff := reconnectInterval
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.mu.RLock()
			alive := c.isAlive()
			c.mu.RUnlock()

			if alive {
				backoff = reconnectInterval
				continue
			}

			slog.Warn("libvirt: connection lost, attempting reconnect...")
			if err := c.Reconnect(); err != nil {
				slog.Error("libvirt: reconnect failed", "error", err, "retry_in", backoff)
				backoff = min(backoff*2, reconnectMaxBackoff)
				continue
			}

			// Re-enumerate running domains after reconnect to reconcile state.
			if domains, err := c.ListDomains(); err == nil {
				slog.Info("libvirt: re-enumerated domains after reconnect", "count", len(domains))
			}

			backoff = reconnectInterval
		}
	}
}

// isAlive checks if the libvirt connection is still working.
func (c *Client) isAlive() bool {
	if c.virt == nil {
		return false
	}
	// A lightweight check: try to get the libvirt version.
	_, err := c.virt.ConnectGetLibVersion()
	return err == nil
}

// RegisterDomainEventCallback sets a callback that fires on domain lifecycle
// events (start, stop, crash, shutdown). This provides immediate VM death
// detection instead of relying on polling (#44).
func (c *Client) RegisterDomainEventCallback(cb DomainEventCallback) {
	c.mu.Lock()
	c.eventCallback = cb
	c.mu.Unlock()
}

// Close disconnects from libvirtd. It returns within about
// clientCloseTimeout (and the readers' own bound) whatever libvirt does: a
// connection that does not close in time has its socket closed under it,
// which fails every call still waiting on it, and Close reports that.
func (c *Client) Close() error {
	c.stateReaderMu.Lock()
	readers := []*StateReader{c.stateReader, c.secureReader}
	c.stateReaderMu.Unlock()
	var wg sync.WaitGroup
	for _, r := range readers {
		if r == nil {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.Close() //nolint:errcheck // best effort; the main connection's answer is the one returned
		}()
	}
	wg.Wait()
	// mu is taken in a goroutine of its own: a call libvirt does not answer
	// can hold it (the reconnect loop's liveness check holds it for reading).
	done := make(chan error, 1)
	go func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.virt == nil {
			done <- nil
			return
		}
		done <- c.virt.Disconnect()
	}()
	timer := time.NewTimer(clientCloseTimeout)
	defer timer.Stop()
	select {
	case err := <-done:
		return err
	case <-timer.C:
	}
	c.connMu.Lock()
	conn := c.conn
	c.connMu.Unlock()
	if conn != nil {
		conn.Close() //nolint:errcheck // what is waiting on it fails; that is the point
	}
	return fmt.Errorf("libvirt: the connection to libvirtd did not close within %s; its socket was closed", clientCloseTimeout)
}

// Libvirt returns the underlying go-libvirt handle for advanced operations.
func (c *Client) Libvirt() *golibvirt.Libvirt {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.virt
}

// NodeInfo returns host CPU/memory info.
func (c *Client) NodeInfo() (cpus int, memMiB int, err error) {
	_, rMemory, _, _, rNodes, rSockets, rCores, rThreads, err := c.virt.NodeGetInfo()
	if err != nil {
		return 0, 0, fmt.Errorf("node info: %w", err)
	}
	totalCPUs := int(rNodes) * int(rSockets) * int(rCores) * int(rThreads)
	memMiB = int(rMemory / 1024) // rMemory is in KiB
	return totalCPUs, memMiB, nil
}
