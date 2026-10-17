package corrosion

import (
	"context"
	"log/slog"
)

// SensitiveLaneMerged reports whether this process has completed a
// sensitive-lane anti-entropy exchange with a peer: the digests agreed, or the
// differing tables were pulled and merged without error. After either, this
// node holds every credential row, live or retired, that the peer held.
//
// It gates the one write that cannot be judged without that: copying a host's
// old-column password into a credential row that does not exist here
// (credentials_split.go, RETIRED HOST CREDENTIALS). Like replica freshness it
// has no durable form; a restarted process waits for one exchange again, which
// costs one anti-entropy cycle.
func (c *Client) SensitiveLaneMerged() bool { return c.sensitiveLaneMerged.Load() }

func (c *Client) markSensitiveLaneMerged(peer string) {
	if c.sensitiveLaneMerged.CompareAndSwap(false, true) {
		slog.Info("sensitive lane merged with a peer; host credential copies may proceed", "peer", peer)
	}
}

// mayCopyHostCredentials reports whether the split pass may copy a host's
// old-column password where no credential row exists: once the sensitive lane
// has merged, or when this node holds no live host but itself, so no peer
// holds a row it has not pulled.
func (c *Client) mayCopyHostCredentials(ctx context.Context) (bool, error) {
	if c.SensitiveLaneMerged() {
		return true, nil
	}
	rows, err := c.Query(ctx, `SELECT COUNT(*) AS n FROM hosts WHERE deleted_at IS NULL AND name != ?`, c.HostName())
	if err != nil {
		return false, err
	}
	return len(rows) == 1 && rows[0].Int("n") == 0, nil
}
