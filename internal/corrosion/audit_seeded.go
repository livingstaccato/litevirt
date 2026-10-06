package corrosion

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/litevirt/litevirt/internal/secretfile"
)

// Seeded: does this replica hold the cluster's history?
//
// AdmitHost hands a re-added machine the audit chain position of its name, read
// from the admitting node's replica (audit_hold.go), and "no history" from a
// replica that simply has not received the history yet is the fork the hold
// exists to prevent. Neither of the obvious signals says whether a replica has
// it. "One anti-entropy exchange completed" is satisfied by an exchange with a
// peer as empty as this one — in drill 6 three hosts are rebuilt together, and
// a rebuilt host's first exchange is as likely to be with another rebuilt host
// as with a survivor. "Alone in the cluster" is satisfied by a rebuilt host at
// first boot, whose hosts table names only itself.
//
// Seeded is that fact, carried forward. A replica is seeded when:
//
//   - it founded the cluster (the genesis mint in daemon.seedAdminUser): there
//     is no earlier history to lack;
//   - it already held rows of its own host the first time a build with this
//     marker ran on it, and was not holding them: an existing member at a
//     rolling upgrade. The decision is taken once per state.db and recorded,
//     so a rebuilt host that later writes rows of its own is NOT grandfathered
//     on a restart;
//   - otherwise, only once it has completed an anti-entropy exchange with a peer
//     that reported itself seeded and not holding its own audit rows. That
//     exchange merged every table that differed, so this replica now holds
//     everything that seeded peer held. An older peer reports nothing, which
//     reads as not seeded.
//
// The marker is local and never replicated: it is a statement about this
// replica. It is a file under data_dir bound to this state.db's voter
// incarnation (minted once per state.db by InitSchema), so it dies with the
// replica — a lost, reseeded or replaced state.db gets a new incarnation and the
// old marker no longer counts. No table is added, so there is no schema change
// and no statement shape.

// AuditSeededFileName is the marker under data_dir.
const AuditSeededFileName = "audit-seeded.json"

type auditSeededMarker struct {
	Incarnation string `json:"incarnation"`
	Seeded      bool   `json:"seeded"`
	Reason      string `json:"reason"`
	At          string `json:"at"`
}

// auditSeededState is a client's view of its marker. A client with no data dir
// (tests) keeps it in memory only.
type auditSeededState struct {
	mu      sync.Mutex
	loaded  bool
	decided bool
	seeded  bool
}

func (c *Client) auditSeededPath() string {
	if c.dataDir == "" {
		return ""
	}
	return filepath.Join(c.dataDir, AuditSeededFileName)
}

// loadAuditSeededLocked reads the marker once. Caller holds c.seeded.mu.
func (c *Client) loadAuditSeededLocked(ctx context.Context) {
	if c.seeded.loaded {
		return
	}
	path := c.auditSeededPath()
	if path == "" {
		c.seeded.loaded = true
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			slog.Warn("could not read this replica's seeded marker; it is treated as not seeded",
				"file", path, "error", err)
		}
		c.seeded.loaded = true
		return
	}
	var m auditSeededMarker
	inc, ierr := c.VoterIncarnation(ctx)
	if json.Unmarshal(data, &m) != nil || ierr != nil || m.Incarnation != inc {
		// Another state.db's marker: this replica has decided nothing yet.
		c.seeded.loaded = true
		return
	}
	c.seeded.loaded, c.seeded.decided, c.seeded.seeded = true, true, m.Seeded
}

func (c *Client) writeAuditSeededLocked(ctx context.Context, seeded bool, reason string) error {
	c.seeded.decided, c.seeded.seeded = true, seeded
	path := c.auditSeededPath()
	if path == "" {
		return nil
	}
	inc, err := c.VoterIncarnation(ctx)
	if err != nil {
		return err
	}
	data, err := json.Marshal(auditSeededMarker{Incarnation: inc, Seeded: seeded, Reason: reason,
		At: time.Now().UTC().Format(time.RFC3339)})
	if err != nil {
		return err
	}
	return secretfile.Write(path, data, 0o600)
}

// AuditSeeded reports whether this replica is seeded (see above).
func (c *Client) AuditSeeded(ctx context.Context) bool {
	c.seeded.mu.Lock()
	defer c.seeded.mu.Unlock()
	c.loadAuditSeededLocked(ctx)
	return c.seeded.seeded
}

// MarkAuditSeeded records that this replica is seeded, durably. why is logged
// and kept in the marker.
func (c *Client) MarkAuditSeeded(ctx context.Context, why string) error {
	c.seeded.mu.Lock()
	defer c.seeded.mu.Unlock()
	c.loadAuditSeededLocked(ctx)
	if c.seeded.seeded {
		return nil
	}
	if err := c.writeAuditSeededLocked(ctx, true, why); err != nil {
		return fmt.Errorf("record this replica as seeded: %w", err)
	}
	slog.Info("this replica now holds the cluster's history (seeded); it may vouch for audit chain "+
		"positions at host admission", "reason", why)
	return nil
}

// MarkAuditSeededForTests marks a test client seeded, as a bootstrapped
// cluster's founder would be.
func (c *Client) MarkAuditSeededForTests() {
	_ = c.MarkAuditSeeded(context.Background(), "test")
}

// DecideAuditSeeded takes the once-per-state.db decision at daemon start. It
// returns whether the replica is seeded. A replica that has decided already
// keeps its decision; an undecided one is seeded only if it holds rows of its
// own host and is not holding them — an existing member at a rolling upgrade.
// Called after ConfigureAuditHold and before the daemon writes anything.
func DecideAuditSeeded(ctx context.Context, c *Client, host string) (bool, error) {
	held := c.AuditChainHeld(ctx, host)
	c.seeded.mu.Lock()
	defer c.seeded.mu.Unlock()
	c.loadAuditSeededLocked(ctx)
	if c.seeded.decided {
		return c.seeded.seeded, nil
	}
	rows, err := c.Query(ctx, `SELECT 1 AS present FROM audit_log WHERE host_name = ? LIMIT 1`, host)
	if err != nil {
		return false, err
	}
	seeded := len(rows) > 0 && !held
	reason := "first start of this build on a replica holding none of its own audit history"
	if seeded {
		reason = "first start of this build on a replica already holding its own audit history (upgrade)"
	} else if held {
		reason = "first start of this build while holding its own audit rows"
	}
	if err := c.writeAuditSeededLocked(ctx, seeded, reason); err != nil {
		return seeded, fmt.Errorf("record this replica's seeded decision: %w", err)
	}
	slog.Info("recorded whether this replica holds the cluster's history", "seeded", seeded, "reason", reason)
	return seeded, nil
}
