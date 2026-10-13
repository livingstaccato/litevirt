package corrosion

// The held signal, re-derived from anti-entropy.
//
// A WAL entry this node holds (parked_entries.go) lives in memory. A restart,
// or a crash between the batch's commit and the hold being recorded, forgets
// it, while the row it carries is still not applied here. If the held signal
// lived only there, an operator who restarts the daemon to clear the alert
// would see it go green with the row still divergent.
//
// So the signal is also derived from state: every anti-entropy pass that is
// offered a row of a natural-key identity table and refuses it on a constraint
// records the refusal here, under the row's table and id, naming the host that
// wrote it. The sender keeps offering the row on every pass for as long as
// this node lacks it, so a refusal that still stands is re-recorded after a
// restart within one pass. A refusal clears when that row applies (by
// anti-entropy, by the WAL, or by a held entry's retry), when a decision makes
// it obsolete (decideIdentityCollision skips it), or when no pass has re-
// recorded it for heldRefusalTTL — several pass intervals — because the
// sender stopped offering it.
//
// Replicator.ParkedEntries reports these beside the held WAL entries, so
// litevirt_replication_parked_entries and replication_entry_parked cover both.

import (
	"sort"
	"sync"
	"time"
)

// heldRefusalTTL is how long a refusal stands without being re-recorded. A
// pass runs every minute by default, so this is several missed passes.
var heldRefusalTTL = 10 * time.Minute

type heldRefusal struct {
	table, id, origin, err string
	first, last            time.Time
}

type heldRefusals struct {
	mu sync.Mutex
	m  map[string]*heldRefusal
}

func heldRefusalKey(table, id string) string { return table + "\x00" + id }

func (c *Client) noteHeldRefusal(table, id, origin, errText string) {
	if id == "" {
		return
	}
	now := time.Now()
	c.held.mu.Lock()
	defer c.held.mu.Unlock()
	if c.held.m == nil {
		c.held.m = make(map[string]*heldRefusal)
	}
	k := heldRefusalKey(table, id)
	if h, ok := c.held.m[k]; ok {
		h.last, h.err, h.origin = now, errText, origin
		return
	}
	c.held.m[k] = &heldRefusal{table: table, id: id, origin: origin, err: errText, first: now, last: now}
}

func (c *Client) hasHeldRefusals() bool {
	c.held.mu.Lock()
	defer c.held.mu.Unlock()
	return len(c.held.m) > 0
}

func (c *Client) clearHeldRefusal(table, id string) {
	c.held.mu.Lock()
	defer c.held.mu.Unlock()
	delete(c.held.m, heldRefusalKey(table, id))
}

// HeldRefusals reports the anti-entropy refusals still standing, oldest first.
func (c *Client) HeldRefusals() []ParkedEntry {
	now := time.Now()
	c.held.mu.Lock()
	defer c.held.mu.Unlock()
	out := make([]ParkedEntry, 0, len(c.held.m))
	for k, h := range c.held.m {
		if now.Sub(h.last) > heldRefusalTTL {
			delete(c.held.m, k)
			continue
		}
		out = append(out, ParkedEntry{
			Origin: h.origin, Table: h.table, RowID: h.id, Error: h.err, HeldAt: h.first, Source: "ae",
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].HeldAt.Equal(out[j].HeldAt) {
			return out[i].HeldAt.Before(out[j].HeldAt)
		}
		return out[i].RowID < out[j].RowID
	})
	return out
}

// ForgetHeldRefusalsForTest drops every recorded refusal, as a process
// restart does. Test seam: the fleet harness restarts a node over the same
// Client, so a scenario models what the new process would not remember.
func (c *Client) ForgetHeldRefusalsForTest() {
	c.held.mu.Lock()
	c.held.m = nil
	c.held.mu.Unlock()
}
