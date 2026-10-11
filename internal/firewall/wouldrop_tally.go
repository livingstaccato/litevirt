package firewall

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// WouldDropTally keeps this host's observe-mode evidence across everything that
// zeroes the kernel's counters: every replace of the per-NIC table (a resync, a
// VM or container starting, stopping or migrating on the host) re-creates its
// rules and their counters, and a tap name is handed to the next VM to start.
// Before each replace the applier harvests the live counters into a total kept
// per workload, MAC, side and rule, persisted in a file, so `lv firewall
// enforce status` reports everything observed "since" a time that only an
// explicit reset moves (re-review I-4).
type WouldDropTally struct {
	path string
	read func(context.Context) ([]WouldDrop, error)

	mu    sync.Mutex
	state tallyState
}

// NICOwner names the NIC a tap belonged to.
type NICOwner struct {
	Workload string
	MAC      string
}

// TallyEntry is one total.
type TallyEntry struct {
	Workload string `json:"workload"`
	MAC      string `json:"mac,omitempty"`
	Side     string `json:"side"`
	Rule     string `json:"rule"`
	Packets  uint64 `json:"packets"`
	Bytes    uint64 `json:"bytes"`
	// Device is the tap the counter is on now; "" when the NIC is not on
	// this host at the moment.
	Device string `json:"-"`
}

type tallyState struct {
	Since  time.Time              `json:"since"`
	Totals map[string]*TallyEntry `json:"totals"`
	// Offset is what the live counters held when the tally was last reset:
	// the kernel's counters cannot be zeroed without replacing the table, so
	// the reset discounts them instead until the next harvest.
	Offset map[string][2]uint64 `json:"offset,omitempty"`
}

// NewWouldDropTally opens the tally kept at path, starting a new one "since"
// now when there is none (or it cannot be read).
func NewWouldDropTally(path string, now time.Time) *WouldDropTally {
	t := &WouldDropTally{path: path, read: WouldDrops}
	if b, err := os.ReadFile(path); err == nil && json.Unmarshal(b, &t.state) == nil && !t.state.Since.IsZero() {
		return t
	}
	t.state = tallyState{Since: now.UTC()}
	return t
}

func tallyKey(o NICOwner, side, rule string) string {
	return strings.Join([]string{o.Workload, strings.ToLower(o.MAC), side, rule}, "\x00")
}

// owned resolves the live counters to their workloads. A counter on a device
// no owner is known for is kept under the device's name.
func owned(wd []WouldDrop, owners map[string]NICOwner) map[string]*TallyEntry {
	out := map[string]*TallyEntry{}
	for _, w := range wd {
		o, ok := owners[w.Device]
		if !ok {
			o = NICOwner{Workload: w.Device}
		}
		k := tallyKey(o, w.Side, w.Rule)
		e := out[k]
		if e == nil {
			e = &TallyEntry{Workload: o.Workload, MAC: strings.ToLower(o.MAC), Side: w.Side, Rule: w.Rule, Device: w.Device}
			out[k] = e
		}
		e.Packets += w.Packets
		e.Bytes += w.Bytes
	}
	return out
}

func sub(a, b uint64) uint64 {
	if a < b {
		return 0
	}
	return a - b
}

// Harvest adds the live counters, which owners maps to their workloads, into
// the totals and saves them. The caller is about to replace (or remove) the
// table the counters are in.
func (t *WouldDropTally) Harvest(ctx context.Context, owners map[string]NICOwner) error {
	wd, err := t.read(ctx)
	if err != nil {
		return err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.state.Totals == nil {
		t.state.Totals = map[string]*TallyEntry{}
	}
	for k, e := range owned(wd, owners) {
		off := t.state.Offset[k]
		p, b := sub(e.Packets, off[0]), sub(e.Bytes, off[1])
		if p == 0 && b == 0 {
			continue
		}
		tot := t.state.Totals[k]
		if tot == nil {
			tot = &TallyEntry{Workload: e.Workload, MAC: e.MAC, Side: e.Side, Rule: e.Rule}
			t.state.Totals[k] = tot
		}
		tot.Packets += p
		tot.Bytes += b
	}
	t.state.Offset = nil
	return t.saveLocked()
}

// Snapshot is the totals plus what the live counters hold now, and the time
// they are counted from.
func (t *WouldDropTally) Snapshot(ctx context.Context, owners map[string]NICOwner) (time.Time, []TallyEntry, error) {
	wd, err := t.read(ctx)
	t.mu.Lock()
	defer t.mu.Unlock()
	merged := map[string]*TallyEntry{}
	for k, e := range t.state.Totals {
		c := *e
		merged[k] = &c
	}
	for k, e := range owned(wd, owners) {
		off := t.state.Offset[k]
		m := merged[k]
		if m == nil {
			m = &TallyEntry{Workload: e.Workload, MAC: e.MAC, Side: e.Side, Rule: e.Rule}
			merged[k] = m
		}
		m.Device = e.Device
		m.Packets += sub(e.Packets, off[0])
		m.Bytes += sub(e.Bytes, off[1])
	}
	out := make([]TallyEntry, 0, len(merged))
	for _, e := range merged {
		out = append(out, *e)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Workload != b.Workload {
			return a.Workload < b.Workload
		}
		if a.MAC != b.MAC {
			return a.MAC < b.MAC
		}
		if a.Side != b.Side {
			return a.Side < b.Side
		}
		return a.Rule < b.Rule
	})
	return t.state.Since, out, err
}

// Reset clears the totals and counts from now; what the live counters already
// hold is discounted.
func (t *WouldDropTally) Reset(ctx context.Context, owners map[string]NICOwner, now time.Time) error {
	wd, err := t.read(ctx)
	if err != nil {
		return err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.state = tallyState{Since: now.UTC(), Totals: map[string]*TallyEntry{}, Offset: map[string][2]uint64{}}
	for k, e := range owned(wd, owners) {
		t.state.Offset[k] = [2]uint64{e.Packets, e.Bytes}
	}
	return t.saveLocked()
}

func (t *WouldDropTally) saveLocked() error {
	if t.path == "" {
		return nil
	}
	b, err := json.Marshal(t.state)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(t.path), 0o700); err != nil {
		return err
	}
	tmp := t.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, t.path); err != nil {
		return errors.Join(fmt.Errorf("save would-drop tally: %w", err), os.Remove(tmp))
	}
	return nil
}

// nicOwners maps each NIC of p to its owner.
func nicOwners(p Plan) map[string]NICOwner {
	out := make(map[string]NICOwner, len(p.NICs))
	for _, n := range p.NICs {
		mac := n.MAC
		if mac == "" && n.Guard != nil {
			mac = n.Guard.MAC
		}
		out[n.NICDev] = NICOwner{Workload: n.VMName, MAC: strings.ToLower(mac)}
	}
	return out
}

// WouldDropTotals is this host's observe-mode evidence: the totals since the
// tally's start, or, with no tally, what the live counters hold now.
func (a *Applier) WouldDropTotals(ctx context.Context) (time.Time, []TallyEntry, error) {
	a.mu.Lock()
	t, owners := a.tally, a.ownersLocked()
	a.mu.Unlock()
	if t != nil {
		return t.Snapshot(ctx, owners)
	}
	wd, err := WouldDrops(ctx)
	var out []TallyEntry
	for _, e := range owned(wd, owners) {
		out = append(out, *e)
	}
	return time.Time{}, out, err
}

// ResetWouldDrops restarts the totals from now.
func (a *Applier) ResetWouldDrops(ctx context.Context, now time.Time) error {
	a.mu.Lock()
	t, owners := a.tally, a.ownersLocked()
	a.mu.Unlock()
	if t == nil {
		return errors.New("this host keeps no would-drop totals")
	}
	return t.Reset(ctx, owners, now)
}

func (a *Applier) ownersLocked() map[string]NICOwner {
	out := make(map[string]NICOwner, len(a.lastOwners))
	for k, v := range a.lastOwners {
		out[k] = v
	}
	return out
}

// WouldDropTotals: see Applier.WouldDropTotals.
func (r *Reconciler) WouldDropTotals(ctx context.Context) (time.Time, []TallyEntry, error) {
	return r.applier.WouldDropTotals(ctx)
}

// ResetWouldDrops: see Applier.ResetWouldDrops.
func (r *Reconciler) ResetWouldDrops(ctx context.Context, now time.Time) error {
	return r.applier.ResetWouldDrops(ctx, now)
}
