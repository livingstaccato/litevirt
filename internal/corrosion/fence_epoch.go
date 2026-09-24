package corrosion

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

// SharedDiskFenceWindow bounds how recent a proof-grade fence must be to authorize
// a shared-disk cross-host transfer — a stale prior fence of the old owner must not
// authorize a fresh transfer. It is the EXECUTOR-side check; the coordinator's
// proofGradeFenceRef already enforces the tighter recentFenceWindow (5m) at mint.
// This window is deliberately WIDER (recentFenceWindow + a MaxSkew margin) because
// the executor compares the coordinator's wall timestamp against ITS OWN clock, and
// a REJECT here is terminal — a zero-margin window would false-reject a legitimately
// recent fence under normal inter-host clock skew (≤ MaxSkew). Recency is a
// secondary defense; the fence_epoch already binds the specific authorizing row.
const SharedDiskFenceWindow = 10 * time.Minute

// FenceCheck classifies a proof-grade-fence verification: OK to proceed, RETRY
// (the referenced fencing_log row hasn't replicated here yet — transient), or
// REJECT (no/inadequate proof-grade fence — terminal).
type FenceCheck int

const (
	FenceOK FenceCheck = iota
	FenceRetry
	FenceReject
)

// CheckProofGradeFence re-reads the fence_epoch's fencing_log row and classifies
// whether it PROVES a proof-grade power-off within window. It never trusts a stale
// hosts.state=="fenced" — only the append-only fencing_log row the fence_epoch
// names. The caller maps the tri-state to its own error vocabulary (grpc
// Unavailable for RETRY, FailedPrecondition + storage_unverified for REJECT).
//
// oldOwner is the VM's ACTUAL recorded owner when the caller knows it independently
// (the promote path, whose vm.HostName is still the pre-transfer owner) — an extra
// cross-check that the coordinator's fence_epoch binds that exact host. Pass "" when
// the caller can't independently derive the old owner (the reschedule/reconciler
// path re-points host_name to the target before the reconciler runs); the check then
// trusts the proof-protected fence_epoch.Host and only re-verifies that host's
// fencing_log row is proof-grade + recent.
func CheckProofGradeFence(ctx context.Context, c *Client, fenceEpoch, oldOwner string, window time.Duration) (FenceCheck, string) {
	ref, ok := ParseFenceEpoch(fenceEpoch)
	if !ok {
		// Empty includes a proof minted by a pre-fence_epoch node (mixed-version).
		return FenceReject, "no proof-grade fence bound"
	}
	expectHost := ref.Host
	if oldOwner != "" {
		if ref.Host != oldOwner {
			return FenceReject, fmt.Sprintf("fence_epoch binds host %q, not old owner %q", ref.Host, oldOwner)
		}
		expectHost = oldOwner
	}
	row, found, err := GetFenceLog(ctx, c, ref.FenceID)
	if err != nil {
		return FenceRetry, fmt.Sprintf("read fence log %s: %v", ref.FenceID, err)
	}
	if !found {
		// The row rides the same replication as the carried proof — retry, not refuse.
		return FenceRetry, fmt.Sprintf("fence_epoch row %s for %q not yet replicated", ref.FenceID, expectHost)
	}
	if row.HostName != expectHost || !FenceProofGrade(row.Method, row.Result) {
		return FenceReject, fmt.Sprintf("fence %s of %q is not proof-grade (method=%s result=%s)",
			ref.FenceID, row.HostName, row.Method, row.Result)
	}
	if ts, perr := time.Parse(time.RFC3339, row.Timestamp); perr != nil || time.Since(ts) > window {
		return FenceReject, fmt.Sprintf("fence %s is stale or undated", ref.FenceID)
	}
	return FenceOK, ""
}

// Fence assurance levels: what a recorded fence actually ESTABLISHES about the
// host, as opposed to what its result string says happened.
const (
	// FenceVerified: the host was powered off AND observed off afterwards
	// (IPMI: chassis power off, then a power-status read that says off).
	FenceVerified = "verified"
	// FenceOperatorConfirmed: a human ran `lv host fence-confirm` after
	// ensuring the host is down.
	FenceOperatorConfirmed = "operator-confirmed"
	// FenceRequested: the host accepted a poweroff (SSH) or the heartbeat was
	// stopped (watchdog), and nothing looked afterwards. The host may be off;
	// the record cannot say.
	FenceRequested = "requested"
	// FenceAssumed: the request itself is not known to have arrived. Only the
	// lenient best-effort path produces it — SSH failed and it proceeded.
	FenceAssumed = "assumed"
	// FenceAwaitingConfirmation: a manual fence, waiting for a human. Not a
	// failure — that is the strategy working as designed.
	FenceAwaitingConfirmation = "awaiting-confirmation"
	// FenceFailed: the fence ran and reported failure.
	FenceFailed = "failed"
	// FenceUnknown: a pair this code does not recognise. Never a success.
	FenceUnknown = "unknown"
)

// FenceAssurance classifies a fencing_log (method, result) pair.
//
// It exists because the result column cannot make the distinction that
// matters. The coordinator and the operator FenceHost path both write "fenced"
// for any fence.Result with Success, so an ssh row and an ipmi row are
// identical in the table while meaning different things: IPMI powered the host
// off and then observed it off; SSH had a shell accept a poweroff command.
//
// The classification is derived at READ time from what every row already
// records, rather than stored. That needs no schema change and no new
// replicated statement shape, and it classifies every historical row too,
// which a new column never could.
//
// FenceProofGrade is defined in terms of this, so the shared-storage gate and
// every operator surface read one classification rather than two that can
// drift apart.
func FenceAssurance(method, result string) string {
	switch {
	case result == "manual-confirmed":
		return FenceOperatorConfirmed
	case method == "manual" && result == "partial":
		return FenceAwaitingConfirmation
	case result == "partial":
		switch method {
		case "ipmi", "ssh", "watchdog", "best-effort-ssh":
			return FenceFailed
		}
	case result == "fenced":
		switch method {
		case "ipmi":
			return FenceVerified
		case "ssh", "watchdog":
			return FenceRequested
		case "best-effort-ssh":
			return FenceAssumed
		}
	}
	return FenceUnknown
}

// FenceProofGrade reports whether a fencing_log (method, result) pair PROVES the
// old owner is actually powered off — the bar a cross-host SHARED-disk ownership
// transfer must clear (capabilities.SharedStorageFenceV1). It accepts ONLY a
// confirmed power-off:
//
//   - result "fenced" + method "ipmi": IPMI/BMC power-off with verify.
//   - result "manual-confirmed": an operator ran `lv host fence-confirm` after
//     physically powering the host off.
//
// It REJECTS a best-effort / plain SSH "fenced" (a lenient SSH poweroff reports
// success but never confirms the host is down), a "partial" (failed) fence, an
// unconfirmed "manual", and a "watchdog" result (a self-fence timer can't be
// positively verified on all hardware). This is deliberately STRICTER than the
// per-host safe_fence gate, which a best-effort success can satisfy — a shared
// writable disk started on a second host while the first may still write it
// corrupts the disk, so only a proven power-off is acceptable.
func FenceProofGrade(method, result string) bool {
	switch FenceAssurance(method, result) {
	case FenceVerified, FenceOperatorConfirmed:
		return true
	default:
		return false
	}
}

// FenceEpochRef binds a cross-host transfer proof to the SPECIFIC fence of the old
// owner that authorizes it. It is carried in RuntimeActionProof.fence_epoch and the
// executor re-reads FenceID from fencing_log to re-verify a proof-grade power-off
// (never a stale hosts.state=="fenced").
type FenceEpochRef struct {
	Host    string // old owner that was fenced
	FenceID string // fencing_log row id
	TS      string // RFC3339 event time of that fence (audit/recency hint)
}

// String renders the wire form "host=<h>;fence_id=<id>;ts=<ts>", or "" when there
// is no fence to bind (FenceID empty) — an empty fence_epoch means "no proof-grade
// fence", which a new executor treats as fail-closed for a shared-disk transfer.
func (r FenceEpochRef) String() string {
	if r.FenceID == "" {
		return ""
	}
	return fmt.Sprintf("host=%s;fence_id=%s;ts=%s", r.Host, r.FenceID, r.TS)
}

// ParseFenceEpoch parses the wire form written by FenceEpochRef.String. ok=false
// for an empty string (no binding) or a malformed value (missing host/fence_id).
func ParseFenceEpoch(s string) (FenceEpochRef, bool) {
	if s == "" {
		return FenceEpochRef{}, false
	}
	var ref FenceEpochRef
	for _, part := range strings.Split(s, ";") {
		k, v, found := strings.Cut(part, "=")
		if !found {
			continue
		}
		switch k {
		case "host":
			ref.Host = v
		case "fence_id":
			ref.FenceID = v
		case "ts":
			ref.TS = v
		}
	}
	if ref.Host == "" || ref.FenceID == "" {
		return FenceEpochRef{}, false
	}
	return ref, true
}

// GetFenceLog reads a single fencing_log row by id (append-only, wall-clock —
// NOT an LWW row). found=false when no such row has replicated here yet, which
// the caller treats as retryable (the row rides the same replication as a
// carried proof), never as a terminal refusal.
func GetFenceLog(ctx context.Context, c *Client, id string) (FenceLogRecord, bool, error) {
	rows, err := c.Query(ctx,
		`SELECT id, host_name, method, result, timestamp, detail FROM fencing_log WHERE id = ?`, id)
	if err != nil {
		return FenceLogRecord{}, false, err
	}
	if len(rows) == 0 {
		return FenceLogRecord{}, false, nil
	}
	r := rows[0]
	return FenceLogRecord{
		ID: r.String("id"), HostName: r.String("host_name"), Method: r.String("method"),
		Result: r.String("result"), Detail: r.String("detail"), Timestamp: r.String("timestamp"),
	}, true, nil
}

// RecentFences returns fencing_log rows newer than since, newest first, at most
// limit of them.
//
// The recency filter and the ordering are done in Go on the parsed RFC3339
// timestamp, not in SQL, for the reason fenceWithinWindow gives: comparing
// fencing_log.timestamp as text against anything but another RFC3339 string is
// unreliable across the SQLite engines this code runs on. A row whose timestamp
// does not parse is skipped — it cannot be shown to be recent.
func RecentFences(ctx context.Context, c *Client, since time.Time, limit int) ([]FenceLogRecord, error) {
	rows, err := c.Query(ctx,
		`SELECT id, host_name, method, result, timestamp, detail FROM fencing_log`)
	if err != nil {
		return nil, err
	}
	type stamped struct {
		at  time.Time
		rec FenceLogRecord
	}
	var out []stamped
	for _, r := range rows {
		ts, perr := time.Parse(time.RFC3339, r.String("timestamp"))
		if perr != nil || !ts.After(since) {
			continue
		}
		out = append(out, stamped{ts, FenceLogRecord{
			ID: r.String("id"), HostName: r.String("host_name"), Method: r.String("method"),
			Result: r.String("result"), Detail: r.String("detail"), Timestamp: r.String("timestamp"),
		}})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].at.After(out[j].at) })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	recs := make([]FenceLogRecord, len(out))
	for i, s := range out {
		recs[i] = s.rec
	}
	return recs, nil
}
