package storage

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Removing an rbd image. `rbd rm` deletes every data object of the image
// before it returns — minutes for a large, fully written one — so a delete
// bounded by any fixed cap a request can wait for was killed part-way, and the
// image was left behind, still using its capacity, with nothing in litevirt
// naming it.
//
// So an image is removed in two steps, the way `rbd rm` itself does them:
//
//  1. `rbd trash mv` once no client watches it. Metadata only: quick, and the
//     same whatever the image's size. The move is recorded (by the image's
//     id) before it runs, so one killed part-way is settled by id, not lost.
//     rbd does NOT refuse to move an image a client has open (lab 2, 19.2.3),
//     so the moved image's watchers are checked again by id; one a client
//     opened in between is put back under its name and the delete refused as
//     in use. Otherwise the name is free from here on, and the delete reports
//     success.
//  2. `rbd trash rm <pool>/<id>` in the background, with no short cap,
//     retried until rbd has removed it. Each pending purge is tracked
//     (CephPendingPurges), kept in a file under the data directory so a
//     restart resumes it (ResumeCephPurges), and one that keeps failing is
//     named by the ceph_trash_leftover condition. `rbd trash rm` refuses an
//     image a client still has open (exit 16, lab 2): such an entry is HELD,
//     never purged automatically, and named with `rbd trash restore`.
//
// Only an image this host moved to the trash, or one an interrupted `rbd rm`
// left there (source REMOVING), is ever purged: an image someone moved there
// by hand is theirs to restore.

// cephPurgeStateFile is the file, under the daemon's data directory, the
// pending purges are kept in.
const cephPurgeStateFile = "ceph-trash-purges.json"

// cephPurgeSetAsideMarker is in the name an unreadable queue file is moved to.
const cephPurgeSetAsideMarker = ".unreadable-"

// trashMoveTimeout bounds one `rbd trash mv`: metadata only, but it takes the
// image's lock, which a killed client's watch holds for about 30 s.
const trashMoveTimeout = 2 * time.Minute

// trashCheckTimeout bounds the calls that settle a move: the trash listing,
// the image's id, its watchers, a restore.
const trashCheckTimeout = 30 * time.Second

// purgeCallTimeout bounds one `rbd trash rm`. Not a cap a large image
// outlives: it only keeps a wedged rbd from holding the purge forever; the
// purge is then retried, and resumes where the last one stopped.
const purgeCallTimeout = 12 * time.Hour

// userBusyBudget is how long a user's delete waits for the clients watching
// an image to go before refusing it as in use: past the 30 s a dead client's
// watch lasts (lab 2), so a delete the blocking `rbd rm` it replaces would
// have completed still completes; a live client keeps it refused. A var for
// tests (OverrideCephBusyBudgetForTest).
var userBusyBudget = 45 * time.Second

// busyAnswerSlack is what a wait for watchers leaves of its caller's deadline,
// to answer "in use" in, rather than fail on a cancelled context.
const busyAnswerSlack = 5 * time.Second

// The state of a tracked trash entry.
const (
	// CephPurgeQueued: moved to the trash; purged in the background.
	CephPurgeQueued = ""
	// CephPurgeHeld: a client had the image open in the trash; never purged
	// automatically (it may be a running VM's disk) — named for an operator.
	CephPurgeHeld = "held"
	// CephPurgeHalfMoved: a `rbd trash mv` that failed left the image in the
	// trash AND under its name; never purged — named for an operator.
	CephPurgeHalfMoved = "half_moved"
	// cephPurgeMoving: a `rbd trash mv` is running, or was interrupted; its
	// outcome is settled by the image's id (settleMove).
	cephPurgeMoving = "moving"
	// CephPurgeMoving is cephPurgeMoving, for those naming such an entry:
	// the image may still be live under its name.
	CephPurgeMoving = cephPurgeMoving
)

// CephPurge is an rbd image moved to its pool's trash that this host still
// owes a `rbd trash rm` (or an operator's decision, when held).
type CephPurge struct {
	Pool  string `json:"pool"`  // the rbd pool (and namespace) of the trash
	ID    string `json:"id"`    // the image's id, what `rbd trash rm` removes
	Image string `json:"image"` // the name it had
	// Opts are the pool's identity and monitors (id, keyring, conf,
	// mon_host): paths and names, never a key.
	Opts      map[string]string `json:"opts,omitempty"`
	Since     time.Time         `json:"since"`
	Attempts  int               `json:"attempts"`
	LastError string            `json:"last_error,omitempty"`
	State     string            `json:"state,omitempty"`
	// Claimed: found in the trash, left by an interrupted `rbd rm`, not
	// moved there by this host.
	Claimed bool `json:"claimed,omitempty"`
}

// TrashRef is the purge's `rbd trash rm` argument, <pool>/<id>.
func (p CephPurge) TrashRef() string { return p.Pool + "/" + p.ID }

type cephPurgeEntry struct {
	CephPurge
	run     cmdRunner // nil → cephRunner (a purge resumed after a restart)
	looping bool
}

type cephPurgeQueue struct {
	mu       sync.Mutex
	m        map[string]*cephPurgeEntry // TrashRef → entry
	dir      string                     // where the queue is kept ("" → memory only)
	setAside []string                   // unreadable queue files, moved aside
	writeMu  sync.Mutex
}

var cephPurges = &cephPurgeQueue{m: map[string]*cephPurgeEntry{}}

// cephPurgeGo runs a purge loop; tests run purges by hand instead.
var cephPurgeGo = func(f func()) { go f() }

// syncFile flushes a file (or a directory) to disk; tests watch it.
var syncFile = func(f *os.File) error { return f.Sync() }

// purgeOpts is the part of a pool's options a purge needs to reach it.
func purgeOpts(opts map[string]string) map[string]string {
	out := map[string]string{}
	for _, k := range []string{"id", "keyring", "conf", "mon_host"} {
		if v := opts[k]; v != "" {
			out[k] = v
		}
	}
	return out
}

// track records pool's trash entry id (image) in the given state, and saves
// the queue; an entry already tracked takes the new state.
func (d *cephDriver) track(pool, id, image, state string, claimed bool) {
	ref := pool + "/" + id
	q := cephPurges
	q.mu.Lock()
	e, ok := q.m[ref]
	if !ok {
		// The runner the delete ran with (a test's stand-in stays its own,
		// even after the test restores the real one).
		e = &cephPurgeEntry{CephPurge: CephPurge{Pool: pool, ID: id, Image: image, Opts: purgeOpts(d.opts), Since: time.Now().UTC()}, run: d.runner()}
		q.m[ref] = e
	}
	e.State, e.Claimed = state, e.Claimed || claimed
	q.mu.Unlock()
	q.save()
}

// startPurge starts the background loop of a tracked entry, unless one runs.
func startPurge(ref string) {
	q := cephPurges
	q.mu.Lock()
	e, ok := q.m[ref]
	start := ok && !e.looping
	if start {
		e.looping = true
	}
	q.mu.Unlock()
	if start {
		cephPurgeGo(func() { purgeLoop(ref) })
	}
}

// queuePurge records that pool's trash holds image (id) for this host to
// purge, and starts its purge.
func (d *cephDriver) queuePurge(pool, id, image string, claimed bool) {
	d.track(pool, id, image, CephPurgeQueued, claimed)
	slog.Info("ceph: image moved to the trash; its objects are purged in the background",
		"image", pool+"/"+image, "trash", pool+"/"+id)
	startPurge(pool + "/" + id)
}

// hold stops a tracked entry from being purged automatically, saying why.
func (q *cephPurgeQueue) hold(ref, state, why string) {
	q.mu.Lock()
	if e, ok := q.m[ref]; ok {
		e.State, e.LastError = state, why
	}
	q.mu.Unlock()
	q.save()
}

// purgeLoop retries one purge until it is done, backing off to ten minutes.
func purgeLoop(ref string) {
	defer func() {
		q := cephPurges
		q.mu.Lock()
		if e, ok := q.m[ref]; ok {
			e.looping = false
		}
		q.mu.Unlock()
	}()
	wait := 10 * time.Second
	for !attemptCephPurge(ref) {
		if !cephSleep(context.Background(), wait) {
			return
		}
		wait = min(wait*2, 10*time.Minute)
	}
}

// attemptCephPurge runs one `rbd trash rm` of a queued purge (settling an
// interrupted move first); done is true once there is nothing more for the
// loop to do: it is gone from the trash (or from the queue), or held.
func attemptCephPurge(ref string) (done bool) {
	q := cephPurges
	q.mu.Lock()
	e, ok := q.m[ref]
	var p CephPurge
	var run cmdRunner
	if ok {
		p, run = e.CephPurge, e.run
	}
	q.mu.Unlock()
	if !ok || p.State == CephPurgeHeld || p.State == CephPurgeHalfMoved {
		return true
	}
	d := &cephDriver{opts: p.Opts, run: run}
	if p.State == cephPurgeMoving {
		switch d.settleMove(context.Background(), p.Pool, p.ID, p.Image) {
		case moveNotDone:
			q.forget(ref)
			slog.Info("ceph: an interrupted move to the trash never happened; nothing to purge", "image", p.Pool+"/"+p.Image, "id", p.ID)
			return true
		case moveHalf:
			q.hold(ref, CephPurgeHalfMoved, halfMovedWhy(p.Pool, p.ID, p.Image))
			slog.Warn("ceph: an interrupted move left the image in the trash and under its name; not purged",
				"image", p.Pool+"/"+p.Image, "trash", ref, "by_hand", "rbd trash restore "+ref)
			return true
		case moveUnknown:
			q.failed(ref, "the trash or the image could not be read to settle an interrupted move to the trash")
			return false
		}
		d.track(p.Pool, p.ID, p.Image, CephPurgeQueued, false)
	}
	ctx, cancel := context.WithTimeout(context.Background(), purgeCallTimeout)
	defer cancel()
	out, err := d.rbd(ctx, d.rbdArgs("trash", "rm", "--", ref)...)
	if err == nil || (rbdErrno(err) == rbdENOENT && !d.trashHolds(ctx, p.Pool, p.ID)) {
		q.forget(ref)
		slog.Info("ceph: purged an image from the trash", "image", p.Pool+"/"+p.Image, "trash", ref)
		return true
	}
	msg := fmt.Sprintf("%v: %s", err, strings.TrimSpace(string(out)))
	if rbdErrno(err) == rbdEBUSY && !p.Claimed {
		// A client has the image open in the trash: it opened it before
		// the move (rbd does not refuse to move an open image). It may be a
		// running VM's disk: never purged automatically.
		q.hold(ref, CephPurgeHeld, fmt.Sprintf("a client has the image open in the trash, so it is not purged (%s); "+
			"it may be a running VM's disk: restore it with `rbd trash restore %s`, or remove it with `rbd trash rm %s` once nothing uses it", msg, ref, ref))
		slog.Warn("ceph: a client has an image in the trash open; it is held, not purged",
			"image", p.Pool+"/"+p.Image, "trash", ref, "error", msg, "restore", "rbd trash restore "+ref)
		return true
	}
	q.failed(ref, msg)
	slog.Warn("ceph: an image in the rbd trash is not purged yet; retrying",
		"image", p.Pool+"/"+p.Image, "trash", ref, "error", msg,
		"by_hand", "rbd trash rm "+ref)
	return false
}

func halfMovedWhy(pool, id, image string) string {
	ref := pool + "/" + id
	return fmt.Sprintf("a `rbd trash mv` of %s/%s that failed left it in the trash as %s and still under its name; it is not purged: "+
		"put it back with `rbd trash restore %s` (check `rbd trash ls --all --long %s` and `rbd info %s/%s` first)",
		pool, image, ref, ref, pool, pool, image)
}

// failed records a failed attempt of a tracked entry.
func (q *cephPurgeQueue) failed(ref, msg string) {
	q.mu.Lock()
	if e, ok := q.m[ref]; ok {
		e.Attempts++
		e.LastError = msg
	}
	q.mu.Unlock()
	q.save()
}

// The outcome of a `rbd trash mv` that did not report success.
type moveOutcome int

const (
	moveUnknown moveOutcome = iota // the trash or the name could not be read
	moveDone                       // in the trash, gone from the pool
	moveNotDone                    // not in the trash
	moveHalf                       // in the trash AND still under its name
)

// settleMove decides, by the image's id, what a `rbd trash mv` of
// pool/image (id) that did not report success did.
func (d *cephDriver) settleMove(ctx context.Context, pool, id, image string) moveOutcome {
	cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), trashCheckTimeout)
	defer cancel()
	entries, err := d.trashList(cctx, pool)
	if err != nil {
		return moveUnknown
	}
	inTrash := false
	for _, e := range entries {
		inTrash = inTrash || e.ID == id
	}
	// The trash answered as this identity, so ENOENT for the name is the
	// image's, not a missing keyring's.
	nameID, _, err := d.info(cctx, pool+"/"+image)
	switch {
	case err != nil && rbdErrno(err) == rbdENOENT:
		nameID = ""
	case err != nil:
		return moveUnknown
	}
	switch {
	case inTrash && nameID == id:
		return moveHalf
	case inTrash:
		return moveDone
	default:
		return moveNotDone
	}
}

// trashHolds reports whether pool's trash lists id; true when the trash cannot
// be read (a purge is never forgotten on a guess).
func (d *cephDriver) trashHolds(ctx context.Context, pool, id string) bool {
	entries, err := d.trashList(ctx, pool)
	if err != nil {
		return true
	}
	for _, e := range entries {
		if e.ID == id {
			return true
		}
	}
	return false
}

type trashEntry struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Source string `json:"source"`
}

// trashList lists pool's trash, every source (`--all`: an interrupted rm's
// entries are REMOVING, which the default listing leaves out), and with
// `--long`, without which rbd prints no `source` (lab 2, 19.2.3).
func (d *cephDriver) trashList(ctx context.Context, pool string) ([]trashEntry, error) {
	out, err := d.rbd(ctx, d.rbdArgs("trash", "ls", "--all", "--long", "--format", "json", "--", pool)...)
	if err != nil {
		return nil, fmt.Errorf("rbd trash ls %s: %w: %s", pool, err, strings.TrimSpace(string(out)))
	}
	var entries []trashEntry
	if err := decodeRBDJSON(out, &entries); err != nil {
		return nil, fmt.Errorf("rbd trash ls %s: %w", pool, err)
	}
	return entries, nil
}

// decodeRBDJSON reads rbd's JSON answer into v. The runner hands back stdout
// and stderr together, so a warning rbd prints before the JSON ("did not
// load config file, using default settings.") is skipped: the answer is read
// from the first line that starts a JSON value, and anything after it is
// ignored.
func decodeRBDJSON(out []byte, v any) error {
	err := json.Unmarshal(out, v)
	if err == nil {
		return nil
	}
	for off := 0; off < len(out); {
		line := out[off:]
		if t := bytes.TrimLeft(line, " \t\r"); len(t) > 0 && (t[0] == '{' || t[0] == '[') {
			if json.NewDecoder(bytes.NewReader(out[off:])).Decode(v) == nil {
				return nil
			}
		}
		nl := bytes.IndexByte(line, '\n')
		if nl < 0 {
			break
		}
		off += nl + 1
	}
	return err
}

func (q *cephPurgeQueue) forget(ref string) {
	q.mu.Lock()
	delete(q.m, ref)
	q.mu.Unlock()
	q.save()
}

// save writes the queue to its file (replaced whole), when it has one.
func (q *cephPurgeQueue) save() {
	q.writeMu.Lock()
	defer q.writeMu.Unlock()
	q.mu.Lock()
	dir := q.dir
	list := q.listLocked()
	q.mu.Unlock()
	if dir == "" {
		return
	}
	raw, err := json.MarshalIndent(list, "", "  ")
	if err == nil {
		err = writeFileAtomic(filepath.Join(dir, cephPurgeStateFile), raw)
	}
	if err != nil {
		slog.Warn("ceph: the trash purge queue was not saved; a restart forgets what it holds", "error", err)
	}
}

// writeFileAtomic replaces path with data durably: the new file is synced
// before it is renamed into place, and its directory after, so a power loss
// leaves either the old queue or the new one — never an empty or torn file.
func writeFileAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := syncFile(tmp); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return syncFile(dir)
}

func (q *cephPurgeQueue) listLocked() []CephPurge {
	out := make([]CephPurge, 0, len(q.m))
	for _, e := range q.m {
		p := e.CephPurge
		p.Opts = purgeOpts(e.Opts)
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].TrashRef() < out[j].TrashRef() })
	return out
}

// CephPendingPurges lists the images in a ceph pool's trash this host still
// owes a purge (or holds for an operator), by trash reference.
func CephPendingPurges() []CephPurge {
	q := cephPurges
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.listLocked()
}

// CephPurgeQueueSetAside lists the queue files found unreadable (a torn
// write) and moved aside: what they tracked is no longer purged, so they are
// named for an operator until removed.
func CephPurgeQueueSetAside() []string {
	q := cephPurges
	q.mu.Lock()
	defer q.mu.Unlock()
	return append([]string(nil), q.setAside...)
}

// ResumeCephPurges keeps the purge queue under dir from now on, and resumes
// the purges a previous run of the daemon left in it — settling first, by
// id, any move to the trash it was making. A queue file that cannot be read
// is moved aside (CephPurgeQueueSetAside names it) and an error says so, but
// the queue is kept under dir all the same.
func ResumeCephPurges(dir string) error {
	q := cephPurges
	path := filepath.Join(dir, cephPurgeStateFile)
	raw, err := os.ReadFile(path)
	var saved []CephPurge
	var unreadable error
	switch {
	case err != nil && !errors.Is(err, os.ErrNotExist):
		unreadable = err
	case len(raw) > 0:
		if err := json.Unmarshal(raw, &saved); err != nil {
			unreadable, saved = err, nil
		}
	}
	var resumeErr error
	if unreadable != nil {
		aside := path + cephPurgeSetAsideMarker + time.Now().UTC().Format("20060102T150405.000000000Z")
		if rerr := os.Rename(path, aside); rerr != nil {
			// Not kept under dir: saving would overwrite what it tracked.
			return fmt.Errorf("the ceph trash purge queue %s cannot be read (%v) nor moved aside (%v); purges are kept in memory only", path, unreadable, rerr)
		}
		resumeErr = fmt.Errorf("the ceph trash purge queue %s cannot be read (%v); moved aside as %s, and named by ceph_trash_leftover", path, unreadable, aside)
		slog.Warn("ceph: the trash purge queue was unreadable and is set aside", "file", aside, "error", unreadable)
	}
	asides, _ := filepath.Glob(path + cephPurgeSetAsideMarker + "*")
	sort.Strings(asides)
	var start []string
	q.mu.Lock()
	q.dir = dir
	q.setAside = asides
	for _, p := range saved {
		if p.Pool == "" || p.ID == "" {
			continue
		}
		ref := p.TrashRef()
		e, ok := q.m[ref]
		if !ok {
			e = &cephPurgeEntry{CephPurge: p}
			q.m[ref] = e
		}
		if !e.looping && e.State != CephPurgeHeld && e.State != CephPurgeHalfMoved {
			start = append(start, ref)
		}
	}
	q.mu.Unlock()
	q.save()
	for _, ref := range start {
		startPurge(ref)
	}
	if len(start) > 0 {
		slog.Info("ceph: resumed purging images a previous run moved to the trash", "count", len(start))
	}
	return resumeErr
}

// RecheckHeldCephPurges forgets the held entries (CephPurgeHeld,
// CephPurgeHalfMoved) an operator has dealt with: their trash, answering,
// no longer lists them.
func RecheckHeldCephPurges(ctx context.Context) {
	q := cephPurges
	q.mu.Lock()
	var held []CephPurge
	var runs []cmdRunner
	for _, e := range q.m {
		if e.State == CephPurgeHeld || e.State == CephPurgeHalfMoved {
			held, runs = append(held, e.CephPurge), append(runs, e.run)
		}
	}
	q.mu.Unlock()
	for i, p := range held {
		d := &cephDriver{opts: p.Opts, run: runs[i]}
		cctx, cancel := context.WithTimeout(ctx, trashCheckTimeout)
		holds := d.trashHolds(cctx, p.Pool, p.ID)
		cancel()
		if !holds {
			q.forget(p.TrashRef())
			slog.Info("ceph: a held image is no longer in the trash", "image", p.Pool+"/"+p.Image, "trash", p.TrashRef())
		}
	}
}

// attemptCephPurges runs one attempt of every queued purge (tests).
func attemptCephPurges() {
	for _, p := range CephPendingPurges() {
		attemptCephPurge(p.TrashRef())
	}
}

// RunCephPurgesOnceForTest runs one attempt of every queued purge, for tests
// in other packages that stop the background loops (OverrideCephPurgeLoopForTest).
func RunCephPurgesOnceForTest() { attemptCephPurges() }

// OverrideCephPurgeLoopForTest stops queued purges from starting background
// loops (they run only through RunCephPurgesOnceForTest), and empties the
// queue; it returns the restore.
func OverrideCephPurgeLoopForTest() func() {
	prev := cephPurgeGo
	cephPurgeGo = func(func()) {}
	resetCephPurgeQueue()
	return func() {
		cephPurgeGo = prev
		resetCephPurgeQueue()
	}
}

// OverrideCephBusyBudgetForTest sets how long a user's delete waits for an
// image's watchers to go; it returns the restore.
func OverrideCephBusyBudgetForTest(d time.Duration) func() {
	prev := userBusyBudget
	userBusyBudget = d
	return func() { userBusyBudget = prev }
}

func resetCephPurgeQueue() {
	q := cephPurges
	q.mu.Lock()
	q.m = map[string]*cephPurgeEntry{}
	q.dir = ""
	q.setAside = nil
	q.mu.Unlock()
}

// cephInUseError is a delete refused because a client still has the image
// open: a VM somewhere still runs on it.
type cephInUseError struct {
	ref, status string
}

func (e *cephInUseError) Error() string {
	return fmt.Sprintf("ceph image %s is in use (another client still has it open; stop the VM using it first): %s", e.ref, e.status)
}

// watchers reports the clients `rbd status` lists as watching ref, with rbd's
// own output to name them. An answer that cannot be read is "watched": an
// image is never moved on a guess.
func (d *cephDriver) watchers(ctx context.Context, ref string) (bool, string, error) {
	out, err := d.rbd(ctx, d.rbdArgs("status", "--format", "json", "--", ref)...)
	text := strings.TrimSpace(string(out))
	if err != nil {
		return false, text, fmt.Errorf("rbd status %s: %w: %s", ref, err, text)
	}
	var st struct {
		Watchers *[]json.RawMessage `json:"watchers"`
	}
	if jerr := decodeRBDJSON(out, &st); jerr != nil || st.Watchers == nil {
		return true, "rbd status gave no answer that could be read, so the image is taken as in use: " + text, nil
	}
	return len(*st.Watchers) > 0, text, nil
}

// info is the id rbd keeps ref under (what its trash entry is named by; ""
// for a format-1 image) and its snapshot count.
func (d *cephDriver) info(ctx context.Context, ref string) (string, int, error) {
	out, err := d.rbd(ctx, d.rbdArgs("info", "--format", "json", "--", ref)...)
	if err != nil {
		return "", 0, fmt.Errorf("rbd info %s: %w: %s", ref, err, strings.TrimSpace(string(out)))
	}
	var info struct {
		ID        string `json:"id"`
		Snapshots int    `json:"snapshot_count"`
	}
	if err := decodeRBDJSON(out, &info); err != nil {
		return "", 0, fmt.Errorf("rbd info %s: %w", ref, err)
	}
	return info.ID, info.Snapshots, nil
}

// imageID is the id rbd keeps ref under: what its trash entry is named by.
// An image with snapshots is refused, as `rbd rm` refuses it: a clone may
// hang off one, and the trash must not take its parent from under it.
// (snapshot_count may leave out snapshots in the trash namespace, a clone
// v2 parent's: such an image reaches the trash, and its purge then fails —
// retried, and named — until its children are gone. Nothing is lost.)
func (d *cephDriver) imageID(ctx context.Context, ref string) (string, error) {
	id, snaps, err := d.info(ctx, ref)
	if err != nil {
		return "", err
	}
	if snaps > 0 {
		return "", fmt.Errorf("ceph image %s has %d snapshot(s); not removing it (remove them first)", ref, snaps)
	}
	return id, nil
}

// trashedWatchers lists the clients watching pool's image id — one in the
// trash, which `rbd status` cannot name (it takes no image id in 19.2.3) —
// as rados lists the watchers of the image's header object.
func (d *cephDriver) trashedWatchers(ctx context.Context, pool, id string) (bool, string, error) {
	cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), trashCheckTimeout)
	defer cancel()
	p, ns, hasNS := strings.Cut(pool, "/")
	args := []string{"-p", p}
	if hasNS {
		args = append(args, "--namespace", ns)
	}
	args = append(args, "listwatchers", "rbd_header."+id)
	out, err := d.runner()(cctx, "rados", d.rbdArgs(args...)...)
	text := strings.TrimSpace(string(out))
	if err != nil {
		return false, text, fmt.Errorf("rados listwatchers %s/rbd_header.%s: %w: %s", pool, id, err, text)
	}
	var who []string
	for _, line := range strings.Split(text, "\n") {
		if strings.Contains(line, "watcher=") {
			who = append(who, strings.TrimSpace(line))
		}
	}
	return len(who) > 0, strings.Join(who, "; "), nil
}

// removeImage removes ref: moved to its pool's trash once no client watches
// it (waiting up to busyBudget for the watchers to go, and no longer than
// its caller's deadline allows), then purged in the background. An image a
// client still watches after that — or opened as it was moved — is refused
// as in use (*cephInUseError), and stays where it is. Errors keep rbd's exit
// status (rbdErrno), so a caller can tell an image that is gone (ENOENT).
func (d *cephDriver) removeImage(ctx context.Context, ref string, busyBudget time.Duration) error {
	pool, image, ok := cutLast(ref, "/")
	if !ok {
		return fmt.Errorf("ceph image %q names no pool", ref)
	}
	if dl, ok := ctx.Deadline(); ok {
		busyBudget = min(busyBudget, max(time.Until(dl)-busyAnswerSlack, 0))
	}
	wait, spent := time.Second, time.Duration(0)
	for {
		watched, text, err := d.watchers(ctx, ref)
		if err != nil {
			return err
		}
		if !watched {
			id, err := d.imageID(ctx, ref)
			if err != nil {
				return err
			}
			if id == "" {
				// An image with no id (format 1) cannot go to the trash; rbd
				// rm it, with no short cap.
				return d.rmNoCap(ctx, ref)
			}
			busy, out, err := d.moveToTrash(ctx, pool, id, image)
			if !busy {
				return err
			}
			// rbd refused the move as busy: a client opened it in between.
			text = out
		}
		if spent >= busyBudget {
			return &cephInUseError{ref: ref, status: text}
		}
		if !cephSleep(ctx, wait) {
			return fmt.Errorf("ceph image %s is still watched (%s): %w", ref, text, ctx.Err())
		}
		spent += wait
		wait = min(wait*2, 10*time.Second)
	}
}

// moveToTrash moves pool/image (id) to the trash and queues its purge: the
// move is recorded first, a move that failed is settled by id, and a moved
// image a client has open is put back. busy is a move rbd refused as busy
// (out its output), for the caller to wait on as for a watcher.
func (d *cephDriver) moveToTrash(ctx context.Context, pool, id, image string) (busy bool, out string, err error) {
	ref, tref := pool+"/"+image, pool+"/"+id
	d.track(pool, id, image, cephPurgeMoving, false)
	mctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), trashMoveTimeout)
	raw, merr := d.rbd(mctx, d.rbdArgs("trash", "mv", "--", ref)...)
	cancel()
	out = strings.TrimSpace(string(raw))
	if merr != nil {
		if rbdErrno(merr) == rbdEBUSY {
			cephPurges.forget(tref)
			return true, out, nil
		}
		moveErr := fmt.Errorf("rbd trash mv %s: %w: %s", ref, merr, out)
		// It may have moved the image anyway (killed part-way): settled by
		// the image's id.
		switch d.settleMove(ctx, pool, id, image) {
		case moveNotDone:
			cephPurges.forget(tref)
			return false, out, moveErr
		case moveHalf:
			cephPurges.hold(tref, CephPurgeHalfMoved, halfMovedWhy(pool, id, image))
			return false, out, fmt.Errorf("%w; it is left in the trash as %s and under its name, and named by ceph_trash_leftover: `rbd trash restore %s`", moveErr, tref, tref)
		case moveUnknown:
			// Settled later, in the background (and at the next start).
			startPurge(tref)
			return false, out, fmt.Errorf("%w; whether it moved is not known yet, and is settled in the background", moveErr)
		}
		slog.Warn("ceph: a move to the trash reported failure but moved the image", "image", ref, "trash", tref, "error", moveErr)
	}
	// rbd does not refuse to move an image a client has open (lab 2): a
	// client that opened it after the watcher check still has it, in the
	// trash. Put it back under its name and refuse.
	watched, who, werr := d.trashedWatchers(ctx, pool, id)
	switch {
	case werr != nil:
		// Cannot tell: the purge itself refuses an image a client has open
		// (`rbd trash rm` exits 16), and holds it.
		slog.Warn("ceph: the watchers of an image moved to the trash could not be listed; its purge refuses it if a client has it open",
			"image", ref, "trash", tref, "error", werr)
	case watched:
		rctx, rcancel := context.WithTimeout(context.WithoutCancel(ctx), trashCheckTimeout)
		rout, rerr := d.rbd(rctx, d.rbdArgs("trash", "restore", "--", tref)...)
		rcancel()
		if rerr == nil {
			cephPurges.forget(tref)
			slog.Warn("ceph: a client opened an image as it was moved to the trash; restored under its name", "image", ref, "watchers", who)
			return false, out, &cephInUseError{ref: ref, status: who + " (it was put back from the trash)"}
		}
		why := fmt.Sprintf("a client opened the image as it was moved to the trash (%s), and putting it back failed (%v: %s): "+
			"it may be a running VM's disk: restore it with `rbd trash restore %s`", who, rerr, strings.TrimSpace(string(rout)), tref)
		cephPurges.hold(tref, CephPurgeHeld, why)
		return false, out, &cephInUseError{ref: ref, status: why}
	}
	d.queuePurge(pool, id, image, false)
	return false, out, nil
}

// rmNoCap is `rbd rm` of an image that has no trash form, detached from the
// caller and with no short cap.
func (d *cephDriver) rmNoCap(ctx context.Context, ref string) error {
	cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), purgeCallTimeout)
	defer cancel()
	if out, err := d.rbd(cctx, d.rbdArgs("rm", "--", ref)...); err != nil {
		return fmt.Errorf("rbd rm %s: %w: %s", ref, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// claimTrashLeftovers queues the purge of what an interrupted `rbd rm` of
// pool/image left in the trash (source REMOVING); an entry of that name
// someone moved there by hand is named in the log and left alone (and named
// by ceph_trash_leftover, through UntrackedTrash).
func (d *cephDriver) claimTrashLeftovers(ctx context.Context, pool, image string) {
	entries, err := d.trashList(ctx, pool)
	if err != nil {
		slog.Warn("ceph: the trash could not be checked for a leftover of a deleted image", "image", pool+"/"+image, "error", err)
		return
	}
	queued := map[string]bool{}
	for _, p := range CephPendingPurges() {
		queued[p.TrashRef()] = true
	}
	for _, e := range entries {
		if e.Name != image || queued[pool+"/"+e.ID] {
			continue
		}
		if strings.EqualFold(e.Source, "REMOVING") {
			slog.Warn("ceph: an interrupted rbd rm left the image in the trash; purging it", "image", pool+"/"+image, "trash", pool+"/"+e.ID)
			d.queuePurge(pool, e.ID, image, true)
			continue
		}
		slog.Warn("ceph: the rbd trash holds an image of this name that litevirt did not put there; left for its owner",
			"image", pool+"/"+image, "trash", pool+"/"+e.ID, "source", e.Source, "by_hand", "rbd trash rm "+pool+"/"+e.ID)
	}
}

// CephTrashEntry is an entry of a ceph pool's trash.
type CephTrashEntry struct {
	Pool, ID, Name, Source string
}

// TrashRef is the entry's <pool>/<id>.
func (e CephTrashEntry) TrashRef() string { return e.Pool + "/" + e.ID }

// CephTrashScanner is a driver whose pool has a trash to scan.
type CephTrashScanner interface {
	UntrackedTrash(ctx context.Context) ([]CephTrashEntry, error)
}

// litevirtImageRe is a litevirt VM disk's image name, <vm>-<disk>.
var litevirtImageRe = regexp.MustCompile(`^[A-Za-z0-9_.]+-[A-Za-z0-9_.-]+$`)

// UntrackedTrash lists the entries of the pool's trash named like a
// litevirt image (a VM disk, a staging copy, a base) that no purge on this
// host tracks: left by an interrupted `rbd rm`, by a queue a crash lost, or
// by another host. An operator's own images, by name, are left out.
func (d *cephDriver) UntrackedTrash(ctx context.Context) ([]CephTrashEntry, error) {
	entries, err := d.trashList(ctx, d.pool)
	if err != nil {
		return nil, err
	}
	tracked := map[string]bool{}
	for _, p := range CephPendingPurges() {
		tracked[p.TrashRef()] = true
	}
	var out []CephTrashEntry
	for _, e := range entries {
		if tracked[d.pool+"/"+e.ID] {
			continue
		}
		if !strings.Contains(e.Name, incomingMarker) && !IsCephBaseImage(e.Name) && !litevirtImageRe.MatchString(e.Name) {
			continue
		}
		out = append(out, CephTrashEntry{Pool: d.pool, ID: e.ID, Name: e.Name, Source: e.Source})
	}
	return out, nil
}

// cutLast splits s around the last sep.
func cutLast(s, sep string) (before, after string, found bool) {
	if i := strings.LastIndex(s, sep); i >= 0 {
		return s[:i], s[i+len(sep):], true
	}
	return s, "", false
}
