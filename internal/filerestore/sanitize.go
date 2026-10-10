package filerestore

import (
	"archive/tar"
	"bufio"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash/maphash"
	"io"
	"path"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"

	"github.com/litevirt/litevirt/internal/filerestore/wire"
)

// Host-side handling of what the restore VM returns. The agent runs on the
// backed-up data, so whatever it says is untrusted: a compromised guest
// kernel or agent could answer anything. Nothing here follows a path, opens
// a file, or writes to the host's filesystem; it validates and re-encodes.

// SanitizeVolumes keeps the volumes with a valid name, at most MaxVolumes.
func SanitizeVolumes(in []Volume) []Volume {
	var out []Volume
	seen := map[string]bool{}
	for _, v := range in {
		if len(out) >= MaxVolumes {
			break
		}
		if !wire.ValidName(v.Name) || !utf8.ValidString(v.Name) || seen[v.Name] {
			continue
		}
		seen[v.Name] = true
		fsType := v.FSType
		if len(fsType) > 32 || !utf8.ValidString(fsType) {
			fsType = ""
		}
		out = append(out, Volume{Name: v.Name, FSType: fsType})
	}
	return out
}

// SanitizeEntries validates a listing: valid, unique, UTF-8 names (a name
// that is not UTF-8 cannot travel in the RPC and is counted in skipped),
// a known type, non-negative size, permission bits only, a bounded symlink
// target, at most MaxListEntries.
func SanitizeEntries(in []Entry) (out []Entry, skipped int) {
	seen := map[string]bool{}
	for _, e := range in {
		if len(out) >= MaxListEntries {
			skipped += len(in) - MaxListEntries
			break
		}
		if !wire.ValidName(e.Name) || !utf8.ValidString(e.Name) || seen[e.Name] {
			skipped++
			continue
		}
		seen[e.Name] = true
		switch e.Type {
		case TypeFile, TypeDir, TypeSymlink, TypeOther:
		default:
			e.Type = TypeOther
		}
		if e.Size < 0 || e.Type != TypeFile {
			e.Size = 0
		}
		e.Mode &= 0o777
		if e.Type != TypeSymlink || len(e.Target) > MaxPathLen || !utf8.ValidString(e.Target) || strings.ContainsRune(e.Target, 0) {
			e.Target = ""
		}
		out = append(out, e)
	}
	return out, skipped
}

// TarLimits bound one extraction.
type TarLimits struct {
	MaxBytes   int64 // total file bytes written to the archive
	MaxEntries int   // entries written
}

// TarStats reports what SanitizeStream wrote and left out.
type TarStats struct {
	Entries int
	Bytes   int64 // file content bytes in the archive
	Skipped int   // entries refused (name, type, outside the selection, under a symlink, duplicate)
	// LinksDropped counts symlinks left out because their target is
	// absolute or leads outside the archive (also counted in Skipped).
	LinksDropped int
	Truncated    bool
}

// ErrLimit means the extraction hit a bound; the archive written so far is
// complete and valid, but not everything selected is in it.
var ErrLimit = errors.New("extraction limit reached")

// maxRecords bounds the records read (written or refused), so a stream of
// refused entries cannot spin forever. (A var for tests.)
var maxRecords = 4 * DefaultMaxEntries

// maxTracked bounds the names one extraction remembers (to refuse
// duplicates and entries under a symlink). Each costs a fixed 16-byte key,
// so the memory an extraction can make the host hold is bounded no matter
// how long the names are. (A var for tests.)
var maxTracked = DefaultMaxEntries

// MaxDepth bounds the components of an extracted name. Real trees are far
// shallower.
const MaxDepth = 256

// tarHeaderAllowance is what one tar header can cost beyond its name and
// link target (the header block, a PAX block, padding), counted against
// the archive's byte cap.
const tarHeaderAllowance = 3 * 512

// nameKey is the fixed-size key a name is remembered by: a hash of its
// Unicode case-folded, NFC-normalized form, so names that a case-insensitive
// or normalizing filesystem (macOS, Windows) would extract to one path
// collide here too — "ſ" and "s", "ς" and "σ" included.
type nameKey [16]byte

// keyCalls counts keyOf calls (tests bound the per-record work).
var keyCalls int64

func keyOf(name string) nameKey {
	return keyOfFolded(fold(name))
}

// fold is a name's case-folded, NFC-normalized form. A Caser keeps state:
// one per call, never shared between goroutines.
func fold(name string) string {
	return norm.NFC.String(cases.Fold().String(norm.NFC.String(name)))
}

func keyOfFolded(folded string) nameKey {
	atomic.AddInt64(&keyCalls, 1)
	sum := sha256.Sum256([]byte(folded))
	var k nameKey
	copy(k[:], sum[:16])
	return k
}

// linkTrie holds the (folded) paths of the symlinks an archive holds, by
// component, so "is any ancestor of this name a symlink?" is one walk down
// the name — O(its length) whatever the depths of the links.
//
// Its memory is bounded by its node count, not by what the guest sends: one
// flat map from (parent node, hash of component) to a node number, 16 bytes
// of key and 4 of value per node, holding no string of the guest's. Nodes
// (maxTrieNodes) and links (maxLinks) are capped; past either cap the
// extraction stops (ErrLimit). A hash collision can only merge two
// components, which makes a name look under a link that it is not under —
// it is refused, never let through: a real link's path always maps to the
// same nodes.
type linkTrie struct {
	seed  maphash.Seed
	kids  map[trieKey]uint32 // (parent, component) -> node; node 0 is the root
	link  []bool             // by node
	links int
}

type trieKey struct {
	parent uint32
	comp   uint64
}

// maxTrieNodes and maxLinks bound the trie (vars for tests). 64 Ki nodes
// cost about 3 MB and cover any real tree's symlinks.
var (
	maxTrieNodes = 1 << 16
	maxLinks     = 1 << 14
)

func (t *linkTrie) init() {
	if t.kids == nil {
		t.seed = maphash.MakeSeed()
		t.kids = map[trieKey]uint32{}
		t.link = []bool{false}
	}
}

func (t *linkTrie) key(parent uint32, comp string) trieKey {
	return trieKey{parent: parent, comp: maphash.String(t.seed, comp)}
}

// add records a symlink at folded; false, recording nothing, when that would
// pass a cap.
func (t *linkTrie) add(folded string) bool {
	t.init()
	if t.links >= maxLinks {
		return false
	}
	comps := strings.Split(folded, "/")
	// Walk what exists; the rest are new nodes. Past a cap, nothing is
	// recorded.
	n, i := uint32(0), 0
	for ; i < len(comps); i++ {
		next, ok := t.kids[t.key(n, comps[i])]
		if !ok {
			break
		}
		n = next
	}
	if len(t.link)-1+len(comps)-i > maxTrieNodes {
		return false
	}
	for ; i < len(comps); i++ {
		next := uint32(len(t.link))
		t.kids[t.key(n, comps[i])] = next
		t.link = append(t.link, false)
		n = next
	}
	if !t.link[n] {
		t.link[n] = true
		t.links++
	}
	return true
}

// underLink reports whether a proper ancestor of folded is a symlink.
func (t *linkTrie) underLink(folded string) bool {
	if t.kids == nil {
		return false
	}
	comps := strings.Split(folded, "/")
	n := uint32(0)
	for _, c := range comps[:len(comps)-1] {
		next, ok := t.kids[t.key(n, c)]
		if !ok {
			return false
		}
		if t.link[next] {
			return true
		}
		n = next
	}
	return false
}

// SanitizeStream reads the agent's record stream from src (wire.Record
// lines and file bytes) and writes a fresh tar archive to dst holding only
// what is safe to hand a caller:
//
//   - names: relative, clean, no "..", at most MaxDepth components, every
//     component a valid name, UTF-8 with no control or bidi characters,
//     bounded, and inside one of the selected paths (selections are
//     "<volume>/<path>", as the agent names entries);
//   - types: directories, regular files and symlinks only;
//   - a symlink only with a relative target that stays inside the archive
//     (resolved against the link's own directory); an absolute or escaping
//     one is left out and counted in LinksDropped;
//   - no entry under a symlink this archive already holds, and no name twice
//     — compared Unicode case-folded and NFC-normalized, so extracting the
//     archive on a case-insensitive filesystem cannot write through a link
//     either;
//   - headers built from scratch: permission bits only (no setuid, setgid or
//     sticky), no owner, no xattrs;
//   - bounded: the whole archive's bytes, headers included (ErrLimit, the
//     archive still closed and valid), entries, records read, names
//     remembered, and each record line. A size is compared without
//     overflow, and the bytes counted are the bytes written.
//
// The stream is not tar: no PAX records, sparse maps or long-name
// extensions reach a parser here. It never resolves, opens or creates a
// path.
func SanitizeStream(dst io.Writer, src *bufio.Reader, selections []string, lim TarLimits) (TarStats, error) {
	var st TarStats
	if lim.MaxBytes <= 0 {
		lim.MaxBytes = DefaultMaxBytes
	}
	if lim.MaxEntries <= 0 {
		lim.MaxEntries = DefaultMaxEntries
	}
	cw := &countingWriter{w: dst}
	tw := tar.NewWriter(cw)
	seen := map[nameKey]struct{}{}
	var links linkTrie
	records := 0
	var discarded int64 // bytes of refused entries read and dropped
	var limitErr error
	for {
		rec, err := wire.ReadRecord(src)
		if err != nil {
			_ = tw.Close()
			return st, fmt.Errorf("restore VM stream: %w", err)
		}
		if rec.End {
			break
		}
		if records++; records > maxRecords {
			_ = tw.Close()
			return st, fmt.Errorf("restore VM sent more than %d records", maxRecords)
		}
		size := int64(0)
		if rec.Type == TypeFile {
			size = rec.Size
		}
		if size < 0 {
			_ = tw.Close()
			return st, fmt.Errorf("restore VM sent a negative size for %q", wire.Escape(rec.Name))
		}
		name, ok := cleanTarName(rec.Name)
		refuse := !ok || !underSelection(name, selections)
		var key nameKey
		var folded string
		if !refuse {
			folded = fold(name) // once per record
			key = keyOfFolded(folded)
			_, dup := seen[key]
			refuse = dup || links.underLink(folded)
		}
		if !refuse {
			switch rec.Type {
			case TypeDir, TypeFile:
			case TypeSymlink:
				if !linkTargetOK(name, rec.Link) {
					refuse = true
					st.LinksDropped++
				}
			default:
				refuse = true
			}
		}
		if refuse {
			st.Skipped++
			// Refused bytes are bounded by the same cap as written ones.
			if size > lim.MaxBytes-discarded {
				_ = tw.Close()
				return st, fmt.Errorf("restore VM sent more refused data than the %d-byte extraction limit", lim.MaxBytes)
			}
			discarded += size
			if err := discard(src, size); err != nil {
				_ = tw.Close()
				return st, err
			}
			continue
		}
		// Overflow-safe, and over the whole archive: this entry's header
		// (name, link, blocks) and data against what is left of the cap.
		cost := int64(len(name)+len(rec.Link)) + tarHeaderAllowance
		if st.Entries >= lim.MaxEntries || size > lim.MaxBytes-cw.n || cost > lim.MaxBytes-cw.n-size {
			st.Truncated = true
			limitErr = ErrLimit
			break
		}
		if len(seen) >= maxTracked {
			st.Truncated = true
			limitErr = fmt.Errorf("%w: more than %d entries to track", ErrLimit, maxTracked)
			break
		}
		// A link is tracked before its header is written: past the trie's
		// caps the extraction stops, and the archive holds no link it does
		// not know of.
		if rec.Type == TypeSymlink && !links.add(folded) {
			st.Truncated = true
			limitErr = fmt.Errorf("%w: more symlinks than one extraction tracks (%d links, %d path components)", ErrLimit, maxLinks, maxTrieNodes)
			break
		}
		h := &tar.Header{Name: name, Mode: int64(rec.Mode & 0o777), ModTime: clampTime(rec.MTime), Format: tar.FormatPAX}
		switch rec.Type {
		case TypeDir:
			h.Typeflag, h.Name = tar.TypeDir, name+"/"
		case TypeFile:
			h.Typeflag, h.Size = tar.TypeReg, size
		case TypeSymlink:
			h.Typeflag, h.Linkname = tar.TypeSymlink, rec.Link
		}
		if err := tw.WriteHeader(h); err != nil {
			return st, err
		}
		seen[key] = struct{}{}
		if size > 0 {
			before := cw.n
			_, err := io.CopyN(tw, src, size)
			// What was written, not what was claimed.
			st.Bytes += cw.n - before
			if err != nil {
				return st, fmt.Errorf("restore VM stream ended inside %s: %w", wire.Escape(name), err)
			}
		}
		st.Entries++
	}
	if err := tw.Close(); err != nil {
		return st, err
	}
	return st, limitErr
}

// linkTargetOK reports whether a symlink at name may point at target: a
// relative target whose ".." components, if any, all come first, and which,
// resolved against the link's directory, stays inside the archive.
//
// The leading-".." rule is what makes the lexical check true physically: a
// kernel resolves a symlink component BEFORE a ".." that follows it, so
// "up/../../.." through a link "up" that points upward climbs further than
// its spelling suggests. With ".." only at the front, the climb happens from
// the link's own directory — which is never under a symlink (no entry is) —
// and every link the rest of the path passes through obeys the same rule, so
// by induction no chain of links leaves the archive.
func linkTargetOK(name, target string) bool {
	if target == "" || len(target) > MaxPathLen || !utf8.ValidString(target) || strings.ContainsRune(target, 0) ||
		strings.HasPrefix(target, "/") || wire.HasUnsafe(target) {
		return false
	}
	leading := true
	for _, c := range strings.Split(target, "/") {
		switch {
		case c == "..":
			if !leading {
				return false
			}
		case c == "" || c == ".":
			return false // not a clean relative path
		default:
			leading = false
		}
	}
	resolved := path.Clean(path.Join(path.Dir(name), target))
	return resolved != ".." && !strings.HasPrefix(resolved, "../") && resolved != "."
}

// countingWriter counts the bytes written through it.
type countingWriter struct {
	w io.Writer
	n int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

// discard skips a refused file's bytes.
func discard(r io.Reader, n int64) error {
	if n <= 0 {
		return nil
	}
	if _, err := io.CopyN(io.Discard, r, n); err != nil {
		return fmt.Errorf("restore VM stream ended inside a refused entry: %w", err)
	}
	return nil
}

// cleanTarName validates an entry name: relative, already clean, no "..",
// valid components, UTF-8, bounded.
func cleanTarName(n string) (string, bool) {
	n = strings.TrimSuffix(n, "/")
	if n == "" || len(n) > MaxPathLen || strings.HasPrefix(n, "/") || !utf8.ValidString(n) {
		return "", false
	}
	if path.Clean(n) != n {
		return "", false
	}
	if strings.Count(n, "/") >= MaxDepth || wire.HasUnsafe(n) {
		return "", false // too deep, or a control, bidi or invisible character
	}
	for _, c := range strings.Split(n, "/") {
		if !wire.ValidName(c) {
			return "", false
		}
	}
	return n, true
}

// underSelection reports whether name is a selection or below one.
func underSelection(name string, selections []string) bool {
	for _, s := range selections {
		if name == s || strings.HasPrefix(name, s+"/") {
			return true
		}
	}
	return false
}

// SelectionNames maps request paths ("/<volume>/<path>") to the names the
// agent writes ("<volume>/<path>"), cleaning and validating each.
func SelectionNames(paths []string) ([]string, error) {
	if len(paths) == 0 || len(paths) > MaxRequestPaths {
		return nil, fmt.Errorf("select 1..%d paths", MaxRequestPaths)
	}
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		clean, err := CleanArchivePath(p)
		if err != nil {
			return nil, err
		}
		if clean == "/" {
			return nil, fmt.Errorf("%w: select a volume or a path in one (/<volume>/...), not /", ErrBadPath)
		}
		out = append(out, strings.TrimPrefix(clean, "/"))
	}
	return out, nil
}

func clampTime(unix int64) time.Time {
	if unix < 0 || unix > 253402300799 { // 9999-12-31
		return time.Unix(0, 0)
	}
	return time.Unix(unix, 0)
}
