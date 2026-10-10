package filerestore

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
	"time"
	"unicode/utf8"
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
		if !ValidName(v.Name) || !utf8.ValidString(v.Name) || seen[v.Name] {
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
		if !ValidName(e.Name) || !utf8.ValidString(e.Name) || seen[e.Name] {
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
	MaxBytes   int64 // total file bytes
	MaxEntries int   // entries written
}

// TarStats reports what SanitizeTar wrote and left out.
type TarStats struct {
	Entries   int
	Bytes     int64
	Skipped   int // entries refused (name, type, outside the selection, under a symlink, duplicate)
	Truncated bool
}

// ErrLimit means the extraction hit a TarLimits bound; the archive written
// so far is complete and valid, but not everything selected is in it.
var ErrLimit = errors.New("extraction limit reached")

// maxTarHeaders bounds the headers read (written or skipped), so a stream
// of refused entries cannot spin forever. (A var for tests.)
var maxTarHeaders = 4 * DefaultMaxEntries

// SanitizeTar reads the agent's tar stream from src and writes a fresh
// archive to dst holding only what is safe to hand a caller:
//
//   - names: relative, clean, no "..", every component a valid name, UTF-8,
//     bounded, and inside one of the selected paths (selections are
//     "<volume>/<path>", as the agent names entries);
//   - types: directories, regular files and symlinks only (no hard links,
//     devices, fifos);
//   - no entry under a symlink this archive already holds, and no name
//     twice — so extracting the archive cannot write through a link;
//   - headers rebuilt from scratch: permission bits only (no setuid,
//     setgid or sticky), no owner, no xattrs or PAX records from the guest;
//   - bounded total bytes and entries (ErrLimit; the archive is still
//     closed and valid).
//
// It never resolves, opens or creates a path.
func SanitizeTar(dst io.Writer, src io.Reader, selections []string, lim TarLimits) (TarStats, error) {
	var st TarStats
	if lim.MaxBytes <= 0 {
		lim.MaxBytes = DefaultMaxBytes
	}
	if lim.MaxEntries <= 0 {
		lim.MaxEntries = DefaultMaxEntries
	}
	tr := tar.NewReader(src)
	tw := tar.NewWriter(dst)
	seen := map[string]bool{}
	symlinks := map[string]bool{}
	headers := 0
	var limitErr error
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			_ = tw.Close()
			return st, fmt.Errorf("restore VM sent a malformed archive: %w", err)
		}
		if headers++; headers > maxTarHeaders {
			_ = tw.Close()
			return st, fmt.Errorf("restore VM sent more than %d archive headers", maxTarHeaders)
		}
		name, ok := cleanTarName(h.Name)
		if !ok || !underSelection(name, selections) || seen[name] || underSymlink(name, symlinks) {
			st.Skipped++
			continue
		}
		out := &tar.Header{Name: name, Mode: h.Mode & 0o777, ModTime: clampTime(h.ModTime), Format: tar.FormatPAX}
		switch h.Typeflag {
		case tar.TypeDir:
			out.Typeflag, out.Name = tar.TypeDir, name+"/"
		case tar.TypeReg, tar.TypeRegA:
			if h.Size < 0 {
				st.Skipped++
				continue
			}
			out.Typeflag, out.Size = tar.TypeReg, h.Size
		case tar.TypeSymlink:
			if h.Linkname == "" || len(h.Linkname) > MaxPathLen || !utf8.ValidString(h.Linkname) || strings.ContainsRune(h.Linkname, 0) {
				st.Skipped++
				continue
			}
			out.Typeflag, out.Linkname = tar.TypeSymlink, h.Linkname
		default:
			st.Skipped++
			continue
		}
		if st.Entries >= lim.MaxEntries || st.Bytes+out.Size > lim.MaxBytes {
			st.Truncated = true
			limitErr = ErrLimit
			break
		}
		if err := tw.WriteHeader(out); err != nil {
			return st, err
		}
		seen[name] = true
		if out.Typeflag == tar.TypeSymlink {
			symlinks[name] = true
		}
		if out.Size > 0 {
			n, err := io.CopyN(tw, tr, out.Size)
			st.Bytes += n
			if err != nil {
				return st, fmt.Errorf("restore VM archive ended inside %s: %w", name, err)
			}
		}
		st.Entries++
	}
	if err := tw.Close(); err != nil {
		return st, err
	}
	return st, limitErr
}

// cleanTarName validates an archive entry name: relative, already clean,
// no "..", valid components, UTF-8, bounded. A directory's trailing slash
// is dropped.
func cleanTarName(n string) (string, bool) {
	n = strings.TrimSuffix(n, "/")
	if n == "" || len(n) > MaxPathLen || strings.HasPrefix(n, "/") || !utf8.ValidString(n) {
		return "", false
	}
	if path.Clean(n) != n {
		return "", false
	}
	for _, c := range strings.Split(n, "/") {
		if !ValidName(c) {
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

// underSymlink reports whether any proper ancestor of name is a symlink the
// archive already holds.
func underSymlink(name string, symlinks map[string]bool) bool {
	if len(symlinks) == 0 {
		return false
	}
	for i := 0; i < len(name); i++ {
		if name[i] == '/' && symlinks[name[:i]] {
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

func clampTime(t time.Time) time.Time {
	if t.Before(time.Unix(0, 0)) || t.After(time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)) {
		return time.Unix(0, 0)
	}
	return t
}
