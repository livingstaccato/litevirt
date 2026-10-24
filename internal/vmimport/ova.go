package vmimport

import (
	"archive/tar"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Archive resource caps (DoS guards). An OVA is an uncompressed tar whose disk
// members are legitimately large, so the ceilings are generous — they exist to
// stop a pathological archive (millions of members, absurd sizes) from filling
// the import staging dir before any quota check runs.
const (
	maxArchiveMembers   = 4096
	maxArchiveTotalSize = 8 << 40 // 8 TiB across all members
	maxMemberSize       = 4 << 40 // 4 TiB single member
)

// safeJoin cleans a tar member name and joins it under dest, rejecting absolute
// paths and "../" traversal (tar-slip). Returns the absolute destination path.
func safeJoin(dest, name string) (string, error) {
	clean := filepath.Clean("/" + strings.ReplaceAll(name, "\\", "/")) // force-relative
	clean = strings.TrimPrefix(clean, "/")
	if clean == "" || clean == "." {
		return "", fmt.Errorf("empty archive member name")
	}
	target := filepath.Join(dest, clean)
	// Ensure the result is still under dest (defends against any residual escape).
	rel, err := filepath.Rel(dest, target)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("archive member %q escapes destination", name)
	}
	return target, nil
}

// Reserve admits an extraction that will have written total bytes once the
// member or device it is about to write is done. Each call names the running
// total, so a refusal stops the extraction before that write.
type Reserve func(total uint64) error

// Budget is a Reserve that admits up to b bytes in all.
func Budget(b uint64) Reserve {
	return func(total uint64) error {
		if total > b {
			return fmt.Errorf("extraction needs %d bytes, more than the %d it may write on this host", total, b)
		}
		return nil
	}
}

// ovaMembers judges an archive's regular members by the name UnpackOVA
// writes each under: the base name of its cleaned path. Every identity check
// (is it a descriptor, has the name been seen) uses that name, never the raw
// one, so "a.ovf/." is the descriptor a.ovf it would overwrite.
type ovaMembers struct {
	count    int
	declared int64             // the sizes their headers declare, in all
	seen     map[string]string // case-folded flattened name -> raw name
	ovf      string            // raw name of the descriptor, once seen
}

// admit counts hdr and returns its flattened name and whether it is a
// descriptor. It refuses the member cap, the member and archive size caps
// (on the sizes headers declare, so a refusal needs no body read), a name
// that cleans to nothing or escapes, a second descriptor, and a name an
// earlier member already holds (case-insensitively, as some filesystems
// hold them).
func (m *ovaMembers) admit(hdr *tar.Header) (flat string, isOVF bool, err error) {
	m.count++
	if m.count > maxArchiveMembers {
		return "", false, fmt.Errorf("ova exceeds member cap (%d)", maxArchiveMembers)
	}
	if hdr.Size > maxMemberSize {
		return "", false, fmt.Errorf("ova member %q exceeds size cap", hdr.Name)
	}
	target, err := safeJoin("/", hdr.Name)
	if err != nil {
		return "", false, err
	}
	flat = filepath.Base(target)
	isOVF = strings.EqualFold(filepath.Ext(flat), ".ovf")
	if isOVF && m.ovf != "" {
		return "", false, errSecondDescriptor(m.ovf, hdr.Name)
	}
	key := strings.ToLower(flat)
	if prev, ok := m.seen[key]; ok {
		return "", false, fmt.Errorf("ova member %q repeats the name of %q (both extract to %q)", hdr.Name, prev, flat)
	}
	if m.seen == nil {
		m.seen = map[string]string{}
	}
	if hdr.Size > maxArchiveTotalSize-m.declared {
		return "", false, fmt.Errorf("ova exceeds total size cap")
	}
	m.declared += hdr.Size
	m.seen[key] = hdr.Name
	if isOVF {
		m.ovf = hdr.Name
	}
	return flat, isOVF, nil
}

// UnpackOVA extracts an OVA tar stream into dest (slip-safe, capped) and returns
// the path to the single .ovf descriptor. An archive with a second .ovf member
// is refused before that member is written: a preview (InspectOVA) describes
// the first, so importing any other would import a VM nobody previewed. A
// member whose flattened name repeats an earlier member's is refused too,
// rather than written over it.
// Symlink/hardlink/device members are rejected. Disk members and the descriptor land flat under dest. Each
// member's size is reserved before it is written, below the fixed archive
// cap: dest usually shares a filesystem with the daemon's database, and the
// member is cut off at the size it reserved.
func UnpackOVA(r io.Reader, dest string, reserve Reserve) (ovfPath string, err error) {
	tr := tar.NewReader(r)
	var (
		members ovaMembers
		total   int64
	)
	for {
		hdr, e := tr.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			return "", fmt.Errorf("read ova tar: %w", e)
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			continue // flat layout; directories are not needed
		case tar.TypeReg, tar.TypeRegA:
			// extract below
		default:
			return "", fmt.Errorf("ova member %q has disallowed type %d (symlink/hardlink/device not permitted)", hdr.Name, hdr.Typeflag)
		}
		flat, isOVF, e := members.admit(hdr)
		if e != nil {
			return "", e
		}
		// Flatten: keep only the base name so split-VMDK extents + descriptor sit
		// beside each other (OVF hrefs are relative basenames).
		target := filepath.Join(dest, flat)
		reserved := members.declared
		if e := reserve(uint64(reserved)); e != nil {
			return "", fmt.Errorf("ova member %q: %w", hdr.Name, e)
		}
		n, e := writeCapped(target, tr, &total, reserved)
		if e != nil {
			return "", e
		}
		_ = n
		if isOVF {
			ovfPath = target
		}
	}
	if ovfPath == "" {
		return "", fmt.Errorf("no .ovf descriptor found in OVA")
	}
	return ovfPath, nil
}

// writeCapped copies src to a new file at path, enforcing the cumulative total cap.
func writeCapped(path string, src io.Reader, total *int64, limit int64) (int64, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return 0, fmt.Errorf("create %s: %w", path, err)
	}
	defer f.Close()
	lr := &cappedReader{r: src, total: total, limit: limit}
	n, err := io.Copy(f, lr)
	if err != nil {
		return n, err
	}
	if err := f.Sync(); err != nil {
		return n, fmt.Errorf("sync %s: %w", path, err)
	}
	return n, nil
}

// cappedReader fails once the cumulative bytes read across the archive exceed
// limit.
type cappedReader struct {
	r     io.Reader
	total *int64
	limit int64
}

func (c *cappedReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	*c.total += int64(n)
	if *c.total > c.limit {
		return n, fmt.Errorf("archive exceeds the %d bytes it may extract on this host", c.limit)
	}
	return n, err
}

// errSecondDescriptor is the refusal of an archive with two .ovf members.
func errSecondDescriptor(first, second string) error {
	return fmt.Errorf("ova has more than one .ovf descriptor (%q and %q); refusing an archive whose VM is ambiguous", first, second)
}

// maxInspectTrailer bounds how much InspectOVA skips after the descriptor
// looking for a second one: room for a manifest and certificate, never a disk.
const maxInspectTrailer = 1 << 20

// InspectOVA reads the tar only until the .ovf member and returns its bytes,
// for lv import --inspect: the disk members are neither extracted nor, when
// the descriptor comes first (as the OVF specification has it), read at all.
// It refuses what UnpackOVA would refuse among the members it reads (their
// types, names and declared sizes), so a preview does not describe an
// archive the import would reject at its head. It does not reserve room:
// whether the host can hold the extraction is the import's question.
//
// After the descriptor it reads on only through small members (a manifest,
// a certificate: maxInspectTrailer bytes in all) and refuses a second .ovf
// among them. Every member is judged by the name the import writes it
// under (ovaMembers). A second descriptor behind a disk is out of its sight; the
// import (UnpackOVA) refuses that archive.
func InspectOVA(r io.Reader) ([]byte, error) {
	tr := tar.NewReader(r)
	var members ovaMembers
	for {
		hdr, e := tr.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			return nil, fmt.Errorf("read ova tar: %w", e)
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			continue
		case tar.TypeReg, tar.TypeRegA:
		default:
			return nil, fmt.Errorf("ova member %q has disallowed type %d (symlink/hardlink/device not permitted)", hdr.Name, hdr.Typeflag)
		}
		_, isOVF, e := members.admit(hdr)
		if e != nil {
			return nil, e
		}
		if isOVF {
			if hdr.Size > maxDescriptorSize {
				return nil, fmt.Errorf("ovf descriptor implausibly large (%d bytes)", hdr.Size)
			}
			data, e := io.ReadAll(io.LimitReader(tr, maxDescriptorSize))
			if e != nil {
				return nil, fmt.Errorf("read ovf descriptor: %w", e)
			}
			if e := inspectTrailer(tr, &members); e != nil {
				return nil, e
			}
			return data, nil
		}
	}
	return nil, fmt.Errorf("no .ovf descriptor found in OVA")
}

// inspectTrailer reads the members after the descriptor first while each
// fits what is left of maxInspectTrailer, refusing a second .ovf or what
// UnpackOVA refuses. It stops, without reading the member's body, at the
// first member too large to skip (a disk) or at the end of the archive.
func inspectTrailer(tr *tar.Reader, members *ovaMembers) error {
	left := int64(maxInspectTrailer)
	for {
		hdr, e := tr.Next()
		if e == io.EOF {
			return nil
		}
		if e != nil {
			return fmt.Errorf("read ova tar: %w", e)
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			continue
		case tar.TypeReg, tar.TypeRegA:
		default:
			return fmt.Errorf("ova member %q has disallowed type %d (symlink/hardlink/device not permitted)", hdr.Name, hdr.Typeflag)
		}
		if _, _, e := members.admit(hdr); e != nil {
			return e
		}
		if hdr.Size > left {
			return nil
		}
		left -= hdr.Size
	}
}

// maxDescriptorSize bounds the .ovf InspectOVA reads into memory.
const maxDescriptorSize = 64 << 20
