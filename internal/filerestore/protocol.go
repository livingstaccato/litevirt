// Package filerestore reads individual files out of a backup without
// restoring the whole disk, and without the host ever mounting or parsing
// the backed-up filesystem.
//
// The filesystem is read inside a throwaway restore VM (docs/design/
// backup-file-restore.md): the host's own kernel, booted with an initramfs
// whose /init is this very litevirt binary running as the restore agent. The
// backup is attached read-only as the VM's only disk (served from the repo
// by the in-process NBD server), the VM has no NIC, and its one channel to
// the host is vsock. The agent mounts the guest filesystems read-only inside
// the VM — the guest kernel parses them, never the host's — and answers
// list and tar requests over vsock.
//
// Everything that comes back is untrusted: the host validates every listing
// entry and re-encodes the tar stream entry by entry (sanitize.go), with
// bounded names, sizes and counts, and streams it to the caller. Nothing is
// ever written to a host path the guest's data chose.
package filerestore

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
)

// AgentPort is the vsock port the agent listens on inside the restore VM.
const AgentPort = 5000

// Kernel command-line parameters the host boots the restore VM with. The
// kernel passes name=value parameters it does not know to init as
// environment variables (names without dots, which would make them module
// parameters).
const (
	envAgent = "litevirt_filerestore" // "1": run as the restore agent
	envKind  = "litevirt_fr_kind"     // KindFS or KindArchive
)

// What the restore VM's disk holds.
const (
	// KindFS is a disk image: mount its filesystems (partitions, or the
	// whole disk).
	KindFS = "fs"
	// KindArchive is a container backup: a tar archive of the container's
	// directory.
	KindArchive = "archive"
)

// Wire protocol. The host writes one JSON Request per line; the agent
// answers each with one JSON Response line, and for "tar" a raw tar stream
// follows a successful Response until EOF of that archive (the tar
// end-of-archive marker). One request at a time per connection.
const (
	OpVolumes  = "volumes"
	OpList     = "list"
	OpTar      = "tar"
	OpShutdown = "shutdown"
)

// Request is one host → agent request. Path / Paths are archive paths:
// "/<volume>/<path inside it>" ("/" lists the volumes).
type Request struct {
	Op    string   `json:"op"`
	Path  string   `json:"path,omitempty"`
	Paths []string `json:"paths,omitempty"`
	// MaxBytes / MaxEntries bound a tar the agent sends (the host enforces
	// its own bounds regardless).
	MaxBytes   int64 `json:"max_bytes,omitempty"`
	MaxEntries int   `json:"max_entries,omitempty"`
}

// Response is the agent's reply line.
type Response struct {
	Error     string   `json:"error,omitempty"`
	Entries   []Entry  `json:"entries,omitempty"`
	Volumes   []Volume `json:"volumes,omitempty"`
	Truncated bool     `json:"truncated,omitempty"`
}

// Entry types.
const (
	TypeFile    = "file"
	TypeDir     = "dir"
	TypeSymlink = "symlink"
	TypeOther   = "other" // device, fifo, socket: listed, never extracted
)

// Entry is one directory entry.
type Entry struct {
	Name   string `json:"name"`
	Type   string `json:"type"`
	Size   int64  `json:"size"`
	Mode   uint32 `json:"mode"` // permission bits only
	MTime  int64  `json:"mtime"`
	Target string `json:"target,omitempty"` // symlink target, shown, never followed
}

// Volume is one filesystem the agent mounted (a partition, the whole disk,
// or a container archive).
type Volume struct {
	Name   string `json:"name"`
	FSType string `json:"fstype"`
}

// Limits on what the host accepts from the restore VM. They bound memory
// and output regardless of what the agent claims.
const (
	MaxNameLen        = 255
	MaxPathLen        = 4096
	MaxListEntries    = 10000
	MaxVolumes        = 64
	MaxRequestPaths   = 256
	maxResponseLine   = 8 << 20
	DefaultMaxEntries = 200000
	DefaultMaxBytes   = int64(16) << 30
)

// ErrBadPath is returned for a request path that is not a clean archive path.
var ErrBadPath = errors.New("invalid path")

// CleanArchivePath validates and normalizes a caller-supplied archive path:
// absolute, no "..", no NUL, bounded. "/" is the volume list.
func CleanArchivePath(p string) (string, error) {
	if p == "" {
		p = "/"
	}
	if !strings.HasPrefix(p, "/") || strings.ContainsRune(p, 0) || len(p) > MaxPathLen {
		return "", fmt.Errorf("%w %q: want an absolute path like /<volume>/etc/hosts", ErrBadPath, p)
	}
	for _, c := range strings.Split(p, "/") {
		if c == ".." {
			return "", fmt.Errorf("%w %q: '..' is not allowed", ErrBadPath, p)
		}
	}
	return path.Clean(p), nil
}

// SplitVolume splits a clean archive path into its volume and the path
// inside it ("" for the volume root).
func SplitVolume(p string) (vol, rel string) {
	p = strings.TrimPrefix(p, "/")
	if i := strings.IndexByte(p, '/'); i >= 0 {
		return p[:i], p[i+1:]
	}
	return p, ""
}

// ValidName reports whether s is acceptable as one path component.
func ValidName(s string) bool {
	if s == "" || s == "." || s == ".." || len(s) > MaxNameLen {
		return false
	}
	return !strings.ContainsAny(s, "/\x00")
}

// lineConn frames JSON lines over a stream.
type lineConn struct {
	r *bufio.Reader
	w io.Writer
}

func newLineConn(rw io.ReadWriter) *lineConn {
	return &lineConn{r: bufio.NewReaderSize(rw, 64<<10), w: rw}
}

func (c *lineConn) send(v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	_, err = c.w.Write(b)
	return err
}

// recv reads one JSON line into v, refusing a line over maxResponseLine.
func (c *lineConn) recv(v any) error {
	var line []byte
	for {
		frag, err := c.r.ReadSlice('\n')
		line = append(line, frag...)
		if len(line) > maxResponseLine {
			return fmt.Errorf("protocol line exceeds %d bytes", maxResponseLine)
		}
		if err == nil {
			break
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		return err
	}
	return json.Unmarshal(line, v)
}
