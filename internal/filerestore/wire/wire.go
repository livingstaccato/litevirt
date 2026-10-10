// Package wire is the protocol between the host and the file-restore agent
// in a restore VM (docs/design/backup-file-restore.md): request and response
// lines, and the record stream an extraction is sent as.
//
// It is shared by the host side (internal/filerestore) and the agent
// (internal/filerestore/agent), and holds no logic that reads guest data.
package wire

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

// Kernel command-line parameters the restore VM is booted with. The kernel
// passes name=value parameters it does not know to init as environment
// variables (names without dots, which would make them module parameters).
const (
	EnvAgent = "litevirt_filerestore" // "1": run as the restore agent
	EnvKind  = "litevirt_fr_kind"     // KindFS or KindArchive
	EnvIdle  = "litevirt_fr_idle"     // seconds without a request before the agent powers off
)

// FwCfgNonce is the fw_cfg item the session's nonce is handed to the guest
// in; the agent echoes it to OpHello.
const FwCfgNonce = "opt/litevirt/nonce"

// What the restore VM's disk holds.
const (
	// KindFS is a disk image: mount its filesystems (partitions, or the
	// whole disk).
	KindFS = "fs"
	// KindArchive is a container backup: a tar archive of the container's
	// directory.
	KindArchive = "archive"
)

// Requests. The host writes one JSON Request per line; the agent answers each
// with one JSON Response line. A successful OpTar response is followed by a
// record stream (WriteRecord ... WriteEnd).
const (
	OpHello    = "hello"
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
	// MaxBytes / MaxEntries bound an extraction the agent sends (the host
	// enforces its own bounds regardless).
	MaxBytes   int64 `json:"max_bytes,omitempty"`
	MaxEntries int   `json:"max_entries,omitempty"`
}

// Response is the agent's reply line.
type Response struct {
	Error     string   `json:"error,omitempty"`
	Nonce     string   `json:"nonce,omitempty"`
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

// Limits on what the host accepts from the restore VM.
const (
	MaxNameLen        = 255
	MaxPathLen        = 4096
	MaxListEntries    = 10000
	MaxVolumes        = 64
	MaxRequestPaths   = 256
	MaxResponseLine   = 8 << 20
	MaxRecordLine     = 16 << 10
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

// LineConn frames JSON lines over a stream.
type LineConn struct {
	R *bufio.Reader
	w io.Writer
}

// NewLineConn wraps rw.
func NewLineConn(rw io.ReadWriter) *LineConn {
	return &LineConn{R: bufio.NewReaderSize(rw, 64<<10), w: rw}
}

// Send writes v as one JSON line.
func (c *LineConn) Send(v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	_, err = c.w.Write(b)
	return err
}

// Recv reads one JSON line into v, refusing a line over MaxResponseLine.
func (c *LineConn) Recv(v any) error {
	line, err := ReadLine(c.R, MaxResponseLine)
	if err != nil {
		return err
	}
	return json.Unmarshal(line, v)
}

// ErrLineTooLong is a protocol line over its bound.
var ErrLineTooLong = errors.New("protocol line too long")

// ReadLine reads one '\n'-terminated line of at most max bytes. It never
// buffers more than max (+ the reader's buffer) bytes.
func ReadLine(r *bufio.Reader, max int) ([]byte, error) {
	var line []byte
	for {
		frag, err := r.ReadSlice('\n')
		if len(line)+len(frag) > max {
			return nil, fmt.Errorf("%w (over %d bytes)", ErrLineTooLong, max)
		}
		line = append(line, frag...)
		if err == nil {
			return line, nil
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if errors.Is(err, io.EOF) && len(line) > 0 {
			return nil, io.ErrUnexpectedEOF
		}
		return nil, err
	}
}

// Record is one entry of an extraction stream: a JSON line, then exactly
// Size bytes of a regular file's content. The stream ends with a record
// whose End is set.
//
// The host does not read tar from the agent: tar's extensions (PAX records,
// GNU sparse maps, long names) are parsing surface a hostile agent could
// use. A record is one bounded line and a byte count; the host writes the
// tar itself.
type Record struct {
	Name  string `json:"n,omitempty"`
	Type  string `json:"t,omitempty"`
	Size  int64  `json:"s,omitempty"`
	Mode  uint32 `json:"m,omitempty"`
	MTime int64  `json:"mt,omitempty"`
	Link  string `json:"l,omitempty"`
	End   bool   `json:"end,omitempty"`
}

// ErrRecordTooLong is a record whose line would exceed MaxRecordLine.
var ErrRecordTooLong = errors.New("record too long")

// WriteRecord writes a record's line. A regular file's Size bytes follow,
// written by the caller.
func WriteRecord(w io.Writer, r Record) error {
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if len(b)+1 > MaxRecordLine {
		return ErrRecordTooLong
	}
	_, err = w.Write(append(b, '\n'))
	return err
}

// ReadRecord reads one record line (not its data).
func ReadRecord(r *bufio.Reader) (Record, error) {
	line, err := ReadLine(r, MaxRecordLine)
	if err != nil {
		return Record{}, err
	}
	var rec Record
	if err := json.Unmarshal(line, &rec); err != nil {
		return Record{}, fmt.Errorf("malformed record: %w", err)
	}
	return rec, nil
}
