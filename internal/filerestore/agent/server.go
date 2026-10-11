// Package agent is the file-restore agent: the code that runs as /init
// INSIDE a restore VM, mounts the backed-up filesystems there and answers the
// host over vsock (docs/design/backup-file-restore.md).
//
// The host never runs this package's readers on guest data: only
// cmd/litevirt's main (to become the agent when booted as one) and the
// test-only filerestoretest package import it.
package agent

import (
	"errors"
	"fmt"
	"io"
	"sort"

	"github.com/litevirt/litevirt/internal/filerestore/wire"
)

// Server answers the host's requests. It is portable — the VM-only parts
// (mounting, vsock, power-off) live in agent_linux.go — so the protocol is
// tested in-process against directories and archives.
type Server struct {
	vols  map[string]Volume
	nonce string
	// touch is called on every request and while an extraction streams;
	// the idle watchdog powers the VM off when it stops being called.
	touch func()
}

// NewServer serves vols. nonce is echoed to OpHello so the host knows it
// reached its own VM.
func NewServer(vols map[string]Volume, nonce string) *Server {
	return &Server{vols: vols, nonce: nonce, touch: func() {}}
}

var errStopWalk = errors.New("stop")

// ServeConn answers requests on one connection until EOF. shutdown reports
// that the host asked the VM to power off.
func (a *Server) ServeConn(rw io.ReadWriter) (shutdown bool, err error) {
	c := wire.NewLineConn(rw)
	for {
		var req wire.Request
		if err := c.Recv(&req); err != nil {
			if errors.Is(err, io.EOF) {
				return false, nil
			}
			return false, err
		}
		a.touch()
		switch req.Op {
		case wire.OpHello:
			if err := c.Send(wire.Response{Nonce: a.nonce}); err != nil {
				return false, err
			}
		case wire.OpShutdown:
			return true, c.Send(wire.Response{})
		case wire.OpVolumes:
			if err := c.Send(wire.Response{Volumes: a.volumes()}); err != nil {
				return false, err
			}
		case wire.OpList:
			if err := c.Send(a.list(req.Path)); err != nil {
				return false, err
			}
		case wire.OpTar:
			if err := a.extract(c, rw, req); err != nil {
				return false, err
			}
		default:
			if err := c.Send(wire.Response{Error: fmt.Sprintf("unknown op %q", req.Op)}); err != nil {
				return false, err
			}
		}
	}
}

func (a *Server) volumes() []wire.Volume {
	out := make([]wire.Volume, 0, len(a.vols))
	for name, v := range a.vols {
		out = append(out, wire.Volume{Name: name, FSType: v.fstype()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (a *Server) lookup(p string) (Volume, string, string, error) {
	clean, err := wire.CleanArchivePath(p)
	if err != nil {
		return nil, "", "", err
	}
	name, rel := wire.SplitVolume(clean)
	v := a.vols[name]
	if v == nil {
		return nil, "", "", fmt.Errorf("no volume %q", name)
	}
	return v, name, rel, nil
}

func (a *Server) list(p string) wire.Response {
	if clean, err := wire.CleanArchivePath(p); err == nil && clean == "/" {
		var out []wire.Entry
		for _, v := range a.volumes() {
			out = append(out, wire.Entry{Name: v.Name, Type: wire.TypeDir, Mode: 0o755})
		}
		return wire.Response{Entries: out}
	}
	v, _, rel, err := a.lookup(p)
	if err != nil {
		return wire.Response{Error: err.Error()}
	}
	entries, truncated, err := v.list(rel, wire.MaxListEntries)
	if err != nil {
		return wire.Response{Error: err.Error()}
	}
	return wire.Response{Entries: entries, Truncated: truncated}
}

// extract answers an OpTar request: an error Response, or an OK Response
// followed by a record stream of every selected path. Record names are
// "<volume>/<path>". Only directories, regular files and symlinks are sent;
// a file that cannot be opened is left out.
func (a *Server) extract(c *wire.LineConn, w io.Writer, req wire.Request) error {
	if len(req.Paths) == 0 || len(req.Paths) > wire.MaxRequestPaths {
		return c.Send(wire.Response{Error: fmt.Sprintf("want 1..%d paths", wire.MaxRequestPaths)})
	}
	type sel struct {
		v        Volume
		vol, rel string
	}
	var sels []sel
	for _, p := range req.Paths {
		v, vol, rel, err := a.lookup(p)
		if err != nil {
			return c.Send(wire.Response{Error: err.Error()})
		}
		// Resolve now, so a bad path is an error Response, not a short stream.
		if err := v.walk(rel, func(string, wire.Entry, func() (io.ReadCloser, error)) error { return errStopWalk }); err != nil && !errors.Is(err, errStopWalk) {
			return c.Send(wire.Response{Error: fmt.Sprintf("%s: %v", p, err)})
		}
		sels = append(sels, sel{v, vol, rel})
	}
	if err := c.Send(wire.Response{}); err != nil {
		return err
	}
	maxBytes, maxEntries := req.MaxBytes, req.MaxEntries
	if maxBytes <= 0 {
		maxBytes = wire.DefaultMaxBytes
	}
	if maxEntries <= 0 {
		maxEntries = wire.DefaultMaxEntries
	}
	var sent int64
	entries := 0
	for _, s := range sels {
		err := s.v.walk(s.rel, func(name string, e wire.Entry, open func() (io.ReadCloser, error)) error {
			if entries >= maxEntries || sent >= maxBytes {
				return errStopWalk
			}
			a.touch()
			full := s.vol
			if name != "" {
				full += "/" + name
			}
			rec := wire.Record{Name: full, Mode: e.Mode & 0o777, MTime: e.MTime}
			var rc io.ReadCloser
			switch e.Type {
			case wire.TypeDir:
				rec.Type = wire.TypeDir
			case wire.TypeSymlink:
				rec.Type, rec.Link = wire.TypeSymlink, e.Target
			case wire.TypeFile:
				if open == nil {
					return nil
				}
				var err error
				if rc, err = open(); err != nil {
					return nil
				}
				rec.Type, rec.Size = wire.TypeFile, e.Size
			default:
				return nil
			}
			if err := wire.WriteRecord(w, rec); err != nil {
				if rc != nil {
					rc.Close()
				}
				if errors.Is(err, wire.ErrRecordTooLong) {
					return nil // an entry whose record cannot be encoded is left out
				}
				return err
			}
			entries++
			if rc != nil {
				defer rc.Close()
				// Exactly Size bytes: a file that shrank since the stat is
				// padded with zeros, one that grew is cut.
				n, _ := io.CopyN(w, rc, e.Size)
				if n < e.Size {
					if _, perr := io.CopyN(w, zeroReader{}, e.Size-n); perr != nil {
						return perr
					}
				}
				sent += e.Size
			}
			return nil
		})
		if err != nil && !errors.Is(err, errStopWalk) {
			return err
		}
	}
	return wire.WriteRecord(w, wire.Record{End: true})
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}
