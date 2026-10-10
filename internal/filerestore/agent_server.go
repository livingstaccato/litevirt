package filerestore

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"sort"
	"time"
)

// agentServer answers the host's requests inside the restore VM. It is
// portable — the VM-only parts (mounting, vsock) live in agent_linux.go — so
// the protocol is tested in-process against directories and archives.
type agentServer struct {
	vols map[string]volume
}

var errStopWalk = errors.New("stop")

// serveConn answers requests on one connection until EOF. shutdown reports
// that the host asked the VM to power off.
func (a *agentServer) serveConn(rw io.ReadWriter) (shutdown bool, err error) {
	c := newLineConn(rw)
	for {
		var req Request
		if err := c.recv(&req); err != nil {
			if errors.Is(err, io.EOF) {
				return false, nil
			}
			return false, err
		}
		switch req.Op {
		case OpShutdown:
			return true, c.send(Response{})
		case OpVolumes:
			if err := c.send(Response{Volumes: a.volumes()}); err != nil {
				return false, err
			}
		case OpList:
			if err := c.send(a.list(req.Path)); err != nil {
				return false, err
			}
		case OpTar:
			if err := a.tar(c, rw, req); err != nil {
				return false, err
			}
		default:
			if err := c.send(Response{Error: fmt.Sprintf("unknown op %q", req.Op)}); err != nil {
				return false, err
			}
		}
	}
}

func (a *agentServer) volumes() []Volume {
	out := make([]Volume, 0, len(a.vols))
	for name, v := range a.vols {
		out = append(out, Volume{Name: name, FSType: v.fstype()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (a *agentServer) lookup(p string) (volume, string, string, error) {
	clean, err := CleanArchivePath(p)
	if err != nil {
		return nil, "", "", err
	}
	name, rel := SplitVolume(clean)
	v := a.vols[name]
	if v == nil {
		return nil, "", "", fmt.Errorf("no volume %q", name)
	}
	return v, name, rel, nil
}

func (a *agentServer) list(p string) Response {
	if clean, err := CleanArchivePath(p); err == nil && clean == "/" {
		var out []Entry
		for _, v := range a.volumes() {
			out = append(out, Entry{Name: v.Name, Type: TypeDir, Mode: 0o755})
		}
		return Response{Entries: out}
	}
	v, _, rel, err := a.lookup(p)
	if err != nil {
		return Response{Error: err.Error()}
	}
	entries, truncated, err := v.list(rel, MaxListEntries)
	if err != nil {
		return Response{Error: err.Error()}
	}
	return Response{Entries: entries, Truncated: truncated}
}

// tar answers a tar request: an error Response, or an OK Response followed
// by one tar archive of every selected path. Archive names are
// "<volume>/<path>", directories end in "/". Only directories, regular files
// and symlinks are written; a file that cannot be opened is left out.
func (a *agentServer) tar(c *lineConn, w io.Writer, req Request) error {
	if len(req.Paths) == 0 || len(req.Paths) > MaxRequestPaths {
		return c.send(Response{Error: fmt.Sprintf("want 1..%d paths", MaxRequestPaths)})
	}
	type sel struct {
		v        volume
		vol, rel string
	}
	var sels []sel
	for _, p := range req.Paths {
		v, vol, rel, err := a.lookup(p)
		if err != nil {
			return c.send(Response{Error: err.Error()})
		}
		// Resolve now, so a bad path is an error Response, not a short archive.
		if err := v.walk(rel, func(string, Entry, func() (io.ReadCloser, error)) error { return errStopWalk }); err != nil && !errors.Is(err, errStopWalk) {
			return c.send(Response{Error: fmt.Sprintf("%s: %v", p, err)})
		}
		sels = append(sels, sel{v, vol, rel})
	}
	if err := c.send(Response{}); err != nil {
		return err
	}
	maxBytes, maxEntries := req.MaxBytes, req.MaxEntries
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBytes
	}
	if maxEntries <= 0 {
		maxEntries = DefaultMaxEntries
	}
	tw := tar.NewWriter(w)
	var sent int64
	entries := 0
	for _, s := range sels {
		err := s.v.walk(s.rel, func(name string, e Entry, open func() (io.ReadCloser, error)) error {
			if entries >= maxEntries || sent >= maxBytes {
				return errStopWalk
			}
			full := s.vol
			if name != "" {
				full += "/" + name
			}
			h := &tar.Header{Name: full, Mode: int64(e.Mode & 0o777), ModTime: time.Unix(e.MTime, 0), Format: tar.FormatPAX}
			var rc io.ReadCloser
			switch e.Type {
			case TypeDir:
				h.Typeflag, h.Name = tar.TypeDir, full+"/"
			case TypeSymlink:
				h.Typeflag, h.Linkname = tar.TypeSymlink, e.Target
			case TypeFile:
				if open == nil {
					return nil
				}
				var err error
				if rc, err = open(); err != nil {
					return nil
				}
				h.Typeflag, h.Size = tar.TypeReg, e.Size
			default:
				return nil
			}
			if err := tw.WriteHeader(h); err != nil {
				if rc != nil {
					rc.Close()
				}
				return err
			}
			entries++
			if rc != nil {
				defer rc.Close()
				// Exactly Size bytes: a file that shrank since the stat is
				// padded with zeros, one that grew is cut.
				n, err := io.CopyN(tw, rc, e.Size)
				if n < e.Size {
					if _, perr := io.CopyN(tw, zeroReader{}, e.Size-n); perr != nil {
						return perr
					}
					_ = err
				}
				sent += e.Size
			}
			return nil
		})
		if err != nil && !errors.Is(err, errStopWalk) {
			return err
		}
	}
	return tw.Close()
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}
