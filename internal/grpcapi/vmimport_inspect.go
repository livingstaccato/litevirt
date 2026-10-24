package grpcapi

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/vmimport"
)

// importChunks is an import's upload: the first frame's chunk, then each
// further frame's. Bytes peeked at are replayed, so a source can be sniffed
// before it is decided whether to stage it.
type importChunks struct {
	recv  func() (*pb.ImportVMRequest, error)
	queue [][]byte
	eof   bool
	cur   []byte
	read  int64
}

func newImportChunks(stream pb.LiteVirt_ImportVMServer, first []byte) *importChunks {
	c := &importChunks{recv: stream.Recv}
	if len(first) > 0 {
		c.queue = append(c.queue, first)
	}
	return c
}

// next returns the next chunk, or io.EOF once the client has sent its last.
func (c *importChunks) next() ([]byte, error) {
	if len(c.queue) > 0 {
		b := c.queue[0]
		c.queue = c.queue[1:]
		return b, nil
	}
	if c.eof {
		return nil, io.EOF
	}
	req, err := c.recv()
	if err == io.EOF {
		c.eof = true
		return nil, io.EOF
	}
	if err != nil {
		return nil, err
	}
	return req.Chunk, nil
}

// peek returns the upload's first n bytes (fewer if it is shorter) without
// consuming them.
func (c *importChunks) peek(n int) ([]byte, error) {
	var head []byte
	for _, b := range c.queue {
		head = append(head, b...)
	}
	for len(head) < n && !c.eof {
		req, err := c.recv()
		if err == io.EOF {
			c.eof = true
			break
		}
		if err != nil {
			return nil, err
		}
		c.queue = append(c.queue, req.Chunk)
		head = append(head, req.Chunk...)
	}
	if len(head) > n {
		head = head[:n]
	}
	return head, nil
}

// Read reads the upload as a stream, under the same ceiling as staging it.
func (c *importChunks) Read(p []byte) (int, error) {
	for len(c.cur) == 0 {
		b, err := c.next()
		if err != nil {
			return 0, err
		}
		c.cur = b
	}
	n := copy(p, c.cur)
	c.cur = c.cur[n:]
	c.read += int64(n)
	if c.read > maxRestoreBytes {
		return n, status.Errorf(codes.ResourceExhausted, "import upload exceeded the %d-byte ceiling", maxRestoreBytes)
	}
	return n, nil
}

// inspectOVASource describes an OVA for --inspect from its .ovf descriptor
// alone. It reads the archive from where the import would — the upload, or
// the --server-path file under the same path check — only up to the
// descriptor, and writes nothing. ok is false for a source that is not an OVA
// tar (a directory, a bare .ovf, a Proxmox or VMA source): the caller inspects
// it the way it imports it, having consumed nothing.
func (s *Server) inspectOVASource(ctx context.Context, first *pb.ImportVMRequest, chunks *importChunks) (fv *vmimport.ForeignVM, ok bool, err error) {
	var (
		head []byte
		r    io.Reader
	)
	if first.SourcePath != "" {
		p, err := s.resolveStagedPath(ctx, first.SourcePath)
		if err != nil {
			return nil, false, err
		}
		fi, err := os.Stat(p)
		if err != nil || !fi.Mode().IsRegular() || strings.EqualFold(filepath.Ext(p), ".ovf") {
			return nil, false, nil
		}
		f, err := os.Open(p)
		if err != nil {
			return nil, false, nil
		}
		defer f.Close()
		head = make([]byte, 512)
		n, _ := io.ReadFull(f, head)
		head = head[:n]
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			return nil, false, nil
		}
		r = f
	} else {
		if head, err = chunks.peek(512); err != nil {
			return nil, false, err
		}
		r = chunks
	}
	format := strings.ToLower(strings.TrimSpace(first.SourceFormat))
	if format == "" || format == "auto" {
		format = sniffImportHead(head)
	}
	if (format != "ova" && format != "ovf") || !isTarHead(head) {
		return nil, false, nil
	}
	data, err := vmimport.InspectOVA(r)
	if err != nil {
		if st, isStatus := status.FromError(err); isStatus {
			return nil, true, st.Err()
		}
		return nil, true, status.Errorf(codes.InvalidArgument, "parse source: %v", err)
	}
	fv, err = vmimport.ParseOVFBytes(data)
	if err != nil {
		return nil, true, status.Errorf(codes.InvalidArgument, "parse source: %v", err)
	}
	return fv, true, nil
}
