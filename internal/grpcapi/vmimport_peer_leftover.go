package grpcapi

import (
	"context"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// A crashed import's leftovers in a pool several hosts share are known as
// such only to the host that wrote them: its placement record is host-local.
// A re-import on another host (the first is drained, say) asks the hosts
// sharing the pool whether their record shows the file there as their dead
// import's, unchanged since, and takes it for a leftover only on a yes. A host
// that does not answer in time, or answers no, leaves the file judged as
// before: by age.

// importPeerAskTimeout bounds how long a re-import waits for one host.
const importPeerAskTimeout = 3 * time.Second

// importPeerAskMaxFiles bounds one question.
const importPeerAskMaxFiles = 256

// peerDeadImportFiles asks every other host with pool which of files their
// placement record shows their dead import left there, in exactly the state
// seen here. dead holds the names any host vouched for; unasked names the
// hosts that could not be asked. The default pool ("") is each host's own and
// is asked of no one.
func (s *Server) peerDeadImportFiles(ctx context.Context, pool string, files []importSibling) (dead map[string]bool, unasked []string) {
	if pool == "" || len(files) == 0 {
		return nil, nil
	}
	pools, err := corrosion.ListAllStoragePools(ctx, s.db)
	if err != nil {
		return nil, []string{"the hosts sharing pool " + pool}
	}
	var hosts []string
	for _, p := range pools {
		if p.Name == pool && p.HostName != s.hostName {
			hosts = append(hosts, p.HostName)
		}
	}
	if len(hosts) == 0 {
		return nil, nil
	}
	req := &pb.ImportLeftoverStatusRequest{Pool: pool}
	for _, f := range files {
		if len(req.Files) == importPeerAskMaxFiles {
			break
		}
		_, ino, size, mtime, ok := fileState(f.fi)
		if !ok {
			continue
		}
		req.Files = append(req.Files, &pb.ImportLeftoverFile{
			Name: f.name, Ino: ino, Size: size, MtimeNs: mtime, CtimeNs: fileCtimeNs(f.fi),
		})
	}
	var (
		mu sync.Mutex
		wg sync.WaitGroup
	)
	dead = map[string]bool{}
	for _, h := range hosts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			names, err := s.askImportLeftoverStatus(ctx, h, req)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				unasked = append(unasked, h)
				return
			}
			for _, n := range names {
				dead[n] = true
			}
		}()
	}
	wg.Wait()
	sort.Strings(unasked)
	return dead, unasked
}

// askImportLeftoverStatus asks one host, within importPeerAskTimeout.
func (s *Server) askImportLeftoverStatus(ctx context.Context, host string, req *pb.ImportLeftoverStatusRequest) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, importPeerAskTimeout)
	defer cancel()
	c, done, err := s.dialPeer(ctx, host)
	if err != nil {
		return nil, err
	}
	defer done()
	resp, err := c.ImportLeftoverStatus(ctx, req)
	if err != nil {
		return nil, err
	}
	asked := map[string]bool{}
	for _, f := range req.Files {
		asked[f.Name] = true
	}
	var out []string
	for _, n := range resp.Dead {
		if asked[n] { // an answer never adds a file
			out = append(out, n)
		}
	}
	return out, nil
}

// ImportLeftoverStatus answers, from this host's placement record alone, which
// of the named files in one of its pools a dead import of this host left
// there, in exactly the asked state. Peer-only. It reads no file: the names
// select records, and a record answers only for the inode, size and times it
// holds.
func (s *Server) ImportLeftoverStatus(ctx context.Context, req *pb.ImportLeftoverStatusRequest) (*pb.ImportLeftoverStatusResponse, error) {
	if err := s.requirePeerCert(ctx); err != nil {
		return nil, err
	}
	if req.Pool == "" {
		return nil, status.Error(codes.InvalidArgument, "a pool is required; the default pool is each host's own")
	}
	if len(req.Files) > importPeerAskMaxFiles {
		return nil, status.Errorf(codes.InvalidArgument, "at most %d files per question", importPeerAskMaxFiles)
	}
	ref, ok := s.resolvePool(ctx, req.Pool)
	if !ok {
		return nil, status.Errorf(codes.NotFound, "storage pool %q not found on %s", req.Pool, s.hostName)
	}
	dir, err := fileBasedPoolDir(s.dataDir, ref)
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "pool %q is not file-backed", req.Pool)
	}
	resp := &pb.ImportLeftoverStatusResponse{}
	for _, f := range req.Files {
		if !plainFileName(f.Name) {
			return nil, status.Errorf(codes.InvalidArgument, "%q is not a plain file name", f.Name)
		}
		rec, ok := s.importPlacementOf(filepath.Join(dir, f.Name))
		if ok && rec.matchesState(f.Ino, f.Size, f.MtimeNs, f.CtimeNs) && s.importPlacementDead(rec) {
			resp.Dead = append(resp.Dead, f.Name)
		}
	}
	return resp, nil
}

// plainFileName is a name of one file in a directory: no separator, not "."
// or "..", not empty, no NUL.
func plainFileName(n string) bool {
	return n != "" && n != "." && n != ".." && len(n) <= 255 &&
		!strings.ContainsAny(n, "/\\\x00") && filepath.Base(n) == n
}
