package grpcapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pbsstore"
	"github.com/litevirt/litevirt/internal/tenancy"
)

// Backup entry statuses reported by InspectContainer.
const (
	backupAvailable = "available"
	backupNotFound  = "not_found"
	backupUnknown   = "unknown"
	backupForeign   = "foreign"
)

// backupProbeTimeout bounds one peer's answer to ProbeContainerBackups.
const backupProbeTimeout = 5 * time.Second

// ProbeContainerBackups answers, for this host, whether each repo can be
// opened here (a logical name resolved in this host's own config) and whether
// it holds a backup of the named container in the named project. Peer-only:
// it exists so InspectContainer can find a backup on whichever host holds it.
func (s *Server) ProbeContainerBackups(ctx context.Context, req *pb.ProbeContainerBackupsRequest) (*pb.ProbeContainerBackupsResponse, error) {
	if err := s.requirePeerCert(ctx); err != nil {
		return nil, err
	}
	if req.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "name required")
	}
	resp := &pb.ProbeContainerBackupsResponse{}
	for _, r := range req.Repos {
		resp.Results = append(resp.Results, s.probeContainerBackupRepo(ctx, req.Name, req.Project, r))
	}
	return resp, nil
}

// probeContainerBackupRepo opens repo on this host and looks for container
// backup manifests of name. A manifest is attributed to the container when its
// embedded spec names the same project; manifests of the name in other
// projects only make the repo "foreign" for this container.
func (s *Server) probeContainerBackupRepo(ctx context.Context, name, project, repo string) *pb.ContainerBackupProbe {
	out := &pb.ContainerBackupProbe{Repo: repo}
	path := ""
	if p, ok := s.backupRepos[repo]; ok {
		path = p
	} else if p, err := corrosion.GetBackupRepoPath(ctx, s.db, repo); err == nil && p != "" {
		path = p
	} else if filepath.IsAbs(repo) {
		path = repo
	} else {
		out.Detail = fmt.Sprintf("repo %q is not registered on %s", repo, s.hostName)
		return out
	}
	r, err := pbsstore.Open(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			out.Detail = fmt.Sprintf("repo %s is not present on %s", path, s.hostName)
		} else {
			out.Detail = fmt.Sprintf("repo %s cannot be opened on %s: %v", path, s.hostName, err)
		}
		return out
	}
	out.Opened = true
	ms, err := r.ListManifests()
	if err != nil {
		out.Detail = fmt.Sprintf("repo %s cannot be listed on %s: %v", path, s.hostName, err)
		return out
	}
	want := tenancy.NormalizeProject(project)
	for _, m := range ms {
		if m.VMName != name || m.DiskName != containerBackupDisk || m.ContainerSpecJSON == "" {
			continue
		}
		var spec containerBackupSpec
		if json.Unmarshal([]byte(m.ContainerSpecJSON), &spec) != nil {
			continue
		}
		if tenancy.NormalizeProject(spec.Project) != want {
			out.Foreign = true
			continue
		}
		out.Attributed = true
		if m.Timestamp > out.LatestTimestamp {
			out.LatestTimestamp = m.Timestamp
		}
	}
	if out.Attributed {
		out.Foreign = false
	} else if !out.Foreign {
		out.Detail = fmt.Sprintf("repo %s on %s holds no backup of %s", path, s.hostName, name)
	}
	return out
}

// resolveContainerBackups decides each container_backups entry's status at
// read time. The index has no host or project column, so an entry proves
// nothing about whose backup it is or where it lives: this host is asked
// first, then every other host. An entry is "available" where a host holds a
// manifest of this container's name AND project; "foreign" when the only
// manifests of the name belong to other projects; "not_found" when every host
// answered and none holds one; "unknown" when some host could not be asked.
// The entries themselves are never changed.
func (s *Server) resolveContainerBackups(ctx context.Context, rec *corrosion.ContainerRecord, refs []*pb.ContainerBackupRef) {
	if len(refs) == 0 {
		return
	}
	project := tenancy.NormalizeProject(rec.Project)
	type agg struct {
		foreign  bool
		reasons  []string
		resolved bool
	}
	st := make(map[string]*agg, len(refs))
	var pending []string
	for _, r := range refs {
		st[r.Repo] = &agg{}
		pending = append(pending, r.Repo)
	}
	byRepo := map[string]*pb.ContainerBackupRef{}
	for _, r := range refs {
		byRepo[r.Repo] = r
	}
	apply := func(host string, p *pb.ContainerBackupProbe) {
		a, ok := st[p.Repo]
		if !ok || a.resolved {
			return
		}
		switch {
		case p.Attributed:
			a.resolved = true
			ref := byRepo[p.Repo]
			ref.Status, ref.Available, ref.Location = backupAvailable, true, host
			ref.LatestTimestamp, ref.UnavailableReason = p.LatestTimestamp, ""
		case p.Foreign:
			a.foreign = true
		case p.Detail != "":
			a.reasons = append(a.reasons, p.Detail)
		}
	}

	// This host first: the common case (a local repo, or a shared one) needs
	// no peer at all.
	if s.db != nil {
		for _, repo := range pending {
			apply(s.hostName, s.probeContainerBackupRepo(ctx, rec.Name, project, repo))
		}
	}
	var left []string
	for _, repo := range pending {
		if !st[repo].resolved {
			left = append(left, repo)
		}
	}

	allAnswered := true
	if len(left) > 0 {
		hosts, err := corrosion.ListHosts(ctx, s.db)
		if err != nil {
			allAnswered = false
		}
		var mu sync.Mutex
		var wg sync.WaitGroup
		for _, h := range hosts {
			if h.Name == s.hostName {
				continue
			}
			wg.Add(1)
			go func(host string) {
				defer wg.Done()
				res, perr := s.probePeerContainerBackups(ctx, host, rec.Name, project, left)
				mu.Lock()
				defer mu.Unlock()
				if perr != nil {
					allAnswered = false
					for _, repo := range left {
						st[repo].reasons = append(st[repo].reasons, fmt.Sprintf("host %s could not be asked: %v", host, status.Convert(perr).Message()))
					}
					return
				}
				for _, p := range res {
					apply(host, p)
				}
			}(h.Name)
		}
		wg.Wait()
	}

	for _, repo := range left {
		a, ref := st[repo], byRepo[repo]
		if a.resolved {
			continue
		}
		ref.Available = false
		switch {
		case a.foreign:
			ref.Status = backupForeign
			ref.UnavailableReason = "the repo holds backups of a same-named container in another project, not this one"
		case allAnswered:
			ref.Status = backupNotFound
			ref.UnavailableReason = joinReasons(a.reasons)
		default:
			ref.Status = backupUnknown
			ref.UnavailableReason = joinReasons(a.reasons)
		}
	}
}

func (s *Server) probePeerContainerBackups(ctx context.Context, host, name, project string, repos []string) ([]*pb.ContainerBackupProbe, error) {
	pctx, cancel := context.WithTimeout(ctx, backupProbeTimeout)
	defer cancel()
	c, closeFn, err := s.dialPeer(pctx, host)
	if err != nil {
		return nil, err
	}
	defer closeFn()
	resp, err := c.ProbeContainerBackups(pctx, &pb.ProbeContainerBackupsRequest{Name: name, Project: project, Repos: repos})
	if err != nil {
		return nil, err
	}
	return resp.GetResults(), nil
}

func joinReasons(rs []string) string {
	out := ""
	for i, r := range rs {
		if i > 0 {
			out += "; "
		}
		out += r
	}
	return out
}

// filterContainerBackups applies what the caller may see. Without the admin
// role a caller sees only entries attributed to this container (the index is
// shared by same-named containers in other projects), and no reason text,
// which can carry host paths.
func filterContainerBackups(d *pb.ContainerDetail, admin bool) *pb.ContainerDetail {
	if admin || d == nil {
		return d
	}
	kept := d.Backups[:0]
	for _, b := range d.Backups {
		// An available entry carries no reason (resolveContainerBackups
		// clears it), so what remains holds no host path.
		if b.GetStatus() == backupAvailable {
			kept = append(kept, b)
		}
	}
	d.Backups = kept
	return d
}
