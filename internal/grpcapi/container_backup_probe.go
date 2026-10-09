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
	"github.com/litevirt/litevirt/internal/safename"
	"github.com/litevirt/litevirt/internal/tenancy"
)

// Backup entry statuses reported by InspectContainer.
const (
	backupAvailable = "available"
	backupNotFound  = "not_found"
	backupUnknown   = "unknown"
	backupForeign   = "foreign"
	// backupOtherLineage: the repo holds backups of another container of this
	// name in this project (a deleted predecessor, or a copy restored beside
	// it), which failover will not restore.
	backupOtherLineage = "other_lineage"
)

// backupProbeTimeout bounds one host's answer: a peer's ProbeContainerBackups,
// and this host's own probe. A var only so a test can shorten it.
var backupProbeTimeout = 5 * time.Second

// backupProbeConcurrency caps how many repo probes run at once on a host,
// for inspects from any number of callers and peers.
const backupProbeConcurrency = 4

// backupManifestTTL is how long a repo's parsed manifests of one container
// name are reused.
const backupManifestTTL = 30 * time.Second

type manifestCacheEntry struct {
	ms []pbsstore.Manifest
	at time.Time
}

// backupProbeSlots is the host's probe limiter.
func (s *Server) backupProbeSlots() chan struct{} {
	s.backupProbeOnce.Do(func() { s.backupProbeSem = make(chan struct{}, backupProbeConcurrency) })
	return s.backupProbeSem
}

// ProbeContainerBackups answers, for this host, whether each repo can be
// opened here (a logical name resolved in this host's own config) and whether
// it holds a backup of the named container: its project and, when the request
// names one, its lineage. Peer-only: it exists so InspectContainer can find a
// backup on whichever host holds it.
func (s *Server) ProbeContainerBackups(ctx context.Context, req *pb.ProbeContainerBackupsRequest) (*pb.ProbeContainerBackupsResponse, error) {
	if err := s.requirePeerCert(ctx); err != nil {
		return nil, err
	}
	if err := safename.ValidateContainerName(req.Name); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	resp := &pb.ProbeContainerBackupsResponse{}
	for _, r := range req.Repos {
		resp.Results = append(resp.Results, s.probeContainerBackupRepo(ctx, req.Name, req.Project, req.OwnerId, r))
	}
	return resp, nil
}

// probeContainerBackupRepo opens repo on this host and reads the container
// backup manifests of name (only that name's directory). A manifest is
// attributed to the container by the rule failover restores by
// (manifestOwnedBy): the same project, and the same lineage where both the
// manifest and ownerID carry one. Manifests of the name in other projects make
// the repo foreign as well; same-project manifests of another lineage are
// reported as other_lineage. An empty ownerID (an older peer asking) matches
// by project, as before. The work is bounded: it waits for a probe slot only
// until ctx ends, stops the walk when ctx ends, and reuses a recent read of
// the same repo and name.
func (s *Server) probeContainerBackupRepo(ctx context.Context, name, project, ownerID, repo string) *pb.ContainerBackupProbe {
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
	ms, err := s.containerManifests(ctx, path, name)
	if err != nil {
		switch {
		case errors.Is(err, fs.ErrNotExist):
			out.Detail = fmt.Sprintf("repo %s is not present on %s", path, s.hostName)
		default:
			out.Unreadable = true
			out.Detail = fmt.Sprintf("repo %s could not be read on %s: %v", path, s.hostName, err)
		}
		return out
	}
	out.Opened = true
	want := tenancy.NormalizeProject(project)
	owner := &corrosion.ContainerRecord{Name: name, Project: want,
		CreateSpec: corrosion.EncodeCreateSpec(corrosion.ContainerCreateSpec{OwnerID: ownerID})}
	for i := range ms {
		m := &ms[i]
		if m.ContainerSpecJSON == "" {
			continue
		}
		var spec containerBackupSpec
		if json.Unmarshal([]byte(m.ContainerSpecJSON), &spec) != nil {
			continue
		}
		if !manifestOwnedBy(m, owner) {
			if tenancy.NormalizeProject(spec.Project) != want {
				out.Foreign = true
			} else {
				out.OtherLineage = true
			}
			continue
		}
		out.Attributed = true
		if m.Timestamp > out.LatestTimestamp {
			out.LatestTimestamp, out.LatestTotalBytes = m.Timestamp, m.TotalSize
		}
	}
	if !out.Attributed && !out.Foreign && !out.OtherLineage {
		out.Detail = fmt.Sprintf("repo %s on %s holds no backup of %s", path, s.hostName, name)
	}
	return out
}

// containerManifests returns the rootfs manifests of name in the repo at
// path, from the cache when a read younger than backupManifestTTL exists.
func (s *Server) containerManifests(ctx context.Context, path, name string) ([]pbsstore.Manifest, error) {
	key := path + "\x00" + name
	s.backupManifestMu.Lock()
	if e, ok := s.backupManifests[key]; ok && time.Since(e.at) < backupManifestTTL {
		s.backupManifestMu.Unlock()
		return e.ms, nil
	}
	s.backupManifestMu.Unlock()

	if err := ctx.Err(); err != nil {
		return nil, err // an abandoned caller starts no walk
	}
	slots := s.backupProbeSlots()
	select {
	case slots <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	defer func() { <-slots }()
	r, err := pbsstore.Open(path)
	if err != nil {
		return nil, err
	}
	ms, err := r.ManifestsFor(ctx, name, containerBackupDisk)
	if err != nil {
		return nil, err
	}
	s.backupManifestMu.Lock()
	if s.backupManifests == nil {
		s.backupManifests = map[string]manifestCacheEntry{}
	}
	s.backupManifests[key] = manifestCacheEntry{ms: ms, at: time.Now()}
	s.backupManifestMu.Unlock()
	return ms, nil
}

// resolveContainerBackups decides each container_backups entry's status at
// read time. The index has no host or project column, so an entry proves
// nothing about whose backup it is or where it lives: this host is asked
// first, then every other host. An entry is "available" where a host holds a
// manifest of this container's name, project AND lineage (the rule failover
// restores by); "other_lineage" when the only manifests of the name in this
// project are another lineage's (a deleted predecessor's, or a copy restored
// beside it); "foreign" when the only manifests of the name belong to other
// projects; "not_found" when every host answered and none holds one;
// "unknown" when some host could not be asked. The entries themselves are
// never changed.
func (s *Server) resolveContainerBackups(ctx context.Context, rec *corrosion.ContainerRecord, refs []*pb.ContainerBackupRef) {
	if len(refs) == 0 {
		return
	}
	project := tenancy.NormalizeProject(rec.Project)
	ownerID := corrosion.DecodeCreateSpec(rec.CreateSpec).OwnerID
	type agg struct {
		foreign      bool
		otherLineage bool
		unanswered   bool // some host could not say whether it holds it
		reasons      []string
		resolved     bool
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
			// Size and time come from THIS container's own newest manifest,
			// never from the index row: (ct_name, repo) is shared by
			// same-named containers, and the row holds whichever wrote last.
			ref.TotalBytes, ref.UpdatedAt = p.LatestTotalBytes, p.LatestTimestamp
		case p.Foreign || p.OtherLineage:
			a.foreign = a.foreign || p.Foreign
			a.otherLineage = a.otherLineage || p.OtherLineage
		case p.Unreadable:
			a.unanswered = true
			a.reasons = append(a.reasons, p.Detail)
		case p.Detail != "":
			a.reasons = append(a.reasons, p.Detail)
		}
	}

	// This host first: the common case (a local repo, or a shared one) needs
	// no peer at all.
	//
	// Bounded like a peer's answer (backupProbeTimeout), whatever deadline the
	// caller has — a CLI has none. The walk runs on its own goroutine because
	// file reads on a hung network mount ignore ctx: the inspect answers at
	// the deadline with the entries unknown, and the walk finishes (or not)
	// in the background, holding only its probe slot.
	if s.db != nil {
		for _, p := range s.probeLocalBounded(ctx, rec.Name, project, ownerID, pending) {
			apply(s.hostName, p)
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
				res, perr := s.probePeerContainerBackups(ctx, host, rec.Name, project, ownerID, left)
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
		case a.otherLineage:
			// Same project, so ahead of foreign: it is the likelier
			// mistake (an operator who recreated the name) to explain.
			ref.Status = backupOtherLineage
			ref.UnavailableReason = "the repo holds backups of another container of this name in this project (deleted, or a copy restored beside it), not this one; failover will not restore them"
		case a.foreign:
			ref.Status = backupForeign
			ref.UnavailableReason = "the repo holds backups of a same-named container in another project, not this one"
		case allAnswered && !a.unanswered:
			ref.Status = backupNotFound
			ref.UnavailableReason = joinReasons(a.reasons)
		default:
			ref.Status = backupUnknown
			ref.UnavailableReason = joinReasons(a.reasons)
		}
	}
}

func (s *Server) probePeerContainerBackups(ctx context.Context, host, name, project, ownerID string, repos []string) ([]*pb.ContainerBackupProbe, error) {
	pctx, cancel := context.WithTimeout(ctx, backupProbeTimeout)
	defer cancel()
	c, closeFn, err := s.dialPeer(pctx, host)
	if err != nil {
		return nil, err
	}
	defer closeFn()
	// A peer that predates owner_id ignores it and matches by project.
	resp, err := c.ProbeContainerBackups(pctx, &pb.ProbeContainerBackupsRequest{Name: name, Project: project, OwnerId: ownerID, Repos: repos})
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

// hiddenRepoPath stands in for an absolute repo path shown to a non-admin.
const hiddenRepoPath = "(host path)"

// filterContainerBackups applies what the caller may see. Without the admin
// role a caller sees only entries attributed to this container (the index is
// shared by same-named containers in other projects), and no host paths:
// no reason text, no rootfs path, and no absolute repo path.
func filterContainerBackups(d *pb.ContainerDetail, admin bool) *pb.ContainerDetail {
	if admin || d == nil {
		return d
	}
	d.RootfsPath = ""
	kept := d.Backups[:0]
	for _, b := range d.Backups {
		// An available entry carries no reason (resolveContainerBackups
		// clears it), so what remains holds no host path.
		if b.GetStatus() == backupAvailable {
			if filepath.IsAbs(b.Repo) {
				b.Repo = hiddenRepoPath
			}
			kept = append(kept, b)
		}
	}
	d.Backups = kept
	return d
}

// probeLocalBounded probes repos on this host within backupProbeTimeout. A
// repo not answered by then is reported unreadable (so it stays unknown).
func (s *Server) probeLocalBounded(ctx context.Context, name, project, ownerID string, repos []string) []*pb.ContainerBackupProbe {
	lctx, cancel := context.WithTimeout(ctx, backupProbeTimeout)
	defer cancel()
	results := make(chan *pb.ContainerBackupProbe, len(repos))
	go func() {
		for _, repo := range repos {
			results <- s.probeContainerBackupRepo(lctx, name, project, ownerID, repo)
		}
	}()
	got := make(map[string]*pb.ContainerBackupProbe, len(repos))
	for len(got) < len(repos) {
		select {
		case p := <-results:
			got[p.Repo] = p
		case <-lctx.Done():
			for _, repo := range repos {
				if _, ok := got[repo]; !ok {
					got[repo] = &pb.ContainerBackupProbe{Repo: repo, Unreadable: true,
						Detail: fmt.Sprintf("probe on %s did not finish in %s", s.hostName, backupProbeTimeout)}
				}
			}
		}
	}
	out := make([]*pb.ContainerBackupProbe, 0, len(repos))
	for _, repo := range repos {
		out = append(out, got[repo])
	}
	return out
}
