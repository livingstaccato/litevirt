package grpcapi

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pbsstore"
)

// rootfsMeasureBudget bounds the rootfs walk, so inspecting a container with a
// very large tree answers (with the size unmeasured) instead of hanging.
const rootfsMeasureBudget = 10 * time.Second

// InspectContainer returns one container's full detail — the container
// analogue of InspectVM. It is a read: ct.read on the container's own path,
// with the existence-oracle protection every single-container read has (an
// out-of-scope caller gets the same PermissionDenied for a container that
// exists as for one that does not).
//
// The cluster row, NICs, snapshots and backup index come from the replicated
// store; the privilege mode, the rootfs and whether each backup repo can still
// be opened are facts only the container's host has, so the call is answered
// there. If that host cannot be reached, the cluster view is returned with
// host_detail=false and those fields unknown, rather than nothing.
func (s *Server) InspectContainer(ctx context.Context, req *pb.InspectContainerRequest) (*pb.ContainerDetail, error) {
	if err := s.requirePermPrecheck(ctx, "viewer"); err != nil {
		return nil, err
	}
	if req.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "name required")
	}
	project, known := s.containerProject(ctx, req.HostName, req.Name)
	if err := s.requirePermResolved(ctx, known, ctRBACPathFor(project, req.Name), ctRBACPathFor("", req.Name),
		"ct.read", "viewer", containerWhat(req.Name)); err != nil {
		return nil, err
	}
	host, rec, err := s.resolveContainerHost(ctx, req.HostName, req.Name)
	if err != nil {
		return nil, err
	}
	if host != s.hostName {
		c, closeFn, derr := s.dialPeer(ctx, host)
		if derr == nil {
			defer closeFn()
			fwd := &pb.InspectContainerRequest{Name: req.Name, HostName: host}
			d, ferr := c.InspectContainer(ctx, fwd)
			if ferr == nil {
				return d, nil
			}
			derr = ferr
		}
		// The owner is unreachable (or predates this RPC): answer with what the
		// cluster knows, and say the host-local fields are unknown.
		d, cerr := s.containerDetailFromCluster(ctx, rec)
		if cerr != nil {
			return nil, cerr
		}
		markHostDetailUnknown(d, fmt.Sprintf("host %s unreachable: %v", host, status.Convert(derr).Message()))
		return d, nil
	}

	d, err := s.containerDetailFromCluster(ctx, rec)
	if err != nil {
		return nil, err
	}
	s.addHostLocalContainerDetail(ctx, req.Name, d)
	return d, nil
}

// containerDetailFromCluster builds the detail from replicated state alone.
func (s *Server) containerDetailFromCluster(ctx context.Context, rec *corrosion.ContainerRecord) (*pb.ContainerDetail, error) {
	d := &pb.ContainerDetail{
		Container:   toPbContainer(*rec),
		IsTemplate:  rec.IsTemplate,
		Privilege:   "unknown",
		RootfsBytes: -1,
	}
	spec := corrosion.DecodeCreateSpec(rec.CreateSpec)
	d.Template, d.Distro, d.Release, d.Arch = spec.Template, spec.Distro, spec.Release, spec.Arch

	ifaces, err := corrosion.GetContainerInterfaces(ctx, s.db, rec.HostName, rec.Name)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read interfaces: %v", err)
	}
	d.Interfaces = containerInterfaceDetails(spec.Networks, ifaces)

	snaps, err := corrosion.ListContainerSnapshots(ctx, s.db, rec.HostName, rec.Name)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read snapshots: %v", err)
	}
	for _, sn := range snaps {
		d.Snapshots = append(d.Snapshots, &pb.ContainerSnapshot{
			Id: sn.ID, CtName: sn.CtName, HostName: sn.HostName, Name: sn.Name,
			State: sn.State, SizeBytes: sn.SizeBytes, Type: sn.Type, CreatedAt: sn.CreatedAt,
		})
	}

	bks, err := corrosion.ListContainerBackups(ctx, s.db, rec.Name)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read backups: %v", err)
	}
	for _, b := range bks {
		d.Backups = append(d.Backups, &pb.ContainerBackupRef{
			Repo: b.Repo, TotalBytes: b.TotalBytes, UpdatedAt: b.UpdatedAt,
		})
	}
	return d, nil
}

// containerInterfaceDetails joins the create spec's NICs (names, raw bridges)
// with the managed interface rows (addresses, veths, security groups) by
// ordinal. A row with no spec entry (a container created before create_spec)
// is still listed.
func containerInterfaceDetails(spec []corrosion.ContainerNetwork, rows []corrosion.ContainerInterfaceRecord) []*pb.ContainerInterfaceDetail {
	byOrd := map[int]corrosion.ContainerInterfaceRecord{}
	for _, r := range rows {
		byOrd[r.Ordinal] = r
	}
	var out []*pb.ContainerInterfaceDetail
	for i, n := range spec {
		d := &pb.ContainerInterfaceDetail{
			Name: n.Name, NetworkName: n.NetworkName, Bridge: n.Bridge,
			Ip: n.IP, Mac: n.MAC, SecurityGroups: n.SecurityGroups,
		}
		if r, ok := byOrd[i]; ok {
			d.NetworkName, d.Ip, d.Mac, d.Veth, d.SecurityGroups = r.NetworkName, r.IP, r.MAC, r.VethDevice, r.SecurityGroups
			delete(byOrd, i)
		}
		out = append(out, d)
	}
	for i := 0; len(byOrd) > 0; i++ {
		if r, ok := byOrd[i]; ok {
			out = append(out, &pb.ContainerInterfaceDetail{
				NetworkName: r.NetworkName, Ip: r.IP, Mac: r.MAC, Veth: r.VethDevice, SecurityGroups: r.SecurityGroups,
			})
			delete(byOrd, i)
		}
	}
	return out
}

// addHostLocalContainerDetail fills what only the container's host knows.
func (s *Server) addHostLocalContainerDetail(ctx context.Context, name string, d *pb.ContainerDetail) {
	d.HostDetail = true
	if s.containerRuntime != nil {
		if rootfs, err := s.containerRuntime.ContainerRootFSPath(name); err == nil && rootfs != "" {
			d.RootfsPath = rootfs
			d.RootfsBytes = measureTree(ctx, rootfs, rootfsMeasureBudget)
			// LXC keeps the config beside the rootfs (<lxcpath>/<name>/config).
			d.Privilege = lxcPrivilege(filepath.Join(filepath.Dir(rootfs), "config"))
		}
	}
	for _, b := range d.Backups {
		b.Available, b.UnavailableReason = s.backupRepoAvailable(ctx, b.Repo)
	}
}

func markHostDetailUnknown(d *pb.ContainerDetail, reason string) {
	d.HostDetail = false
	d.Privilege = "unknown"
	d.RootfsBytes = -1
	for _, b := range d.Backups {
		b.Available, b.UnavailableReason = false, reason
	}
}

// backupRepoAvailable decides at read time whether a backup index entry's
// repo can still be opened on this host. The entry itself is never touched: a
// repo that is unmounted rather than deleted comes back, and its backups with
// it. Only the location is probed — no repo permission is exercised.
func (s *Server) backupRepoAvailable(ctx context.Context, repo string) (bool, string) {
	path := ""
	if p, ok := s.backupRepos[repo]; ok {
		path = p
	} else if p, err := corrosion.GetBackupRepoPath(ctx, s.db, repo); err == nil && p != "" {
		path = p
	} else if filepath.IsAbs(repo) {
		path = repo
	} else {
		return false, fmt.Sprintf("repo %q is not registered on %s", repo, s.hostName)
	}
	if _, err := pbsstore.Open(path); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, fmt.Sprintf("repo %s does not exist on %s", path, s.hostName)
		}
		return false, fmt.Sprintf("repo %s cannot be opened on %s: %v", path, s.hostName, err)
	}
	return true, ""
}

// lxcPrivilege reads an LXC container config and reports "unprivileged" when
// it maps ids (lxc.idmap, or the pre-2.1 lxc.id_map), "privileged" when it
// does not, and "unknown" when the config cannot be read. Included config
// files are followed, since an idmap can come from an include.
func lxcPrivilege(configPath string) string {
	mapped, ok := lxcConfigMapsIDs(configPath, 0)
	switch {
	case !ok:
		return "unknown"
	case mapped:
		return "unprivileged"
	default:
		return "privileged"
	}
}

func lxcConfigMapsIDs(path string, depth int) (mapped, ok bool) {
	if depth > 4 {
		return false, true
	}
	f, err := os.Open(path)
	if err != nil {
		return false, false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		key, val = strings.TrimSpace(key), strings.TrimSpace(val)
		switch key {
		case "lxc.idmap", "lxc.id_map":
			if val != "" {
				return true, true
			}
		case "lxc.include":
			for _, inc := range lxcIncludeFiles(val) {
				if m, _ := lxcConfigMapsIDs(inc, depth+1); m {
					return true, true
				}
			}
		}
	}
	return false, sc.Err() == nil
}

// lxcIncludeFiles expands an lxc.include value: a file, or a directory whose
// *.conf files are included.
func lxcIncludeFiles(p string) []string {
	st, err := os.Stat(p)
	if err != nil {
		return nil
	}
	if !st.IsDir() {
		return []string{p}
	}
	m, _ := filepath.Glob(filepath.Join(p, "*.conf"))
	return m
}

// measureTree sums the apparent size of the regular files under root without
// following symlinks, or returns -1 if the walk fails or exceeds budget.
func measureTree(ctx context.Context, root string, budget time.Duration) int64 {
	deadline := time.Now().Add(budget)
	var total int64
	err := filepath.WalkDir(root, func(_ string, de fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if ctx.Err() != nil || time.Now().After(deadline) {
			return context.DeadlineExceeded
		}
		if de.Type().IsRegular() {
			if info, ierr := de.Info(); ierr == nil {
				total += info.Size()
			}
		}
		return nil
	})
	if err != nil {
		return -1
	}
	return total
}
