package grpcapi

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/auth"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// A storage pool that names a directory on the host makes the daemon write
// there as root: VM disks, uploaded content, an NFS mount laid over it. An
// operator who could aim a `dir` pool at any existing directory and then upload
// a file with any name and content into it had root on every host they did it
// on — /etc/cron.d/<name>, /root/.ssh/authorized_keys, or
// <data_dir>/audit-seeded-assert, which the next daemon start obeys.

// hostPathEngineCtx seeds the auth engine with one binding for user `name` and
// returns that user's context. A binding is what an RBAC deployment gives a
// tenant, so this is the shape of a real project-scoped caller.
func hostPathEngineCtx(t *testing.T, s *Server, name, role, path string) context.Context {
	t.Helper()
	ctx := context.Background()
	if err := corrosion.InsertUser(ctx, s.db, name, "operator", "x"); err != nil {
		t.Fatalf("InsertUser: %v", err)
	}
	if err := auth.SeedBuiltinRoles(ctx, s.db); err != nil {
		t.Fatalf("SeedBuiltinRoles: %v", err)
	}
	if err := corrosion.InsertRoleBinding(ctx, s.db, corrosion.RoleBindingRecord{
		ID: name + "-binding", Path: path, Role: role,
		Principal: "user:" + name + "@local", Propagate: true,
	}); err != nil {
		t.Fatalf("InsertRoleBinding: %v", err)
	}
	engine := auth.NewEngine(s.db)
	if err := engine.Reload(ctx); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	s.SetAuthEngine(engine)
	out := context.WithValue(context.Background(), ctxKeyUsername, name)
	return context.WithValue(out, ctxKeyRole, "operator")
}

func uploadAs(ctx context.Context, s *Server, pool, filename, body string) error {
	st := &fakeUploadStream{ctx: ctx, msgs: []*pb.UploadStoragePoolContentRequest{
		{PoolName: pool, Filename: filename},
		{Chunk: []byte(body)},
	}}
	return s.UploadStoragePoolContent(st)
}

// The reported exploit, end to end: an operator aims a dir pool at the data
// directory and uploads the audit assertion file into it.
func TestPoolHostPath_OperatorCannotWriteIntoTheDataDir(t *testing.T) {
	s := newPoolTestServer(t)
	op := userCtx("op", "operator")

	_, err := s.CreateStoragePool(op, &pb.CreateStoragePoolRequest{
		Name: "evil", Driver: "dir", Target: s.dataDir,
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("operator creating a dir pool on the data dir: got %v, want PermissionDenied", err)
	}
	upErr := uploadAs(op, s, "evil", "audit-seeded-assert", "x")
	if _, err := os.Lstat(filepath.Join(s.dataDir, "audit-seeded-assert")); err == nil {
		t.Fatalf("an operator wrote <data_dir>/audit-seeded-assert as root (upload err=%v)", upErr)
	}
}

// Every way a pool can name the host's filesystem needs cluster-root authority,
// for a plain operator and for a project-scoped one alike.
func TestPoolHostPath_NonRootCallersCannotNameHostPaths(t *testing.T) {
	reqs := func(dir string) map[string]*pb.CreateStoragePoolRequest {
		return map[string]*pb.CreateStoragePoolRequest{
			"dir target":        {Driver: "dir", Target: dir},
			"local target":      {Driver: "local", Target: dir},
			"nfs target":        {Driver: "nfs", Source: "nas:/x", Target: dir},
			"nfs mount options": {Driver: "nfs", Source: "nas:/x", Options: map[string]string{"options": "bind"}},
			"btrfs source":      {Driver: "btrfs", Source: dir},
			"ceph conf":         {Driver: "ceph", Source: "rbd", Options: map[string]string{"conf": filepath.Join(dir, "c.conf")}},
			"ceph keyring":      {Driver: "ceph", Source: "rbd", Options: map[string]string{"keyring": filepath.Join(dir, "k")}},
		}
	}
	callers := map[string]func(t *testing.T, s *Server) (context.Context, string){
		"legacy operator": func(*testing.T, *Server) (context.Context, string) {
			return userCtx("op", "operator"), ""
		},
		"project operator": func(t *testing.T, s *Server) (context.Context, string) {
			return hostPathEngineCtx(t, s, "pat", "Operator", projectRBACBase("acme")), "acme"
		},
		"project admin": func(t *testing.T, s *Server) (context.Context, string) {
			return hostPathEngineCtx(t, s, "pam", "Admin", projectRBACBase("acme")), "acme"
		},
		"root operator": func(t *testing.T, s *Server) (context.Context, string) {
			return hostPathEngineCtx(t, s, "rob", "Operator", "/"), ""
		},
	}
	for cname, mk := range callers {
		for rname, req := range reqs(t.TempDir()) {
			t.Run(cname+"/"+rname, func(t *testing.T) {
				s := newPoolTestServer(t)
				ctx, project := mk(t, s)
				req.Name, req.Project = "p", project
				_, err := s.CreateStoragePool(ctx, req)
				if status.Code(err) != codes.PermissionDenied {
					t.Fatalf("got %v, want PermissionDenied", err)
				}
				if _, ok, _ := corrosion.GetStoragePool(adminCtx(), s.db, s.hostName, "p"); ok {
					t.Fatalf("the refused pool was persisted")
				}
			})
		}
	}
}

// What an operator could always do, they still can: a pool that lives in the
// daemon's own disk area names no host path.
func TestPoolHostPath_ProjectOperatorKeepsPoolsWithoutHostPaths(t *testing.T) {
	s := newPoolTestServer(t)
	pat := hostPathEngineCtx(t, s, "pat", "Operator", projectRBACBase("acme"))
	if _, err := s.CreateStoragePool(pat, &pb.CreateStoragePoolRequest{
		Name: "mine", Driver: "local", Project: "acme",
	}); err != nil {
		t.Fatalf("a local pool with no target: %v", err)
	}
}

// A cluster-root Admin may name a host directory, by binding or by legacy role.
func TestPoolHostPath_RootAdminMayNameAHostDirectory(t *testing.T) {
	for name, mk := range map[string]func(t *testing.T, s *Server) context.Context{
		"legacy admin": func(*testing.T, *Server) context.Context { return adminCtx() },
		"root Admin binding": func(t *testing.T, s *Server) context.Context {
			return hostPathEngineCtx(t, s, "ada", "Admin", "/")
		},
	} {
		t.Run(name, func(t *testing.T) {
			s := newPoolTestServer(t)
			if _, err := s.CreateStoragePool(mk(t, s), &pb.CreateStoragePoolRequest{
				Name: "san", Driver: "dir", Target: t.TempDir(),
			}); err != nil {
				t.Fatalf("root admin creating a dir pool: %v", err)
			}
		})
	}
}

// Some directories are refused to everyone, admin included: a pool there is a
// foot-gun at best, and the same upload path writes root-owned files into it.
func TestPoolHostPath_ProtectedDirectoriesAreRefusedEvenToAdmin(t *testing.T) {
	s := newPoolTestServer(t)
	// Outside the test's temp root, so "parent of the data dir" below is
	// refused for containing the data dir, not for containing the PKI dir.
	pki, err := os.MkdirTemp("", "pki")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(pki) })
	s.pkiDir = pki
	images := filepath.Join(s.dataDir, "images")
	if err := os.MkdirAll(images, 0o755); err != nil {
		t.Fatal(err)
	}
	links := t.TempDir()
	toData := filepath.Join(links, "to-data")
	toEtc := filepath.Join(links, "to-etc")
	if err := os.Symlink(s.dataDir, toData); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc", toEtc); err != nil {
		t.Fatal(err)
	}
	cases := map[string]*pb.CreateStoragePoolRequest{
		"data dir":                  {Driver: "dir", Target: s.dataDir},
		"data dir internals":        {Driver: "dir", Target: images},
		"data dir via dot-dot":      {Driver: "local", Target: s.dataDir + "/disks/../state"},
		"parent of the data dir":    {Driver: "dir", Target: filepath.Dir(s.dataDir)},
		"pki dir":                   {Driver: "dir", Target: s.pkiDir},
		"etc":                       {Driver: "dir", Target: "/etc"},
		"cron.d":                    {Driver: "dir", Target: "/etc/cron.d"},
		"root home":                 {Driver: "local", Target: "/root/.ssh"},
		"filesystem root":           {Driver: "dir", Target: "/"},
		"proc":                      {Driver: "dir", Target: "/proc"},
		"relative":                  {Driver: "local", Target: "rel/dir"},
		"symlink to data dir":       {Driver: "dir", Target: toData},
		"symlink to etc":            {Driver: "dir", Target: toEtc},
		"new dir under etc symlink": {Driver: "local", Target: filepath.Join(toEtc, "new")},
		"nfs mounted over etc":      {Driver: "nfs", Source: "nas:/x", Target: "/etc"},
		"btrfs under usr":           {Driver: "btrfs", Source: "/usr/local/vm"},
		"nfs source deriving ..":    {Driver: "nfs", Source: ".."},
		"data dir disks":            {Driver: "dir", Target: filepath.Join(s.dataDir, "disks")},
	}
	for name, req := range cases {
		t.Run(name, func(t *testing.T) {
			req.Name = "p"
			_, err := s.CreateStoragePool(adminCtx(), req)
			if status.Code(err) != codes.InvalidArgument {
				t.Fatalf("got %v, want InvalidArgument", err)
			}
		})
	}

	// The daemon's own pool area stays usable.
	own := filepath.Join(s.dataDir, "pools", "elsewhere")
	if err := os.MkdirAll(own, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateStoragePool(adminCtx(), &pb.CreateStoragePoolRequest{
		Name: "default2", Driver: "dir", Target: own,
	}); err != nil {
		t.Fatalf("a dir pool under <data_dir>/pools: %v", err)
	}
}

// An upload is a plain image-like file name: no leading dot, an image or ISO
// extension, and never over something already there — a file or a symlink.
func TestPoolUpload_NamePolicy(t *testing.T) {
	s, _, dirB, _ := contentServer(t)
	peer := contentPeerCtx(t, s)

	for _, bad := range []string{".bashrc", ".hidden.iso", "authorized_keys", "job.sh", "x.service", "root"} {
		if err := uploadAs(peer, s, "poolB", bad, "x"); status.Code(err) != codes.InvalidArgument {
			t.Errorf("upload %q: got %v, want InvalidArgument", bad, err)
		}
		if _, err := os.Lstat(filepath.Join(dirB, bad)); err == nil {
			t.Errorf("upload %q was written", bad)
		}
	}
	if err := uploadAs(peer, s, "poolB", "Installer.ISO", "x"); err != nil {
		t.Errorf("an upper-case .ISO is an ISO: %v", err)
	}

	// No clobber.
	existing := filepath.Join(dirB, "exists.iso")
	if err := os.WriteFile(existing, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	st := &fakeUploadStream{ctx: peer, msgs: []*pb.UploadStoragePoolContentRequest{
		{PoolName: "poolB", Filename: "exists.iso"},
		{Chunk: []byte("new")},
	}}
	if err := s.UploadStoragePoolContent(st); status.Code(err) != codes.AlreadyExists {
		t.Errorf("upload over an existing file: got %v, want AlreadyExists", err)
	}
	if st.idx != 1 {
		t.Errorf("a taken name is refused before streaming, but %d frames were read", st.idx)
	}
	if got, _ := os.ReadFile(existing); string(got) != "old" {
		t.Errorf("existing file was overwritten: %q", got)
	}

	// No write through, or over, a symlink.
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dirB, "link.iso")
	if err := os.Symlink(victim, link); err != nil {
		t.Fatal(err)
	}
	if err := uploadAs(peer, s, "poolB", "link.iso", "pwned"); err == nil {
		t.Errorf("upload over a symlink succeeded")
	}
	if got, _ := os.ReadFile(victim); string(got) != "keep" {
		t.Errorf("symlink target was written: %q", got)
	}
	if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Errorf("the symlink was replaced (err=%v)", err)
	}
	ents, _ := os.ReadDir(dirB)
	for _, e := range ents {
		if filepath.Ext(e.Name()) == ".tmp" {
			t.Errorf("a refused upload left %s behind", e.Name())
		}
	}
}

// A pool created before this check, aimed somewhere it now refuses, still lists
// — but takes no upload and gives up no file, from a user or a peer.
func TestPoolUpload_ExistingPoolOnAProtectedDirectoryRefusesWrites(t *testing.T) {
	s, _, _, _ := contentServer(t)
	peer := contentPeerCtx(t, s)
	if err := corrosion.UpsertStoragePool(adminCtx(), s.db, corrosion.StoragePoolRecord{
		HostName: s.hostName, Name: "legacy", Driver: "dir", Target: s.dataDir, State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	keep := filepath.Join(s.dataDir, "keep.iso")
	if err := os.WriteFile(keep, []byte("state"), 0o644); err != nil {
		t.Fatal(err)
	}

	for name, ctx := range map[string]context.Context{"admin": adminCtx(), "peer": peer} {
		if err := uploadAs(ctx, s, "legacy", "audit-seeded-assert.iso", "x"); status.Code(err) != codes.FailedPrecondition {
			t.Errorf("%s upload into a protected pool: got %v, want FailedPrecondition", name, err)
		}
		if _, err := s.DeleteStoragePoolContent(ctx, &pb.DeleteStoragePoolContentRequest{
			PoolName: "legacy", Filename: "keep.iso",
		}); status.Code(err) != codes.FailedPrecondition {
			t.Errorf("%s delete from a protected pool: got %v, want FailedPrecondition", name, err)
		}
	}
	if _, err := os.Stat(keep); err != nil {
		t.Errorf("a file in the protected pool was deleted: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(s.dataDir, "audit-seeded-assert.iso")); err == nil {
		t.Errorf("an upload landed in the data dir")
	}
	// Round 2: it is not even listed — its directory may be /root/.ssh.
	if _, err := s.ListStoragePoolContents(adminCtx(), &pb.ListStoragePoolContentsRequest{PoolName: "legacy"}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("listing a protected pool: got %v, want FailedPrecondition", err)
	}
}

const hostPathStackYAML = `
version: "1"
name: web
volumes:
  scratch:
    driver: dir
    target: %s
vms:
  app:
    image: base
    disks:
      data: { size: 1G, storage: scratch }
`

// A compose volume is a pool by another name, and deploying a stack is an
// operator action: the same authority applies before anything is created.
func TestPoolHostPath_ComposeVolumesNeedRootAuthority(t *testing.T) {
	s := newPoolTestServer(t)
	dir := t.TempDir()
	f := mustParseCompose(t, fmt.Sprintf(hostPathStackYAML, dir))

	if err := s.authorizeComposeHostPaths(userCtx("op", "operator"), f); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("operator deploying a dir volume: got %v, want PermissionDenied", err)
	}
	if err := s.authorizeComposeHostPaths(adminCtx(), f); err != nil {
		t.Fatalf("admin deploying a dir volume: %v", err)
	}

	// Re-deploying the volume exactly as stored needs no new authority.
	if err := corrosion.UpsertStack(adminCtx(), s.db, corrosion.StackRecord{
		Name: "web", ComposeYAML: fmt.Sprintf(hostPathStackYAML, dir), State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.authorizeComposeHostPaths(userCtx("op", "operator"), f); err != nil {
		t.Fatalf("operator re-deploying an unchanged stored volume: %v", err)
	}
	// …but repointing it does.
	moved := mustParseCompose(t, fmt.Sprintf(hostPathStackYAML, t.TempDir()))
	if err := s.authorizeComposeHostPaths(userCtx("op", "operator"), moved); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("operator repointing a stored volume: got %v, want PermissionDenied", err)
	}
	// A protected directory is refused to an admin too.
	etc := mustParseCompose(t, fmt.Sprintf(hostPathStackYAML, "/etc/cron.d"))
	if err := s.authorizeComposeHostPaths(adminCtx(), etc); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("admin deploying a volume on /etc/cron.d: got %v, want InvalidArgument", err)
	}
}

// A stored stack from before the check cannot put a disk in a protected
// directory: resolveVolume refuses it at use time.
func TestPoolHostPath_StoredComposeVolumeOnProtectedDirIsRefusedAtUse(t *testing.T) {
	s := newPoolTestServer(t)
	if err := corrosion.UpsertStack(adminCtx(), s.db, corrosion.StackRecord{
		Name: "web", ComposeYAML: fmt.Sprintf(hostPathStackYAML, "/etc/cron.d"), State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.resolveVolume(adminCtx(), "web", "scratch"); err == nil {
		t.Fatalf("a stored volume on /etc/cron.d resolved")
	}
}

const hostPathRepoYAML = `
version: "1"
name: web
backup-repos:
  nightly:
    path: %s
vms:
  app:
    image: base
`

// A compose backup repo is a host path too: resolveBackupRepoPath already makes
// a custom absolute repo path admin-only, and registering one by name through a
// stack must not be the way around that — nor a way to repoint a name another
// stack registered.
func TestPoolHostPath_ComposeBackupReposNeedRootAuthority(t *testing.T) {
	s := newPoolTestServer(t)
	dir := t.TempDir()
	f := mustParseCompose(t, fmt.Sprintf(hostPathRepoYAML, dir))

	if err := s.authorizeComposeHostPaths(userCtx("op", "operator"), f); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("operator registering a backup repo path: got %v, want PermissionDenied", err)
	}
	if err := corrosion.UpsertBackupRepo(adminCtx(), s.db, corrosion.BackupRepo{Name: "nightly", Path: dir, StackName: "web"}); err != nil {
		t.Fatal(err)
	}
	if err := s.authorizeComposeHostPaths(userCtx("op", "operator"), f); err != nil {
		t.Fatalf("operator re-deploying an unchanged registration: %v", err)
	}
	other := mustParseCompose(t, fmt.Sprintf(hostPathRepoYAML, t.TempDir()))
	if err := s.authorizeComposeHostPaths(userCtx("op", "operator"), other); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("operator repointing a registered repo: got %v, want PermissionDenied", err)
	}
}

func mustParseCompose(t *testing.T, y string) *compose.File {
	t.Helper()
	f, err := compose.ParseBytes([]byte(y))
	if err != nil {
		t.Fatalf("parse compose: %v", err)
	}
	return f
}

// The gate is wired into DeployStack itself, ahead of anything a deploy does.
func TestPoolHostPath_DeployStackRefusesAnOperatorsHostPaths(t *testing.T) {
	for name, y := range map[string]string{
		"volume":      fmt.Sprintf(hostPathStackYAML, t.TempDir()),
		"backup repo": fmt.Sprintf(hostPathRepoYAML, t.TempDir()),
	} {
		t.Run(name, func(t *testing.T) {
			s := newPoolTestServer(t)
			stream := &mockDeployStream{ctx: userCtx("op", "operator")}
			err := s.DeployStack(&pb.DeployStackRequest{ComposeYaml: y}, stream)
			if status.Code(err) != codes.PermissionDenied {
				t.Fatalf("got %v, want PermissionDenied", err)
			}
			if repos, _ := corrosion.ListBackupRepos(adminCtx(), s.db); len(repos) != 0 {
				t.Fatalf("a refused deploy registered %v", repos)
			}
		})
	}
}

// publishNoClobber is the atomic half of no-clobber: the early check can race
// with a file or symlink appearing, and this must still refuse it.
func TestPublishNoClobber_NeverReplaces(t *testing.T) {
	dir := t.TempDir()
	tmp := filepath.Join(dir, ".upload-1.tmp")
	if err := os.WriteFile(tmp, []byte("new"), 0o644); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "a.iso")
	if err := os.WriteFile(file, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := publishNoClobber(tmp, file, "a.iso"); status.Code(err) != codes.AlreadyExists {
		t.Fatalf("over a file: got %v, want AlreadyExists", err)
	}
	if got, _ := os.ReadFile(file); string(got) != "old" {
		t.Fatalf("file replaced: %q", got)
	}
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "b.iso")
	if err := os.Symlink(victim, link); err != nil {
		t.Fatal(err)
	}
	if err := publishNoClobber(tmp, link, "b.iso"); status.Code(err) != codes.AlreadyExists {
		t.Fatalf("over a symlink: got %v, want AlreadyExists", err)
	}
	if got, _ := os.ReadFile(victim); string(got) != "keep" {
		t.Fatalf("written through the symlink: %q", got)
	}
	if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("symlink replaced (err=%v)", err)
	}
	fresh := filepath.Join(dir, "c.iso")
	if err := publishNoClobber(tmp, fresh, "c.iso"); err != nil {
		t.Fatalf("a free name: %v", err)
	}
	if got, _ := os.ReadFile(fresh); string(got) != "new" {
		t.Fatalf("published content = %q", got)
	}
}
