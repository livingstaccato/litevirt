package grpcapi

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/auth"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// VMSpec.iso is attached as a read-only CD-ROM, so whoever names it reads that
// host file from inside the guest. Before this was gated an operator could
// boot a guest with iso=<pki_dir>/host.key and copy the host's peer key — which
// is admin on every node — off /dev/sr0.

// isoServer is provableCreateServer with a real PKI directory holding a host
// key, so a test can aim an ISO at it.
func isoServer(t *testing.T) (*Server, *libvirtfake.Fake, string) {
	t.Helper()
	s, fake := provableCreateServer(t)
	s.pkiDir = filepath.Join(t.TempDir(), "pki")
	if err := os.MkdirAll(s.pkiDir, 0o700); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(s.pkiDir, "host.key")
	if err := os.WriteFile(key, []byte("-----BEGIN PRIVATE KEY-----\nsecret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return s, fake, key
}

func isoCreate(name, iso, project string) *pb.CreateVMRequest {
	req := disklessCreateRequest(name)
	req.Spec.Iso = iso
	req.Spec.Project = project
	// No NIC: a raw bridge needs network authority a project operator lacks,
	// and nothing here is about networks.
	req.Spec.Network = nil
	return req
}

// isoEngineCtx gives user `name` one RBAC binding and returns their context.
func isoEngineCtx(t *testing.T, s *Server, name, role, path string) context.Context {
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
	return userCtx(name, "operator")
}

// isoPool registers a dir pool on the test host owned by project and returns
// its directory.
func isoPool(t *testing.T, s *Server, name, project string) string {
	t.Helper()
	dir := t.TempDir()
	if err := corrosion.UpsertStoragePool(context.Background(), s.db, corrosion.StoragePoolRecord{
		HostName: s.hostName, Name: name, Driver: "dir", Target: dir, Project: project, State: "active",
	}); err != nil {
		t.Fatalf("UpsertStoragePool: %v", err)
	}
	return dir
}

func writeISO(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("CD001"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func assertNoISODomain(t *testing.T, s *Server, fake *libvirtfake.Fake, name, iso string) {
	t.Helper()
	if strings.Contains(fake.DefinedXML(name), iso) {
		t.Fatalf("the refused ISO %s was attached to %s", iso, name)
	}
	if rec, _ := corrosion.GetVM(context.Background(), s.db, name); rec != nil {
		t.Fatalf("a refused create persisted %s", name)
	}
}

// The reported exploit: an operator attaches the host key as a CD-ROM.
func TestVMISO_OperatorCannotAttachTheHostKey(t *testing.T) {
	s, fake, key := isoServer(t)
	_, err := s.CreateVM(userCtx("op", "operator"), isoCreate("leak", key, ""))
	if err == nil {
		t.Fatalf("an operator attached %s as an ISO", key)
	}
	assertNoISODomain(t, s, fake, "leak", key)
}

// Any host path outside a pool needs storage.hostpath at "/", which no
// operator holds — legacy, project-scoped or rooted.
func TestVMISO_NonAdminCannotNameAHostPath(t *testing.T) {
	callers := map[string]func(t *testing.T, s *Server) (context.Context, string){
		"legacy operator": func(*testing.T, *Server) (context.Context, string) { return userCtx("op", "operator"), "" },
		"project operator": func(t *testing.T, s *Server) (context.Context, string) {
			return isoEngineCtx(t, s, "pat", "Operator", projectRBACBase("acme")), "acme"
		},
		"project admin": func(t *testing.T, s *Server) (context.Context, string) {
			return isoEngineCtx(t, s, "pam", "Admin", projectRBACBase("acme")), "acme"
		},
		"root operator": func(t *testing.T, s *Server) (context.Context, string) {
			return isoEngineCtx(t, s, "rob", "Operator", "/"), ""
		},
	}
	for cname, mk := range callers {
		t.Run(cname, func(t *testing.T) {
			s, fake, _ := isoServer(t)
			if err := corrosion.InsertProject(context.Background(), s.db, corrosion.ProjectRecord{Name: "acme"}); err != nil {
				t.Fatal(err)
			}
			ctx, project := mk(t, s)
			iso := filepath.Join(t.TempDir(), "shadow.iso")
			writeISO(t, iso)
			_, err := s.CreateVM(ctx, isoCreate("v", iso, project))
			if status.Code(err) != codes.PermissionDenied {
				t.Fatalf("got %v, want PermissionDenied", err)
			}
			assertNoISODomain(t, s, fake, "v", iso)
		})
	}
}

// What the content browser offers keeps working: a project operator attaches
// an .iso from a pool its project owns.
func TestVMISO_ProjectOperatorMayAttachAPoolISO(t *testing.T) {
	s, fake, _ := isoServer(t)
	if err := corrosion.InsertProject(context.Background(), s.db, corrosion.ProjectRecord{Name: "acme"}); err != nil {
		t.Fatal(err)
	}
	pat := isoEngineCtx(t, s, "pat", "Operator", projectRBACBase("acme"))
	dir := isoPool(t, s, "isos", "acme")
	iso := filepath.Join(dir, "debian-12.iso")
	writeISO(t, iso)
	if _, err := s.CreateVM(pat, isoCreate("inst", iso, "acme")); err != nil {
		t.Fatalf("a pool ISO the caller may read: %v", err)
	}
	if !strings.Contains(fake.DefinedXML("inst"), iso) {
		t.Fatalf("the pool ISO was not attached:\n%s", fake.DefinedXML("inst"))
	}
}

// A pool file is only an ISO if it is a plain .iso in a pool the caller may
// read and the VM's project may use.
func TestVMISO_PoolRouteRefusals(t *testing.T) {
	cases := map[string]func(t *testing.T, s *Server, own, other string) string{
		"another project's pool": func(t *testing.T, s *Server, own, other string) string {
			p := filepath.Join(other, "theirs.iso")
			writeISO(t, p)
			return p
		},
		"not an .iso (a VM disk)": func(t *testing.T, s *Server, own, other string) string {
			p := filepath.Join(own, "web-1-root.qcow2")
			writeISO(t, p)
			return p
		},
		"a symlink to the host key": func(t *testing.T, s *Server, own, other string) string {
			p := filepath.Join(own, "evil.iso")
			if err := os.Symlink(filepath.Join(s.pkiDir, "host.key"), p); err != nil {
				t.Fatal(err)
			}
			return p
		},
		"a symlink to a file outside the pool": func(t *testing.T, s *Server, own, other string) string {
			out := filepath.Join(t.TempDir(), "x.iso")
			writeISO(t, out)
			p := filepath.Join(own, "out.iso")
			if err := os.Symlink(out, p); err != nil {
				t.Fatal(err)
			}
			return p
		},
		"traversal out of the pool": func(t *testing.T, s *Server, own, other string) string {
			return own + "/../" + filepath.Base(own) + "/x.iso"
		},
		"a dot file": func(t *testing.T, s *Server, own, other string) string {
			p := filepath.Join(own, ".hidden.iso")
			writeISO(t, p)
			return p
		},
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			s, fake, _ := isoServer(t)
			for _, p := range []string{"acme", "other"} {
				if err := corrosion.InsertProject(context.Background(), s.db, corrosion.ProjectRecord{Name: p}); err != nil {
					t.Fatal(err)
				}
			}
			pat := isoEngineCtx(t, s, "pat", "Operator", projectRBACBase("acme"))
			own := isoPool(t, s, "isos", "acme")
			other := isoPool(t, s, "theirs", "other")
			iso := mk(t, s, own, other)
			_, err := s.CreateVM(pat, isoCreate("v", iso, "acme"))
			if c := status.Code(err); c != codes.PermissionDenied && c != codes.InvalidArgument {
				t.Fatalf("got %v, want PermissionDenied or InvalidArgument", err)
			}
			assertNoISODomain(t, s, fake, "v", iso)
		})
	}
}

// A root Admin may name a host path (by legacy role or by binding), but never a
// protected one.
func TestVMISO_AdminHostPaths(t *testing.T) {
	s, fake, key := isoServer(t)
	ok := filepath.Join(t.TempDir(), "virtio-win.iso")
	writeISO(t, ok)
	if _, err := s.CreateVM(adminCtx(), isoCreate("good", ok, "")); err != nil {
		t.Fatalf("admin naming %s: %v", ok, err)
	}
	if !strings.Contains(fake.DefinedXML("good"), ok) {
		t.Fatal("the admin's ISO was not attached")
	}

	stateDB := filepath.Join(s.dataDir, "state.db")
	cidata := filepath.Join(s.dataDir, "cloudinit", "other.iso")
	for _, p := range []string{stateDB, cidata} {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		writeISO(t, p)
	}
	// An existing, harmless file reached through "..": refused for being unclean.
	if err := os.MkdirAll(filepath.Join(filepath.Dir(ok), "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	unclean := filepath.Dir(ok) + "/sub/../virtio-win.iso"
	link := filepath.Join(t.TempDir(), "innocent.iso")
	if err := os.Symlink(key, link); err != nil {
		t.Fatal(err)
	}
	for i, p := range []string{key, stateDB, cidata, link, "/etc/shadow", "/proc/self/environ", "relative.iso", unclean,
		t.TempDir(), filepath.Join(t.TempDir(), "missing.iso")} {
		name := "bad" + string(rune('a'+i))
		_, err := s.CreateVM(adminCtx(), isoCreate(name, p, ""))
		if status.Code(err) != codes.InvalidArgument {
			t.Errorf("admin naming %s: got %v, want InvalidArgument", p, err)
		}
		assertNoISODomain(t, s, fake, name, p)
	}
}

// The forwarded leg arrives as a peer, which passes every authority check; the
// owner's own filesystem check still refuses a planted symlink.
func TestVMISO_OwnerRefusesASymlinkFromAPeer(t *testing.T) {
	s, fake, key := isoServer(t)
	own := isoPool(t, s, "isos", "")
	link := filepath.Join(own, "planted.iso")
	if err := os.Symlink(key, link); err != nil {
		t.Fatal(err)
	}
	// A forwarded leg: the mTLS peer, which the interceptor admits as admin.
	peer := peerCtxFor(t, s, "entry-node")
	peer = context.WithValue(peer, ctxKeyUsername, "entry-node")
	peer = context.WithValue(peer, ctxKeyRole, "admin")
	_, err := s.CreateVM(peer, isoCreate("fwd", link, ""))
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("peer-forwarded create with a planted symlink: got %v, want InvalidArgument", err)
	}
	assertNoISODomain(t, s, fake, "fwd", link)
}

// A VM created before the gate, whose stored ISO is a protected file, does not
// start again; one with an ordinary ISO starts as before.
func TestVMISO_StartRefusesAStoredProtectedISO(t *testing.T) {
	s, fake, key := isoServer(t)
	ok := filepath.Join(t.TempDir(), "ok.iso")
	writeISO(t, ok)
	for _, name := range []string{"old-bad", "old-good"} {
		if _, err := s.CreateVM(adminCtx(), isoCreate(name, ok, "")); err != nil {
			t.Fatalf("CreateVM %s: %v", name, err)
		}
		if err := fake.DestroyDomain(name); err != nil {
			t.Fatalf("DestroyDomain: %v", err)
		}
		if err := s.db.Execute(context.Background(), `UPDATE vms SET state = 'stopped' WHERE name = ?`, name); err != nil {
			t.Fatal(err)
		}
	}
	// What a pre-fix create would have stored.
	rec, _ := corrosion.GetVM(context.Background(), s.db, "old-bad")
	var spec pb.VMSpec
	if err := json.Unmarshal([]byte(rec.Spec), &spec); err != nil {
		t.Fatal(err)
	}
	spec.Iso = key
	b, _ := json.Marshal(&spec)
	if err := s.db.Execute(context.Background(), `UPDATE vms SET spec = ? WHERE name = 'old-bad'`, string(b)); err != nil {
		t.Fatal(err)
	}

	if _, err := s.StartVM(adminCtx(), &pb.StartVMRequest{Name: "old-bad"}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("starting a VM whose stored ISO is the host key: got %v, want FailedPrecondition", err)
	}
	if st, _ := fake.DomainState("old-bad"); st == "running" {
		t.Fatal("the VM with the host key as its ISO was started")
	}
	if _, err := s.StartVM(adminCtx(), &pb.StartVMRequest{Name: "old-good"}); err != nil {
		t.Fatalf("starting a VM with an ordinary ISO: %v", err)
	}
}
