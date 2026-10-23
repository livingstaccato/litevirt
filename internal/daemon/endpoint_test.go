package daemon

import (
	"go/ast"
	"go/parser"
	"go/token"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/litevirt/litevirt/internal/endpointfile"
)

// The daemon publishes its endpoint for a non-root lv: the gRPC port and PKI
// directory and nothing else, 0644, replacing what was there (here a stale
// 0600 file) by a rename.
//
// Mutations: publish nothing: red. Leave the temp file's 0600: red. Write
// the whole config: red.
func TestPublishEndpoint_WritesOnlyThePortAndPKIDirWorldReadable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("a root daemon writes /run/litevirt/endpoint")
	}
	dir := filepath.Join(t.TempDir(), "data")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil { // not the umask's: the writer refuses a group-writable dir
		t.Fatal(err)
	}
	path := filepath.Join(dir, "endpoint")
	if err := os.WriteFile(path, []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	before, _ := os.Stat(path)
	t.Cleanup(endpointfile.SetReaderOwnerForTest(os.Getuid()))
	cfg := &Config{GRPCPort: 9443, PKIDir: "/etc/litevirt/pki", DataDir: dir, HostName: "node-1"}
	(&Daemon{cfg: cfg}).publishEndpoint()

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if want := "grpc_port: 9443\npki_dir: /etc/litevirt/pki\n"; string(got) != want {
		t.Fatalf("endpoint file = %q, want %q", got, want)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o644 {
		t.Errorf("endpoint file mode = %o, want 0644", fi.Mode().Perm())
	}
	if os.SameFile(before, fi) {
		t.Error("the file was rewritten in place, not replaced by a rename")
	}
	if e, err := endpointfile.Read(path); err != nil || e.GRPCPort != 9443 {
		t.Errorf("lv's reader rejects what the daemon wrote: %+v, %v", e, err)
	}
	if leftovers, _ := filepath.Glob(filepath.Join(dir, ".endpoint-*")); len(leftovers) != 0 {
		t.Errorf("temp files left behind: %v", leftovers)
	}
}

// The listener and the endpoint file come together: listenGRPC binds the
// port and then publishes it.
//
// Mutation: drop publishEndpoint from listenGRPC: red.
func TestListenGRPC_PublishesTheBoundPort(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("a root daemon writes /run/litevirt/endpoint")
	}
	free, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := free.Addr().(*net.TCPAddr).Port
	free.Close()
	dir := filepath.Join(t.TempDir(), "data")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(endpointfile.SetReaderOwnerForTest(os.Getuid()))
	lis, err := (&Daemon{cfg: &Config{GRPCPort: port, PKIDir: "/etc/litevirt/pki", DataDir: dir}}).listenGRPC()
	if err != nil {
		t.Skipf("port %d was taken between picking and binding it: %v", port, err)
	}
	defer lis.Close()
	e, err := endpointfile.Read(filepath.Join(dir, "endpoint"))
	if err != nil || e.GRPCPort != port {
		t.Fatalf("endpoint file = %+v, %v; want port %d", e, err, port)
	}
}

// Run reaches its gRPC listener only through listenGRPC, which publishes the
// endpoint file. Run itself is not run by any test (it needs root, libvirt
// and a cluster), so this reads its source: a Run that listens some other way
// leaves a non-root lv on the default port with nothing red.
//
// Mutations: Run calls net.Listen itself again: red. Run drops the call: red.
func TestRun_ListensThroughListenGRPC(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "daemon.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var run *ast.FuncDecl
	for _, decl := range f.Decls {
		if fd, ok := decl.(*ast.FuncDecl); ok && fd.Name.Name == "Run" && fd.Recv != nil {
			run = fd
		}
	}
	if run == nil {
		t.Fatal("no (*Daemon).Run in daemon.go")
	}
	calls := 0
	ast.Inspect(run.Body, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if x, ok := sel.X.(*ast.Ident); ok {
			if x.Name == "d" && sel.Sel.Name == "listenGRPC" {
				calls++
			}
			if x.Name == "net" && sel.Sel.Name == "Listen" {
				t.Errorf("Run calls net.Listen at %v: the gRPC listener must come from listenGRPC, which publishes the endpoint file",
					fset.Position(sel.Pos()))
			}
		}
		return true
	})
	if calls != 1 {
		t.Fatalf("Run calls d.listenGRPC %d times, want once", calls)
	}
}
