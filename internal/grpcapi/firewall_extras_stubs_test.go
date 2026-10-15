package grpcapi

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// firewallExtrasStubFiles maps each firewall-extras track's stub file to the
// RPCs it owns. A track deletes an RPC's stub when it implements it.
var firewallExtrasStubFiles = map[string][]string{
	"firewall_synflood_stubs.go":  {"GetFirewallSynflood", "SetFirewallSynflood"},
	"firewall_log_stubs.go":       {"GetFirewallLogPolicy", "SetFirewallLogPolicy", "ListFirewallLog"},
	"firewall_tag_group_stubs.go": {"ListFirewallTagGroups", "SetFirewallTagGroup", "DeleteFirewallTagGroup", "ListFirewallTags", "SetFirewallTags"},
}

func firewallExtrasRPCs() []string {
	var out []string
	for _, rpcs := range firewallExtrasStubFiles {
		out = append(out, rpcs...)
	}
	sort.Strings(out)
	return out
}

// serverMethodFiles maps each method declared on *Server in this package's
// non-test files to the file that declares it.
func serverMethodFiles(t *testing.T) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	fset := token.NewFileSet()
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, n, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if ok && recvTypeName(fd) == "Server" {
				out[fd.Name.Name] = n
			}
		}
	}
	return out
}

func recvTypeName(fd *ast.FuncDecl) string {
	if fd.Recv == nil || len(fd.Recv.List) == 0 {
		return ""
	}
	t := fd.Recv.List[0].Type
	if st, ok := t.(*ast.StarExpr); ok {
		t = st.X
	}
	if id, ok := t.(*ast.Ident); ok {
		return id.Name
	}
	return ""
}

// Every firewall-extras RPC is declared on *Server, never left to the embedded
// UnimplementedLiteVirtServer: either as its track's stub, which answers
// Unimplemented so `lv` can tell the operator to upgrade the daemon, or, once
// the track lands, as its implementation in another file.
//
// Mutations: delete a stub method (it falls through to the embedded server)
// — red; make a stub return nil, nil — red.
func TestFirewallExtrasStubs_AnswerUnimplemented(t *testing.T) {
	declared := serverMethodFiles(t)
	s := testServer(t)
	sv := reflect.ValueOf(s)
	for file, rpcs := range firewallExtrasStubFiles {
		for _, rpc := range rpcs {
			where, ok := declared[rpc]
			if !ok {
				t.Errorf("%s is not declared on *Server: keep its stub in %s until the track implements it", rpc, file)
				continue
			}
			if where != file {
				continue // implemented by its track
			}
			m := sv.MethodByName(rpc)
			req := reflect.New(m.Type().In(1).Elem())
			out := m.Call([]reflect.Value{reflect.ValueOf(context.Background()), req})
			err, _ := out[1].Interface().(error)
			if status.Code(err) != codes.Unimplemented || !strings.Contains(err.Error(), rpc) {
				t.Errorf("stub %s in %s = %v, want Unimplemented naming the RPC", rpc, file, err)
			}
			if !out[0].IsNil() {
				t.Errorf("stub %s returned a reply", rpc)
			}
		}
	}
}
