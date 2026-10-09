package grpcapi

import (
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// composeISOCreate is the create a compose file's VM with iso: makes.
func composeISOCreate(t *testing.T, name, iso, project string) *pb.CreateVMRequest {
	t.Helper()
	spec, err := compose.BuildVMSpec(name, name, &compose.VMDef{ISO: iso, CPU: 1, Memory: 256}, &compose.File{Name: "st"})
	if err != nil {
		t.Fatalf("BuildVMSpec: %v", err)
	}
	spec.Project = project
	spec.Network = nil
	return &pb.CreateVMRequest{Spec: spec}
}

// A compose file's iso: is judged exactly as any create's ISO: an Admin's
// host path is attached as the installer CD-ROM (it was refused as an image
// name, lab-recheck-5 11:17), and a non-admin still cannot name a host path
// through compose any more than directly.
func TestComposeISO_IsJudgedAsAnyCreatesISO(t *testing.T) {
	s, fake, _ := isoServer(t)
	p := filepath.Join(t.TempDir(), "x.iso")
	writeLibFile(t, p, isoBody)

	if _, err := s.CreateVM(adminCtx(), composeISOCreate(t, "adm", p, "")); err != nil {
		t.Fatalf("admin compose iso host path: %v", err)
	}
	if !strings.Contains(fake.DefinedXML("adm"), p) {
		t.Fatal("the compose file's ISO was not attached")
	}

	pat := acmeOperator(t, s)
	// Positive control: the same operator's compose create naming a library
	// ISO succeeds, so the refusal below is the host-path rule and nothing
	// else about this create.
	libraryMode(t, s, corrosion.ISOLibraryShared)
	lib := globalLibrary(t, s)
	writeLibFile(t, filepath.Join(lib, "debian-12.iso"), isoBody)
	if _, err := s.CreateVM(pat, composeISOCreate(t, "oplib", "isos/debian-12.iso", "acme")); err != nil {
		t.Fatalf("operator compose iso from the library: %v", err)
	}
	if !strings.Contains(fake.DefinedXML("oplib"), filepath.Join(mustEval(t, lib), "debian-12.iso")) {
		t.Fatal("the operator's library ISO was not attached")
	}
	_, err := s.CreateVM(pat, composeISOCreate(t, "op", p, "acme"))
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("operator compose iso host path: got %v, want PermissionDenied", err)
	}
	if !strings.Contains(err.Error(), "iso") {
		t.Fatalf("the operator's refusal %q is not the ISO rule", err)
	}
}
