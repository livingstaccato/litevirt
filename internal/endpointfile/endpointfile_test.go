package endpointfile

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRead_RoundTrip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "endpoint")
	if err := Write(p, Endpoint{GRPCPort: 9443, PKIDir: "/etc/litevirt/pki"}); err != nil {
		t.Fatal(err)
	}
	e, err := Read(p)
	if err != nil || e != (Endpoint{GRPCPort: 9443, PKIDir: "/etc/litevirt/pki"}) {
		t.Fatalf("Read = %+v, %v", e, err)
	}
}

func TestRead_MissingIsNotExist(t *testing.T) {
	if _, err := Read(filepath.Join(t.TempDir(), "endpoint")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Read of a missing file = %v, want fs.ErrNotExist", err)
	}
}

// Nothing in a malformed file is trusted.
//
// Mutations: drop KnownFields, the port check, the absolute-path check or the
// size bound: the matching case red.
func TestRead_RefusesAMalformedFile(t *testing.T) {
	for name, body := range map[string]string{
		"not yaml":       "grpc_port: [\n",
		"empty":          "",
		"unknown key":    "grpc_port: 7443\npki_dir: /etc/litevirt/pki\nbind_password: x\n",
		"no port":        "pki_dir: /etc/litevirt/pki\n",
		"port too large": "grpc_port: 70000\npki_dir: /etc/litevirt/pki\n",
		"relative pki":   "grpc_port: 7443\npki_dir: pki\n",
		"no pki":         "grpc_port: 7443\n",
		"too large":      "grpc_port: 7443\npki_dir: /etc/litevirt/pki\n#" + strings.Repeat("x", maxSize),
	} {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "endpoint")
			if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
			if e, err := Read(p); err == nil || errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("Read = %+v, %v; want a malformed-file error", e, err)
			}
		})
	}
}

func TestWrite_RefusesWhatReadWouldRefuse(t *testing.T) {
	p := filepath.Join(t.TempDir(), "endpoint")
	if err := Write(p, Endpoint{GRPCPort: 0, PKIDir: "/x"}); err == nil {
		t.Fatal("wrote port 0")
	}
	if _, err := os.Stat(p); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("a refused write left a file: %v", err)
	}
}
