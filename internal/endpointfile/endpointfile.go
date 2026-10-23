// Package endpointfile is the daemon's non-secret endpoint file,
// /run/litevirt/endpoint: what a local `lv` needs to dial this node's daemon
// (its gRPC port and PKI directory) without reading /etc/litevirt/config.yaml,
// which is root's and 0600 because it can hold inline secrets.
//
// The daemon writes it at start, 0644, atomically. It holds those two values
// and nothing else. A reader that finds it malformed does not trust any of it.
package endpointfile

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Path is where the daemon writes the file. A var so tests can move it.
var Path = "/run/litevirt/endpoint"

// maxSize bounds a read: the real file is two short lines.
const maxSize = 4096

// Endpoint is the file's content.
type Endpoint struct {
	GRPCPort int    `yaml:"grpc_port"`
	PKIDir   string `yaml:"pki_dir"`
}

func (e Endpoint) validate() error {
	if e.GRPCPort < 1 || e.GRPCPort > 65535 {
		return fmt.Errorf("grpc_port %d is not a TCP port", e.GRPCPort)
	}
	if e.PKIDir == "" || !filepath.IsAbs(e.PKIDir) || strings.ContainsAny(e.PKIDir, "\n\r\x00") {
		return fmt.Errorf("pki_dir %q is not an absolute path", e.PKIDir)
	}
	return nil
}

// Write writes e to path atomically (a temp file beside it, renamed over
// it), mode 0644, creating its directory 0755 if needed.
func Write(path string, e Endpoint) error {
	if err := e.validate(); err != nil {
		return err
	}
	out, err := yaml.Marshal(e)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".endpoint-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp) // a no-op once renamed
	if _, err := f.Write(out); err != nil {
		f.Close()
		return err
	}
	if err := f.Chmod(0o644); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Read reads and checks the file at path. A missing file is an error
// satisfying errors.Is(err, fs.ErrNotExist); any other error means the file
// is there and must not be used.
func Read(path string) (Endpoint, error) {
	f, err := os.Open(path)
	if err != nil {
		return Endpoint{}, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxSize+1))
	if err != nil {
		return Endpoint{}, err
	}
	if len(raw) > maxSize {
		return Endpoint{}, fmt.Errorf("larger than %d bytes", maxSize)
	}
	var e Endpoint
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&e); err != nil {
		if errors.Is(err, io.EOF) {
			return Endpoint{}, errors.New("empty")
		}
		return Endpoint{}, err
	}
	if err := e.validate(); err != nil {
		return Endpoint{}, err
	}
	return e, nil
}
