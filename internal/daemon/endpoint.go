package daemon

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"

	"github.com/litevirt/litevirt/internal/endpointfile"
)

// endpointFilePath is where this daemon publishes its endpoint file: the
// path a local `lv` reads (/run/litevirt/endpoint) for a root daemon, and
// under data_dir for any other (a test or development daemon, which must not
// write over a real node's).
func endpointFilePath(dataDir string) string {
	if os.Geteuid() == 0 {
		return endpointfile.Path
	}
	return filepath.Join(dataDir, "endpoint")
}

// publishEndpoint writes the endpoint file: this daemon's gRPC port and PKI
// directory, and nothing else. config.yaml is 0600 because it can hold
// inline secrets; the endpoint file is 0644, so a non-root `lv` on the node
// finds the daemon without reading it. A failure is logged, not fatal: `lv`
// then falls back to the defaults.
func (d *Daemon) publishEndpoint() {
	path := endpointFilePath(d.cfg.DataDir)
	if err := endpointfile.Write(path, endpointfile.Endpoint{GRPCPort: d.cfg.GRPCPort, PKIDir: d.cfg.PKIDir}); err != nil {
		slog.Warn("could not publish the endpoint file; a non-root CLI on this node falls back to the default port",
			"path", path, "error", err)
	}
}

// listenGRPC opens the gRPC listener and, once it is open, publishes the
// endpoint file (publishEndpoint), so the file never names a port this
// daemon failed to bind. Run's only way to the listener: a test pins that Run
// calls it (TestRun_ListensThroughListenGRPC).
func (d *Daemon) listenGRPC() (net.Listener, error) {
	lis, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", d.cfg.GRPCPort))
	if err != nil {
		return nil, fmt.Errorf("listen: %w", err)
	}
	d.publishEndpoint()
	return lis, nil
}
