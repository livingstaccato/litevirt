package daemon

import (
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/litevirt/litevirt/internal/pki"
)

// localRecyclingConn is the web UI's and the REST gateway's client of this
// daemon's own gRPC listener. It reconnects when this host's certificate is
// renewed (pki.RecyclingConn): the server accepts no new RPC on a connection
// made with the replaced certificate.
func (d *Daemon) localRecyclingConn() (*pki.RecyclingConn, error) {
	return localRecyclingConn(d.cfg.PKIDir, d.cfg.GRPCPort)
}

func localRecyclingConn(pkiDir string, port int) (*pki.RecyclingConn, error) {
	return pki.NewRecyclingConn(pkiDir, func() (*grpc.ClientConn, error) {
		tlsCfg, err := pki.ClientTLSConfig(pkiDir)
		if err != nil {
			return nil, err
		}
		return grpc.NewClient(fmt.Sprintf("127.0.0.1:%d", port),
			grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)),
			grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(localMaxRecvMsgSize)),
		)
	})
}
