package main

import (
	"context"
	"time"

	"github.com/spf13/cobra"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/cli"
)

func newHostRenewCertCmd() *cobra.Command {
	var opts cli.RenewCertOptions
	cmd := &cobra.Command{
		Use:   "renew-cert <host>",
		Short: "Renew a host's cluster (mTLS) certificate in place",
		Long: `Issue a successor to a host's cluster certificate, install it, and revoke the old one.

Host certificates last five years. The daemon reports how long its certificate
has left (litevirt_certificate_expiry_timestamp_seconds) and notifies from 30
days out (certificate.expiring); renew any time before that.

The host keeps running throughout: its daemon serves the new certificate from
the next handshake on, with no restart, and peers accept it immediately because
the CA-signed successor names the certificate they have on record. The command
confirms the host presents the new certificate before it revokes the old one,
and puts the old pair back if it does not.

Must run from the machine that holds the cluster CA private key (the one that
ran 'lv host init'): there is no CSR flow. Peers on an older litevirt release do
not recognise the successor and accept it once the host's re-recorded serial
reaches them by replication — renew after an upgrade has finished.

  lv host renew-cert host-b
  lv host renew-cert host-b --ssh root@10.0.50.11`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				return cli.HostRenewCert(ctx, c, args[0], opts)
			})
		},
	}
	cmd.Flags().StringVar(&opts.SSHTarget, "ssh", "",
		"SSH target for the host (default root@<host>) — needed when the litevirt host name is not the address you reach it on")
	cmd.Flags().IntVar(&opts.GRPCPort, "grpc-port", 7443, "the host's gRPC port, dialled to confirm the certificate it presents")
	cmd.Flags().BoolVar(&opts.KeepOld, "keep-old", false,
		"do not revoke the replaced certificate (it stays CA-valid until it expires)")
	cmd.Flags().DurationVar(&opts.Wait, "wait", 90*time.Second, "how long to wait for each confirmation")
	return cmd
}
