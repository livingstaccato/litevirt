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

The old certificate is revoked unless the host is a member of the adopted voter
generation: that generation's certificate carries the host's votes signed with
it, and revoking would stop a node that adopts the generation later from
verifying it until the voter set next changes. Revoke it then with
'lv host revoke-cert', or now with --revoke-old.

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
	cmd.Flags().BoolVar(&opts.RevokeOld, "revoke-old", false,
		"revoke the replaced certificate even when the host is a voter")
	cmd.MarkFlagsMutuallyExclusive("keep-old", "revoke-old")
	cmd.Flags().DurationVar(&opts.Wait, "wait", 90*time.Second, "how long to wait for each confirmation")
	return cmd
}

func newHostUICertCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ui-cert",
		Short: "Manage a host's custom web UI certificate (corporate PKI)",
	}
	cmd.AddCommand(newHostUICertSetCmd(), newHostUICertClearCmd())
	return cmd
}

func newHostUICertSetCmd() *cobra.Command {
	var opts cli.UICertOptions
	cmd := &cobra.Command{
		Use:   "set <host> --cert <chain.pem> --key <key.pem>",
		Short: "Install a certificate from your own PKI for a host's web UI",
		Long: `Install a certificate chain and key for the web UI on one host.

The chain file holds the server certificate first, then each intermediate in
order (the root is optional). Before anything is sent the command checks that
the key matches, the chain is in order, nothing in it has expired, it is a
server certificate, and its names cover the host — its litevirt name or
address, or every --name you give. The daemon checks it again before serving.

The key is installed at /etc/litevirt/pki/ui.key with mode 0600 and is never
printed. The UI serves the certificate from the next connection, switching from
plain HTTP to HTTPS within seconds if needed — no restart. Replace it with
another 'set' (renewals work the same way); 'clear' goes back to ACME or the
cluster certificate.

  lv host ui-cert set host-b --cert ui-chain.pem --key ui.key
  lv host ui-cert set host-b --cert ui-chain.pem --key ui.key --name hv-b.corp.example`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				return cli.HostUICertSet(ctx, c, args[0], opts)
			})
		},
	}
	cmd.Flags().StringVar(&opts.CertPath, "cert", "", "PEM file: the server certificate followed by its intermediates, in order")
	cmd.Flags().StringVar(&opts.KeyPath, "key", "", "PEM file: the server certificate's private key")
	cmd.Flags().StringSliceVar(&opts.Names, "name", nil,
		"a name the UI is reached by, which the certificate must cover (repeatable; default: the host's name or address)")
	cmd.Flags().StringVar(&opts.SSHTarget, "ssh", "", "SSH target for the host (default root@<host>)")
	_ = cmd.MarkFlagRequired("cert")
	_ = cmd.MarkFlagRequired("key")
	return cmd
}

func newHostUICertClearCmd() *cobra.Command {
	var opts cli.UICertOptions
	cmd := &cobra.Command{
		Use:   "clear <host>",
		Short: "Remove a host's custom web UI certificate",
		Long: `Remove the custom UI certificate from a host. The UI then serves ACME's
certificate when acme: is configured; otherwise the cluster certificate when
ui_tls is on, or plain HTTP under the default ui_tls: auto. No restart.

  lv host ui-cert clear host-b`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return cli.HostUICertClear(cmd.Context(), args[0], opts)
		},
	}
	cmd.Flags().StringVar(&opts.SSHTarget, "ssh", "", "SSH target for the host (default root@<host>)")
	return cmd
}

func newHostRevokeCertCmd() *cobra.Command {
	var serial string
	var grpcPort int
	cmd := &cobra.Command{
		Use:   "revoke-cert <host> --serial <hex>",
		Short: "Revoke a host certificate a renewal replaced",
		Long: `Revoke one certificate serial issued to a host and publish the CRL.

This is the deferred half of 'lv host renew-cert': for a certificate kept with
--keep-old, or a voter's replaced certificate held until the voter set changed.
It refuses the serial the cluster records for the host and the one the host
presents — revoking either would cut the host off; removing a host is
'lv host rm'. Run it where the cluster CA key is.

  lv host revoke-cert host-b --serial 4f1c…`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				return cli.HostRevokeCert(ctx, c, args[0], serial, grpcPort)
			})
		},
	}
	cmd.Flags().StringVar(&serial, "serial", "", "the certificate serial to revoke (hex, as renew-cert printed it)")
	cmd.Flags().IntVar(&grpcPort, "grpc-port", 7443, "the host's gRPC port, dialled to make sure it is not presenting this serial")
	_ = cmd.MarkFlagRequired("serial")
	return cmd
}
