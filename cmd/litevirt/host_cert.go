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

The host generates the new key itself and sends only a certificate request;
the key never crosses SSH. It installs the certificate as one atomic switch (a
crash at any point leaves a pair the daemon starts with), and its daemon serves
it from the next handshake on, with no restart. Peers accept it immediately
because the CA-signed successor names the certificate they have on record. The
command confirms the host presents the new certificate, and puts the old one
back only when the host demonstrably still presents it; an issued successor
that is never used is revoked.

The replaced certificate is then revoked. When revoking it now would leave the
newest voter generation unverifiable for a node that adopts it later, the
revocation is recorded as owed (a degraded condition, notified daily) and the
cluster publishes it by itself once that is safe; --revoke-old revokes now
regardless, --keep-old not at all ('lv host revoke-cert' later). It refuses
while hosts run different builds unless --force.

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
		"revoke the replaced certificate now, even when the voter chain would hold it as owed")
	cmd.Flags().BoolVar(&opts.Force, "force", false, "renew although hosts run different builds")
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
	var force bool
	cmd := &cobra.Command{
		Use:   "revoke-cert <host> --serial <hex>",
		Short: "Revoke a host certificate a renewal replaced",
		Long: `Revoke one certificate serial issued to a host and publish the CRL.

The manual path after 'lv host renew-cert': a certificate kept with --keep-old,
an owed revocation you want published now, or a successor a failed renewal
left. It accepts only a serial known to be the host's — one this machine's
renewal log records for it, or the predecessor named by the certificate the
host presents — and refuses any serial another host is recorded with. The
host's own live certificate, or the one it presents, needs --force: revoking it
cuts the host off and gets it FENCED (removing a host is 'lv host rm'). If the
host's presented certificate cannot be read, it refuses unless --force. Run it
where the cluster CA key is.

  lv host revoke-cert host-b --serial 4f1c…`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				return cli.HostRevokeCert(ctx, c, args[0], serial, grpcPort, force)
			})
		},
	}
	cmd.Flags().StringVar(&serial, "serial", "", "the certificate serial to revoke (hex, as renew-cert printed it)")
	cmd.Flags().IntVar(&grpcPort, "grpc-port", 7443, "the host's gRPC port, dialled to make sure it is not presenting this serial")
	cmd.Flags().BoolVar(&force, "force", false,
		"revoke even the host's live or presented certificate (fences it), or when its certificate cannot be read")
	_ = cmd.MarkFlagRequired("serial")
	return cmd
}
