package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/litevirt/litevirt/internal/pki"
)

// newHostPKICmd is the host side of `lv host renew-cert`, run over SSH on the
// host being renewed. Hidden: it is an internal protocol between two copies of
// this binary, not an operator command. The private key is generated and kept
// here; only a certificate request leaves and only a certificate comes back.
func newHostPKICmd() *cobra.Command {
	var dir string
	cmd := &cobra.Command{
		Use:    "host-pki",
		Short:  "Host side of certificate renewal (internal)",
		Hidden: true,
	}
	cmd.PersistentFlags().StringVar(&dir, "pki-dir", "/etc/litevirt/pki", "the host's PKI directory")
	out := func(v any) error { return json.NewEncoder(os.Stdout).Encode(v) }

	var name string
	gen := &cobra.Command{
		Use:  "gen-csr",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			id, csr, err := pki.GenerateRenewalCSR(dir, name)
			if err != nil {
				return err
			}
			return out(map[string]string{"staging": id, "csr": string(csr)})
		},
	}
	gen.Flags().StringVar(&name, "name", "", "the host name the request is for")

	var staging string
	install := &cobra.Command{
		Use:  "install",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cert, err := io.ReadAll(io.LimitReader(os.Stdin, 1<<20))
			if err != nil {
				return err
			}
			prev, next, err := pki.InstallRenewal(dir, staging, cert)
			if err != nil {
				return err
			}
			return out(map[string]string{"previous": prev, "serial": next})
		},
	}
	install.Flags().StringVar(&staging, "staging", "", "the staging id gen-csr returned")

	abandon := &cobra.Command{
		Use:  "abandon",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error { return pki.AbandonStaging(dir, staging) },
	}
	abandon.Flags().StringVar(&staging, "staging", "", "the staging id gen-csr returned")

	var to string
	rollback := &cobra.Command{
		Use:  "rollback",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if to == "" {
				return fmt.Errorf("--to is required")
			}
			return pki.RollbackRenewal(dir, to)
		},
	}
	rollback.Flags().StringVar(&to, "to", "", "the serial to switch back to")

	commit := &cobra.Command{
		Use:  "commit",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error { return pki.CommitRenewal(dir) },
	}

	for _, c := range []*cobra.Command{gen, install, abandon, rollback, commit} {
		c.Hidden = true
		cmd.AddCommand(c)
	}
	return cmd
}
