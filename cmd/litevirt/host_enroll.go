package main

import (
	"github.com/litevirt/litevirt/internal/cli"
	"github.com/spf13/cobra"
)

func newHostEnrollCmd() *cobra.Command {
	return &cobra.Command{Use: "host-enroll", Hidden: true, Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		request, err := cli.DecodeHostEnrollment(cmd.InOrStdin())
		if err != nil {
			return err
		}
		return cli.RunHostEnrollment(cmd.Context(), request)
	}}
}
