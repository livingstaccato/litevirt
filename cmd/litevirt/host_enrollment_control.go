package main

import (
	"github.com/litevirt/litevirt/internal/cli"
	"github.com/spf13/cobra"
)

func newHostEnrollmentControlCmd() *cobra.Command {
	return &cobra.Command{
		Use:    "host-enroll-control <rollback|launcher|worker>",
		Hidden: true,
		Args:   cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return cli.RunEnrollmentControl(cmd.Context(), args[0])
		},
	}
}
