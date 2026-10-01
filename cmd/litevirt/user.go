package main

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/cli"
)

func newUserCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "user",
		Short: "Manage users and API tokens",
	}
	cmd.AddCommand(
		newUserCreateCmd(),
		newUserListCmd(),
		newUserDeleteCmd(),
		newUserPasswdCmd(),
		newTokenCreateCmd(),
		newTokenRevokeCmd(),
		newUserResetAdminCmd(),
	)
	return cmd
}

// newUserPasswdCmd changes a local-realm password: your own (after the current
// one) or, as admin, another user's (a reset, no old password needed).
func newUserPasswdCmd() *cobra.Command {
	var oldPw, newPw string
	cmd := &cobra.Command{
		Use:   "passwd [username]",
		Short: "Change a password (your own, or another user's as admin)",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var username string
			if len(args) == 1 {
				username = args[0]
			}
			if newPw == "" {
				var err error
				if newPw, err = cli.ReadPassword("New password: "); err != nil {
					return err
				}
				confirm, err := cli.ReadPassword("Confirm new password: ")
				if err != nil {
					return err
				}
				if confirm != newPw {
					return fmt.Errorf("passwords do not match")
				}
			}
			// Changing your own password requires the current one; an admin
			// resetting another user's password does not.
			if username == "" && oldPw == "" {
				var err error
				if oldPw, err = cli.ReadPassword("Current password: "); err != nil {
					return err
				}
			}
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				if _, err := c.ChangePassword(ctx, &pb.ChangePasswordRequest{
					Username: username, OldPassword: oldPw, NewPassword: newPw,
				}); err != nil {
					return err
				}
				fmt.Println("Password changed.")
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&oldPw, "old-password", "", "current password (prompts if unset; not needed for an admin reset of another user)")
	cmd.Flags().StringVar(&newPw, "new-password", "", "new password (prompts if unset)")
	return cmd
}

func newUserCreateCmd() *cobra.Command {
	var role string
	var password string
	cmd := &cobra.Command{
		Use:   "create <username>",
		Short: "Create a user",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if password == "" {
				var err error
				password, err = cli.ReadPassword("Password: ")
				if err != nil {
					return err
				}
			}
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				u, err := c.CreateUser(ctx, &pb.CreateUserRequest{
					Username: args[0],
					Password: password,
					Role:     role,
				})
				if err != nil {
					return err
				}
				fmt.Printf("Created user %q (role: %s)\n", u.Username, u.Role)
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&role, "role", "viewer", "Role: admin, operator, viewer")
	cmd.Flags().StringVar(&password, "password", "", "Password (reads from terminal if not set)")
	return cmd
}

func newUserListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ls",
		Short: "List users",
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.ListUsers(ctx, &emptypb.Empty{})
				if err != nil {
					return err
				}

				w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
				fmt.Fprintln(w, "USERNAME\tROLE\tCREATED")
				for _, u := range resp.Users {
					created := ""
					if u.CreatedAt != nil {
						created = u.CreatedAt.AsTime().Format("2006-01-02")
					}
					fmt.Fprintf(w, "%s\t%s\t%s\n", u.Username, u.Role, created)
				}
				return w.Flush()
			})
		},
	}
}

func newUserDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delete <username>",
		Short: "Delete a user",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				_, err := c.DeleteUser(ctx, &pb.DeleteUserRequest{Username: args[0]})
				if err != nil {
					return err
				}
				fmt.Printf("Deleted user %q\n", args[0])
				return nil
			})
		},
	}
}

func newTokenCreateCmd() *cobra.Command {
	var expires string
	var scopePaths []string
	cmd := &cobra.Command{
		Use:   "token-create <username> <token-name>",
		Short: "Create an API token for a user",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				tok, err := c.CreateToken(ctx, &pb.CreateTokenRequest{
					Username:   args[0],
					Name:       args[1],
					Expires:    expires,
					ScopePaths: scopePaths,
				})
				if err != nil {
					return err
				}
				fmt.Printf("Token ID:  %s\n", tok.Id)
				fmt.Printf("Token:     %s\n", tok.Token)
				if len(scopePaths) > 0 {
					fmt.Printf("Scope:     %v\n", scopePaths)
				}
				fmt.Println("\nSave this token — it will not be shown again.")
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&expires, "expires", "", "Expiry time (RFC3339, e.g. 2026-12-31T00:00:00Z)")
	cmd.Flags().StringSliceVar(&scopePaths, "scope-path", nil,
		"Restrict the token to a path subtree (repeatable; e.g. --scope-path /projects/acme)")
	return cmd
}

func newTokenRevokeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "token-revoke <token-id>",
		Short: "Revoke an API token",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				_, err := c.RevokeToken(ctx, &pb.RevokeTokenRequest{Id: args[0]})
				if err != nil {
					return err
				}
				fmt.Printf("Token %q revoked\n", args[0])
				return nil
			})
		},
	}
}
