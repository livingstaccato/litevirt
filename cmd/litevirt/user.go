package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

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
		newUserDisableCmd(),
		newUserEnableCmd(),
		newUserExpireCmd(),
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
				fmt.Fprintln(w, "USERNAME\tROLE\tCREATED\tSTATUS\tEXPIRES")
				for _, u := range resp.Users {
					created := ""
					if u.CreatedAt != nil {
						created = u.CreatedAt.AsTime().Format("2006-01-02")
					}
					fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", u.Username, u.Role, created,
						userStatusLabel(u, time.Now()), orDash(u.GetExpiresAt()))
					// STATUS is the daemon's verdict, by the daemon's clock (m1).
				}
				return w.Flush()
			})
		},
	}
}

func newUserDeleteCmd() *cobra.Command {
	var exact bool
	cmd := &cobra.Command{
		Use:   "delete <username>",
		Short: "Delete a user (its sessions and API tokens are revoked)",
		Long: `Delete a user. Its sessions and API tokens are revoked and its open streams
end. Names are matched ignoring case and surrounding spaces; two accounts that
differ only that way are refused by every lookup — remove one with --exact,
which matches the name exactly as stored (admin, audited).`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				_, err := c.DeleteUser(ctx, &pb.DeleteUserRequest{Username: args[0], Exact: exact})
				if err != nil {
					return err
				}
				fmt.Printf("Deleted user %q\n", args[0])
				return nil
			})
		},
	}
	cmd.Flags().BoolVar(&exact, "exact", false, "match the name exactly as stored (to remove one of two case-duplicates)")
	return cmd
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

// userStatusLabel is the STATUS column of `lv user ls`.
func userStatusLabel(u *pb.User, now time.Time) string {
	if st := u.GetStatus(); st != "" {
		return st
	}
	// A daemon that predates User.status: judge it here.
	if u.GetDisabled() {
		return "disabled"
	}
	if e := u.GetExpiresAt(); e != "" {
		if t, err := time.Parse(time.RFC3339, e); err != nil || !now.Before(t) {
			return "expired"
		}
	}
	return "active"
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// setUserAccount is the one call behind disable, enable and expire.
func setUserAccount(cmd *cobra.Command, req *pb.SetUserAccountRequest, done string) error {
	return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
		u, err := c.SetUserAccount(ctx, req)
		if err != nil {
			return err
		}
		fmt.Printf("%s (status: %s, expires: %s)\n", done, userStatusLabel(u, time.Now()), orDash(u.GetExpiresAt()))
		return nil
	})
}

func newUserDisableCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "disable <username>",
		Short: "Disable an account: no login, and its sessions and API tokens stop working",
		Long: `Disable an account (admin only). It cannot log in through any realm, its
sessions are ended, and its API tokens are refused until it is re-enabled
with ` + "`lv user enable`" + `. Refused for the last admin that is enabled with no
expiry, and until login_policy_v1 has latched on every host.

A disable cannot reach the distributable lv-cli client certificate, which
authenticates as the cluster admin with no user behind it; turn on
auth.strict_mtls_identity to close that path.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			t := true
			return setUserAccount(cmd, &pb.SetUserAccountRequest{Username: args[0], Disabled: &t},
				fmt.Sprintf("Disabled user %q", args[0]))
		},
	}
}

func newUserEnableCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "enable <username>",
		Short: "Re-enable a disabled account",
		Long: `Re-enable an account disabled with ` + "`lv user disable`" + ` (admin only). Its
API tokens work again; its sessions were ended by the disable and stay ended.
An expiry is left as it is: clear it with ` + "`lv user expire <username> never`" + `.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			f := false
			return setUserAccount(cmd, &pb.SetUserAccountRequest{Username: args[0], Disabled: &f},
				fmt.Sprintf("Enabled user %q", args[0]))
		},
	}
}

func newUserExpireCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "expire <username> <RFC3339|never>",
		Short: "Set or clear the instant an account stops authenticating",
		Long: `Set the instant an account stops authenticating (admin only), e.g.
2026-12-31T00:00:00Z, or "never" to clear it. From that instant the account
cannot log in and its sessions and API tokens are refused. Setting an expiry
ends the account's current sessions. Refused for the last admin that is
enabled with no expiry, and until login_policy_v1 has latched on every host.`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			exp := args[1]
			if strings.EqualFold(exp, "never") {
				exp = ""
			}
			return setUserAccount(cmd, &pb.SetUserAccountRequest{Username: args[0], ExpiresAt: &exp},
				fmt.Sprintf("Set expiry of user %q", args[0]))
		},
	}
}
