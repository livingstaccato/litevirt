package main

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

func newSessionCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "session",
		Short: "Manage active login sessions",
	}
	cmd.AddCommand(newSessionListCmd(), newSessionRevokeCmd())
	return cmd
}

func newSessionListCmd() *cobra.Command {
	var username string
	cmd := &cobra.Command{
		Use:   "ls",
		Short: "List active sessions (own by default; --user requires admin)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.ListSessions(ctx, &pb.ListSessionsRequest{Username: username})
				if err != nil {
					return err
				}
				w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
				fmt.Fprintln(w, "ID\tUSER\tREALM\tIP\tLAST USED\tEXPIRES")
				for _, s := range resp.Sessions {
					fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
						shortID(s.Id), s.Username, s.Realm, s.Ip, s.LastUsedAt, s.ExpiresAt)
				}
				return w.Flush()
			})
		},
	}
	cmd.Flags().StringVar(&username, "user", "", "List sessions for another user (admin only)")
	return cmd
}

func newSessionRevokeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "revoke <session-id>",
		Short: "Revoke an active session",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				if _, err := c.RevokeSession(ctx, &pb.RevokeSessionRequest{Id: args[0]}); err != nil {
					return err
				}
				fmt.Printf("Session %s revoked.\n", args[0])
				return nil
			})
		},
	}
}

func newTwoFactorCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "2fa",
		Short: "Manage two-factor authentication",
	}
	cmd.AddCommand(new2FAListCmd(), new2FAEnrollCmd(), new2FADisableCmd(), new2FAPolicyCmd())
	return cmd
}

func new2FAListCmd() *cobra.Command {
	var username string
	cmd := &cobra.Command{
		Use:   "ls",
		Short: "List enrolled second factors",
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.ListTwoFactors(ctx, &pb.ListTwoFactorsRequest{Username: username})
				if err != nil {
					return err
				}
				w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
				fmt.Fprintln(w, "METHOD\tLABEL\tENROLLED\tLAST USED")
				for _, f := range resp.Factors {
					fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", f.Method, f.Label, f.EnrolledAt, f.LastUsedAt)
				}
				return w.Flush()
			})
		},
	}
	cmd.Flags().StringVar(&username, "user", "", "List for another user (admin only)")
	return cmd
}

func new2FAEnrollCmd() *cobra.Command {
	var username, label string
	cmd := &cobra.Command{
		Use:   "enroll-totp",
		Short: "Enroll a TOTP authenticator (returns provisioning URL + recovery codes)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.EnrollTOTP(ctx, &pb.EnrollTOTPRequest{
					Username: username, Label: label,
				})
				if err != nil {
					return err
				}
				fmt.Printf("Provisioning URL: %s\n", resp.OtpauthUrl)
				fmt.Printf("Manual secret:    %s\n", resp.SecretBase32)
				fmt.Println("\nRecovery codes (each usable once — save them now):")
				for _, code := range resp.RecoveryCodes {
					fmt.Printf("  %s\n", code)
				}
				if resp.GetSessionEnded() {
					fmt.Println("\nThis was an enrollment-only session and the enrollment ended it.")
					fmt.Println("Log in again with `lv login`, using a code from the new authenticator.")
				}
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&username, "user", "", "Enroll for another user (admin only); empty = self")
	cmd.Flags().StringVar(&label, "label", "", "Label for this factor (e.g. phone, yubikey)")
	return cmd
}

func new2FADisableCmd() *cobra.Command {
	var username, method, label string
	cmd := &cobra.Command{
		Use:   "disable",
		Short: "Disable an enrolled second factor",
		RunE: func(cmd *cobra.Command, args []string) error {
			if method == "" {
				return fmt.Errorf("--method is required (totp or webauthn)")
			}
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				if _, err := c.DisableTwoFactor(ctx, &pb.DisableTwoFactorRequest{
					Username: username, Method: method, Label: label,
				}); err != nil {
					return err
				}
				fmt.Println("Second factor disabled.")
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&username, "user", "", "Disable for another user (admin only); empty = self")
	cmd.Flags().StringVar(&method, "method", "", "totp | webauthn")
	cmd.Flags().StringVar(&label, "label", "", "Specific factor label (matches the enrolment label)")
	return cmd
}

// new2FAPolicyCmd shows or sets the cluster-wide mandatory second-factor
// policy. One flat subcommand: no argument shows it.
func new2FAPolicyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "policy [off|all|<realm>[,<realm>...]]",
		Short: "Show or set the mandatory second-factor policy (admin to set)",
		Long: `With no argument, show the cluster-wide second-factor policy.

With one, set it (admin only):

  off                 no second factor is required (the default)
  all                 every realm requires one
  local,ldap:corp     only the named realms require one

A user in a covered realm with no factor enrolled is not locked out: login
gives them an enrollment-only session that can enroll a factor
(` + "`lv 2fa enroll-totp`" + `) and nothing else, and the enrollment ends it.
Setting the policy ends every live session in a realm it newly covers,
your own included. API tokens are not subject to it.

Refused until login_policy_v1 has latched on every host.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				var p *pb.LoginPolicy
				var err error
				if len(args) == 0 {
					p, err = c.GetLoginPolicy(ctx, &emptypb.Empty{})
				} else {
					p, err = c.SetLoginPolicy(ctx, &pb.SetLoginPolicyRequest{Require_2Fa: args[0]})
				}
				if err != nil {
					return err
				}
				fmt.Printf("Second factor required: %s\n", p.GetRequire_2Fa())
				if p.GetSetBy() != "" {
					fmt.Printf("Set by:                 %s at %s\n", p.GetSetBy(), p.GetUpdatedAt())
				}
				if !p.GetSettable() {
					fmt.Println("Not settable here yet:  login_policy_v1 has not latched on every host")
				}
				if len(args) == 1 {
					fmt.Printf("Sessions ended:         %d (log in again if yours was one)\n", p.GetSessionsRevoked())
				}
				return nil
			})
		},
	}
}

// shortID truncates session IDs for table output. Full id is required to
// revoke, but the short form is enough to recognise.
func shortID(s string) string {
	if len(s) > 12 {
		return s[:12] + "…"
	}
	return s
}
