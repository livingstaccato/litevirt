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
		Long: `Revoke an active session by the ID that lv session ls shows.

The ID column shows the first 12 characters of the session id: the full id is
the session's bearer secret and is never displayed. Any unambiguous prefix of
at least 8 characters names the session (a trailing "…" pasted from the table
is ignored); a prefix that matches more than one session is refused and the
matches are listed.

You may revoke your own sessions. An admin may revoke anyone's: list them with
lv session ls --user <name>. A prefix only ever matches sessions you may
revoke.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id := strings.TrimSpace(args[0])
			id = strings.TrimSuffix(strings.TrimSuffix(id, "…"), "...")
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				if _, err := c.RevokeSession(ctx, &pb.RevokeSessionRequest{Id: id}); err != nil {
					return err
				}
				fmt.Printf("Session %s revoked.\n", id)
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
	cmd.AddCommand(new2FAListCmd(), new2FAEnrollCmd(), new2FADisableCmd(), new2FAPolicyCmd(), new2FAEnrollCodeCmd())
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
	var username, label, code string
	cmd := &cobra.Command{
		Use:   "enroll-totp",
		Short: "Enroll a TOTP authenticator (returns provisioning URL + recovery codes)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.EnrollTOTP(ctx, &pb.EnrollTOTPRequest{
					Username: username, Label: label, EnrollmentCode: code,
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
	cmd.Flags().StringVar(&code, "code", "", "Enrollment code from an administrator (needed for a first factor under the login policy)")
	return cmd
}

// new2FAEnrollCodeCmd issues the single-use code a user needs to enroll a first
// factor from an enrollment-only session.
func new2FAEnrollCodeCmd() *cobra.Command {
	var ttl time.Duration
	cmd := &cobra.Command{
		Use:   "enroll-code <username>",
		Short: "Issue a single-use code with which <username> enrolls a first factor (admin)",
		Long: `Issue a single-use, short-lived enrollment code for <username> (admin only;
works as root on a node through the local root channel). Under the mandatory
second-factor policy, a user with no factor gets an enrollment-only session
and needs this code to enroll one (` + "`lv 2fa enroll-totp --code <code>`" + `),
unless the policy was set with --allow-self-enroll and its deadline has not
passed. The code is shown once and stored hashed; issuing another replaces it.
Hand it over out of band.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				r, err := c.IssueEnrollmentCode(ctx, &pb.IssueEnrollmentCodeRequest{
					Username: args[0], TtlSeconds: int64(ttl / time.Second),
				})
				if err != nil {
					return err
				}
				fmt.Printf("Enrollment code for %s (single use, until %s):\n  %s\n", args[0], r.GetExpiresAt(), r.GetCode())
				if on := r.GetIssuedOn(); on != "" {
					fmt.Printf("It works only through node %s: the user logs in to that node to enroll.\n", on)
				}
				return nil
			})
		},
	}
	cmd.Flags().DurationVar(&ttl, "ttl", time.Hour, "How long the code is valid (at most 24h)")
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
	var allowSelf bool
	var enrollBy string
	cmd := &cobra.Command{
		Use:   "policy [off|all|<realm>[,<realm>...]]",
		Short: "Show or set the mandatory second-factor policy (admin to set)",
		Long: `With no argument, show the cluster-wide second-factor policy.

With one, set it (admin only):

  off                 no second factor is required (the default)
  all                 every realm requires one
  local,ldap:corp     only the named realms require one

A user in a covered realm with no factor enrolled is not locked out: login
gives them an enrollment-only session that can enroll a factor and nothing
else, and the enrollment ends it. By default enrolling that first factor
needs a single-use code from an administrator (` + "`lv 2fa enroll-code <user>`" + `).
--allow-self-enroll --enroll-by <RFC3339> lets users enroll without one until
the deadline; setting the policy again without the flag closes the window.
Setting the policy ends every live session in a realm it newly covers,
your own included. API tokens are not subject to it.

Refused until the cluster upgrade has finished (the login_policy feature of
the release, ` + "`lv cluster upgrade-status`" + `).`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				var p *pb.LoginPolicy
				var err error
				if len(args) == 0 {
					p, err = c.GetLoginPolicy(ctx, &emptypb.Empty{})
				} else {
					p, err = c.SetLoginPolicy(ctx, &pb.SetLoginPolicyRequest{
						Require_2Fa: args[0], AllowSelfEnroll: allowSelf, EnrollBy: enrollBy,
					})
				}
				if err != nil {
					return err
				}
				fmt.Printf("Second factor required: %s\n", p.GetRequire_2Fa())
				if p.GetSetBy() != "" {
					fmt.Printf("Set by:                 %s at %s\n", p.GetSetBy(), p.GetUpdatedAt())
				}
				if p.GetSelfEnrollBy() != "" {
					fmt.Printf("Self-enrollment until:  %s\n", p.GetSelfEnrollBy())
				} else {
					fmt.Println("Self-enrollment:        off (a first factor needs `lv 2fa enroll-code`)")
				}
				for _, w := range p.GetWarnings() {
					fmt.Printf("Warning:                %s\n", w)
				}
				if !p.GetSettable() {
					fmt.Println("Not settable here yet:  the cluster upgrade has not finished (lv cluster upgrade-status)")
				}
				if len(args) == 1 {
					fmt.Printf("Sessions ended:         %d (log in again if yours was one)\n", p.GetSessionsRevoked())
				}
				return nil
			})
		},
	}
	cmd.Flags().BoolVar(&allowSelf, "allow-self-enroll", false,
		"let users with no factor enroll their first one without an enrollment code, until --enroll-by")
	cmd.Flags().StringVar(&enrollBy, "enroll-by", "", "RFC3339 instant self-enrollment ends (with --allow-self-enroll)")
	return cmd
}

// shortID truncates session IDs for table output. The full id is the
// session's bearer secret, so it is never printed; lv session revoke accepts
// the short form (an unambiguous prefix).
func shortID(s string) string {
	if len(s) > 12 {
		return s[:12] + "…"
	}
	return s
}
