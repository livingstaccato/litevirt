package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// newNotifyCmd manages operator notification targets + routes (#5).
func newNotifyCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "notify", Short: "Manage operator notifications (webhook/Slack/email)"}
	cmd.AddCommand(newNotifyTargetCmd(), newNotifyRouteCmd(), newNotifyTestCmd())
	return cmd
}

func newNotifyTargetCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "target", Short: "Manage notification targets"}
	cmd.AddCommand(newNotifyTargetAddCmd(), newNotifyTargetLsCmd(), newNotifyTargetRmCmd())
	return cmd
}

// emailTargetFlags are the SMTP settings of an email target.
type emailTargetFlags struct {
	host, tls, user, passwordFile, from string
	port                                int
	to                                  []string
	skipVerify                          bool
}

// buildTargetConfig renders the stored JSON config for a target. The SMTP
// password is read from a file (or "-" for stdin), never from a flag, so it
// stays out of shell history and the process list.
func buildTargetConfig(typ, url string, e emailTargetFlags, stdin io.Reader) (string, error) {
	if typ != "email" {
		if url == "" {
			return "", fmt.Errorf("--url is required")
		}
		cfg, _ := json.Marshal(map[string]string{"url": url})
		return string(cfg), nil
	}
	if url != "" {
		return "", fmt.Errorf("--url does not apply to an email target")
	}
	if e.host == "" || e.from == "" || len(e.to) == 0 {
		return "", fmt.Errorf("an email target needs --smtp-host, --from and at least one --to")
	}
	m := map[string]any{"host": e.host, "from": e.from, "to": e.to}
	if e.port != 0 {
		m["port"] = e.port
	}
	if e.tls != "" {
		m["tls"] = e.tls
	}
	if e.skipVerify {
		m["tls_skip_verify"] = true
	}
	if e.user != "" {
		m["username"] = e.user
	}
	if e.passwordFile != "" {
		var raw []byte
		var err error
		if e.passwordFile == "-" {
			raw, err = io.ReadAll(stdin)
		} else {
			raw, err = os.ReadFile(e.passwordFile)
		}
		if err != nil {
			return "", fmt.Errorf("read SMTP password: %w", err)
		}
		pw := strings.TrimRight(string(raw), "\r\n")
		if pw == "" {
			return "", fmt.Errorf("SMTP password file is empty")
		}
		m["password"] = pw
	}
	cfg, _ := json.Marshal(m)
	return string(cfg), nil
}

func newNotifyTargetAddCmd() *cobra.Command {
	var name, typ, url string
	var disabled bool
	var e emailTargetFlags
	cmd := &cobra.Command{
		Use:   "add",
		Short: "Add a notification target (webhook, slack or email)",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := buildTargetConfig(typ, url, e, cmd.InOrStdin())
			if err != nil {
				return err
			}
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				t, err := c.CreateNotificationTarget(ctx, &pb.CreateNotificationTargetRequest{
					Name: name, Type: typ, Config: cfg, Enabled: !disabled,
				})
				if err != nil {
					return fmt.Errorf("add target: %w", err)
				}
				fmt.Printf("Target %q (%s) created: %s\n", t.Name, t.Type, t.Id)
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "target name (required)")
	cmd.Flags().StringVar(&typ, "type", "webhook", "target type: webhook | slack | email")
	cmd.Flags().StringVar(&url, "url", "", "webhook / Slack incoming-webhook URL (webhook and slack targets)")
	cmd.Flags().StringVar(&e.host, "smtp-host", "", "SMTP server host (email targets)")
	cmd.Flags().IntVar(&e.port, "smtp-port", 0, "SMTP port (default 587 starttls, 465 implicit, 25 none)")
	cmd.Flags().StringVar(&e.tls, "smtp-tls", "", "starttls (default) | implicit | none; certificates are always verified unless --smtp-tls-skip-verify")
	cmd.Flags().BoolVar(&e.skipVerify, "smtp-tls-skip-verify", false, "do not verify the SMTP server certificate (self-signed lab relay)")
	cmd.Flags().StringVar(&e.user, "smtp-user", "", "SMTP username")
	cmd.Flags().StringVar(&e.passwordFile, "smtp-password-file", "", "file holding the SMTP password ('-' reads stdin)")
	cmd.Flags().StringVar(&e.from, "from", "", "sender address (email targets)")
	cmd.Flags().StringSliceVar(&e.to, "to", nil, "recipient address, repeatable (email targets)")
	cmd.Flags().BoolVar(&disabled, "disabled", false, "create disabled")
	cmd.MarkFlagRequired("name")
	return cmd
}

func newNotifyTargetLsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ls",
		Short: "List notification targets",
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.ListNotificationTargets(ctx, &pb.ListNotificationTargetsRequest{})
				if err != nil {
					return err
				}
				w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
				fmt.Fprintf(w, "ID\tNAME\tTYPE\tENABLED\tCONFIG\n")
				for _, t := range resp.Targets {
					fmt.Fprintf(w, "%s\t%s\t%s\t%t\t%s\n", t.Id, t.Name, t.Type, t.Enabled, t.Config)
				}
				return w.Flush()
			})
		},
	}
}

func newNotifyTargetRmCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rm <id>",
		Short: "Delete a notification target",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				if _, err := c.DeleteNotificationTarget(ctx, &pb.DeleteNotificationTargetRequest{Id: args[0]}); err != nil {
					return err
				}
				fmt.Printf("Target %s deleted\n", args[0])
				return nil
			})
		},
	}
}

func newNotifyRouteCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "route", Short: "Manage notification routes"}
	cmd.AddCommand(newNotifyRouteAddCmd(), newNotifyRouteLsCmd(), newNotifyRouteRmCmd())
	return cmd
}

func newNotifyRouteAddCmd() *cobra.Command {
	var pattern, target, minSeverity string
	var disabled bool
	cmd := &cobra.Command{
		Use:   "add",
		Short: "Route an event pattern to a target",
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				r, err := c.CreateNotificationRoute(ctx, &pb.CreateNotificationRouteRequest{
					EventPattern: pattern, TargetId: target, MinSeverity: minSeverity, Enabled: !disabled,
				})
				if err != nil {
					return fmt.Errorf("add route: %w", err)
				}
				fmt.Printf("Route %s → target %s (%s, ≥%s) created\n", r.EventPattern, r.TargetId, r.Id, r.MinSeverity)
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&pattern, "pattern", "*", "event glob: '*', 'backup.*', 'host.fenced'")
	cmd.Flags().StringVar(&target, "target", "", "target ID (required)")
	cmd.Flags().StringVar(&minSeverity, "min-severity", "info", "info | warn | error")
	cmd.Flags().BoolVar(&disabled, "disabled", false, "create disabled")
	cmd.MarkFlagRequired("target")
	return cmd
}

func newNotifyRouteLsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ls",
		Short: "List notification routes",
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.ListNotificationRoutes(ctx, &pb.ListNotificationRoutesRequest{})
				if err != nil {
					return err
				}
				w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
				fmt.Fprintf(w, "ID\tPATTERN\tTARGET\tMIN-SEVERITY\tENABLED\n")
				for _, r := range resp.Routes {
					fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%t\n", r.Id, r.EventPattern, r.TargetId, r.MinSeverity, r.Enabled)
				}
				return w.Flush()
			})
		},
	}
}

func newNotifyRouteRmCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rm <id>",
		Short: "Delete a notification route",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				if _, err := c.DeleteNotificationRoute(ctx, &pb.DeleteNotificationRouteRequest{Id: args[0]}); err != nil {
					return err
				}
				fmt.Printf("Route %s deleted\n", args[0])
				return nil
			})
		},
	}
}

func newNotifyTestCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "test <target-id>",
		Short: "Send a test notification to a target",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				if _, err := c.TestNotificationTarget(ctx, &pb.TestNotificationTargetRequest{Id: args[0]}); err != nil {
					return fmt.Errorf("test: %w", err)
				}
				fmt.Println("Test notification sent.")
				return nil
			})
		},
	}
}
