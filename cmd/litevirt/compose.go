package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"golang.org/x/term"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/cli"
	"github.com/litevirt/litevirt/internal/compose"
)

// stdinIsTerminal reports whether stdin is an interactive terminal. A var so
// tests can pin it.
var stdinIsTerminal = func() bool { return term.IsTerminal(int(os.Stdin.Fd())) }

func newComposeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "compose",
		Short: "Manage VM stacks via compose files",
	}
	cmd.AddCommand(
		newUpCmd(),
		newDownCmd(),
		newPsCmd(),
		newDiffCmd(),
		newStackLsCmd(),
		newExportCmd(),
	)
	return cmd
}

func newUpCmd() *cobra.Command {
	var (
		file        string
		yes         bool
		allowWeaken bool
	)
	cmd := &cobra.Command{
		Use:   "up",
		Short: "Deploy or update a stack from a compose file",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Read raw YAML — needed for DeployStack RPC.
			yamlData, err := os.ReadFile(file)
			if err != nil {
				return fmt.Errorf("read compose file: %w", err)
			}

			f, err := compose.ParseNamed(file, yamlData)
			if err != nil {
				return err
			}
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				if err := requireTagGroupSupport(ctx, c, composeRuleCIDRs(f)...); err != nil {
					return err
				}
				// Dry-run via DeployStack to get the plan from the server.
				dryStream, err := c.DeployStack(ctx, &pb.DeployStackRequest{
					ComposeYaml: string(yamlData),
					DryRun:      true,
					AllowWeaken: allowWeaken,
				})
				if err != nil {
					return fmt.Errorf("deploy dry-run: %w", err)
				}

				var ops []compose.Op
				for {
					p, err := dryStream.Recv()
					if err != nil {
						if err.Error() != "EOF" {
							// Check if this is a real error (auth, network, etc.)
							// vs normal end-of-stream.
							st, ok := status.FromError(err)
							if ok && st.Code() != codes.OK {
								return fmt.Errorf("dry-run failed: %s", st.Message())
							}
						}
						break
					}
					ops = append(ops, compose.Op{
						Kind:   compose.OpKind(p.Phase),
						VMName: p.VmName,
						Detail: p.Detail,
					})
				}

				if len(ops) == 0 {
					fmt.Println("Nothing to do — stack is up to date.")
					return nil
				}

				// Print plan. Under each VM created or updated, what its
				// healthcheck will actually probe.
				healthchecks := healthchecksByInstance(f)
				fmt.Printf("Stack %q:\n\n", f.Name)
				for _, op := range ops {
					switch op.Kind {
					case compose.OpCreate:
						fmt.Printf("  + %s\n", op.Detail)
						printHealthcheck(healthchecks, op.VMName)
					case compose.OpUpdate:
						fmt.Printf("  ~ %s\n", op.Detail)
						printHealthcheck(healthchecks, op.VMName)
					case compose.OpDelete:
						fmt.Printf("  - %s\n", op.Detail)
					case "network":
						fmt.Printf("  # %s\n", op.Detail)
					case "loadbalancer":
						fmt.Printf("  # %s\n", op.Detail)
					case "warning":
						fmt.Printf("  warning: %s\n", op.Detail)
					default:
						fmt.Printf("    %s\n", op.Detail)
					}
				}
				fmt.Println()

				if !yes {
					if !stdinIsTerminal() {
						return errNoTTYConfirm
					}
					ok, err := cli.Confirm(ctx, os.Stdin, os.Stdout, "Apply?")
					if err != nil {
						return err
					}
					if !ok {
						fmt.Println("Aborted.")
						return nil
					}
				}

				// Execute via DeployStack RPC (handles VM creation, stack record, LB, etc.).
				stream, err := c.DeployStack(ctx, &pb.DeployStackRequest{
					ComposeYaml: string(yamlData),
					AllowWeaken: allowWeaken,
				})
				if err != nil {
					return fmt.Errorf("deploy stack: %w", err)
				}

				// Per-action failures arrive as "error" progress and the stream
				// still ends OK, so they must be counted here: a stack with a
				// failed action is not "deployed".
				var deployErr error
				var failed []string
				withheld := 0
				seenFailed := map[string]bool{}
				for {
					p, err := stream.Recv()
					if err != nil {
						if ierr := interruptedReplace("compose up "+f.Name, "deploy", "lv compose up", err); ierr != nil {
							deployErr = ierr
						} else if st, ok := status.FromError(err); ok && st.Code() != codes.OK {
							deployErr = fmt.Errorf("deploy failed: %s", st.Message())
						}
						break
					}
					switch p.Phase {
					case "error":
						fmt.Fprintf(os.Stderr, "  error %s: %s\n", p.VmName, p.Error)
						if !seenFailed[p.VmName] {
							seenFailed[p.VmName] = true
							failed = append(failed, p.VmName)
						}
					case "done":
						fmt.Printf("  %s: done\n", p.VmName)
					case "warning":
						// Printed in the plan above; counted here so a withheld
						// restore is not lost above a long deploy log.
						withheld += strings.Count(p.Detail, " not restored: ")
					default:
						fmt.Printf("  %s: %s\n", p.VmName, p.Detail)
					}
				}
				if deployErr != nil {
					return deployErr
				}
				if len(failed) > 0 {
					return fmt.Errorf("stack %q: %d of %d actions failed (%s)",
						f.Name, len(failed), max(countVMActions(ops), len(failed)), strings.Join(failed, ", "))
				}

				fmt.Printf("\nStack %q deployed.\n", f.Name)
				if withheld > 0 {
					fmt.Printf("%d NIC security restore(s) were withheld; see the warnings in the plan above.\n", withheld)
				}
				return nil
			})
		},
	}
	cmd.Flags().StringVarP(&file, "file", "f", "litevirt-compose.yaml", "Compose file path")
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "Skip confirmation prompt")
	cmd.Flags().BoolVar(&allowWeaken, "allow-weaken", false,
		"Restore declared NIC security groups, and declared guards looser than the ones enforced now, over runtime changes (lv sg bind, lv firewall nic-guard set)")
	return cmd
}

// errNoTTYConfirm refuses a confirmation prompt that nobody can answer: over
// a non-tty session (ssh without -t, CI, a pipe) stdin can stay open and
// silent, and the prompt would block forever with no hint why.
var errNoTTYConfirm = errors.New("stdin is not a terminal, so the confirmation prompt cannot be answered; review the plan and re-run with -y to apply")

// healthchecksByInstance maps every VM instance the file defines to a
// one-line description of what its healthcheck probes.
func healthchecksByInstance(f *compose.File) map[string]string {
	out := map[string]string{}
	for base, vm := range f.VMs {
		if vm.HealthCheck == nil {
			continue
		}
		d := vm.HealthCheck.Describe()
		for r := 0; r < vm.EffectiveReplicas(); r++ {
			out[vm.InstanceName(base, r)] = d
		}
	}
	return out
}

func printHealthcheck(healthchecks map[string]string, vm string) {
	if d, ok := healthchecks[vm]; ok {
		fmt.Printf("      healthcheck: %s\n", d)
	}
}

// countVMActions counts the plan entries that execute a VM action (create,
// update, delete) — the denominator for the failure summary.
func countVMActions(ops []compose.Op) int {
	n := 0
	for _, op := range ops {
		switch op.Kind {
		case compose.OpCreate, compose.OpUpdate, compose.OpDelete:
			n++
		}
	}
	return n
}

func newDownCmd() *cobra.Command {
	var (
		file      string
		stackName string
		yes       bool
	)
	cmd := &cobra.Command{
		Use:   "down",
		Short: "Tear down a stack",
		RunE: func(cmd *cobra.Command, args []string) error {
			var name string
			if cmd.Flags().Changed("name") {
				name = stackName
			} else {
				f, err := compose.Parse(file)
				if err != nil {
					return err
				}
				name = f.Name
			}

			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.ListVMs(ctx, &pb.ListVMsRequest{StackName: name})
				if err != nil {
					return fmt.Errorf("list VMs: %w", err)
				}

				if len(resp.Vms) == 0 {
					fmt.Printf("Stack %q has no running VMs — cleaning up stack record.\n", name)
				} else {
					fmt.Printf("Will delete %d VM(s) in stack %q:\n", len(resp.Vms), name)
				}
				for _, vm := range resp.Vms {
					fmt.Printf("  - %s (%s)\n", vm.Name, vm.State)
				}

				if !yes {
					if !stdinIsTerminal() {
						return errNoTTYConfirm
					}
					ok, err := cli.Confirm(ctx, os.Stdin, os.Stdout, "Confirm?")
					if err != nil {
						return err
					}
					if !ok {
						fmt.Println("Aborted.")
						return nil
					}
				}

				// Use DeleteStack RPC which handles VM deletion, LB cleanup, and stack record removal.
				stream, err := c.DeleteStack(ctx, &pb.DeleteStackRequest{
					Name: name,
				})
				if err != nil {
					return fmt.Errorf("delete stack: %w", err)
				}

				// Per-VM failures arrive as "error" status and the stream still
				// ends OK, so they must be counted here, as compose up does: a
				// stack with a VM that could not be deleted is not torn down.
				var downErr error
				var failed, seen []string
				seenFailed, seenVM := map[string]bool{}, map[string]bool{}
				for {
					p, err := stream.Recv()
					if err != nil {
						if ierr := interruptedDelete("compose down "+name, err, "lv compose ls", "lv ls"); ierr != nil {
							downErr = ierr
						} else if st, ok := status.FromError(err); ok && st.Code() != codes.OK {
							downErr = fmt.Errorf("delete failed: %s", st.Message())
						}
						break
					}
					// Not only VMs: a network that could not be deprovisioned or
					// a failed container listing arrives named for itself, and
					// an unnamed error still counts.
					item := p.VmName
					if item == "" && p.Status == "error" {
						item = "stack resource"
					}
					if item != "" && !seenVM[item] && p.Status != "kept" {
						seenVM[item] = true
						seen = append(seen, item)
					}
					if p.Status == "kept" && seenVM[item] {
						// Reported "deleting" and then found not to be the
						// stack's: no deletion, so not in the count.
						delete(seenVM, item)
						seen = removeString(seen, item)
					}
					switch p.Status {
					case "error":
						fmt.Fprintf(os.Stderr, "  error %s: %s\n", item, p.Error)
						if !seenFailed[item] {
							seenFailed[item] = true
							failed = append(failed, item)
						}
					case "deleted":
						fmt.Printf("  deleted %s\n", p.VmName)
					case "kept":
						// A VM of a member's name the stack did not create.
						fmt.Printf("  kept %s: %s\n", p.VmName, p.Error)
					case "absent":
						// A member whose create failed: nothing to delete.
						fmt.Printf("  absent %s: %s\n", p.VmName, p.Error)
					default:
						fmt.Printf("  %s: %s\n", p.VmName, p.Status)
					}
				}
				if downErr != nil {
					return downErr
				}
				if len(failed) > 0 {
					return fmt.Errorf("stack %q: %d of %d deletions failed (%s); the stack is left in state \"deleting\" and the daemon retries the teardown",
						name, len(failed), len(seen), strings.Join(failed, ", "))
				}

				fmt.Printf("Stack %q torn down.\n", name)
				return nil
			})
		},
	}
	cmd.Flags().StringVarP(&file, "file", "f", "litevirt-compose.yaml", "Compose file path")
	cmd.Flags().StringVar(&stackName, "name", "", "Stack name (use instead of compose file)")
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "Skip confirmation prompt")
	return cmd
}

func newPsCmd() *cobra.Command {
	var file string
	cmd := &cobra.Command{
		Use:   "ps",
		Short: "List VMs in a stack",
		RunE: func(cmd *cobra.Command, args []string) error {
			f, err := compose.Parse(file)
			if err != nil {
				return err
			}

			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.ListVMs(ctx, &pb.ListVMsRequest{StackName: f.Name})
				if err != nil {
					return fmt.Errorf("list VMs: %w", err)
				}

				w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
				fmt.Fprintf(w, "NAME\tHOST\tSTATE\tCPU\tMEMORY\tIP\n")
				for _, vm := range resp.Vms {
					ip := "<unknown>"
					if len(vm.Interfaces) > 0 && vm.Interfaces[0].Ip != "" {
						ip = vm.Interfaces[0].Ip
					}
					fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%dMiB\t%s\n",
						vm.Name, vm.HostName, vm.State,
						vm.CpuActual, vm.MemActualMib, ip)
				}
				return w.Flush()
			})
		},
	}
	cmd.Flags().StringVarP(&file, "file", "f", "litevirt-compose.yaml", "Compose file path")
	return cmd
}

func newDiffCmd() *cobra.Command {
	var (
		file        string
		allowWeaken bool
	)
	cmd := &cobra.Command{
		Use:   "diff",
		Short: "Show what lv compose up would change",
		RunE: func(cmd *cobra.Command, args []string) error {
			yamlData, err := os.ReadFile(file)
			if err != nil {
				return fmt.Errorf("read compose file: %w", err)
			}
			if _, err := compose.ParseNamed(file, yamlData); err != nil {
				return err
			}
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				// The server's plan, made exactly as lv compose up's (placement,
				// name collisions, the live NIC security and what the caller may
				// restore of it), so the diff and the deploy cannot disagree.
				resp, err := c.DiffStack(ctx, &pb.DiffStackRequest{ComposeYaml: string(yamlData), AllowWeaken: allowWeaken})
				if err != nil {
					if st, ok := status.FromError(err); ok {
						return errors.New(st.Message())
					}
					return err
				}
				printServerDiff(resp)
				return nil
			})
		},
	}
	cmd.Flags().StringVarP(&file, "file", "f", "litevirt-compose.yaml", "Compose file path")
	cmd.Flags().BoolVar(&allowWeaken, "allow-weaken", false,
		"Plan as lv compose up --allow-weaken would: restore declared NIC security groups and looser declared guards over runtime changes")
	return cmd
}

// printServerDiff prints a DiffStack plan: its warnings, then each entry, then
// the workload summary.
func printServerDiff(resp *pb.DiffStackResponse) {
	var creates, updates, deletes, unchanged int
	var lines []string
	for _, e := range resp.GetEntries() {
		if w, ok := strings.CutPrefix(e.GetDetail(), "⚠ "); ok && e.GetVmName() == "" {
			fmt.Printf("warning: %s\n", w)
			continue
		}
		workload := e.GetVmName() != "" && !strings.HasPrefix(e.GetDetail(), "dns ")
		mark := "    "
		switch e.GetOperation() {
		case pb.DiffOp_DIFF_CREATE:
			mark = "  + "
			if workload {
				creates++
			}
		case pb.DiffOp_DIFF_UPDATE:
			mark = "  ~ "
			if workload {
				updates++
			}
		case pb.DiffOp_DIFF_DELETE:
			mark = "  - "
			if workload {
				deletes++
			}
		default:
			if workload {
				unchanged++
			}
		}
		lines = append(lines, mark+e.GetDetail())
	}
	fmt.Printf("Plan: %d to create, %d to update, %d to delete, %d unchanged\n", creates, updates, deletes, unchanged)
	for _, l := range lines {
		fmt.Println(l)
	}
}

func newStackLsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ls",
		Short: "List all deployed stacks",
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.ListStacks(ctx, nil)
				if err != nil {
					return fmt.Errorf("list stacks: %w", err)
				}

				w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
				fmt.Fprintln(w, "NAME\tSTATE\tVMs\tRUNNING\tSTOPPED\tERROR\tCREATED")
				for _, s := range resp.Stacks {
					created := "-"
					if s.CreatedAt != nil {
						created = s.CreatedAt.AsTime().Format("2006-01-02 15:04")
					}
					fmt.Fprintf(w, "%s\t%s\t%d\t%d\t%d\t%d\t%s\n",
						s.Name, s.State, s.VmCount,
						s.Running, s.Stopped, s.Error,
						created,
					)
				}
				return w.Flush()
			})
		},
	}
}

func newExportCmd() *cobra.Command {
	var output string
	cmd := &cobra.Command{
		Use:   "export <stack-name>",
		Short: "Export a stack's compose YAML",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.ExportStack(ctx, &pb.ExportStackRequest{Name: args[0]})
				if err != nil {
					return fmt.Errorf("export stack: %w", err)
				}

				if output != "" {
					if err := os.WriteFile(output, []byte(resp.ComposeYaml), 0644); err != nil {
						return fmt.Errorf("write file: %w", err)
					}
					fmt.Printf("Exported stack %q to %s\n", resp.Name, output)
					return nil
				}

				fmt.Print(resp.ComposeYaml)
				return nil
			})
		},
	}
	cmd.Flags().StringVarP(&output, "output", "o", "", "Write YAML to file instead of stdout")
	return cmd
}

// removeString returns ss without s.
func removeString(ss []string, s string) []string {
	out := ss[:0:0]
	for _, x := range ss {
		if x != s {
			out = append(out, x)
		}
	}
	return out
}
