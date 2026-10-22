package main

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/safename"
)

// projectSpellingsDocs is where the finding points: there is no repair
// command, because deleting one spelling retires the grants under the RBAC
// root both spellings share.
const projectSpellingsDocs = "docs/diagnostics.md#lv-doctor-project-spellings"

// multiSpelledProjects groups live projects by canonical name and returns
// each name live under more than one spelling, with its spellings sorted.
// The default project and names with no canonical form are skipped. Pure so
// the selection is testable without a cluster.
func multiSpelledProjects(ps []*pb.Project) map[string][]string {
	by := map[string][]string{}
	for _, p := range ps {
		canon, err := safename.CanonicalProjectName(p.GetName())
		if err != nil || canon == "/" || canon == "/_default" {
			continue
		}
		by[canon] = append(by[canon], p.GetName())
	}
	out := map[string][]string{}
	for canon, names := range by {
		if len(names) > 1 {
			sort.Strings(names)
			out[canon] = names
		}
	}
	return out
}

func newDoctorProjectSpellingsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "project-spellings",
		Short: "Report projects live under more than one spelling",
		Long: `List project names that are live under more than one spelling ("acme" beside
"/acme"), which a create on a much older release could leave.

It checks the spellings only: the project listing carries no incarnation. A
listed project that still holds its pre-upgrade identity is not given a stable
one by the project adoption pass, and
litevirt_project_adoption_blocked{reason="spellings"} counts those.

Read-only. There is no repair command: deleting one spelling retires the grants
under the RBAC root both share. See ` + projectSpellingsDocs + `.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.ListProjects(ctx, &emptypb.Empty{})
				if err != nil {
					return fmt.Errorf("list projects: %w", err)
				}
				found := multiSpelledProjects(resp.GetProjects())
				if len(found) == 0 {
					fmt.Println("every project is live under one spelling")
					return nil
				}
				canons := make([]string, 0, len(found))
				for canon := range found {
					canons = append(canons, canon)
				}
				sort.Strings(canons)
				for _, canon := range canons {
					fmt.Printf("%s: live as %s\n", canon, strings.Join(found[canon], ", "))
				}
				fmt.Printf("\n%d project(s) are live under more than one spelling. One that still holds its pre-upgrade\n", len(found))
				fmt.Println("identity is not adopted (litevirt_project_adoption_blocked counts those).")
				fmt.Printf("Do not delete a spelling to merge them; see %s.\n", projectSpellingsDocs)
				return nil
			})
		},
	}
}
