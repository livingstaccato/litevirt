package fleet

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/cli"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// `lv host rm --dead` of a voter's host: a refused removal changes nothing,
// the voter set included. Before the fix the CLI removed the vote first and
// only then reached the daemon's removal checks, so every refusal below left
// the generation advanced and the host still there.

// deadVoterFleet is a four-node fleet with an adopted voter generation of all
// four and recovery claims on, whose d is killed and fenced proof-grade; the
// CLI holds the cluster CA (withOperatorPKI on a).
func deadVoterFleet(t *testing.T, seed int64) (c *Cluster, a, d *Node) {
	t.Helper()
	ctx := context.Background()
	c = New(t, Options{Nodes: 4, IndependentReplicas: true, FaultSeed: seed})
	a, d = c.Nodes[0], c.Nodes[3]
	c.WaitConverged(t, convergeTimeout)
	genesisByTick(t, c, a)
	enableRecoveryClaims(t, c)
	c.Kill(d)
	if err := corrosion.InsertFenceLog(ctx, a.DB, corrosion.FenceLogRecord{ID: "confirm-" + d.Name, HostName: d.Name,
		Method: "manual", Result: "manual-confirmed", Detail: "operator powered it off"}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpdateHostState(ctx, a.DB, d.Name, "fenced"); err != nil {
		t.Fatal(err)
	}
	withOperatorPKI(t, a)
	if member, _ := voterOf(t, a, d); !member {
		t.Fatalf("fixture: %s is not a voter, so the vote-first order is not exercised", d.Name)
	}
	return c, a, d
}

// voterOf reports whether d is a member of the generation n has adopted, and
// that generation.
func voterOf(t *testing.T, n, d *Node) (bool, int64) {
	t.Helper()
	cfg, err := corrosion.AdoptedVoterConfig(context.Background(), n.DB)
	if err != nil {
		t.Fatal(err)
	}
	_, member := cfg.Member(d.Name)
	return member, cfg.Generation
}

// requireUnchanged fails unless d is still a voter at gen and still a host.
func requireUnchanged(t *testing.T, a, d *Node, gen int64) {
	t.Helper()
	if member, g := voterOf(t, a, d); !member || g != gen {
		t.Errorf("after the refused removal %s is a voter=%v at generation %d, want a voter at %d", d.Name, member, g, gen)
	}
	if h, _ := corrosion.GetHost(context.Background(), a.DB, d.Name); h == nil || h.State == "removed" {
		t.Errorf("%s was removed by a refused removal: %+v", d.Name, h)
	}
}

// requireRemoved fails unless d is neither a voter nor a host.
func requireRemoved(t *testing.T, a, d *Node) {
	t.Helper()
	if member, g := voterOf(t, a, d); member {
		t.Errorf("%s is still a voter at generation %d after its removal", d.Name, g)
	}
	if h, _ := corrosion.GetHost(context.Background(), a.DB, d.Name); h != nil && h.State != "removed" {
		t.Errorf("%s is %s after its removal", d.Name, h.State)
	}
}

// rmQuorumGate is claimsGate with the voter majority set: with is the count
// over the whole voter set, without the count over it without the host a
// decision is about (QuorumProofExcluding).
type rmQuorumGate struct {
	claimsGate
	with, without health.QuorumState
}

func (g rmQuorumGate) QuorumProof(context.Context) (health.QuorumState, int, int) {
	return g.with, 2, 3
}
func (g rmQuorumGate) QuorumProofExcluding(context.Context, string) (health.QuorumState, int, int) {
	return g.without, 2, 2
}

// failingPuller is a currency pull that fails while fails > 0, counting down,
// and otherwise has no peer to ask (proceeds).
type failingPuller struct{ fails atomic.Int32 }

func (*failingPuller) RunOnce(context.Context) bool { return true }
func (p *failingPuller) PullTableNow(context.Context, string, string) (string, []string, error) {
	if p.fails.Add(-1) >= 0 {
		return "", nil, errors.New("peer unreachable (fleet fault)")
	}
	return "", nil, nil
}

// afterVoteClient runs afterVote once ChangeVoterConfig has returned: a
// blocker that appears once the vote is gone.
type afterVoteClient struct {
	pb.LiteVirtClient
	afterVote func()
}

func (c afterVoteClient) ChangeVoterConfig(ctx context.Context, req *pb.ChangeVoterConfigRequest, opts ...grpc.CallOption) (*pb.ChangeVoterConfigResponse, error) {
	resp, err := c.LiteVirtClient.ChangeVoterConfig(ctx, req, opts...)
	c.afterVote()
	return resp, err
}

// afterPlanClient runs afterPlan once PlanDeadHostRemoval has returned: a
// blocker that appears after the plan was read.
type afterPlanClient struct {
	pb.LiteVirtClient
	afterPlan func()
}

func (c afterPlanClient) PlanDeadHostRemoval(ctx context.Context, req *pb.PlanDeadHostRemovalRequest, opts ...grpc.CallOption) (*pb.PlanDeadHostRemovalResponse, error) {
	resp, err := c.LiteVirtClient.PlanDeadHostRemoval(ctx, req, opts...)
	c.afterPlan()
	return resp, err
}

// One refusal per class the daemon or the CLI makes after the voter refusal
// used to be asked. Each is refused, by the dry run too, with d still a voter
// at the same generation and still a host; the cause cleared, the same
// command removes it.
//
// Red on e4c38889e: the vote is removed first, so every class leaves d out of
// the voter set at generation 2 (and the voter dry run asked nothing).
// Mutations: ask the voter refusal first again in removeHostRefusal — every
// daemon class red; drop the CLI's early preflight — every class red; drop
// the CLI's dry CRL mint — the CA class red.
func TestFleet_DeadVoterRemoval_ARefusalKeepsTheVote(t *testing.T) {
	cases := []struct {
		name      string
		seed      int64
		want      string
		block     func(t *testing.T, a, d *Node) (clear func())
		afterPlan func(t *testing.T, a, d *Node)
		between   func(t *testing.T, a, d *Node)
	}{
		{name: "operator_write_currency", seed: 4101, want: "has not caught up",
			block: func(t *testing.T, a, d *Node) func() {
				a.Server.SetHostWriteCurrencyCheck(true)
				a.DB.MarkReplicaStale("fleet: a lagging replica")
				return func() { a.DB.MarkReplicaCaughtUpForTests("fleet") }
			}},
		{name: "voter_majority", seed: 4102, want: "needs a live voter majority",
			block: func(t *testing.T, a, d *Node) func() {
				a.Server.SetGate(rmQuorumGate{with: health.QuorumNo, without: health.QuorumNo})
				return func() { a.Server.SetGate(claimsGate{}) }
			}},
		{name: "hosts_pull", seed: 4103, want: "could not confirm",
			block: func(t *testing.T, a, d *Node) func() {
				p := &failingPuller{}
				p.fails.Store(1 << 30)
				a.Server.SetAntiEntropy(p)
				return func() { p.fails.Store(0) }
			}},
		{name: "admission_reread", seed: 4104, want: "row changed while its removal was checked",
			block: func(t *testing.T, a, d *Node) func() {
				var on atomic.Bool
				on.Store(true)
				a.Server.SetRemoveHostBetweenReadsHook(func(name string) {
					if on.Load() {
						// Another admission of the name lands between the
						// row read and the admission key read (written on
						// this replica only, as one arriving from a peer).
						if err := a.DB.ExecOutOfProcessForTest(`UPDATE hosts SET created_at = ? WHERE name = ?`,
							time.Now().UTC().Format(time.RFC3339Nano), name); err != nil {
							t.Error(err)
						}
					}
				})
				return func() { on.Store(false) }
			}},
		{name: "dead_fence", seed: 4105, want: "is active; --dead removes",
			// The host is recorded active once the plan has read it fenced.
			afterPlan: func(t *testing.T, a, d *Node) {
				if err := corrosion.UpdateHostState(context.Background(), a.DB, d.Name, "active"); err != nil {
					t.Error(err)
				}
			},
			block: func(t *testing.T, a, d *Node) func() { return func() {} },
			// Fenced again for the next run's plan to read.
			between: func(t *testing.T, a, d *Node) {
				if err := corrosion.UpdateHostState(context.Background(), a.DB, d.Name, "fenced"); err != nil {
					t.Error(err)
				}
			}},
		{name: "ca_key", seed: 4106, want: "no cluster CA private key",
			block: func(t *testing.T, a, d *Node) func() {
				dir := t.TempDir()
				if err := os.MkdirAll(filepath.Join(dir, "pki"), 0o700); err != nil {
					t.Fatal(err)
				}
				b, err := os.ReadFile(filepath.Join(a.PKIDir, "ca.crt"))
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, "pki", "ca.crt"), b, 0o600); err != nil {
					t.Fatal(err)
				}
				t.Setenv("LV_CONFIG_DIR", dir)
				return func() { withOperatorPKI(t, a) }
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			c, a, d := deadVoterFleet(t, tc.seed)
			_, gen := voterOf(t, a, d)
			clear := tc.block(t, a, d)
			var lv pb.LiteVirtClient = c.SelfClient(a)
			if tc.afterPlan != nil {
				lv = afterPlanClient{LiteVirtClient: lv, afterPlan: func() { tc.afterPlan(t, a, d) }}
			}

			if err := cli.HostRemoveDead(ctx, lv, d.Name, true); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("the dry run = %v, want refused with %q", err, tc.want)
			}
			requireUnchanged(t, a, d, gen)
			if tc.between != nil {
				tc.between(t, a, d)
			}
			err := cli.HostRemoveDead(ctx, lv, d.Name, false)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("lv host rm --dead %s = %v, want refused with %q", d.Name, err, tc.want)
			}
			requireUnchanged(t, a, d, gen)

			clear()
			if tc.between != nil {
				tc.between(t, a, d)
			}
			if err := cli.HostRemoveDead(ctx, c.SelfClient(a), d.Name, false); err != nil {
				t.Fatalf("lv host rm --dead %s once the cause is cleared: %v", d.Name, err)
			}
			requireRemoved(t, a, d)
		})
	}
}

// A blocker that appears once the vote is gone. A transient one (the
// currency pull failing for a moment) is retried and the removal finishes;
// a lasting one is refused naming the vote it removed and the command that
// finishes the removal, which, once the cause is cleared, does.
//
// Red on e4c38889e: the transient refusal ends the run with the vote removed
// and the host still there, and the lasting one does not say the vote is
// gone. Mutations: drop the post-vote retry — transient red; drop the
// post-vote note — lasting red.
func TestFleet_DeadVoterRemoval_ABlockerAfterTheVote(t *testing.T) {
	t.Run("transient", func(t *testing.T) {
		ctx := context.Background()
		c, a, d := deadVoterFleet(t, 4111)
		p := &failingPuller{}
		a.Server.SetAntiEntropy(p)
		lv := afterVoteClient{LiteVirtClient: c.SelfClient(a), afterVote: func() { p.fails.Store(1) }}
		if err := cli.HostRemoveDead(ctx, lv, d.Name, false); err != nil {
			t.Fatalf("lv host rm --dead %s with the pull failing once after the vote: %v", d.Name, err)
		}
		requireRemoved(t, a, d)
	})
	t.Run("lasting", func(t *testing.T) {
		ctx := context.Background()
		c, a, d := deadVoterFleet(t, 4112)
		lv := afterVoteClient{LiteVirtClient: c.SelfClient(a), afterVote: func() {
			if err := corrosion.UpdateHostState(context.Background(), a.DB, d.Name, "active"); err != nil {
				t.Error(err)
			}
		}}
		_, gen := voterOf(t, a, d)
		err := cli.HostRemoveDead(ctx, lv, d.Name, false)
		if err == nil || !strings.Contains(err.Error(), "is active") {
			t.Fatalf("lv host rm --dead %s with a blocker after the vote = %v, want refused", d.Name, err)
		}
		for _, want := range []string{"vote was removed", "lv host rm --dead " + d.Name} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("the refusal after the vote does not say %q: %v", want, err)
			}
		}
		if member, g := voterOf(t, a, d); member || g != gen+1 {
			t.Errorf("%s is a voter=%v at %d after the vote removal, want removed at %d", d.Name, member, g, gen+1)
		}
		if err := corrosion.UpdateHostState(ctx, a.DB, d.Name, "fenced"); err != nil {
			t.Fatal(err)
		}
		if err := cli.HostRemoveDead(ctx, c.SelfClient(a), d.Name, false); err != nil {
			t.Fatalf("the rerun the refusal names: %v", err)
		}
		requireRemoved(t, a, d)
	})
}

// The one check that depends on the vote is the majority, and it is counted
// without the host the removal is about: a dead voter whose majority forms
// only once its own vote is gone is still removed, the preflight before the
// vote included (it counts as the cluster will once the vote is gone).
//
// Green on e4c38889e as well (it asked nothing before the vote); it guards
// the fix against refusing what it must not. Mutation: count the preflight's
// majority over the whole voter set — red.
func TestFleet_DeadVoterRemoval_TheMajorityWithoutItsVote(t *testing.T) {
	ctx := context.Background()
	c, a, d := deadVoterFleet(t, 4121)
	a.Server.SetGate(rmQuorumGate{with: health.QuorumNo, without: health.QuorumYes})
	lv := c.SelfClient(a)
	if err := cli.HostRemoveDead(ctx, lv, d.Name, true); err != nil {
		t.Fatalf("the dry run of a dead voter whose majority forms only without it: %v", err)
	}
	if err := cli.HostRemoveDead(ctx, lv, d.Name, false); err != nil {
		t.Fatalf("lv host rm --dead of a dead voter whose majority forms only without it: %v", err)
	}
	requireRemoved(t, a, d)
}
