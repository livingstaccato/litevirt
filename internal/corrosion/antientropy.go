package corrosion

import (
	"context"
	"io"
	"log/slog"
	"math/rand"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/pki"
)

// antiEntropyCooldown debounces manual/scheduled triggers: a pass won't start if one ran
// within this window. Well under the default 60s interval (so a scheduled tick is never
// debounced) and well above a hammer loop (so `lv cluster converge --all` in a tight loop
// can't turn into a self-inflicted SQLite-lock load test).
const antiEntropyCooldown = 12 * time.Second

// AntiEntropy periodically compares state digests with peers and triggers
// a merge of the mismatched tables when drift is detected. This is a safety net — the
// primary replication path is the WAL-based Replicator.
type AntiEntropy struct {
	client   *Client
	pkiDir   string
	interval time.Duration

	// mu guards the trigger decision only (not the pass itself): a pass no-ops when one is
	// already running or ran within antiEntropyCooldown. It never bypasses checkPeers's
	// per-table digest-gating (merge only on mismatch) — it just decides whether to run.
	mu         sync.Mutex
	inProgress bool
	lastRan    time.Time

	// sampler chooses the non-relay peers a scheduled pass contacts. Only a
	// pass touches it, and passes never overlap (inProgress), so it needs no
	// lock of its own.
	sampler *aePeerSampler
	// relayCfg is the relay election the pass derives "this node's relays"
	// from. It must match the replicator's, or the pass would favour peers
	// that are not the relays replication actually flows through; the zero
	// value takes the same defaults the daemon's replicator is built with.
	relayCfg RelayConfig
	// legacyRepair is the stand-down (anti_entropy_legacy_repair): pull whole
	// tables, never ask a peer for bucket digests.
	legacyRepair bool
}

// NewAntiEntropy creates an anti-entropy checker.
func NewAntiEntropy(client *Client, pkiDir string, interval time.Duration) *AntiEntropy {
	if interval == 0 {
		interval = 60 * time.Second
	}
	return &AntiEntropy{
		client:   client,
		pkiDir:   pkiDir,
		interval: interval,
		sampler:  newAEPeerSampler(antiEntropySampleSize, rand.New(rand.NewSource(time.Now().UnixNano()))),
	}
}

// SetRelayConfig sets the relay election a scheduled pass uses to find this
// node's relays. Pass the replicator's configuration; call before Start.
func (ae *AntiEntropy) SetRelayConfig(cfg RelayConfig) { ae.relayCfg = cfg }

// SetLegacyRepair makes this node repair the way it did before bucketed
// digests (docs/design/ae-incremental.md): whole mismatched tables, no bucket
// exchange, no digest cache. It still serves the new RPCs to its peers. Call
// before Start.
func (ae *AntiEntropy) SetLegacyRepair(on bool) {
	ae.legacyRepair = on
	ae.client.SetDigestCacheEnabled(!on)
}

// Start runs the anti-entropy loop until ctx is cancelled.
func (ae *AntiEntropy) Start(ctx context.Context) {
	slog.Info("anti-entropy: starting", "interval", ae.interval)
	// A jittered sleep rather than a fixed ticker. Every node's loop starts at
	// roughly the same moment after a cluster boot, and a shared fixed period
	// kept them aligned indefinitely — each pass has every node pulling digests
	// from every other, so aligned passes are an O(N²) burst on one beat.
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(jittered(ae.interval, loopJitter)):
			ae.RunSampledOnce(ctx) // debounced; scheduled ticks share the trigger guard
		}
	}
}

// RunOnce runs a single anti-entropy pass against EVERY member now, unless one is already
// in progress or ran within antiEntropyCooldown, in which case it no-ops. Returns true iff
// a pass actually ran. It blocks until the pass completes, so a caller (e.g. `lv cluster
// converge`) can read digests afterward knowing convergence was attempted. It ONLY
// schedules the existing pass — checkPeers still merges a table only on a digest mismatch.
//
// It is the operator's lever and deliberately not sampled: `lv cluster converge` asks
// for convergence now, and a sampled pass reaches every peer only over several passes.
func (ae *AntiEntropy) RunOnce(ctx context.Context) bool {
	return ae.runGuarded(func() { ae.checkPeers(ctx) })
}

// RunSampledOnce runs one SCHEDULED pass — this node's relays plus a few other peers
// (see checkSampledPeers) — under the same trigger guard as RunOnce. It is what the
// loop in Start runs.
func (ae *AntiEntropy) RunSampledOnce(ctx context.Context) bool {
	return ae.runGuarded(func() { ae.checkSampledPeers(ctx) })
}

func (ae *AntiEntropy) runGuarded(pass func()) bool {
	ae.mu.Lock()
	if ae.inProgress || (!ae.lastRan.IsZero() && time.Since(ae.lastRan) < antiEntropyCooldown) {
		ae.mu.Unlock()
		return false
	}
	ae.inProgress = true
	ae.mu.Unlock()

	pass()

	ae.mu.Lock()
	ae.inProgress = false
	ae.lastRan = time.Now()
	ae.mu.Unlock()
	return true
}

// checkPeers runs a pass against every member.
func (ae *AntiEntropy) checkPeers(ctx context.Context) {
	ae.checkPeerSet(ctx, nil)
}

// checkSampledPeers runs a scheduled pass: this node's relays plus
// antiEntropySampleSize other members, drawn so that every member is still
// reached within a bounded number of passes (see aePeerSampler).
//
// Every member used to be contacted on every pass, so each pass cost the
// cluster N·(N−1) digest exchanges (#262). Relays are always included because
// replication flows through them: they are the peers most likely to hold what
// this node is missing, and a leaf that agrees with its relays agrees with
// what the relay mesh has carried.
func (ae *AntiEntropy) checkSampledPeers(ctx context.Context) {
	ae.checkPeerSet(ctx, func(peers []PeerInfo) []string {
		names := make([]string, 0, len(peers))
		for _, p := range peers {
			names = append(names, p.Name)
		}
		return ae.sampler.pick(names, ae.relayTargets(ctx, peers))
	})
}

// relayTargets is the set of relays this node's pass always contacts: a leaf's
// assigned primary and backup, or, for a relay, every other relay — the peers
// the replicator itself pushes through (RelaySet.TargetsFor, minus a relay's
// leaves, which are reached by sampling like everyone else).
func (ae *AntiEntropy) relayTargets(ctx context.Context, peers []PeerInfo) []string {
	self := ae.client.HostName()
	rs := ComputeRelays(peers, self, ae.relayCfg, RelayEligibleHosts(ctx, ae.client))
	if !rs.IsRelay(self) {
		pair := rs.AssignedRelays(self)
		return dedup(pair[:])
	}
	var out []string
	for _, r := range rs.Relays() {
		if r != self {
			out = append(out, r)
		}
	}
	return out
}

// checkPeerSet runs one pass against the members choose picks (every member
// when choose is nil). A pass against every member is the operator's RunOnce,
// and it repairs observation tables whatever their schedule
// (observation_tables.go).
func (ae *AntiEntropy) checkPeerSet(ctx context.Context, choose func([]PeerInfo) []string) {
	full := choose == nil
	// Captured before ANY read, so a completed exchange marks the replica
	// caught up only if no staleness reset happened while it ran.
	gen := ae.client.replicaFreshnessGen()
	peers := ae.client.Members()
	if len(peers) == 0 {
		ae.client.MarkReplicaStale("sees no gossip peers (anti-entropy)")
		return
	}
	var targets []string
	if choose != nil {
		targets = choose(peers)
	} else {
		for _, p := range peers {
			targets = append(targets, p.Name)
		}
	}

	// Get local digest. A scheduled pass takes it from the digest cache where
	// that is still valid (digest_cache.go); the operator's full pass scans.
	digest, sensitiveDigest := ae.client.StateDigestCached, ae.client.SensitiveStateDigestCached
	if full {
		digest, sensitiveDigest = ae.client.StateDigest, ae.client.SensitiveStateDigest
	}
	localDigests, err := digest(ctx)
	if err != nil {
		slog.Warn("anti-entropy: local digest error", "error", err)
		return
	}
	localMap := make(map[string]TableDigest, len(localDigests))
	for _, d := range localDigests {
		localMap[d.Name] = d
	}
	sensitiveDigests, err := sensitiveDigest(ctx)
	if err != nil {
		slog.Warn("anti-entropy: local sensitive digest error", "error", err)
	}
	sensitiveMap := make(map[string]TableDigest, len(sensitiveDigests))
	for _, d := range sensitiveDigests {
		sensitiveMap[d.Name] = d
	}

	// Each peer gets a deadline of its own. The pass visits peers one at a time,
	// and on the daemon's root context a peer that accepted the connection and
	// then sat on GetStateDigest held the whole pass there indefinitely — every
	// peer after it in the member list was never checked again, and whatever
	// divergence anti-entropy exists to heal stayed unhealed. A dial timeout
	// cannot catch that: the dial succeeded.
	for _, peer := range targets {
		pctx, cancel := context.WithTimeout(ctx, antiEntropyPeerTimeout)
		if ae.checkPeer(pctx, peer, localMap, sensitiveMap, full) {
			ae.client.markReplicaCaughtUp(gen, peer)
		}
		cancel()
	}
}

// checkPeer runs one peer's exchange. It returns true only when the exchange
// COMPLETED — the peer's digests were read and either matched ours or its copy
// of every mismatched table was merged without error (the tables that matched
// already agreed, so either way the local replica now holds what the peer
// held) — which is what marks the local replica
// caught up (see replicaFreshness). An isolated peer, an unreachable one, or a
// failed dump/merge proves nothing and returns false.
func (ae *AntiEntropy) checkPeer(ctx context.Context, peerName string, localMap, sensitiveMap map[string]TableDigest, full bool) bool {
	// The pull half of the isolation regime (§A). PushMutations refuses an
	// isolated node's INJECTION server-side, but anti-entropy is a PULL: we
	// would otherwise merge a quarantined node's state into ours voluntarily,
	// which is the same corruption arriving through the other door. Skipping
	// here needs no capability gate — an isolation is only ever recorded while
	// the regime is active, so a pre-latch cluster has no nonzero epochs to
	// skip on.
	if epoch, reason, err := HostIsolation(ctx, ae.client, peerName); err != nil {
		slog.Warn("anti-entropy: could not read peer isolation — proceeding", "peer", peerName, "error", err)
	} else if epoch > 0 {
		slog.Warn("anti-entropy: NOT merging from an isolated peer",
			"peer", peerName, "isolation_epoch", epoch, "reason", reason,
			"fix", "reseed "+peerName+" to bring it back into the compatibility regime")
		return false
	}
	client, conn, err := ae.peerClient(ctx, peerName)
	if err != nil {
		slog.Debug("anti-entropy: cannot reach peer", "peer", peerName, "error", err)
		return false
	}
	defer conn.Close()

	dctx, dcancel := context.WithTimeout(ctx, antiEntropyDigestTimeout)
	if full {
		// The operator's pass compares what the peer holds now.
		dctx = WithFreshDigest(dctx)
	}
	resp, err := client.GetStateDigest(dctx, &emptypb.Empty{})
	dcancel()
	if err != nil {
		slog.Debug("anti-entropy: digest RPC error", "peer", peerName, "error", err)
		return false
	}

	completed := true
	mismatched := digestMismatches(peerName, resp.Tables, localMap)
	// Observation tables are repaired on their own, slower schedule; control
	// state is repaired now (observation_tables.go). Observations are always
	// due on a replica that is not caught up, so deferring them never holds
	// the replica-freshness signal back.
	pull, observations := splitObservations(mismatched)
	now := time.Now()
	obsDue := len(observations) > 0 && (full || ae.client.observationRepairDue(now))
	if obsDue {
		pull = append(pull, observations...)
	} else if len(observations) > 0 {
		slog.Debug("anti-entropy: observation drift left to its writers until the next observation repair",
			"peer", peerName, "tables", observations)
	}
	// A table whose only difference from this peer is a tie already tracked,
	// proven by an earlier pull at exactly these digests, is not pulled again
	// until either side's digest moves (settled_ties.go). The operator's full
	// pass pulls it regardless.
	remoteMap := make(map[string]*pb.TableDigest, len(resp.Tables))
	for _, r := range resp.Tables {
		remoteMap[r.Name] = r
	}
	if !full {
		var settled []string
		if pull, settled = ae.client.deferSettledTies(peerName, pull, localMap, remoteMap); len(settled) > 0 {
			slog.Debug("anti-entropy: not re-pulling tables whose only difference is an unresolved tie already tracked",
				"peer", peerName, "tables", settled)
		}
	}
	if len(pull) > 0 {
		slog.Info("anti-entropy: syncing from peer", "peer", peerName, "tables", pull)
		// Only the mismatched tables: pulling the full dump for one drifted
		// row made every repair cost the whole cluster's state (#262). And of
		// those, only the buckets that differ, where the peer can say which.
		scope := ae.bucketScope(ctx, client, peerName, pull)
		kept, pullErr, mergeErr := ae.pullAndMerge(ctx, client, pull, scope, nil)
		if pullErr != nil {
			slog.Warn("anti-entropy: dump RPC error", "peer", peerName, "error", pullErr)
			completed = false
		} else if mergeErr != nil {
			// Operational/commit failure during merge: this cycle's convergence is incomplete.
			// The merge is per-row-idempotent and non-destructive, so the next cycle retries.
			slog.Warn("anti-entropy: merge error (will retry next cycle)", "peer", peerName, "error", mergeErr)
			completed = false
		} else {
			slog.Info("anti-entropy: merge complete", "peer", peerName, "tables", pull)
			ae.client.recordSettledTies(ctx, peerName, pull, kept, remoteMap, scope)
			if obsDue {
				ae.client.markObservationsRepaired(now)
			}
		}
	}

	ae.checkSensitivePeer(ctx, client, peerName, sensitiveMap, full)
	return completed
}

// TableDigestsAgree reports whether one table's local digest and a peer's say
// the two nodes hold the same rows.
//
// Exported because it is not only anti-entropy's question. Any caller that has
// to establish "my view of this table is the cluster's view" — the NetBox bind's
// VM-inventory corroboration is the other one — must ask it the SAME way, or two
// answers to one question drift apart: the v1/v2 negotiation below is subtle
// enough that a second copy would eventually compare a v1 hash against a v2 one
// and report permanent, false disagreement.
//
// Pairwise negotiation: compare the order-invariant v2 hash ONLY when BOTH sides
// supplied it (⇒ both have digest_v2 enabled); otherwise compare the positional
// v1 hash. Count is always compared.
func TableDigestsAgree(local TableDigest, remote *pb.TableDigest) bool {
	lh, rh := localAndRemoteHash(local, remote)
	return local.Count == int(remote.GetCount()) && lh == rh
}

// localAndRemoteHash picks the pair of hashes to compare, so the predicate and
// the log line that explains a mismatch cannot disagree about which was used.
func localAndRemoteHash(local TableDigest, remote *pb.TableDigest) (string, string) {
	if local.HashV2 != "" && remote.GetHashV2() != "" {
		return local.HashV2, remote.GetHashV2()
	}
	return local.Hash, remote.GetHash()
}

// digestMismatches returns the tables whose digest differs from the peer.
func digestMismatches(peer string, remote []*pb.TableDigest, localMap map[string]TableDigest) []string {
	var out []string
	for _, r := range remote {
		local, exists := localMap[r.Name]
		if !exists {
			slog.Info("anti-entropy: drift detected", "peer", peer, "table", r.Name, "local_hash", "", "remote_hash", r.Hash)
			out = append(out, r.Name)
			continue
		}
		if TableDigestsAgree(local, r) {
			continue // in sync
		}
		lh, rh := localAndRemoteHash(local, r)
		useV2 := local.HashV2 != "" && r.GetHashV2() != ""
		slog.Info("anti-entropy: drift detected",
			"peer", peer, "table", r.Name, "digest", map[bool]string{true: "v2", false: "v1"}[useV2],
			"local_hash", lh, "remote_hash", rh)
		out = append(out, r.Name)
	}
	return out
}

func (ae *AntiEntropy) checkSensitivePeer(ctx context.Context, client pb.LiteVirtClient, peerName string, localMap map[string]TableDigest, full bool) {
	if len(localMap) == 0 {
		return
	}
	req := &pb.SensitiveStateRequest{Sender: ae.client.HostName()}
	dctx, dcancel := context.WithTimeout(ctx, antiEntropyDigestTimeout)
	if full {
		dctx = WithFreshDigest(dctx)
	}
	resp, err := client.GetSensitiveStateDigest(dctx, req)
	dcancel()
	if err != nil {
		if status.Code(err) == codes.Unimplemented {
			slog.Debug("anti-entropy: peer has no sensitive state digest RPC", "peer", peerName)
			return
		}
		slog.Debug("anti-entropy: sensitive digest RPC error", "peer", peerName, "error", err)
		return
	}

	mismatched := digestMismatches(peerName, resp.Tables, localMap)
	if len(mismatched) == 0 {
		return
	}

	slog.Info("anti-entropy: syncing sensitive state from peer", "peer", peerName, "tables", mismatched)
	// Only the mismatched sensitive tables, and of those the differing
	// buckets. An older server ignores both and sends the whole lane, as it
	// always did. The stand-down asks for the whole lane.
	var scope *pullScope
	if !ae.legacyRepair {
		scope = ae.bucketScope(ctx, client, peerName, mismatched)
		req = &pb.SensitiveStateRequest{Sender: req.GetSender(), Tables: mismatched, Buckets: scope.wire(), BucketScheme: BucketScheme}
	}
	_, pullErr, mergeErr := ae.pullAndMerge(ctx, client, mismatched, scope, req)
	if pullErr != nil {
		if status.Code(pullErr) == codes.Unimplemented {
			slog.Debug("anti-entropy: peer has no sensitive state dump RPC", "peer", peerName)
			return
		}
		slog.Warn("anti-entropy: sensitive dump RPC error", "peer", peerName, "error", pullErr)
		return
	}
	if mergeErr != nil {
		slog.Warn("anti-entropy: sensitive merge error (will retry next cycle)", "peer", peerName, "error", mergeErr)
		return
	}
	slog.Info("anti-entropy: sensitive merge complete", "peer", peerName, "tables", mismatched)
}

// fetchStateDump pulls a peer's full state dump, preferring the chunked
// StreamStateDump RPC (which can't hit the gRPC max-message size) and falling
// back to the legacy unary GetStateDump when the peer is an older build that
// doesn't implement the stream. This keeps anti-entropy working in a
// mixed-version cluster in both directions.
func fetchStateDump(ctx context.Context, client pb.LiteVirtClient) ([]byte, error) {
	stream, err := client.StreamStateDump(ctx, &emptypb.Empty{})
	if err == nil {
		var buf []byte
		for {
			chunk, rerr := stream.Recv()
			if rerr == io.EOF {
				return buf, nil
			}
			if rerr != nil {
				// An old peer reports Unimplemented (usually on the first Recv,
				// so buf is still empty) — fall back to the unary RPC.
				if status.Code(rerr) == codes.Unimplemented {
					break
				}
				return nil, rerr
			}
			buf = append(buf, chunk.Data...)
		}
	} else if status.Code(err) != codes.Unimplemented {
		return nil, err
	}

	// Fallback: legacy unary full-state dump.
	dump, derr := client.GetStateDump(ctx, &emptypb.Empty{})
	if derr != nil {
		return nil, derr
	}
	return dump.Data, nil
}

// fetchTableDump pulls only the named public tables from a peer over
// StreamTableDump, which adds any table their merge reads authority from (see
// ResolveTableDump). A peer on an older build answers Unimplemented, on the call
// or the first Recv, and the pull falls back to the full dump — correct, only
// costlier — so a mixed-version cluster keeps repairing. Any other error is
// this exchange failing and propagates.
func fetchTableDump(ctx context.Context, client pb.LiteVirtClient, tables []string) ([]byte, error) {
	return fetchTableDumpScoped(ctx, client, tables, nil)
}

// fetchTableDumpScoped is fetchTableDump narrowed to scope's buckets (nil: whole
// tables). An older server ignores the narrowing and sends whole tables.
func fetchTableDumpScoped(ctx context.Context, client pb.LiteVirtClient, tables []string, scope *pullScope) ([]byte, error) {
	req := &pb.TableDumpRequest{Tables: tables}
	if b := scope.wire(); b != nil {
		req.Buckets, req.BucketScheme = b, BucketScheme
	}
	stream, err := client.StreamTableDump(ctx, req)
	if err != nil {
		if status.Code(err) == codes.Unimplemented {
			return fetchStateDump(ctx, client)
		}
		return nil, err
	}
	var buf []byte
	for {
		chunk, rerr := stream.Recv()
		if rerr == io.EOF {
			return buf, nil
		}
		if rerr != nil {
			if status.Code(rerr) == codes.Unimplemented {
				return fetchStateDump(ctx, client)
			}
			return nil, rerr
		}
		buf = append(buf, chunk.Data...)
	}
}

func fetchSensitiveStateDump(ctx context.Context, client pb.LiteVirtClient, req *pb.SensitiveStateRequest) ([]byte, error) {
	stream, err := client.StreamSensitiveStateDump(ctx, req)
	if err != nil {
		return nil, err
	}
	var buf []byte
	for {
		chunk, rerr := stream.Recv()
		if rerr == io.EOF {
			return buf, nil
		}
		if rerr != nil {
			return nil, rerr
		}
		buf = append(buf, chunk.Data...)
	}
}

func (ae *AntiEntropy) peerClient(ctx context.Context, peerName string) (pb.LiteVirtClient, *grpc.ClientConn, error) {
	target, err := resolvePeerTarget(ctx, ae.client, peerName)
	if err != nil {
		return nil, nil, err
	}
	// Raise the receive limit so the legacy unary GetStateDump fallback can
	// pull a large full-state dump from an old peer. StreamStateDump chunks
	// stay well under the 4 MiB default and don't need this.
	conn, err := pki.PeerDial(ae.pkiDir, target,
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(antiEntropyMaxMsgSize)))
	if err != nil {
		return nil, nil, err
	}
	return pb.NewLiteVirtClient(conn), conn, nil
}

// antiEntropyPeerTimeout bounds one peer's whole anti-entropy exchange: digest,
// and when the digests disagree, the dump of the mismatched tables and its merge.
//
// Generous on purpose. A total deadline cannot tell an idle hang from a slow
// transfer, and cutting a legitimate dump short is worse than the hang — it
// would stop a large cluster from ever converging. Five minutes is far past
// any dump this tree produces over a LAN and still bounds the pass. A var only
// so tests can shrink it.
var antiEntropyPeerTimeout = 5 * time.Minute

// antiEntropyDigestTimeout bounds each digest RPC on its own. A digest is a few
// bytes; the generous per-peer budget exists for the dump and merge, and on the
// digest it let K hung peers stall every serial pass for K × that budget before
// the healthy peers behind them were reached. A var so tests can move it.
var antiEntropyDigestTimeout = 30 * time.Second

// antiEntropyMaxMsgSize bounds the legacy unary state-dump fallback's receive
// size; matches the server's grpcMaxMsgSize backstop.
const antiEntropyMaxMsgSize = 64 << 20 // 64 MiB

// The full-state merge (MergeStateBytesLWW) lives in sync.go — it is the single
// merge engine shared by all callers.
