package health

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pki"
)

const (
	checkInterval    = 2 * time.Second
	checkTimeout     = 3 * time.Second
	suspectThreshold = 3
	// probeConcurrency caps how many peer health probes run at once per tick.
	probeConcurrency = 16
)

// ProbeInterval is the cadence at which an observer probes each peer. A probe
// is started at most once per tick, so N consecutive failed probes from one
// observer span at least (N-1) × ProbeInterval — the lower bound failover uses
// to tell whether a peer has been down without a break since some instant.
const ProbeInterval = checkInterval

// unreadyFailures is the consecutive_failures an 'unready' row carries, for
// every unready observation in a run: below any fence threshold, and non-zero
// so that recovery (which counts consecutive_failures = 0) never reads it as
// healthy. See checkHost.
const unreadyFailures = 1

// HeartbeatInterval is how often an UNCHANGED host_health verdict is
// re-published so it keeps a current updated_at.
//
// It applies ONLY to peers whose host row is 'offline' or 'fenced' — see
// shouldPersistHealth, which is where that scoping is argued. Restamping every
// healthy peer instead would be N*(N-1) replicated writes per interval.
//
// checkHost used to write only on transition. A failing peer changes every
// probe (consecutive_failures increments), so the failing direction was always
// fresh; a steadily healthy peer changed nothing and its row was written once
// and never again. failover.recoverHosts counts healthy observers whose
// updated_at is inside its freshness cutoff, so it normally saw none and a
// fenced or offline host could not auto-recover.
//
// It MUST stay comfortably below failover's healthFreshness; that relationship
// is pinned by TestHeartbeatFitsInsideHealthFreshness in internal/failover,
// which is the package that owns the cutoff.
//
// A var, not a const, only so tests can shrink it; nothing in production
// reassigns it.
var HeartbeatInterval = 10 * time.Second

// peerState tracks the last known health state for a peer so we only write
// to the database on state transitions, not every tick.
//
// lastHealthyAt/lastFailureAt are LOCAL MONOTONIC anchors (time.Now, so they
// carry a monotonic reading): split-brain timing (Phase 2 self-demotion, Phase 5
// watchdog) must measure elapsed time by the local clock, never by comparing
// cross-node RFC3339 timestamps (which can be ±MaxSkew apart). They live only in
// memory, so a daemon restart deliberately resets them — a restart must re-earn
// its timing, not credit a pre-restart reading.
type peerState struct {
	status        string // "healthy" or "suspect"
	failures      int
	lastHealthyAt time.Time // monotonic; zero if never probed healthy
	lastFailureAt time.Time // monotonic; zero if never probed unhealthy
	// lastWriteAt is when this observer last PUBLISHED a verdict for the peer
	// (monotonic; zero until the first write). It drives the HeartbeatInterval
	// re-publish that keeps an unchanged row's updated_at current.
	lastWriteAt time.Time
	// stallEpoch is the local stall epoch (stall.go) `failures` was counted in.
	// A stall since then discards the count: failures observed before the
	// observer stopped, and the probe that straddled the stop, are not the same
	// run of evidence as failures observed after it.
	stallEpoch uint64
	// answeredUnready is whether the last probe got an unready ANSWER. The
	// silence count restarts after one, because an answer is not silence; it
	// must not restart on every silent probe that follows.
	answeredUnready bool
}

// Checker performs periodic health checks on peer hosts.
type Checker struct {
	hostName string
	pkiDir   string
	db       *corrosion.Client
	tlsCfg   *tls.Config

	// writeFn replaces the host_health write in tests. Nil in production,
	// where checkHost calls the corrosion client directly.
	writeFn func(ctx context.Context, sqlStr string, params ...interface{}) error

	mu     sync.Mutex
	peers  map[string]*peerState // target hostname → cached state
	crlVer int64                 // last published CRL version

	// Warmup / quorum-timing anchors (local monotonic; reset on restart).
	startedAt  time.Time // when Start began; bounds the Unknown warmup window
	probedOnce bool      // set true after the first full probe cycle completes

	// peerPinger fresh-Pings a peer for its capability tokens (SetPeerPinger).
	peerPinger PeerPinger
	// peerReady asks a peer whether it can serve, not merely whether it accepts
	// a TLS connection (SetPeerReadiness). nil keeps the TLS-only probe.
	peerReady PeerReadiness
	// peerCaps caches each peer's advertised capabilities with a short TTL so the
	// replicator can gate proof replication per-peer without a Ping storm.
	peerCaps map[string]peerCapEntry

	// capActiveNeg caches a NEGATIVE CapabilityActive result per token for a short TTL, so
	// the frequent pre-latch Enforced() calls on hot paths (StartVM/MigrateVM/applyLBLocal,
	// the 2s demoter tick, owner-assert) don't re-fan-out fresh Pings every call. Only
	// negatives are cached — Enforced latches on the first positive, so there's no repeated
	// positive recompute to cache; the short TTL bounds how long a just-healed cluster waits
	// to activate.
	capActiveNeg map[string]capNegEntry

	// capActivePos caches a POSITIVE result per token for capActivePosTTL, populated and read
	// ONLY by CapabilityActiveForHealth — the post-latch HA monitor (evaluateHADegraded),
	// which would otherwise re-fan-out a fresh capability sweep across every voting peer on
	// every tick. The ACTIVATION path (CapabilityActive/Enforced) deliberately does NOT read
	// this — the latch must never turn on from a stale positive. A regression on an already-
	// latched cluster still surfaces within the TTL, and the entry is cleared the moment any
	// sweep yields a negative (cacheNeg), so a regression is never masked.
	capActivePos map[string]time.Time

	// activated latches, PER TOKEN, "enforcement has activated cluster-wide"
	// (monotone, durable via a per-token marker file) so a later partition fails
	// closed, not to legacy. Keyed by token so distinct features (Phase 2/4/5) latch
	// INDEPENDENTLY — a single global latch would conflate them. activationPersisted
	// tracks whether each token's durable marker write SUCCEEDED; a failed write is
	// retried on the next Enforced call (a lost marker would re-open the legacy path
	// across a restart during a partition). Per-token marker file = base + "." + token.
	activated            map[string]bool
	activationPersisted  map[string]bool
	activationMarkerBase string

	// selfFenced reports whether THIS node has self-fenced (tripped the watchdog) and is
	// waiting to reboot. When true, ExecutionGate AND DecisionGate fail closed regardless
	// of quorum/role — a doomed node must take no runtime-ownership decide/execute during
	// the fence-timeout window. Injected by the daemon from the watchdog controller;
	// nil-safe (unset → never fenced). This is the central chokepoint that also covers the
	// reconciler's startPendingVM and every other gate consumer.
	selfFenced func() bool

	// clock is the checker's local time source (nil → time.Now). It must carry a
	// monotonic reading in production; tests replace it to model time passing
	// without sleeping.
	clock func() time.Time

	// stall is the local liveness heartbeat's record (stall.go): failed probes
	// observed across, or shortly after, a gap in this process's own execution
	// are not evidence against the peer.
	stall stallState

	// voterSet replaces corrosion.VoterSet for the probe plan in tests. Nil in
	// production.
	voterSet func(context.Context) (map[string]bool, error)
	// planned is the set of peers the last completed cycle's plan probed
	// (probe_plan.go); nil until one has run. PeerUp reads it to tell "not
	// probed by me" from "probed and not healthy".
	planned map[string]bool
	// quorumLostAt is the local instant QuorumProof last read No; zero if it
	// never has in this process. InQuorumRegainGrace reads it. Guarded by mu.
	quorumLostAt time.Time
}

// now reads the checker's local clock.
func (c *Checker) now() time.Time {
	if c.clock != nil {
		return c.clock()
	}
	return time.Now()
}

// SetSelfFenced injects the self-fenced predicate (Phase 2 defense-in-depth). nil-safe.
func (c *Checker) SetSelfFenced(fn func() bool) { c.selfFenced = fn }

// SelfFenced reports whether this node has self-fenced (nil predicate → false). Public so
// the reconcile/health loops can hard-gate runtime actions on it even on paths that don't
// consult Execution/DecisionGate (the markerless legacy path).
func (c *Checker) SelfFenced() bool { return c.isSelfFenced() }

// isSelfFenced reports whether this node has self-fenced (nil predicate → false).
func (c *Checker) isSelfFenced() bool { return c.selfFenced != nil && c.selfFenced() }

type peerCapEntry struct {
	caps      []string
	fetchedAt time.Time // local monotonic
}

type capNegEntry struct {
	reason string
	at     time.Time // local monotonic
}

// NewChecker creates a new health checker.
func NewChecker(hostName, pkiDir string, db *corrosion.Client) *Checker {
	return &Checker{
		hostName:            hostName,
		pkiDir:              pkiDir,
		db:                  db,
		peers:               make(map[string]*peerState),
		peerCaps:            make(map[string]peerCapEntry),
		capActiveNeg:        make(map[string]capNegEntry),
		capActivePos:        make(map[string]time.Time),
		activated:           make(map[string]bool),
		activationPersisted: make(map[string]bool),
	}
}

// Start begins periodic health checking. Blocks until context is cancelled.
func (c *Checker) Start(ctx context.Context) {
	// Anchor the warmup clock FIRST. A transient PeerTLSConfig failure below must not leave
	// startedAt==0 — that makes QuorumProof skip warmup and report a permanent false QuorumNo
	// (refusing every gated action on this node; post-Phase-2 it would demote/self-fence a
	// healthy node).
	c.mu.Lock()
	c.startedAt = time.Now()
	c.mu.Unlock()

	// The heartbeat first: a probe must never run without it, or every failure
	// after a quiet spell would read as observed across a stall.
	go c.runStallHeartbeat(ctx)

	// Load TLS config for peer connections; RETRY a transient failure (e.g. a PKI-setup race
	// at boot) rather than giving up — a checker that never loads TLS never probes peers, so
	// it would report a permanent quorum loss. Loud on each failure; recovers when PKI heals.
	var err error
	for {
		c.tlsCfg, err = pki.PeerTLSConfig(c.pkiDir)
		if err == nil {
			break
		}
		slog.Error("health checker: failed to load TLS config; retrying (peer health checks blocked until it succeeds)", "error", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
	}

	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Only a cycle that actually enumerated hosts ends warmup — a ListHosts error
			// probed nobody, so leaving probedOnce false keeps quorum Unknown (not a
			// premature No off an empty c.peers).
			if c.checkAllPeers(ctx) {
				c.mu.Lock()
				c.probedOnce = true
				c.mu.Unlock()
			}
		}
	}
}

// checkAllPeers probes every peer in this node's probe plan (probe_plan.go)
// once. It returns true only when it actually ENUMERATED the host list — a ListHosts error probes nobody and returns false, so the
// caller must not treat that tick as a completed warmup cycle (else Unknown collapses to
// No with an empty c.peers on a single transient DB error).
func (c *Checker) checkAllPeers(ctx context.Context) bool {
	hosts, err := corrosion.ListHosts(ctx, c.db)
	if err != nil {
		slog.Error("health check: list hosts", "error", err)
		return false
	}

	// Check local CRL version and publish it for gossip-based distribution (#49).
	// Only write when the version actually changes.
	localCRLVersion := pki.CRLVersion(c.pkiDir + "/crl.pem")
	if localCRLVersion > 0 {
		c.mu.Lock()
		changed := localCRLVersion != c.crlVer
		if changed {
			c.crlVer = localCRLVersion
		}
		c.mu.Unlock()
		if changed {
			// Bind the timestamp instead of datetime('now'): the receiver-evaluated
			// function is non-deterministic across nodes (each would stamp its own wall
			// clock into the LWW key on apply) and can't be structurally validated. NowTS()
			// is the monotonic LWW clock the rest of the replicated writes use.
			c.db.ExecuteDeferred(ctx,
				`INSERT OR REPLACE INTO crl_versions (host, version, updated_at)
				 VALUES (?, ?, ?)`,
				c.hostName, localCRLVersion, c.db.NowTS())
		}
	}

	var targets []corrosion.HostRecord
	for _, host := range hosts {
		if host.Name == c.hostName {
			continue // don't check ourselves
		}
		if host.State == "maintenance" {
			continue
		}

		// Detect CRL version mismatch (#49).
		if localCRLVersion > 0 {
			rows, qerr := c.db.Query(ctx,
				`SELECT version FROM crl_versions WHERE host = ?`, host.Name)
			if qerr != nil {
				slog.Warn("CRL version check: query failed (skipping stale-CRL detection for peer)",
					"peer", host.Name, "error", qerr)
			} else if len(rows) > 0 {
				peerVersion := rows[0].Int64("version")
				if peerVersion < localCRLVersion {
					slog.Warn("CRL version mismatch: peer has stale CRL — revoked hosts may still connect",
						"peer", host.Name, "peer_version", peerVersion, "local_version", localCRLVersion)
				}
			}
		}

		targets = append(targets, host)
	}

	// All-pairs among voters, sampled for non-voters (probe_plan.go). A voter
	// set that cannot be read leaves the full mesh: the plan only ever drops
	// edges no quorum counts, and without the voter set it cannot tell which.
	names := planCandidates(c.hostName, hosts)
	voters, verr := c.voters(ctx)
	if verr != nil {
		slog.Warn("health check: voter set unreadable; probing every peer this cycle", "error", verr)
		voters = nil
	}
	plan := probePlan(c.hostName, names, voters, nonVoterProbeSample)
	planned := targets[:0:0]
	for _, h := range targets {
		if plan[h.Name] {
			planned = append(planned, h)
		}
	}
	// A peer that left the plan leaves c.peers with it. Its last verdict would
	// otherwise stand forever, and HealthyPeers would keep offering it as
	// proven live. Maintenance hosts are not candidates and keep their entry,
	// exactly as before the plan existed.
	c.mu.Lock()
	for _, name := range names {
		if !plan[name] {
			delete(c.peers, name)
		}
	}
	c.planned = plan
	c.mu.Unlock()
	targets = planned

	// Probe peers with bounded concurrency and wait for the batch. Previously
	// this fired one goroutine per host per tick with no bound — a probe that
	// hangs longer than the tick interval would let goroutines accumulate
	// unboundedly. Now at most probeConcurrency run at once, and the next tick
	// won't start a fresh batch until this one drains.
	boundedFanout(targets, probeConcurrency, func(h corrosion.HostRecord) {
		c.checkHost(ctx, h)
	})
	return true
}

// boundedFanout runs work over items with at most `concurrency` goroutines in
// flight, blocking until all complete. It bounds both peak goroutines and the
// rate of creation (the loop blocks on the semaphore), so a hung worker can't
// accumulate unbounded goroutines.
func boundedFanout[T any](items []T, concurrency int, work func(T)) {
	if concurrency < 1 {
		concurrency = 1
	}
	var wg sync.WaitGroup
	sem := make(chan struct{}, concurrency)
	for _, it := range items {
		wg.Add(1)
		sem <- struct{}{}
		go func(x T) {
			defer wg.Done()
			defer func() { <-sem }()
			work(x)
		}(it)
	}
	wg.Wait()
}

// recoveryPending reports whether the failover coordinator could auto-recover
// a host in this state once it looks healthy again.
//
// These are exactly the two states recoverHosts acts on — everything else hits
// its `default: continue`. 'maintenance' and 'draining' are operator intent and
// are never auto-cleared, so a heartbeat for them would be traffic with no
// reader.
func recoveryPending(state string) bool {
	return state == "offline" || state == "fenced"
}

// shouldPersistHealth decides whether this probe writes a host_health row.
//
// A transition always writes — that is the original contract and what every
// other reader depends on. The second clause exists for ONE reader: the
// coordinator's recovery quorum, which counts only rows newer than
// failover.healthFreshness. A peer that comes back and then stays healthy
// produces no further transitions, so without it the row froze at the instant
// the peer went healthy; by the time recentlyFenced stopped suppressing
// recovery five minutes later, the only healthy row on record was minutes old,
// failed the freshness cutoff, and the host sat `offline` awaiting a manual
// undrain.
//
// The heartbeat is deliberately narrow on both axes.
//
// It is limited to hosts AWAITING RECOVERY because the alternative — restamping
// every healthy row on a timer — is N*(N-1) replicated writes per interval
// across the cluster, for a reader that only ever looks at two states. The
// other three consumers of this table do not need it: the fence quorum selects
// `consecutive_failures >= offlineThreshold`, and a failing peer increments
// that on every probe, so `changed` is already true and those rows are never
// stale; GetClusterHealth and the metrics server read status and last_seen with
// no freshness cutoff at all.
//
// And it is rate-limited to HeartbeatInterval rather than firing every probe,
// because checkInterval is 2s and the cutoff it has to beat is 30s.
//
// That asymmetry — failing rows self-refresh, healthy ones do not — is why the
// bug only ever showed up on the recovery path.
//
// An unready ANSWER gets the same heartbeat, whatever the host's state. Its
// stored count is pinned (see checkHost), so an unready run changes nothing
// after its first probe and would otherwise be written once and go stale. It
// used to be rewritten on every probe instead — ~1,800 replicated writes per
// observer per hour while a peer's store stayed wedged. Nothing reads
// unready-row freshness more tightly than HeartbeatInterval: the fence and
// confirmation quorums exclude unready rows outright, and the dual-run
// detector's last-alive evidence tolerates deadHostSkewMargin (minutes).
func shouldPersistHealth(changed, healthy, answeredUnready, recoveryPending bool, sinceLastWrite time.Duration) bool {
	if changed {
		return true
	}
	if HeartbeatInterval <= 0 || sinceLastWrite < HeartbeatInterval {
		return false
	}
	return answeredUnready || (healthy && recoveryPending)
}

// The two host_health verdict shapes checkHost publishes. Every release since
// v1.3.0 emits both, unchanged.
const (
	healthyVerdictSQL = `INSERT OR REPLACE INTO host_health (observer, target, status, consecutive_failures, last_seen, updated_at)
			 VALUES (?, ?, ?, 0, ?, ?)`
	unhealthyVerdictSQL = `INSERT OR REPLACE INTO host_health (observer, target, status, consecutive_failures, last_seen, updated_at)
			 VALUES (?, ?, ?, ?, ?, ?)`
)

func (c *Checker) checkHost(ctx context.Context, host corrosion.HostRecord) {
	// net.JoinHostPort (not Sprintf): host.Address is a bare host and may be an
	// IPv6 literal, which "%s:%d" would mangle into an unparseable target. Every
	// probe would then fail and this healthy peer would be marked suspect and
	// fenced — a config value silently becoming a fencing event.
	addr := corrosion.PeerTarget(host.Address, host.GRPCPort)
	_, epochBefore := c.beat(c.now())
	result := c.probeHost(ctx, host.Name, addr)
	healthy := result == probeReady

	// Beat on the result, not only in the heartbeat loop: the probe whose
	// deadline ran out while this process was stopped completes the moment it
	// resumes, possibly before the heartbeat goroutine is scheduled.
	observedAt := c.now()
	stallAt, stallEpoch := c.beat(observedAt)
	// Withheld entirely — no state change, no write:
	//   - any result of a probe that STRADDLED a stall. It proves nothing about
	//     the peer after the stall: a timeout ran out while this process was
	//     stopped, and an answer may have arrived before it stopped.
	//   - an unreachable verdict inside the grace window after a stall: this
	//     observer has only just resumed, alongside peers that may be resuming
	//     too. A success there still counts — a peer that answered a probe sent
	//     after the stall is proven — and so does an explicit not-ready answer,
	//     which is the peer's own statement and licenses no fence.
	straddled := stallEpoch != epochBefore
	withhold := straddled || (result == probeUnreachable && inGrace(stallAt, observedAt))

	c.mu.Lock()
	prev, exists := c.peers[host.Name]
	if !exists {
		// Deliberately NOT bootstrapped from the host_health row. A failure
		// count is evidence THIS run gathered, and seeding it from the DB let a
		// just-restarted daemon publish prev+1 with a current updated_at on its
		// very first probe — a fence-quorum-eligible "suspect" verdict carrying
		// a count it never observed. The healthy direction already refuses that
		// credit (gate.go only counts a peer whose lastHealthyAt this run set);
		// the failing direction is the same claim and gets the same rule.
		//
		// The cost is bounded and correct: after a restart a node must re-earn
		// suspectThreshold consecutive failures — about 6 s at checkInterval —
		// before it votes to fence again.
		prev = &peerState{status: "", failures: 0, stallEpoch: stallEpoch}
		c.peers[host.Name] = prev
	}
	if prev.stallEpoch != stallEpoch {
		prev.failures = 0
		prev.stallEpoch = stallEpoch
	}
	if withhold {
		// No state change and no write: the published row keeps its old
		// updated_at and ages out of fencing quorum's freshness window rather
		// than being refreshed by a probe that proves nothing.
		c.mu.Unlock()
		return
	}

	var newStatus string
	var newFailures int

	if healthy {
		newStatus = "healthy"
		newFailures = 0
	} else {
		newFailures = prev.failures + 1
		if result == probeUnreachable && prev.answeredUnready {
			// Every unready probe before this one reached the peer and got an
			// answer, so none of them is silence. The silence count starts
			// here, and "suspect" — what fencing quorum counts — has to be
			// earned with suspectThreshold unanswered probes in a row, as for
			// any peer. Carrying the unready run over made one dropped packet
			// after a long unready stretch fence-eligible on its own.
			newFailures = 1
		}
		switch {
		case result == probeNotReady:
			// Recorded on the FIRST observation, unlike "suspect", which needs
			// suspectThreshold consecutive misses. The threshold exists because
			// silence is ambiguous — one dropped packet must not fence a live
			// host — and because "suspect" is the verdict fencing quorum counts.
			// An unready answer is neither: it is the peer's own statement about
			// itself, delivered over a connection that plainly works, and it
			// licenses no destructive action. Waiting three ticks to write down
			// something the peer already told us only delays the operator's view
			// of it.
			newStatus = StatusUnready
			// And the stored count stays at one, however long the answers go on.
			// Only a coordinator that knows 'unready' excludes it from fence
			// quorum; an older-build leader during a rolling upgrade counts
			// `consecutive_failures >= FailuresToFence` and nothing else, so a
			// climbing count here would read to it as a quorum of observers
			// agreeing the host is dead — a power-off of a host that is
			// answering. The row never carries the count, so no build can count
			// it. One, not zero: zero is what recovery reads as healthy.
			newFailures = unreadyFailures
		case newFailures >= suspectThreshold:
			newStatus = "suspect"
		case prev.status == StatusUnready:
			// Silent, but not yet long enough to call suspect. It stays what
			// it last said it was: publishing "healthy" here would have
			// QuorumProof count a peer that is neither answering nor ready.
			newStatus = StatusUnready
		default:
			newStatus = "healthy"
		}
	}

	// An unchanged unready verdict is not a change. Its count is pinned, so it
	// is kept fresh by the HeartbeatInterval re-publish in shouldPersistHealth
	// rather than by a replicated write on every probe.
	changed := !exists || newStatus != prev.status || newFailures != prev.failures
	prev.answeredUnready = result == probeNotReady
	prev.status = newStatus
	prev.failures = newFailures
	// Local monotonic anchors updated every probe (not just on change) so Phase 2/5
	// timers measure "time since last direct contact" by our own clock.
	mono := c.now()
	if healthy {
		prev.lastHealthyAt = mono
	} else {
		prev.lastFailureAt = mono
	}
	sinceWrite := time.Duration(0)
	if !prev.lastWriteAt.IsZero() {
		sinceWrite = mono.Sub(prev.lastWriteAt)
	} else {
		sinceWrite = HeartbeatInterval // never written: the first probe publishes
	}
	write := shouldPersistHealth(changed, healthy, result == probeNotReady, recoveryPending(host.State), sinceWrite)
	c.mu.Unlock()

	if !write {
		return
	}

	now := c.db.NowTS()
	// Each arm CALLS the corrosion client directly. Do not fold the two into a
	// func value (exec := c.db.ExecuteDeferred): stmtshapecheck finds replicated
	// statements at their call sites, so a write through a func value is
	// invisible to it. That happened once — both verdict shapes vanished from
	// the scan, their ledger entries survived only until the next
	// -emit-ledger, and after that every peer would have refused this
	// observer's verdicts.
	var err error
	if healthy {
		// last_seen is a wall/display column (read as wall time via parseTimestamp), so
		// it must use NowWall, NOT NowTS — NowTS is the LWW key and becomes an HLC string.
		args := []interface{}{c.hostName, host.Name, "healthy", c.db.NowWall(), now}
		if c.writeFn != nil {
			err = c.writeFn(ctx, healthyVerdictSQL, args...)
		} else {
			err = c.db.ExecuteDeferred(ctx, healthyVerdictSQL, args...)
		}
	} else {
		args := []interface{}{c.hostName, host.Name, newStatus, newFailures, nil, now}
		if c.writeFn != nil {
			err = c.writeFn(ctx, unhealthyVerdictSQL, args...)
		} else {
			err = c.db.ExecuteDeferred(ctx, unhealthyVerdictSQL, args...)
		}
	}
	if err != nil {
		// Do NOT advance lastWriteAt. It records when a verdict was PUBLISHED,
		// and stamping it for a write that failed makes an observer publishing
		// nothing indistinguishable from one heartbeating normally — the host
		// it is meant to recover then sits fenced with no log line naming the
		// cause. Leaving it unstamped also retries on the next probe instead
		// of waiting a full heartbeat interval.
		slog.Warn("health: publishing the peer verdict failed",
			"observer", c.hostName, "target", host.Name, "healthy", healthy, "error", err)
		return
	}
	c.mu.Lock()
	prev.lastWriteAt = mono
	c.mu.Unlock()
}

func (c *Checker) probe(addr string) bool {
	dialer := &net.Dialer{Timeout: checkTimeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, c.tlsCfg)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// checkClockSkew compares the local clock with the peer's reported timestamp
// and logs a warning if skew exceeds 1 second. This mitigates LWW resolution
// corruption from NTP misconfiguration (#41).
// A zero peerTimestamp means the peer reported no clock — an older build whose
// PingResponse predates wall_clock, or this node pinging itself. That is
// UNKNOWN, not skew: measuring it against time.Since would read as ~2000 years
// of drift and bury the real signal.
//
// reqStart/reqEnd bracket the Ping RPC that carried the timestamp. The peer
// stamps its clock while BUILDING the response — somewhere inside that
// interval — so the NTP-style estimate compares it against the interval's
// midpoint, canceling the response-path latency to first order. Naively using
// time.Since(peerTimestamp) counts the whole response leg (bounded only by the
// 4s capActivationTimeout) as skew, so any Ping slower than the 1s threshold
// records a perfectly synced peer as skewed — worst during a capability
// fan-out under load, exactly when every voting member is pinged at once, and
// enough to spuriously trip the 5s upgrade-preflight ceiling.
func (c *Checker) checkClockSkew(ctx context.Context, peerName string, peerTimestamp, reqStart, reqEnd time.Time) {
	if peerTimestamp.IsZero() {
		return
	}
	mid := reqStart.Add(reqEnd.Sub(reqStart) / 2)
	skew := peerTimestamp.Sub(mid).Abs()
	if skew > time.Second {
		slog.Warn("clock skew detected — LWW conflict resolution may be unreliable",
			"peer", peerName, "skew", skew, "fix", "Check NTP on "+peerName)
		// Record skew for metrics + preflight. updated_at is RFC3339 (not
		// datetime('now')) so readers can apply an RFC3339 freshness cutoff —
		// a space-separated timestamp mis-sorts against a 'T'-separated cutoff
		// and would make every row read as stale (skew warnings would vanish).
		c.db.ExecuteDeferred(ctx,
			`INSERT OR REPLACE INTO clock_skew (observer, target, skew_seconds, updated_at)
			 VALUES (?, ?, ?, ?)`,
			c.hostName, peerName, skew.Seconds(), time.Now().UTC().Format(time.RFC3339),
		)
	}
}
