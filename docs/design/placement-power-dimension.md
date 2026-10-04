# Placement power dimension

Status: **planned, not implemented; removed 2026-10-04.**

GitHub issues are disabled on this repository, so this note is the tracking
record. It says what the dimension was for, what it needs, and what has to be
true before it comes back.

## What was removed

`internal/placement/dimensions.go` registered a `powerDim` (name `power`,
default weight 5) in `AllDimensions`. It had no telemetry producer: `Used`,
`Capacity` and `Demand` all returned 0. `scoreDimension` skips any dimension
whose capacity is ≤ 0, and the spread-strict pressure cap skips it the same
way, so the dimension never changed a score, a ranking or an eligibility
decision. It was a placeholder that read as a feature in the weights table.

There was no config key for it. Its weight lived only in `DimensionWeights`,
which production never overrides (`Request.Weights` is a test hook), so
removing it changed no operator-visible setting.

`TestRank_ScoresUnchangedByPowerRemoval` pins the scores the engine produced
with the dimension still registered, for every policy, on a fixture that
exercises each wired dimension. They are unchanged after the removal.

## What it was meant to do

Steer new placements, and rebalance proposals, away from hosts that are close
to their power or thermal budget, for two reasons:

- **Headroom on a constrained circuit.** A rack or PDU feed has a hard limit.
  CPU and RAM pressure are poor proxies for draw: an idle 64-core host and a
  busy 16-core host can draw the same. Placing onto a host whose feed is near
  its limit risks a breaker trip that takes out every host on the feed, a
  correlated failure that anti-affinity does not see.
- **Thermal throttling.** A host running hot clocks down, so its free CPU is
  worth less than the number says. Preferring cooler hosts keeps guests off
  hardware that is about to throttle.

It is a soft preference, like every other dimension. It must never be a hard
filter: missing or stale telemetry has to fall back to "no signal", not to
"ineligible".

## Telemetry it needs

| Property | Requirement |
|---|---|
| Source | The host's BMC over IPMI DCMI (`dcmi power reading`), or Redfish `PowerControl` where IPMI is absent. Inlet temperature from the same BMC's sensor records. The node reads its **own** BMC locally; it must not depend on the fencing path's remote IPMI credentials, which exist for a different purpose and are a peer's. |
| Units | Draw in watts (instantaneous, averaged over the BMC's own window, which is reported alongside). Temperature in °C, inlet only. |
| Capacity | Operator-declared, because no BMC reports the feed's budget: a host label giving the host's power budget in watts, following the label-capacity precedent of `placement.iops_capacity` and `placement.netbw_mbps`. A host without the label contributes nothing, as today. |
| Granularity | **Per host** for v1. Per-PSU readings are useful for redundancy alarms but not for placement; record the per-host sum. Per-feed (rack or PDU) aggregation is a later step that needs a feed topology label on each host and a group sum in the snapshot. |
| Freshness | Sample on the order of 30 s, smoothed. A reading older than a stated bound (for example 3× the write backstop) must be treated as **no sample**, so the dimension skips. `host_runtime_usage` today does not check `updated_at` when the snapshot reads it; this dimension must not inherit that gap. |
| Replication | One row per host, written only by that host, through the same path as `host_runtime_usage` (deferred write, deadband, minimum-interval backstop, excluded from anti-entropy). Adding columns to that table, or a sibling table, is a schema bump, and the new statement shapes must enter the compatibility ledger (`make ci-guards` checks both). A node that does not write the columns leaves them NULL, which must read as "no sample" so a mixed-version cluster scores exactly as it does now. |

The sampler belongs next to `internal/daemon/usage_sampler.go`, with the same
split: a pure, testable core that turns readings into a decision to write, and
a thin loop around the BMC call. A BMC read can take seconds or hang; it must
run with its own timeout and must never block the libvirt sampler.

## How it should weigh

- **Default weight 5**, the same as host generation and below every resource
  dimension (CPU 25, RAM 25, disk IOPS 15, network 10, NUMA 10). Power is a
  tie-breaker among hosts that fit, not a driver: it should move a placement
  between two otherwise similar hosts, and never override a clear CPU or RAM
  imbalance.
- **Pressure** is draw divided by the declared budget, through the same
  concave curve as every other dimension, so balance and spread-strict prefer
  headroom and bin-pack prefers fill. Bin-pack consolidating onto hot hosts is
  arguably wrong; decide that explicitly when it lands rather than inheriting
  it.
- **Demand** is 0 for v1. Estimating a workload's draw from its vCPU count is
  guesswork. Per-workload attribution can come later if the readings show it is
  worth it.
- **Spread-strict.** A dimension with capacity is subject to the 50% pressure
  cap, which is a hard filter. Enabling power would make every host above half
  of its budget ineligible for spread-strict workloads. That is too aggressive
  for a signal this noisy. Either exempt power from the cap, or give it its own
  much higher cap, and test whichever is chosen.
- **Thermal** should be a separate dimension from draw if it is built at all,
  with its own weight, so that one can ship without the other.

## Tests required before it returns

1. **Score identity when unconfigured.** With no budget label, or no sample, on
   any host, every policy's ranking and scores equal today's. Extend
   `TestRank_ScoresUnchangedByPowerRemoval` rather than writing a new fixture.
2. **Real signal.** Two hosts identical except for draw: the lower-draw host
   ranks first under balance and spread-strict, and the higher-draw host ranks
   first under bin-pack (or not, if that is the decision; pin it either way).
3. **Weight bound.** A large CPU or RAM imbalance still wins over the largest
   possible power difference at the default weight.
4. **Stale sample skips.** A reading older than the freshness bound
   contributes 0, exactly as a missing one does. Mutation-verify by removing
   the age check and watching the test fail.
5. **NULL from an older writer skips.** A row written by a node without the
   columns contributes 0. This is the mixed-version case.
6. **Spread-strict cap.** Whatever the cap decision is, a test pins it, and a
   host near its power budget is not made ineligible by accident.
7. **Sampler core.** Unit tests for the pure core: the first reading is a
   baseline, the deadband suppresses writes, the backstop forces one, and a
   failed or timed-out BMC read writes nothing rather than a zero.
8. **Fleet.** A `tests/fleet/` scenario in which one node's power row
   replicates and changes where a second node places a VM.
9. **Lab.** An end-to-end check on real hardware that the BMC reading matches
   the vendor tool's output, since the fleet fake cannot prove the BMC side.
