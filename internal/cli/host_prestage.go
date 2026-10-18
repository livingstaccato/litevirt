package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// preStageSchema runs phase 1 of a rolling upgrade: it streams the new binary
// to every target and forward-migrates each one's schema WITHOUT swapping the
// live binary. It returns a non-nil error when a host cannot be pre-staged; NO
// binary has been swapped then, so the operator can fix the host and re-run.
//
// Targets whose daemon predates the PreStageUpgrade RPC report Unimplemented
// and are skipped, not failed: they migrate themselves on restart, and a
// single-version skew is tolerated by the replication handshake.
//
// others are the members the upgrade does not swap. Each receives replication
// from the upgraded targets and refuses every push from a sender whose schema
// is ahead of its own, so each is pre-staged too (its binary is left alone).
// A pre-staged host advertises the new schema at once, so every host is
// probed before any is pre-staged: when a member cannot be reached, or does
// not answer the upgrade RPCs, the upgrade is refused with nothing changed.
// skip names members that are down: one that does not answer is left behind
// with a warning; one that answers is pre-staged anyway.
func preStageSchema(ctx context.Context, client pb.LiteVirtClient, targets, others []*pb.Host, binaryPath string, skip map[string]bool) error {
	data, err := os.ReadFile(binaryPath)
	if err != nil {
		return fmt.Errorf("read binary: %w", err)
	}
	checksum := sha256sum(data)

	// Probe every host first: nothing is pre-staged unless all can be.
	fmt.Println("Probing every member before pre-staging...")
	var stageTargets, stageOthers []*pb.Host
	var unsupported, behind []string
	refused := map[string]string{}
	var refusedTargets, refusedOthers []string
	probes := probeAll(ctx, client, append(slices.Clone(targets), others...))
	for i, h := range targets {
		switch err := probes[i]; {
		case err == nil:
			stageTargets = append(stageTargets, h)
		case status.Code(err) == codes.Unimplemented:
			unsupported = append(unsupported, h.Name)
		default:
			refused[h.Name] = err.Error()
			refusedTargets = append(refusedTargets, h.Name)
		}
	}
	for i, h := range others {
		err := probes[len(targets)+i]
		switch {
		case err == nil:
			stageOthers = append(stageOthers, h)
		case skip[h.Name]:
			behind = append(behind, h.Name)
			fmt.Fprintf(os.Stderr, "  WARNING (--skip-prestage): %s is not pre-staged (%v); when it returns it refuses "+
				"replication from every upgraded host until `lv host upgrade %s`\n", h.Name, err, h.Name)
		default:
			refused[h.Name] = err.Error()
			refusedOthers = append(refusedOthers, h.Name)
		}
	}
	if len(refusedTargets)+len(refusedOthers) > 0 {
		return probeRefusal(targets, refusedTargets, refusedOthers, refused)
	}

	if len(others) > 0 {
		fmt.Printf("Pre-staging schema on %d target(s) and %d other member(s) (safe — no restart)...\n", len(stageTargets), len(stageOthers))
	} else {
		fmt.Println("Pre-staging schema on all targets (safe — no restart)...")
	}

	// Pre-stage every host that answered, even past a failure: a host left
	// out refuses the pushes of every host pre-staged, so the fewer left out
	// the better.
	var prestaged, failedOrder []string
	failed := map[string]string{}
	stagedSchema := int32(0)
	stage := func(h *pb.Host, isTarget bool) {
		resp, err := preStageOneHost(ctx, client, h, data, checksum)
		switch {
		case err == nil:
			prestaged = append(prestaged, h.Name)
			if resp != nil && resp.SchemaVersion > stagedSchema {
				stagedSchema = resp.SchemaVersion
			}
		case isTarget && status.Code(err) == codes.Unimplemented:
			unsupported = append(unsupported, h.Name)
		case !isTarget && skip[h.Name]:
			behind = append(behind, h.Name)
			fmt.Fprintf(os.Stderr, "  WARNING (--skip-prestage): %s could not be pre-staged (%v); it refuses "+
				"replication from every upgraded host until `lv host upgrade %s`\n", h.Name, err, h.Name)
		default:
			failed[h.Name] = err.Error()
			failedOrder = append(failedOrder, h.Name)
		}
	}
	for _, h := range stageTargets {
		stage(h, true)
	}
	for _, h := range stageOthers {
		stage(h, false)
	}
	if len(failed) > 0 {
		return stageFailure(failedOrder, failed, prestaged, stagedSchema, targets)
	}

	switch {
	case len(prestaged) == 0:
		// Every target is on a daemon without the RPC (e.g. the bootstrap
		// upgrade that ships it). Fall back to the plain rolling upgrade.
		fmt.Println("  no daemon supports pre-staging yet — proceeding with rolling upgrade")
		fmt.Println("  (each node migrates its own schema on restart; single-version skew self-heals)")
	default:
		fmt.Printf("  pre-staged %s on %d host(s)", schemaLabel(stagedSchema), len(prestaged))
		if len(unsupported) > 0 {
			fmt.Printf("; %d on older daemons will migrate on restart (%s)",
				len(unsupported), strings.Join(unsupported, ", "))
		}
		fmt.Println()
	}
	if len(behind) > 0 {
		fmt.Printf("  not pre-staged (--skip-prestage): %s\n", strings.Join(behind, ", "))
	}
	fmt.Println()
	return nil
}

// probeAll probes hosts in parallel, at most probeParallelism at once, and
// returns each one's error in the order given.
func probeAll(ctx context.Context, client pb.LiteVirtClient, hosts []*pb.Host) []error {
	errs := make([]error, len(hosts))
	sem := make(chan struct{}, probeParallelism)
	var wg sync.WaitGroup
	for i, h := range hosts {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			errs[i] = probeMember(ctx, client, h)
		}()
	}
	wg.Wait()
	return errs
}

// probeMember checks, changing nothing, that h answers the upgrade RPCs
// through the same forwarding path PreStageUpgrade takes. PreflightUpgrade
// is read-only, and every daemon that has it has PreStageUpgrade.
func probeMember(ctx context.Context, client pb.LiteVirtClient, h *pb.Host) error {
	pctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	_, err := client.PreflightUpgrade(pctx, &pb.PreflightUpgradeRequest{TargetHost: h.Name})
	if err != nil && pctx.Err() == context.DeadlineExceeded && ctx.Err() == nil {
		return fmt.Errorf("no answer within %s: %w", probeTimeout, err)
	}
	return err
}

// probeRefusal is the error for hosts that failed their probe. Nothing has
// been pre-staged or swapped.
func probeRefusal(targets []*pb.Host, refusedTargets, refusedOthers []string, refused map[string]string) error {
	var b strings.Builder
	if len(refusedTargets) > 0 {
		fmt.Fprintf(&b, "%d target(s) cannot be reached:", len(refusedTargets))
		for _, name := range refusedTargets {
			fmt.Fprintf(&b, "\n    %s: %s", name, refused[name])
		}
		b.WriteString("\n")
	}
	if len(refusedOthers) > 0 {
		fmt.Fprintf(&b, "%d member(s) outside this upgrade cannot be pre-staged, and each would refuse "+
			"replication from every upgraded host until it is upgraded:", len(refusedOthers))
		for _, name := range refusedOthers {
			fmt.Fprintf(&b, "\n    %s: %s", name, refused[name])
		}
		b.WriteString("\n")
	}
	b.WriteString("  Nothing was pre-staged and no binary was swapped.")
	if len(refusedOthers) > 0 {
		names := make([]string, 0, len(targets)+len(refusedOthers))
		for _, h := range targets {
			names = append(names, h.Name)
		}
		names = append(names, refusedOthers...)
		down := strings.Join(refusedOthers, ",")
		fmt.Fprintf(&b, " Bring them back and re-run, upgrade them with the rest (lv host upgrade %s), "+
			"skip the ones that are down with --skip-prestage %s (each refuses replication when it returns, "+
			"until it is upgraded), or remove them (lv host rm %s)",
			strings.Join(names, " "), down, strings.Join(refusedOthers, ", lv host rm "))
	} else {
		b.WriteString(" Bring the targets back, or leave them out, and re-run")
	}
	return fmt.Errorf("%s", b.String())
}

// stageFailure is the error for hosts whose pre-stage failed after every
// probe answered. A pre-stage cannot be undone, so it says what is left, and
// the ways out that work: the same binary fails the same way on a re-run.
func stageFailure(failedOrder []string, failed map[string]string, prestaged []string, stagedSchema int32, targets []*pb.Host) error {
	isTarget := map[string]bool{}
	for _, h := range targets {
		isTarget[h.Name] = true
	}
	var b strings.Builder
	fmt.Fprintf(&b, "pre-stage failed on %d host(s); no binary was swapped:", len(failedOrder))
	for _, name := range failedOrder {
		fmt.Fprintf(&b, "\n    %s: %s", name, failed[name])
	}
	if len(prestaged) > 0 {
		sorted := slices.Clone(prestaged)
		slices.Sort(sorted)
		fmt.Fprintf(&b, "\n  %s are pre-staged at %s (they keep running, and restart safely, on their binary).",
			strings.Join(sorted, ", "), schemaLabel(stagedSchema))
	} else {
		b.WriteString("\n  Nothing was pre-staged.")
	}
	for _, name := range failedOrder {
		if isTarget[name] {
			fmt.Fprintf(&b, "\n  %s: fix it and re-run, re-run with a binary built for that host if the binary is "+
				"the cause, or leave it out of this upgrade.", name)
			continue
		}
		fmt.Fprintf(&b, "\n  %s refuses replication from every pre-staged host until it is pre-staged: fix it and "+
			"re-run, re-run with a binary built for that host if the binary is the cause, or proceed without it "+
			"(--skip-prestage %s) and pre-stage it later.", name, name)
	}
	return fmt.Errorf("%s", b.String())
}

func schemaLabel(v int32) string {
	if v > 0 {
		return fmt.Sprintf("schema v%d", v)
	}
	return "the new schema"
}

// preStageOneHost streams the binary to one host's PreStageUpgrade RPC.
func preStageOneHost(ctx context.Context, client pb.LiteVirtClient, h *pb.Host, data []byte, checksum string) (*pb.UpgradeHostResponse, error) {
	fmt.Printf("  %s: staging + migrating schema...\n", h.Name)
	stream, err := client.PreStageUpgrade(ctx)
	if err != nil {
		return nil, err
	}
	first := &pb.UpgradeHostRequest{
		Checksum:   checksum,
		TargetHost: h.Name,
	}
	return sendUpgradeStream(stream, data, first)
}

// sendUpgradeStream sends the first message (with metadata + initial chunk) and
// the remaining chunks, then closes and returns the server's response. A Send
// that returns io.EOF means the server already closed the stream (e.g. an
// Unimplemented RPC on an older daemon) — we stop sending and let CloseAndRecv
// surface the real status.
func sendUpgradeStream(stream grpc.ClientStreamingClient[pb.UpgradeHostRequest, pb.UpgradeHostResponse], data []byte, first *pb.UpgradeHostRequest) (*pb.UpgradeHostResponse, error) {
	const chunkSize = 64 * 1024
	if len(data) > chunkSize {
		first.Chunk = data[:chunkSize]
		data = data[chunkSize:]
	} else {
		first.Chunk = data
		data = nil
	}
	if err := stream.Send(first); err != nil {
		if err == io.EOF {
			return stream.CloseAndRecv()
		}
		return nil, err
	}
	for len(data) > 0 {
		end := min(chunkSize, len(data))
		if err := stream.Send(&pb.UpgradeHostRequest{Chunk: data[:end]}); err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		data = data[end:]
	}
	return stream.CloseAndRecv()
}

// probeParallelism bounds the probes in flight at once.
const probeParallelism = 8

// probeTimeout bounds one probe.
var probeTimeout = 30 * time.Second
