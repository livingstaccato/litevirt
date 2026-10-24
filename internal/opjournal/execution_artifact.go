package opjournal

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"strings"

	"github.com/litevirt/litevirt/internal/automation/contract"
	"github.com/litevirt/litevirt/internal/image"
)

// ExecutionDiskPlan is optional existing-journal data, not an execution grant.
// All effect arguments, including the exact temporary name, are frozen first.
type ExecutionDiskPlan struct {
	PreparationID string                 `json:"preparation_id"`
	EffectID      string                 `json:"effect_id"`
	Generation    uint64                 `json:"generation"`
	Plan          image.ArtifactDiskPlan `json:"plan"`
}

var executionDiskObservationReturned func()

// Test-only observation of the target-close snapshot window, with no lock held.
var executionTargetClosingSnapshot func()

func validateExecutionDisk(r *ExecutionRecord) error {
	d := r.Disk
	if d == nil {
		return nil
	}
	a := d.Plan.Artifact
	t := r.Preparation.Target
	if d.PreparationID != r.Preparation.ID || d.EffectID == "" || d.Generation == 0 || d.Generation != a.Origin.Generation || d.Plan.Validate() != nil || d.Plan.VMName != t.Name || a.OperationID != t.OperationID || a.HostIncarnation != t.HostIncarnation {
		return ErrCorrupt
	}
	if r.Effect != nil && (r.Effect.ID != d.EffectID || r.Effect.Generation != d.Generation) {
		return ErrCorrupt
	}
	return nil
}

// Reject duplicate/unknown plan fields before a controller consumes them.
// The ordinary Entry shape and omitted-plan legacy bytes do not change.
func (r *ExecutionRecord) UnmarshalJSON(raw []byte) error {
	type plain ExecutionRecord
	check := json.NewDecoder(bytes.NewReader(raw))
	var value func(int, reflect.Type) error
	value = func(depth int, shape reflect.Type) error {
		if depth > 16 {
			return ErrCorrupt
		}
		t, err := check.Token()
		if err != nil {
			return err
		}
		for shape.Kind() == reflect.Pointer {
			shape = shape.Elem()
		}
		if d, ok := t.(json.Delim); ok {
			if d == '{' {
				if shape.Kind() != reflect.Struct {
					return ErrCorrupt
				}
				// Only the exact JSON-tag/default field spelling is accepted.
				// encoding/json's ASCII/Unicode fold aliases must never choose
				// a second spelling for the same semantic plan member.
				fields := make(map[string]reflect.Type, shape.NumField())
				for i := 0; i < shape.NumField(); i++ {
					field := shape.Field(i)
					if field.PkgPath != "" {
						continue
					}
					name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
					if name == "-" {
						continue
					}
					if name == "" {
						name = field.Name
					}
					fields[name] = field.Type
				}
				seen := map[string]bool{}
				for check.More() {
					key, err := check.Token()
					if err != nil {
						return err
					}
					s, ok := key.(string)
					field, exact := fields[s]
					if !ok || !exact || seen[s] {
						return ErrCorrupt
					}
					seen[s] = true
					if err = value(depth+1, field); err != nil {
						return err
					}
				}
			} else if d == '[' {
				if shape.Kind() != reflect.Slice && shape.Kind() != reflect.Array {
					return ErrCorrupt
				}
				for check.More() {
					if err = value(depth+1, shape.Elem()); err != nil {
						return err
					}
				}
			} else {
				return ErrCorrupt
			}
			_, err = check.Token()
			return err
		}
		return nil
	}
	if err := value(0, reflect.TypeOf(plain{})); err != nil {
		return fmt.Errorf("%w: disk plan JSON: %v", ErrCorrupt, err)
	}
	if _, err := check.Token(); err != io.EOF {
		return ErrCorrupt
	}
	var decoded plain
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&decoded); err != nil {
		return fmt.Errorf("%w: disk plan JSON: %v", ErrCorrupt, err)
	}
	*r = ExecutionRecord(decoded)
	return nil
}

func (c *ExecutionController) PrepareDiskArtifact(ctx context.Context, p Preparation, id string, generation uint64, plan image.ArtifactDiskPlan) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	s, err := c.lookup(p)
	if err != nil {
		return err
	}
	d := ExecutionDiskPlan{PreparationID: p.ID, EffectID: id, Generation: generation, Plan: plan}
	r := copyExecutionRecord(s.record)
	r.Disk = &d
	if validateExecutionDisk(&r) != nil {
		return ErrExecutionConflict
	}
	if s.record.Disk != nil {
		if *s.record.Disk != d {
			return ErrExecutionConflict
		}
		return nil
	}
	if s.reopened || r.State != "prepared" || r.Effect != nil || s.active != nil {
		return ErrExecutionUnknown
	}
	return c.persist(s, r)
}

// executeArtifactDisk remains package-private because production admission has
// no issuer yet. It reuses the existing synchronous execute/accounting owner.
func (c *ExecutionController) executeArtifactDisk(ctx context.Context, p Preparation, a executionAdmission, store *image.Store) error {
	c.mu.Lock()
	s, err := c.lookup(p)
	if err != nil || s.record.Disk == nil {
		c.mu.Unlock()
		return ErrExecutionUngrant
	}
	d := *s.record.Disk
	c.mu.Unlock()
	if store == nil {
		return ErrExecutionConflict
	}
	return c.execute(ctx, p, d.EffectID, a, func() error { return store.CreateArtifactOverlayDisk(d.Plan) })
}

// ReconcileDiskArtifact recognizes the original file without completing the
// journal effect, clearing reopened, granting issuance or excluding a runtime.
func (c *ExecutionController) ReconcileDiskArtifact(ctx context.Context, p Preparation, store *image.Store) (contract.ArtifactRecord, error) {
	var zero contract.ArtifactRecord
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	c.mu.Lock()
	s, err := c.lookup(p)
	if err != nil {
		c.mu.Unlock()
		return zero, err
	}
	if store == nil || s.record.State != "prepared" || s.record.Disk == nil || validateExecutionDisk(&s.record) != nil || s.active != nil {
		c.mu.Unlock()
		return zero, ErrExecutionUnknown
	}
	d := *s.record.Disk
	done := make(chan struct{})
	s.active = done
	c.calls.Add(1)
	c.mu.Unlock()
	defer func() { c.mu.Lock(); s.active = nil; close(done); c.mu.Unlock(); c.calls.Done() }()
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	observed, err := store.ObserveArtifactDisk(d.Plan)
	if executionDiskObservationReturned != nil {
		executionDiskObservationReturned()
	}
	return observed, err
}
