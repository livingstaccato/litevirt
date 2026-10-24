package opjournal

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"syscall"
)

var (
	ErrExecutionControlled = errors.New("opjournal: execution record requires its controller")
	ErrExecutionOwner      = errors.New("opjournal: execution directory already owned")
	ErrExecutionUngrant    = errors.New("opjournal: execution preparation is ungranted")
	ErrExecutionConflict   = errors.New("opjournal: execution target conflicts")
	ErrExecutionUnknown    = errors.New("opjournal: execution outcome or durability unknown")
)

// ExecutionTarget binds ordinary immutable identities. OwnerEpoch and
// SpecGeneration are NOT certified executor generations or resource UIDs.
type ExecutionTarget struct {
	OperationID, Name, CreatedAt, HostName, HostIncarnation, DomainUUID string
	OwnerEpoch, SpecGeneration                                          int64
}
type Preparation struct {
	ID, RecordID string
	Target       ExecutionTarget
}
type ExecutionEffect struct {
	ID, State  string
	Generation uint64
}
type ExecutionRecord struct {
	Version     int
	Preparation Preparation
	State       string
	Effect      *ExecutionEffect   `json:",omitempty"`
	Disk        *ExecutionDiskPlan `json:",omitempty"`
}

// LocalClosure describes participating synchronous calls only. A running VM or
// independent backend request is not physically excluded by this result.
type LocalClosure struct{ NoNewIssuance, CallsResolved, RuntimeExcluded bool }

type executionTargetState struct {
	record   ExecutionRecord
	active   chan struct{}
	poisoned bool
	reopened bool
}

// executionAdmission deliberately has no exported constructor. There is no
// certified production consumer yet; tests alone establish fixture admission.
type executionAdmission struct {
	preparation string
	target      ExecutionTarget
	generation  uint64
}

type ExecutionController struct {
	mu        sync.Mutex
	j         *Journal
	owner     *os.File
	targets   map[string]*executionTargetState
	closed    bool
	calls     sync.WaitGroup
	closeOnce sync.Once
	closeErr  error
}

func executionRecordID(operation string) string {
	sum := sha256.Sum256([]byte(operation))
	return "execution-" + hex.EncodeToString(sum[:])
}
func validExecutionTarget(t ExecutionTarget) bool {
	if t.OperationID == "" || t.Name == "" || t.CreatedAt == "" || t.HostName == "" || t.HostIncarnation == "" || t.OwnerEpoch <= 0 || t.SpecGeneration <= 0 {
		return false
	}
	u := t.DomainUUID
	if len(u) != 36 || u[8] != '-' || u[13] != '-' || u[18] != '-' || u[23] != '-' || u != strings.ToLower(u) {
		return false
	}
	b, err := hex.DecodeString(strings.ReplaceAll(u, "-", ""))
	if err != nil || len(b) != 16 {
		return false
	}
	for _, v := range b {
		if v != 0 {
			return true
		}
	}
	return false
}
func validateExecutionRecord(e Entry) error {
	r := e.Execution
	if r == nil {
		return nil
	}
	p := r.Preparation
	id, err := hex.DecodeString(p.ID)
	if err != nil || len(id) != 16 || p.ID != strings.ToLower(p.ID) {
		return ErrCorrupt
	}
	if e.Version != entryVersion || e.Stage != r.State || e.CreatedAt != p.Target.CreatedAt || r.Version != 1 || !validExecutionTarget(p.Target) || p.RecordID != executionRecordID(p.Target.OperationID) || e.OperationID != p.RecordID || e.ResourceID != p.Target.Name || e.OwnerEpoch != p.Target.OwnerEpoch || e.SpecGeneration != p.Target.SpecGeneration || e.Kind != "execution" {
		return ErrCorrupt
	}
	if r.State != "prepared" && r.State != "closing" && r.State != "closed" {
		return ErrCorrupt
	}
	if r.Effect != nil && (r.Effect.ID == "" || r.Effect.Generation == 0 || (r.Effect.State != "issued" && r.Effect.State != "completed" && r.Effect.State != "unknown")) {
		return ErrCorrupt
	}
	if r.State == "closed" && r.Effect != nil && r.Effect.State != "completed" {
		return ErrCorrupt
	}
	if err := validateExecutionDisk(r); err != nil {
		return err
	}
	return nil
}
func copyExecutionRecord(r ExecutionRecord) ExecutionRecord {
	if r.Effect != nil {
		v := *r.Effect
		r.Effect = &v
	}
	if r.Disk != nil {
		v := *r.Disk
		r.Disk = &v
	}
	return r
}

// OpenExecutionController owns the journal's execution class for one process
// lifetime. The advisory lock excludes other participating local controllers,
// never libvirtd, remote workers, storage or a powered host.
func OpenExecutionController(j *Journal) (*ExecutionController, error) {
	if j == nil {
		return nil, fmt.Errorf("opjournal: nil journal")
	}
	f, err := os.OpenFile(j.dir+"/.execution-owner.lock", os.O_CREATE|os.O_RDWR, filePerm)
	if err != nil {
		return nil, err
	}
	if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("%w: %v", ErrExecutionOwner, err)
	}
	c := &ExecutionController{j: j, owner: f, targets: map[string]*executionTargetState{}}
	fail := func(err error) (*ExecutionController, error) {
		syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
		return nil, err
	}
	entries, corrupt, err := j.List()
	if err != nil {
		return fail(err)
	}
	if len(corrupt) > 0 {
		return fail(fmt.Errorf("%w: unidentified execution recovery files %v", ErrCorrupt, corrupt))
	}
	for _, e := range entries {
		if e.Execution == nil {
			continue
		}
		if err := validateExecutionRecord(e); err != nil {
			return fail(err)
		}
		r := copyExecutionRecord(*e.Execution)
		name := r.Preparation.Target.Name
		if _, exists := c.targets[name]; exists {
			return fail(ErrExecutionConflict)
		}
		c.targets[name] = &executionTargetState{record: r, reopened: true}
	}
	return c, nil
}
func (c *ExecutionController) persist(s *executionTargetState, r ExecutionRecord) error {
	p := r.Preparation
	e := Entry{Version: entryVersion, OperationID: p.RecordID, OwnerEpoch: p.Target.OwnerEpoch, SpecGeneration: p.Target.SpecGeneration, ResourceID: p.Target.Name, Kind: "execution", Stage: r.State, CreatedAt: p.Target.CreatedAt, Execution: &r}
	if err := validateExecutionRecord(e); err != nil {
		return err
	}
	c.j.mu.Lock()
	defer c.j.mu.Unlock()
	if c.j.FailWrite != nil {
		if err := c.j.FailWrite(e.OperationID); err != nil {
			s.poisoned = true
			return fmt.Errorf("%w: %v", ErrExecutionUnknown, err)
		}
	}
	if err := c.j.writeLocked(e, true); err != nil {
		s.poisoned = true
		return fmt.Errorf("%w: %v", ErrExecutionUnknown, err)
	}
	s.record = copyExecutionRecord(r)
	return nil
}
func (c *ExecutionController) PrepareTarget(ctx context.Context, t ExecutionTarget) (Preparation, error) {
	if err := ctx.Err(); err != nil {
		return Preparation{}, err
	}
	if !validExecutionTarget(t) {
		return Preparation{}, ErrExecutionConflict
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return Preparation{}, ErrExecutionUnknown
	}
	if s := c.targets[t.Name]; s != nil {
		if s.poisoned {
			return Preparation{}, ErrExecutionUnknown
		}
		if s.record.Preparation.Target != t {
			return Preparation{}, ErrExecutionConflict
		}
		return s.record.Preparation, nil
	}
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return Preparation{}, err
	}
	p := Preparation{ID: hex.EncodeToString(random), RecordID: executionRecordID(t.OperationID), Target: t}
	// Refuse a preexisting legacy record rather than convert its class.
	existing, found, err := c.j.Read(p.RecordID)
	if err != nil {
		return Preparation{}, err
	}
	if found && existing != nil {
		return Preparation{}, ErrExecutionConflict
	}
	s := &executionTargetState{}
	c.targets[t.Name] = s
	r := ExecutionRecord{Version: 1, Preparation: p, State: "prepared"}
	if err := c.persist(s, r); err != nil {
		return Preparation{}, err
	}
	return p, nil
}
func (c *ExecutionController) lookup(p Preparation) (*executionTargetState, error) {
	s := c.targets[p.Target.Name]
	if c.closed || s == nil || s.poisoned {
		return nil, ErrExecutionUnknown
	}
	if s.record.Preparation != p {
		return nil, ErrExecutionConflict
	}
	return s, nil
}
func (c *ExecutionController) RecoverTarget(ctx context.Context, p Preparation) (ExecutionRecord, error) {
	if err := ctx.Err(); err != nil {
		return ExecutionRecord{}, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	s, err := c.lookup(p)
	if err != nil {
		return ExecutionRecord{}, err
	}
	return copyExecutionRecord(s.record), nil
}

// execute is package-private and has no production admission issuer. It holds
// the target's issuance side until the real synchronous call AND accounting end.
func (c *ExecutionController) execute(ctx context.Context, p Preparation, id string, a executionAdmission, call func() error) (result error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.mu.Lock()
	s, err := c.lookup(p)
	if err != nil {
		c.mu.Unlock()
		return err
	}
	if a.preparation != p.ID || a.target != p.Target || a.generation == 0 {
		c.mu.Unlock()
		return ErrExecutionUngrant
	}
	if s.record.Disk != nil && (validateExecutionDisk(&s.record) != nil || s.record.Disk.EffectID != id || s.record.Disk.Generation != a.generation) {
		c.mu.Unlock()
		return ErrExecutionUngrant
	}
	if s.reopened || s.record.State != "prepared" || s.record.Effect != nil || s.active != nil || id == "" || call == nil {
		c.mu.Unlock()
		return ErrExecutionUnknown
	}
	r := copyExecutionRecord(s.record)
	r.Effect = &ExecutionEffect{ID: id, State: "issued", Generation: a.generation}
	if err := c.persist(s, r); err != nil {
		c.mu.Unlock()
		return err
	}
	done := make(chan struct{})
	s.active = done
	c.calls.Add(1)
	c.mu.Unlock()
	// Even Goexit/panic must retire local call accounting without claiming that
	// an unreturned external result is known. Panic is not recovered here.
	var callErr error
	returned := false
	defer func() {
		c.mu.Lock()
		r := copyExecutionRecord(s.record)
		r.Effect.State = "unknown"
		if returned && callErr == nil {
			r.Effect.State = "completed"
		}
		persistErr := c.persist(s, r)
		if persistErr != nil {
			s.poisoned = true
			result = persistErr
		}
		s.active = nil
		close(done)
		c.mu.Unlock()
		c.calls.Done()
	}()
	callErr = call()
	returned = true
	if callErr != nil {
		return fmt.Errorf("%w: %v", ErrExecutionUnknown, callErr)
	}
	return nil
}
func (c *ExecutionController) CloseTarget(ctx context.Context, p Preparation) (LocalClosure, error) {
	c.mu.Lock()
	s, err := c.lookup(p)
	if err != nil {
		c.mu.Unlock()
		return LocalClosure{}, err
	}
	if s.record.State != "closed" && s.record.State != "closing" {
		r := copyExecutionRecord(s.record)
		r.State = "closing"
		if err := c.persist(s, r); err != nil {
			c.mu.Unlock()
			return LocalClosure{}, err
		}
	}
	active := s.active
	c.mu.Unlock()
	if executionTargetClosingSnapshot != nil {
		executionTargetClosingSnapshot()
	}
	if active != nil {
		select {
		case <-active:
		case <-ctx.Done():
			return LocalClosure{}, ctx.Err()
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	s, err = c.lookup(p)
	if err != nil {
		return LocalClosure{}, err
	}
	if s.reopened || (s.record.Effect != nil && s.record.Effect.State != "completed") {
		return LocalClosure{}, ErrExecutionUnknown
	}
	r := copyExecutionRecord(s.record)
	r.State = "closed"
	if err := c.persist(s, r); err != nil {
		return LocalClosure{}, err
	}
	return LocalClosure{NoNewIssuance: true, CallsResolved: true, RuntimeExcluded: false}, nil
}
func (c *ExecutionController) Close() error {
	c.closeOnce.Do(func() {
		c.mu.Lock()
		c.closed = true
		c.mu.Unlock()
		c.calls.Wait()
		if err := syscall.Flock(int(c.owner.Fd()), syscall.LOCK_UN); err != nil {
			c.closeErr = err
		}
		if err := c.owner.Close(); c.closeErr == nil {
			c.closeErr = err
		}
	})
	return c.closeErr
}
