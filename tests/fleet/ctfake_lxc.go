package fleet

import (
	"context"

	"github.com/litevirt/litevirt/internal/grpcapi"
	"github.com/litevirt/litevirt/internal/lxc"
)

// LXC is f as the lxc.Runtime the health package's ContainerChecker drives,
// over the same on-disk containers the grpcapi side sees. Only what the
// checker's sweep calls is implemented (Create, Start, State, List); the
// embedded nil interface makes any other call panic, so a scenario that
// reaches one finds out at once rather than passing on a zero value.
func (f *CTFake) LXC() lxc.Runtime { return ctLXC{f: f} }

type ctLXC struct {
	lxc.Runtime
	f *CTFake
}

func (r ctLXC) Create(ctx context.Context, opts lxc.CreateOpts) (*lxc.Container, error) {
	info, err := r.f.CreateContainer(ctx, grpcapi.CreateContainerOpts{Name: opts.Name,
		CPULimit: opts.CPULimit, MemoryMiB: opts.MemoryMiB})
	if err != nil {
		return nil, err
	}
	return &lxc.Container{Name: info.Name, State: lxc.State(info.State), CPULimit: opts.CPULimit,
		MemoryMiB: opts.MemoryMiB, Labels: opts.Labels}, nil
}

func (r ctLXC) Start(ctx context.Context, name string) error { return r.f.StartContainer(ctx, name) }

func (r ctLXC) State(ctx context.Context, name string) (lxc.State, error) {
	st, err := r.f.StateContainer(ctx, name)
	return lxc.State(st), err
}

func (r ctLXC) List(ctx context.Context) ([]string, error) { return r.f.ListContainers(ctx) }
