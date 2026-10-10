package filerestore

import (
	"fmt"
	"net"
)

// InProcessSession runs the agent's protocol server in this process, over
// an in-memory pipe, and returns a Client to it.
//
// FOR TESTS ONLY. It reads dir (KindFS) or parses dev as an archive
// (KindArchive) on the host, which is exactly what production never does:
// there the agent runs inside a restore VM. It exists so packages above this
// one can exercise their RPCs, limits and sanitization end to end without
// KVM.
func InProcessSession(dev BlockDevice, kind, dir string) (*InProcSession, error) {
	vols := map[string]volume{}
	switch kind {
	case KindArchive:
		v, name, err := indexTar(dev, dev.Size())
		if err != nil {
			return nil, err
		}
		vols[name] = v
	case KindFS:
		vols["vda1"] = &dirVolume{root: dir, fs: "ext4"}
	default:
		return nil, fmt.Errorf("kind %q", kind)
	}
	host, guest := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = (&agentServer{vols: vols}).serveConn(guest)
		guest.Close()
	}()
	return &InProcSession{Client: NewClient(host), done: done}, nil
}

// InProcSession is a Client to an in-process agent.
type InProcSession struct {
	*Client
	done chan struct{}
}

// Close ends the session.
func (s *InProcSession) Close() {
	s.Client.Close()
	<-s.done
}
