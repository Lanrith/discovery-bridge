package publication

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/lanrith/discovery-bridge/internal/avahi"
	"github.com/lanrith/discovery-bridge/internal/catalog"
	"github.com/lanrith/discovery-bridge/internal/jsonwire"
	"golang.org/x/sys/unix"
)

// Owner is the independent Avahi publication owner used by the local IPC server.
type Owner interface {
	Reconcile(context.Context, []avahi.Intent) error
	Clear(context.Context) error
	Failed() <-chan struct{}
	Outcomes() (string, time.Duration)
	Err() error
}

// Server admits one producer at a time by kernel Unix peer credentials.
type Server struct {
	Owner       Owner
	Admission   Admission
	ProducerUID uint32
	Watchdog    func()
}

func peerUID(connection *net.UnixConn) (uint32, error) {
	raw, err := connection.SyscallConn()
	if err != nil {
		return 0, err
	}
	var credentials *unix.Ucred
	var credentialErr error
	err = raw.Control(func(fd uintptr) {
		credentials, credentialErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	})
	if err = errors.Join(err, credentialErr); err != nil {
		return 0, err
	}
	return credentials.Uid, nil
}

// Serve takes ownership of the already configured Unix listener. Unauthorized or
// competing clients never change publication. Producer loss clears all its groups.
func (s *Server) Serve(ctx context.Context, listener *net.UnixListener) error {
	if s.Owner == nil || s.Admission.Boot == "" || s.Admission.Owns == nil || len(s.Admission.Links) == 0 {
		return errors.New("publication server requires an owner and explicit admission")
	}
	defer func() { _ = listener.Close() }()
	var mu sync.Mutex
	var producer *net.UnixConn
	var workers sync.WaitGroup
	finished := make(chan struct{})
	stop, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		defer close(finished)
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stop.Done():
			case <-s.Owner.Failed():
			case <-ticker.C:
				if s.Watchdog != nil && s.Owner.Err() == nil {
					s.Watchdog()
				}
				continue
			}
			_ = listener.Close()
			mu.Lock()
			if producer != nil {
				// Wake the producer handler so it withdraws ownership.
				_ = producer.CloseRead()
			}
			mu.Unlock()
			return
		}
	}()
	defer func() { cancel(); <-finished; workers.Wait() }()
	for {
		connection, err := listener.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if failure := s.Owner.Err(); failure != nil {
				return failure
			}
			return err
		}
		uid, err := peerUID(connection)
		mu.Lock()
		if err != nil || uid != s.ProducerUID || producer != nil || s.Owner.Err() != nil {
			mu.Unlock()
			_ = connection.Close()
			continue
		}
		producer = connection
		mu.Unlock()
		workers.Go(func() {
			s.client(stop, connection)
			mu.Lock()
			producer = nil
			mu.Unlock()
		})
	}
}

func frameLine(reader *bufio.Reader) ([]byte, error) {
	return jsonwire.ReadLine(reader, MaxFrame)
}

func (s *Server) client(ctx context.Context, connection *net.UnixConn) {
	defer func() { _ = connection.Close() }()
	defer func() {
		bounded, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = s.Owner.Clear(bounded) // A failed owner has already lost its D-Bus connection.
	}()
	reader := bufio.NewReaderSize(connection, 64*1024)
	var previous int64
	var collector, publisher string
	for {
		if err := connection.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
			return
		}
		payload, err := frameLine(reader)
		if err != nil {
			return
		}
		if previous == 0 && collector == "" && strings.HasPrefix(string(payload), hello) {
			collector = strings.TrimSuffix(strings.TrimPrefix(string(payload), hello), "\n")
			if !token(collector) {
				return
			}
			publisher = publisherGeneration(s.Admission.Links)
			if err := connection.SetWriteDeadline(time.Now().Add(3 * time.Second)); err != nil {
				return
			}
			if _, err := io.WriteString(connection, hello+collector+" "+publisher+"\n"); err != nil {
				return
			}
			continue
		}
		sequence, groups, err := s.Admission.Decode(payload, catalog.Now().Mono, previous)
		if err != nil {
			return
		}
		bounded, cancel := context.WithTimeout(ctx, 3*time.Second)
		err = s.Owner.Reconcile(bounded, groups)
		cancel()
		if err != nil {
			return
		}
		previous = sequence
		if err := connection.SetWriteDeadline(time.Now().Add(3 * time.Second)); err != nil {
			return
		}
		states, until := s.Owner.Outcomes()
		if collector != "" {
			r := Receipt{Sequence: sequence, Collector: collector, Publisher: publisher, States: states, Until: until}
			if s.Owner.Err() != nil || ctx.Err() != nil || (until != 0 && catalog.Now().Mono >= until) {
				return
			}
			if err := json.NewEncoder(connection).Encode(r); err != nil {
				return
			}
			continue
		}
		// A legacy producer cannot represent partial success. Wait for the
		// independent owner to establish its complete snapshot before OK.
		end := time.Now().Add(2500 * time.Millisecond)
		for strings.Contains(states, "P") && !strings.ContainsAny(states, "CF") && time.Now().Before(end) {
			select {
			case <-ctx.Done():
				return
			case <-s.Owner.Failed():
				return
			case <-time.After(20 * time.Millisecond):
			}
			states, until = s.Owner.Outcomes()
		}
		// A legacy client cannot bind a conflict to an unexpired submission
		// or suppress an original on just one link. Close on partial results.
		if strings.Trim(states, "E") != "" || s.Owner.Err() != nil || ctx.Err() != nil || (until != 0 && catalog.Now().Mono >= until) {
			return
		}
		if _, err := io.WriteString(connection, "OK\n"); err != nil {
			return
		}
	}
}
