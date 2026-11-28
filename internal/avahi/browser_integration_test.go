//go:build integration

package avahi

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/lanrith/discovery-bridge/internal/catalog"
	"github.com/lanrith/discovery-bridge/internal/config"
	"github.com/lanrith/discovery-bridge/internal/observation"
	"github.com/lanrith/discovery-bridge/internal/policy"
	"github.com/miekg/dns"
)

func privateBus(t *testing.T) string {
	path, _ := privateBusProcess(t)
	return path
}

func TestStartupWaitsForAvahiInitializationAndHonorsDeadline(t *testing.T) {
	path := privateBus(t)
	f := avahiFixture(t, path, nil)
	var calls atomic.Int32
	var state atomic.Int32
	state.Store(1)
	if err := f.conn.ExportMethodTable(map[string]any{"GetState": func() (int32, *dbus.Error) {
		if calls.Add(1) == 3 {
			state.Store(2)
		}
		return state.Load(), nil
	}}, "/", server); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	b, err := connectBus(ctx, path)
	if err != nil || calls.Load() != 3 {
		t.Fatal("initializing Avahi did not get a fresh running epoch", err, calls.Load())
	}
	b.close()
	state.Store(1)
	short, cancelShort := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancelShort()
	if _, err := connectBus(short, path); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("startup ignored its deadline", err)
	}
	state.Store(4) // Failure is permanent; it must not be retried as initialization.
	before := calls.Load()
	if _, err := connectBus(ctx, path); err == nil || calls.Load() != before+1 {
		t.Fatal("failed Avahi was retried or accepted", err, calls.Load()-before)
	}
}

func privateBusProcess(t *testing.T) (string, *exec.Cmd) {
	t.Helper()
	program, err := exec.LookPath("dbus-daemon")
	if err != nil {
		t.Fatal("integration test needs dbus-daemon", err)
	}
	dir, err := os.MkdirTemp("", "db-lab-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Error(err)
		}
	})
	path := filepath.Join(dir, "bus")
	ctx, cancel := context.WithCancel(context.Background())
	command := exec.CommandContext(ctx, program, "--session", "--nofork", "--nopidfile", "--address=unix:path="+path, "--print-address=1")
	command.WaitDelay = time.Second
	stdout, err := command.StdoutPipe()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); _ = command.Wait() })
	ready := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		if scanner.Scan() {
			ready <- scanner.Text()
		} else {
			ready <- ""
		}
	}()
	select {
	case value := <-ready:
		if !strings.HasPrefix(value, "unix:path="+path) {
			t.Fatal("private D-Bus startup failed")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("private D-Bus startup timed out")
	}
	return path, command
}

type fakeAvahi struct {
	conn         *dbus.Conn
	mu           sync.Mutex
	queries      []Query
	records      map[Query]dns.RR
	freed        []dbus.ObjectPath
	limit        int
	beforeFree   func(dbus.ObjectPath) *dbus.Error
	prepareReply func() (dbus.ObjectPath, *dbus.Error)
}

func avahiFixture(t *testing.T, path string, records map[Query]dns.RR) *fakeAvahi {
	t.Helper()
	conn, err := dbus.Connect("unix:path=" + path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	f := &fakeAvahi{conn: conn, records: records}
	if err := conn.ExportMethodTable(map[string]any{"GetState": func() (int32, *dbus.Error) { return 2, nil }}, "/", server); err != nil {
		t.Fatal(err)
	}
	if err := conn.ExportMethodTable(map[string]any{"RecordBrowserPrepare": f.prepare}, "/", server2); err != nil {
		t.Fatal(err)
	}
	reply, err := conn.RequestName(service, dbus.NameFlagDoNotQueue)
	if err != nil || reply != dbus.RequestNameReplyPrimaryOwner {
		t.Fatal(reply, err)
	}
	return f
}

func (f *fakeAvahi) prepare(index, protocol int32, name string, class, kind uint16, flags uint32) (dbus.ObjectPath, *dbus.Error) {
	if index != 2 || (protocol != 0 && protocol != 1) || class != dns.ClassINET || flags != 2 {
		return "", dbus.MakeFailedError(fmt.Errorf("invalid scoped browser request"))
	}
	family := 4
	if protocol == 1 {
		family = 6
	}
	query := Query{int(index), family, catalog.NameKey(name), kind}
	f.mu.Lock()
	if reply := f.prepareReply; reply != nil {
		f.mu.Unlock()
		return reply()
	}
	if f.limit > 0 && len(f.queries)-len(f.freed) >= f.limit {
		f.mu.Unlock()
		return "", dbus.NewError(service+".TooManyObjectsError", []any{"object quota"})
	}
	f.queries = append(f.queries, query)
	path := dbus.ObjectPath(fmt.Sprintf("/browser/%d", len(f.queries)))
	f.mu.Unlock()
	err := f.conn.ExportMethodTable(map[string]any{
		"Start": func() *dbus.Error {
			if rr := f.records[query]; rr != nil {
				raw, err := rdata(rr)
				if err != nil {
					return dbus.MakeFailedError(err)
				}
				// Send before the Start reply to exercise prepare-before-start routing.
				if err := f.conn.Emit(path, browserInterface+".ItemNew", index, protocol, rr.Header().Name, class, kind, raw, uint32(5)); err != nil {
					return dbus.MakeFailedError(err)
				}
			}
			return nil
		},
		"Free": func() *dbus.Error {
			f.mu.Lock()
			before := f.beforeFree
			f.mu.Unlock()
			if before != nil {
				if err := before(path); err != nil {
					return err
				}
			}
			f.mu.Lock()
			f.freed = append(f.freed, path)
			f.mu.Unlock()
			return nil
		},
	}, path, browserInterface)
	if err != nil {
		return "", dbus.MakeFailedError(err)
	}
	return path, nil
}

func TestRealDBusBrowsingCorrelatesWireAndExpires(t *testing.T) {
	path := privateBus(t)
	var wireRecords []dns.RR
	fixture := make(map[Query]dns.RR)
	for _, text := range []string{
		catalog.Enumeration + " 6 IN PTR _example._tcp.local.",
		`_example._tcp.local. 6 IN PTR Office\032Printer._example._tcp.local.`,
		`Office\032Printer._example._tcp.local. 6 IN SRV 0 0 1234 host.local.`,
		`Office\032Printer._example._tcp.local. 6 IN TXT "binary=\000\255"`,
		"host.local. 6 IN A 192.0.2.42", "host.local. 6 IN AAAA 2001:db8:1::42",
	} {
		rr, err := dns.NewRR(text)
		if err != nil {
			t.Fatal(err)
		}
		wireRecords = append(wireRecords, rr)
		fixture[Query{2, 4, catalog.NameKey(rr.Header().Name), rr.Header().Rrtype}] = rr
	}
	f := avahiFixture(t, path, fixture)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	links := map[int]observation.Link{2: {Source: "lan-a", Generation: "link-a", Families: []int{4, 6}}}
	b, err := ConnectBrowser(ctx, path, links)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if err := b.Seed(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Watch(ctx, Query{2, 4, "_EXAMPLE._tcp.local.", dns.TypePTR}); err != nil {
		t.Fatal(err)
	}
	cache := observation.New()
	for range len(fixture) {
		bounded, stop := context.WithTimeout(ctx, 3*time.Second)
		event, err := b.Next(bounded)
		stop()
		if err != nil {
			t.Fatal(err)
		}
		if err := cache.Hint(event.Epoch, event.Record, event.Added); err != nil {
			t.Fatal(err)
		}
		if err := b.Follow(ctx, event); err != nil {
			t.Fatal(err)
		}
	}
	now := catalog.Moment{Wall: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	if values, err := cache.Records(now); err != nil || len(values) != 0 {
		t.Fatal("browser cache alone produced records", values, err)
	}
	scopes, err := policy.New(map[string][]string{"lan-a": {"192.0.2.0/24", "2001:db8:1::/64"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	message := dns.Msg{MsgHdr: dns.MsgHdr{Response: true, Authoritative: true}, Answer: wireRecords}
	wire, err := message.Pack()
	if err != nil {
		t.Fatal(err)
	}
	packet := observation.Packet{Interface: 2, Generation: "link-a", Family: 4, Source: netip.MustParseAddr("192.0.2.42"), Destination: netip.MustParseAddr("224.0.0.251"), HopLimit: 255, SourcePort: 5353, DestinationPort: 5353, Wire: wire}
	observed, err := observation.Parse(packet, links, scopes, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := cache.Ingest(observed, now.Mono); err != nil {
		t.Fatal(err)
	}
	values, err := cache.Records(now)
	if err != nil || len(values) != 6 {
		t.Fatal("scoped D-Bus and packet graph did not correlate", len(values), err)
	}
	for _, value := range values {
		if value.Expires.Sub(now.Wall) != 6*time.Second {
			t.Fatal("browser hint changed native TTL")
		}
	}
	now.Mono, now.Wall = 6*time.Second, now.Wall.Add(6*time.Second)
	if values, err := cache.Records(now); err != nil || len(values) != 0 {
		t.Fatal("cached D-Bus hints renewed expired records", values, err)
	}
	if err := cache.Ingest(observed, now.Mono); err != nil {
		t.Fatal(err)
	}
	if _, err := f.conn.ReleaseName(service); err != nil {
		t.Fatal(err)
	}
	bounded, stop := context.WithTimeout(ctx, 3*time.Second)
	defer stop()
	if event, err := b.Next(bounded); err == nil || bounded.Err() != nil {
		t.Fatal("owner loss did not wake consumer", event, err)
	}
	cache.ForgetEpoch(b.Epoch())
	if values, err := cache.Records(now); err != nil || len(values) != 0 {
		t.Fatal("Avahi owner loss retained authority", values, err)
	}
	if _, err := b.Watch(ctx, Query{2, 4, "host.local.", dns.TypeA}); err == nil {
		t.Fatal("failed epoch accepted new watch")
	}
}

func TestRealDBusRetirementPreservesLiveDependencies(t *testing.T) {
	path := privateBus(t)
	f := avahiFixture(t, path, nil)
	b, err := ConnectBrowser(context.Background(), path, map[int]observation.Link{2: {Source: "lan-a", Generation: "link-a", Families: []int{4}}})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if err := b.Seed(context.Background()); err != nil {
		t.Fatal(err)
	}
	serviceQuery := Query{2, 4, "example._example._tcp.local.", dns.TypeSRV}
	needed := Query{2, 4, "host.local.", dns.TypeAAAA}
	idle := Query{2, 4, "idle.local.", dns.TypeA}
	for _, query := range []Query{serviceQuery, needed, idle} {
		if _, err := b.Watch(context.Background(), query); err != nil {
			t.Fatal(err)
		}
	}
	rr, err := dns.NewRR("example._example._tcp.local. 0 IN SRV 0 0 1234 host.local.")
	if err != nil {
		t.Fatal(err)
	}
	b.mu.Lock()
	for query := range b.touched {
		b.touched[query] = time.Now().Add(-121 * time.Second)
	}
	servicePath, idlePath := b.queries[serviceQuery], b.queries[idle]
	b.seen[seenKey{servicePath, (catalog.Answer{RR: rr}).Key()}] = rr
	b.mu.Unlock()
	if err := b.Retire(context.Background()); err != nil {
		t.Fatal(err)
	}
	b.mu.Lock()
	_, retainedNeeded := b.queries[needed]
	_, retainedIdle := b.queries[idle]
	b.mu.Unlock()
	f.mu.Lock()
	freed := append([]dbus.ObjectPath(nil), f.freed...)
	f.mu.Unlock()
	if !retainedNeeded || retainedIdle || len(freed) != 1 || freed[0] != idlePath {
		t.Fatal("retirement lost active dependency", retainedNeeded, retainedIdle, freed)
	}
}

func TestStalledAuthenticationClosesSocketWithinDeadline(t *testing.T) {
	dir, err := os.MkdirTemp("", "db-stall-")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	path := filepath.Join(dir, "bus")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	closed := make(chan struct{})
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			close(closed)
			return
		}
		defer func() { _ = conn.Close(); close(closed) }()
		buffer := make([]byte, 64)
		for {
			if _, err := conn.Read(buffer); err != nil {
				return
			}
		}
	}()
	start := time.Now()
	if _, err := connectBus(context.Background(), path); err == nil {
		t.Fatal("stalled authentication succeeded")
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("authentication timeout leaked socket")
	}
	if time.Since(start) > 4*time.Second {
		t.Fatal("authentication exceeded its deadline")
	}
}

func TestPermanentConfiguredWatchDiscoversLateArrival(t *testing.T) {
	path := privateBus(t)
	f := avahiFixture(t, path, nil)
	links := map[int]observation.Link{2: {Source: "lan-a", Generation: "generation", Families: []int{4}}}
	configured := config.Bootstrap{Name: "_example._tcp.local.", Type: "PTR"}
	interest := Query{2, 4, configured.Name, dns.TypePTR}
	idle := Query{2, 4, "_idle._tcp.local.", dns.TypePTR}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	for range 2 {
		b, err := ConnectBrowser(ctx, path, links)
		if err != nil {
			t.Fatal(err)
		}
		if err := b.Seed(ctx, configured, config.Bootstrap{Name: strings.ToUpper(configured.Name), Type: "PTR"}); err != nil {
			t.Fatal(err)
		}
		if admitted, err := b.Watch(ctx, idle); !admitted || err != nil {
			t.Fatal(err)
		}
		b.mu.Lock()
		for q := range b.touched {
			b.touched[q] = time.Now().Add(-121 * time.Second)
		}
		b.mu.Unlock()
		if err := b.Retire(ctx); err != nil {
			t.Fatal(err)
		}
		if _, ok := b.queries[idle]; ok || len(b.queries) != 2 || b.pendingSeeds != 0 {
			t.Fatal("unexpected idle watches", b.queries)
		}
		rr, err := dns.NewRR("_example._tcp.local. 15 IN PTR Late._example._tcp.local.")
		if err != nil {
			t.Fatal(err)
		}
		raw, err := rdata(rr)
		if err != nil {
			t.Fatal(err)
		}
		err = f.conn.Emit(b.queries[interest], browserInterface+".ItemNew", int32(2), int32(0), configured.Name, uint16(dns.ClassINET), uint16(dns.TypePTR), raw, uint32(4))
		if err != nil {
			t.Fatal(err)
		}
		event, err := b.Next(ctx)
		if err != nil || event.Query != interest {
			t.Fatal(event, err)
		}
		cache := observation.New()
		now := catalog.Now()
		if err := cache.Hint(event.Epoch, event.Record, true); err != nil {
			t.Fatal(err)
		}
		if records, err := cache.Records(now); err != nil || len(records) != 0 {
			t.Fatal("empty watch supplied fresh evidence", records, err)
		}
		if err := cache.Ingest([]observation.Record{{Source: "lan-a", Generation: "generation", Family: 4, RR: rr}}, now.Mono); err != nil {
			t.Fatal(err)
		}
		if records, err := cache.Records(now); err != nil || len(records) != 1 {
			t.Fatal("late observation missing", records, err)
		}
		b.Close()
	}
}

func TestMixedBrowserCapacity(t *testing.T) {
	for _, discoverLimitWith := range []string{"catalog", "native"} {
		t.Run(discoverLimitWith, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			path := privateBus(t)
			record, err := dns.NewRR("online.local. 60 IN A 192.0.2.10")
			if err != nil {
				t.Fatal(err)
			}
			owned := Query{2, 4, "online.local.", dns.TypeA}
			next := Query{2, 4, "next.local.", dns.TypeA}
			f := avahiFixture(t, path, map[Query]dns.RR{owned: record})
			f.mu.Lock()
			f.limit = 3
			f.mu.Unlock()
			b, err := ConnectBrowser(ctx, path, map[int]observation.Link{2: {Source: "lan", Generation: "link", Families: []int{4}}})
			if err != nil {
				t.Fatal(err)
			}
			defer b.Close()
			if err := b.Seed(ctx); err != nil {
				t.Fatal(err)
			}
			if ok, err := b.Watch(ctx, owned); !ok || err != nil {
				t.Fatal(ok, err)
			}
			closeNative, err := b.WatchNative(ctx, next)
			if err != nil {
				t.Fatal(err)
			}
			if discoverLimitWith == "native" {
				if _, err := b.WatchNative(ctx, owned); !errors.Is(err, ErrBrowserCapacity) {
					t.Fatal("unexpected native admission", err)
				}
			}
			if ok, err := b.Watch(ctx, next); ok || err != nil {
				t.Fatal("distinct catalog watch did not defer", ok, err)
			}
			if ok, err := b.Watch(ctx, owned); !ok || err != nil {
				t.Fatal("reuse at quota failed", ok, err)
			}
			if event, err := b.Next(ctx); err != nil || event.Query != owned || !event.Added {
				t.Fatal("quota interrupted existing observation", event, err)
			}
			if b.objectLimit != 3 || len(b.order) != 1 {
				t.Fatal("explicit daemon quota did not bound local reservations", b.objectLimit, b.order)
			}
			started, finish := make(chan struct{}), make(chan struct{})
			f.mu.Lock()
			f.beforeFree = func(dbus.ObjectPath) *dbus.Error {
				close(started)
				select {
				case <-finish:
				case <-ctx.Done():
				}
				return nil
			}
			f.mu.Unlock()
			done := make(chan error, 1)
			go func() { done <- closeNative() }()
			select {
			case <-started:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			b.mu.Lock()
			reserved := len(b.native)
			b.mu.Unlock()
			close(finish)
			if err := <-done; err != nil || reserved != 1 {
				t.Fatal("object was not retained through Free", reserved, err)
			}
			if err := closeNative(); err != nil {
				t.Fatal("repeated release failed", err)
			}
			if _, err := b.WatchNative(ctx, owned); !errors.Is(err, ErrBrowserCapacity) {
				t.Fatal("new native demand displaced oldest queued interest", err)
			}
			if discoverLimitWith == "catalog" {
				if ok, err := b.Watch(ctx, next); !ok || err != nil {
					t.Fatal("oldest caller retry did not take the released slot", ok, err)
				}
			} else if err := b.Retire(ctx); err != nil {
				t.Fatal(err)
			}
			if b.queries[next] == "" || len(b.order) != 0 {
				t.Fatal("acknowledged release did not admit deferred interest")
			}
			if _, err := f.conn.ReleaseName(service); err != nil {
				t.Fatal(err)
			}
			if _, err := b.Next(ctx); err == nil || b.Err() == nil {
				t.Fatal("daemon owner loss retained healthy epoch")
			}
		})
	}
}

func TestSeedReservationsAndUncertainRelease(t *testing.T) {
	ctx := t.Context()
	path := privateBus(t)
	f := avahiFixture(t, path, nil)
	b, err := ConnectBrowser(ctx, path, map[int]observation.Link{2: {Source: "lan", Generation: "link", Families: []int{4}}})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	b.objectLimit = 2
	query := Query{2, 4, "ordinary.local.", dns.TypeA}
	release, err := b.WatchNative(ctx, query)
	if err != nil {
		t.Fatal(err)
	}

	// Pause at Seed's reservation boundary, before its per-question Watch.
	seed := Query{2, 4, catalog.Enumeration, dns.TypePTR}
	b.permanent[seed], b.pendingSeeds = true, 1
	if ok, err := b.Watch(ctx, query); ok || err != nil {
		t.Fatal("catalog borrowed an uninstalled seed", ok, err)
	}
	if _, err := b.WatchNative(ctx, query); !errors.Is(err, ErrBrowserCapacity) {
		t.Fatal("native borrowed an uninstalled seed", err)
	}
	if ok, err := b.Watch(ctx, seed); !ok || err != nil || b.pendingSeeds != 0 {
		t.Fatal("required seed failed to consume its reserved slot", ok, err)
	}

	f.mu.Lock()
	f.beforeFree = func(dbus.ObjectPath) *dbus.Error {
		return dbus.MakeFailedError(errors.New("release unconfirmed"))
	}
	f.mu.Unlock()
	if err := release(); err == nil || b.Err() == nil {
		t.Fatal("uncertain native release left epoch available")
	}
	if ok, err := b.Watch(ctx, query); ok || err == nil {
		t.Fatal("reused a slot in a failed epoch", ok, err)
	}
}

func TestDeferredOrdinaryDemandOrderAndExpiry(t *testing.T) {
	ctx := t.Context()
	path := privateBus(t)
	avahiFixture(t, path, nil)
	b, err := ConnectBrowser(ctx, path, map[int]observation.Link{2: {Source: "lan", Generation: "link", Families: []int{4}}})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	b.objectLimit = 2
	if err := b.Seed(ctx); err != nil {
		t.Fatal(err)
	}
	q := func(name string) Query { return Query{2, 4, name + ".local.", dns.TypeA} }
	if ok, err := b.Watch(ctx, q("idle")); !ok || err != nil {
		t.Fatal(ok, err)
	}
	parent, err := dns.NewRR("_test._tcp.local. 60 IN PTR Gone._test._tcp.local.")
	if err != nil {
		t.Fatal(err)
	}
	event := Event{Epoch: b.Epoch(), Added: true, Query: Query{2, 4, "_test._tcp.local.", dns.TypePTR},
		Record: observation.Record{RR: parent}}
	if err := b.Follow(ctx, event); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"expired", "first", "second", "first"} {
		if ok, err := b.Watch(ctx, q(name)); ok || err != nil {
			t.Fatal(ok, err)
		}
	}
	if len(b.order) != 5 {
		t.Fatal("dependencies or repeated deferred watch used unexpected queue positions", b.order)
	}
	old := time.Now().Add(-watchIdle - time.Second)
	b.touched[q("idle")], b.waiting[q("expired")] = old, old
	if err := b.Retire(ctx); err != nil {
		t.Fatal(err)
	}
	if b.queries[q("first")] == "" || b.queries[q("expired")] != "" || len(b.order) != 1 || b.order[0] != q("second") {
		t.Fatal("retired catalog slot failed to serve the oldest eligible interest", b.order)
	}
	for i := range maxBrowserObjects {
		if ok, err := b.Watch(ctx, q(fmt.Sprintf("demand-%d", i))); ok || err != nil {
			t.Fatal(ok, err)
		}
	}
	if len(b.order) != maxBrowserObjects || len(b.waiting) != len(b.order) {
		t.Fatal("excess demand exceeded the epoch queue bound", len(b.order), len(b.waiting))
	}
}

func TestUnexpectedPrepareReplyFailsClosed(t *testing.T) {
	for _, test := range []struct {
		name   string
		path   dbus.ObjectPath
		err    *dbus.Error
		native bool
	}{
		{name: "root object", path: "/"},
		{name: "catalog path returned to native", path: "/browser/1", native: true},
		{name: "native path returned to catalog", path: "/browser/2"},
		{name: "different daemon error", err: dbus.NewError(service+".TooManyEntriesError", nil)},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := t.Context()
			path := privateBus(t)
			f := avahiFixture(t, path, nil)
			b, err := ConnectBrowser(ctx, path, map[int]observation.Link{2: {Source: "lan", Generation: "link", Families: []int{4}}})
			if err != nil {
				t.Fatal(err)
			}
			defer b.Close()
			if err := b.Seed(ctx); err != nil {
				t.Fatal(err)
			}
			query := Query{2, 4, "native.local.", dns.TypeA}
			if _, err := b.WatchNative(ctx, query); err != nil {
				t.Fatal(err)
			}
			f.mu.Lock()
			f.prepareReply = func() (dbus.ObjectPath, *dbus.Error) { return test.path, test.err }
			f.mu.Unlock()
			query.Name = "distinct.local."
			if test.native {
				_, err = b.WatchNative(ctx, query)
			} else {
				_, err = b.Watch(ctx, query)
			}
			if err == nil || b.Err() == nil || errors.Is(err, ErrBrowserCapacity) {
				t.Fatal("unexpected allocation response was treated as quota", err, b.Err())
			}
		})
	}
}
