//go:build integration

package avahi

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/lanrith/discovery-bridge/internal/catalog"
	"github.com/lanrith/discovery-bridge/internal/observation"
	"github.com/miekg/dns"
)

type publicationFixture struct {
	conn                                         *dbus.Conn
	mu                                           sync.Mutex
	exports                                      sync.Mutex
	serial, active, peak, commits, resets, frees int
	delay                                        time.Duration
	paths                                        map[dbus.ObjectPath]bool
	ttls                                         []uint32
}

func publisherFixture(t *testing.T, path string, delay time.Duration) *publicationFixture {
	t.Helper()
	service := avahiFixture(t, path, nil)
	f := &publicationFixture{conn: service.conn, delay: delay, paths: make(map[dbus.ObjectPath]bool)}
	if err := f.conn.ExportMethodTable(map[string]any{
		"GetState":      func() (int32, *dbus.Error) { return 2, nil },
		"EntryGroupNew": f.newGroup,
	}, "/", server); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *publicationFixture) wait() func() {
	f.mu.Lock()
	f.active++
	f.peak = max(f.peak, f.active)
	f.mu.Unlock()
	time.Sleep(f.delay)
	return func() { f.mu.Lock(); f.active--; f.mu.Unlock() }
}

func (f *publicationFixture) newGroup() (dbus.ObjectPath, *dbus.Error) {
	defer f.wait()()
	// godbus' export registration reads its object map outside its own lock.
	// Serialize fixture registration; the production adapter exports no methods.
	f.exports.Lock()
	defer f.exports.Unlock()
	f.mu.Lock()
	f.serial++
	path := dbus.ObjectPath(fmt.Sprintf("/group/%d", f.serial))
	f.paths[path] = true
	f.mu.Unlock()
	err := f.conn.ExportMethodTable(map[string]any{
		"AddRecord": func(index, protocol int32, flags uint32, name string, class, kind uint16, ttl uint32, raw []byte) *dbus.Error {
			defer f.wait()()
			if index < 1 || (protocol != 0 && protocol != 1) || (kind == dns.TypePTR && flags != 0 || kind != dns.TypePTR && flags != 9) || class != dns.ClassINET || (ttl != 1 && ttl != 5) {
				return dbus.MakeFailedError(fmt.Errorf("invalid publication fields"))
			}
			if _, err := rawRecord(name, kind, raw); err != nil {
				return dbus.MakeFailedError(err)
			}
			f.mu.Lock()
			f.ttls = append(f.ttls, ttl)
			f.mu.Unlock()
			return nil
		},
		"Commit": func() *dbus.Error { defer f.wait()(); f.mu.Lock(); f.commits++; f.mu.Unlock(); return nil },
		"Reset":  func() *dbus.Error { defer f.wait()(); f.mu.Lock(); f.resets++; f.mu.Unlock(); return nil },
		"Free": func() *dbus.Error {
			defer f.wait()()
			f.mu.Lock()
			f.frees++
			delete(f.paths, path)
			f.mu.Unlock()
			return nil
		},
	}, path, groupInterface)
	if err != nil {
		return "", dbus.MakeFailedError(err)
	}
	return path, nil
}

func TestPublisherLongLeaseTTLAndShortLeaseTransition(t *testing.T) {
	path := privateBus(t)
	f := publisherFixture(t, path, 0)
	links := map[int]observation.Link{2: {Source: "lan-a", Generation: "link-a", Families: []int{4}}}
	p, err := ConnectPublisher(
		t.Context(),
		path,
		links,
		func(context.Context, int, int, []catalog.Answer) error { return nil },
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := p.Close(context.Background()); err != nil {
			t.Error(err)
		}
	})
	rr, err := dns.NewRR("alias.local. 1 IN A 192.0.2.42")
	if err != nil {
		t.Fatal(err)
	}
	intent := Intent{
		Interface: 2,
		Family:    4,
		Deadline:  catalog.Now().Mono + 20*time.Second,
		Records:   []catalog.Answer{{RR: rr, Unique: true}},
	}
	if err := p.Reconcile(t.Context(), []Intent{intent}); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	ttl := f.ttls[0]
	f.mu.Unlock()
	if ttl != 5 {
		t.Fatalf("long lease still generates TTL-one browse churn: ttl=%d", ttl)
	}
	p.mu.Lock()
	deadline := p.groups[ownerKey{groupKey{2, 4}, host, "alias.local."}].deadline
	p.mu.Unlock()
	if deadline+6*time.Second != intent.Deadline {
		t.Fatal("advertisement can outlive evidence lease", deadline, intent.Deadline)
	}
	intent.Deadline = catalog.Now().Mono + 25*time.Second
	if err := p.Reconcile(t.Context(), []Intent{intent}); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	commits := f.commits
	f.mu.Unlock()
	if commits != 1 {
		t.Fatal("unchanged long lease was republished", commits)
	}
	intent.Deadline = catalog.Now().Mono + 8*time.Second
	if err := p.Reconcile(t.Context(), []Intent{intent}); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	ttls, commits, resets := append([]uint32{}, f.ttls...), f.commits, f.resets
	f.mu.Unlock()
	if len(ttls) != 2 || ttls[1] != 1 || commits != 2 || resets != 1 {
		t.Fatal("short lease did not replace the longer Avahi TTL", ttls, commits, resets)
	}
	if rr.Header().Ttl != 1 {
		t.Fatal("publication changed the caller's record")
	}
}

func TestPublisherParallelGroupsRenewalAndReplacementDeadlines(t *testing.T) {
	path := privateBus(t)
	f := publisherFixture(t, path, 20*time.Millisecond)
	links := make(map[int]observation.Link)
	for index := 1; index <= 6; index++ {
		links[index] = observation.Link{Source: fmt.Sprintf("lan-%d", index), Generation: "link-a", Families: []int{4, 6}}
	}
	var mu sync.Mutex
	goodbyes := 0
	p, err := ConnectPublisher(context.Background(), path, links, func(_ context.Context, _, _ int, values []catalog.Answer) error {
		if len(values) != 1 {
			t.Error("unexpected goodbye signature")
		}
		mu.Lock()
		goodbyes++
		mu.Unlock()
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := p.Close(context.Background()); err != nil {
			t.Error(err)
		}
	}()
	rr, err := dns.NewRR("alias.local. 10 IN A 192.0.2.42")
	if err != nil {
		t.Fatal(err)
	}
	var intents []Intent
	for index := range links {
		for _, family := range []int{4, 6} {
			intents = append(intents, Intent{index, family, catalog.Now().Mono + time.Second, []catalog.Answer{{RR: rr, Unique: true}}})
		}
	}
	start := time.Now()
	if err := p.Reconcile(context.Background(), intents); err != nil {
		t.Fatal(err)
	}
	if time.Since(start) >= time.Second {
		t.Fatal("parallel groups exceeded short lease")
	}
	f.mu.Lock()
	peak, commits := f.peak, f.commits
	f.mu.Unlock()
	if peak <= 1 || peak > 12 || commits != 12 {
		t.Fatal("groups did not run with bounded concurrency", peak, commits)
	}
	// An unchanged renewal extends the lease without another Commit.
	for i := range intents {
		intents[i].Deadline = catalog.Now().Mono + 2*time.Second
	}
	if err := p.Reconcile(context.Background(), intents); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	commits = f.commits
	f.mu.Unlock()
	if commits != 12 {
		t.Fatal("unchanged groups were republished")
	}
	// Removal must finish within the old lease, but replacement creation uses
	// its own deadline once those old groups have actually been withdrawn.
	p.mu.Lock()
	for key, group := range p.groups {
		group.deadline = catalog.Now().Mono + 150*time.Millisecond
		p.groups[key] = group
	}
	p.mu.Unlock()
	for i := range intents {
		intents[i].Records[0].RR = dns.Copy(rr)
		intents[i].Records[0].RR.(*dns.A).A = []byte{192, 0, 2, 43}
		intents[i].Deadline = catalog.Now().Mono + time.Second
	}
	if err := p.Reconcile(context.Background(), intents); err != nil {
		t.Fatal("replacement reused withdrawn deadline", err)
	}
	if err := p.Clear(context.Background()); err != nil {
		t.Fatal(err)
	}
	if groups, records := p.Counts(); groups != 0 || records != 0 {
		t.Fatal("producer clear retained publication")
	}
	mu.Lock()
	removed := goodbyes
	mu.Unlock()
	if removed != 24 {
		t.Fatal("replacement or clear omitted scoped goodbyes", removed)
	}
}

func TestPublisherExpiresIndependently(t *testing.T) {
	path := privateBus(t)
	publisherFixture(t, path, 0)
	p, err := ConnectPublisher(context.Background(), path, map[int]observation.Link{2: {Source: "lan-a", Generation: "link-a", Families: []int{4}}}, func(context.Context, int, int, []catalog.Answer) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := p.Close(context.Background()); err != nil {
			t.Error(err)
		}
	}()
	rr, err := dns.NewRR("alias.local. 30 IN A 192.0.2.42")
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Reconcile(context.Background(), []Intent{{2, 4, catalog.Now().Mono + 150*time.Millisecond, []catalog.Answer{{RR: rr, Unique: true}}}}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-p.Failed():
	case <-time.After(time.Second):
		t.Fatal("independent publication monitor did not withdraw")
	}
	if p.Err() == nil {
		t.Fatal("lost epoch remained available")
	}
	if err := p.Reconcile(context.Background(), nil); err == nil {
		t.Fatal("failed connection accepted renewal")
	}
}

func TestSlowReconciliationCannotExtendPublicationLease(t *testing.T) {
	path := privateBus(t)
	f := publisherFixture(t, path, 100*time.Millisecond)
	p, err := ConnectPublisher(context.Background(), path, map[int]observation.Link{2: {Source: "lan-a", Generation: "link-a", Families: []int{4}}}, func(context.Context, int, int, []catalog.Answer) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := p.Close(context.Background()); err != nil {
			t.Error(err)
		}
	}()
	rr, err := dns.NewRR("alias.local. 30 IN A 192.0.2.42")
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	err = p.Reconcile(context.Background(), []Intent{{2, 4, catalog.Now().Mono + 150*time.Millisecond, []catalog.Answer{{RR: rr, Unique: true}}}})
	if err == nil || p.Err() == nil || time.Since(start) > 500*time.Millisecond {
		t.Fatal("slow D-Bus extended lease", err, time.Since(start))
	}
	f.mu.Lock()
	commits := f.commits
	f.mu.Unlock()
	if commits != 0 {
		t.Fatal("expired creation committed records")
	}
}

func TestIsolatedServiceCollisionsAndSharedDependencies(t *testing.T) {
	path := privateBus(t)
	f := publisherFixture(t, path, 0)
	links := map[int]observation.Link{2: {Source: "lan-a", Generation: "link-a", Families: []int{4}}}
	p, err := ConnectPublisher(t.Context(), path, links, func(context.Context, int, int, []catalog.Answer) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := p.Close(context.Background()); err != nil {
			t.Error(err)
		}
	})

	intent := Intent{Interface: 2, Family: 4, Deadline: catalog.Now().Mono + 20*time.Second}
	add := func(text string) {
		rr, err := dns.NewRR(text)
		if err != nil {
			t.Fatal(err)
		}
		intent.Records = append(intent.Records, catalog.Answer{RR: rr, Source: "lan-a", Unique: rr.Header().Rrtype != dns.TypePTR})
	}
	const serviceType = "_fixture._tcp.local."
	add(catalog.Enumeration + " 20 IN PTR " + serviceType)
	add("shared.local. 20 IN A 192.0.2.10")
	add("third.local. 20 IN A 192.0.2.11")
	for name, target := range map[string]string{"a": "shared.local.", "b": "shared.local.", "c": "third.local."} {
		instance := name + "." + serviceType
		add(serviceType + " 20 IN PTR " + instance)
		add(instance + " 20 IN SRV 0 0 8080 " + target)
		add(instance + ` 20 IN TXT "fixture"`)
	}
	if err := p.Reconcile(t.Context(), []Intent{intent}); err != nil {
		t.Fatal(err)
	}
	wait := func(check func() bool) {
		t.Helper()
		for end := time.Now().Add(time.Second); time.Now().Before(end); {
			if check() {
				return
			}
			if p.Err() != nil {
				t.Fatal(p.Err())
			}
			time.Sleep(5 * time.Millisecond)
		}
		states, _ := p.Outcomes()
		t.Fatalf("timed out waiting for publication transition, outcomes %q", states)
	}
	key := func(kind int, name string) ownerKey { return ownerKey{groupKey{2, 4}, kind, name} }
	object := func(key ownerKey) dbus.ObjectPath {
		p.mu.Lock()
		defer p.mu.Unlock()
		g := p.groups[key]
		if !g.committed {
			return ""
		}
		return g.path
	}
	send := func(key ownerKey, state int32) {
		t.Helper()
		wait(func() bool { return object(key) != "" })
		if err := f.conn.Emit(object(key), groupInterface+".StateChanged", state, "fixture"); err != nil {
			t.Fatal(err)
		}
	}
	hosts := []ownerKey{key(host, "shared.local."), key(host, "third.local.")}
	instances := []ownerKey{key(instance, "a."+serviceType), key(instance, "b."+serviceType), key(instance, "c."+serviceType)}
	enum := key(enumeration, serviceType)
	if states, _ := p.Outcomes(); states != "PPPPPP" || object(instances[0]) != "" {
		t.Fatal("commit advertised unprobed dependencies", states)
	}
	for _, host := range hosts {
		send(host, 2)
	}
	for _, service := range instances {
		send(service, 2)
	}
	send(enum, 2)
	wait(func() bool { states, _ := p.Outcomes(); return states == "EEEEEE" })
	b, c, e := object(instances[1]), object(instances[2]), object(enum)
	send(instances[0], 3)
	wait(func() bool { states, _ := p.Outcomes(); return states == "EECEEE" && object(instances[0]) == "" })
	if object(instances[1]) != b || object(instances[2]) != c || object(enum) != e {
		t.Fatal("independent service or shared enumeration disturbed")
	}

	send(hosts[0], 4)
	wait(func() bool {
		states, _ := p.Outcomes()
		return states == "FECPEE" && object(instances[1]) == "" && object(hosts[0]) == ""
	})
	if err := p.Reconcile(t.Context(), []Intent{intent}); err != nil {
		t.Fatal(err)
	}
	if object(hosts[0]) != "" || object(instances[2]) != c {
		t.Fatal("registration failure retried early or disturbed independent graph")
	}
	time.Sleep(time.Second)
	if err := p.Reconcile(t.Context(), []Intent{intent}); err != nil {
		t.Fatal(err)
	}
	send(hosts[0], 2)
	send(instances[1], 2)
	wait(func() bool { states, _ := p.Outcomes(); return states == "EECEEE" })
	if object(instances[2]) != c || object(enum) != e {
		t.Fatal("retry changed independent objects")
	}
	if _, err := f.conn.ReleaseName("org.freedesktop.Avahi"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-p.Failed():
	case <-time.After(time.Second):
		t.Fatal("daemon owner loss kept registrations active")
	}
	if err := p.Reconcile(t.Context(), []Intent{intent}); err == nil {
		t.Fatal("owner loss permitted replay")
	}
}

func TestOriginalHostCollisionStaysOnOneLinkAndFamily(t *testing.T) {
	path := privateBus(t)
	fixture := publisherFixture(t, path, 0)
	links := map[int]observation.Link{
		2: {Source: "target-a", Generation: "gen", Families: []int{4, 6}},
		3: {Source: "target-b", Generation: "gen", Families: []int{4}},
	}
	p, err := ConnectPublisher(t.Context(), path, links, func(context.Context, int, int, []catalog.Answer) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := p.Close(context.Background()); err != nil {
			t.Error(err)
		}
	}()
	rr, err := dns.NewRR("original.local. 30 IN A 192.0.2.42")
	if err != nil {
		t.Fatal(err)
	}
	var intents []Intent
	for index, link := range links {
		for _, family := range link.Families {
			intents = append(intents, Intent{Interface: index, Family: family, Deadline: catalog.Now().Mono + 24*time.Second,
				Records: []catalog.Answer{{RR: rr, Unique: true, Source: "source-lan"}}})
		}
	}
	if err := p.Reconcile(t.Context(), intents); err != nil {
		t.Fatal(err)
	}
	p.mu.Lock()
	paths := make(map[ownerKey]dbus.ObjectPath)
	for key, g := range p.groups {
		paths[key] = g.path
	}
	p.mu.Unlock()
	for key, path := range paths {
		state := int32(2)
		if key.index == 2 && key.family == 4 {
			state = 3
		}
		if err := fixture.conn.Emit(path, groupInterface+".StateChanged", state, "fixture"); err != nil {
			t.Fatal(err)
		}
	}
	for until := time.Now().Add(time.Second); ; {
		if states, _ := p.Outcomes(); states == "CEE" {
			break
		}
		if time.Now().After(until) {
			t.Fatal("did not isolate original name")
		}
		time.Sleep(5 * time.Millisecond)
	}
	// Renew evidence and then cross the registration TTL threshold. The
	// colliding original stays held even when the other two RRsets re-register.
	if err := p.Reconcile(t.Context(), intents); err != nil {
		t.Fatal(err)
	}
	p.mu.Lock()
	for key, path := range paths {
		g := p.groups[key]
		if key.index == 2 && key.family == 4 {
			if g.path != "" {
				t.Error("colliding original still registered")
			}
		} else if g.path != path {
			t.Error("independent original lost its registration")
		}
	}
	p.mu.Unlock()
	for i := range intents {
		intents[i].Deadline = catalog.Now().Mono + 8*time.Second
	}
	if err := p.Reconcile(t.Context(), intents); err != nil {
		t.Fatal(err)
	}
	if states, _ := p.Outcomes(); states != "CPP" {
		t.Fatal("TTL transition cleared local conflict hold", states)
	}
}
