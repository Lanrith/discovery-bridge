package avahi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/lanrith/discovery-bridge/internal/catalog"
	"github.com/lanrith/discovery-bridge/internal/config"
	"github.com/lanrith/discovery-bridge/internal/dnswire"
	"github.com/lanrith/discovery-bridge/internal/observation"
	"github.com/miekg/dns"
)

// Query stays on one operator-approved interface and transport family.
type Query struct {
	Interface, Family int
	Name              string
	Type              uint16
}

// Event is a browser hint. It deliberately carries no expiry or renewable TTL.
type Event struct {
	Epoch         string
	Query         Query
	Record        observation.Record
	Added, Cached bool
}

const (
	maxBrowserObjects = 1024 // Packaged Avahi per-client ceiling.
	watchIdle         = 120 * time.Second
)

// ErrBrowserCapacity lets a native caller continue its already scoped wire lookup.
var ErrBrowserCapacity = errors.New("avahi browser capacity reached")

type seenKey struct {
	path dbus.ObjectPath
	data string
}

// Browser owns one Avahi connection epoch. Next has one consumer; Watch, Follow
// and Retire may be called concurrently. Closing frees all connection-owned browsers.
type Browser struct {
	bus          *bus
	epoch        string
	links        map[int]observation.Link
	operations   sync.Mutex // Serializes Prepare, Free, seeding and the retry queue.
	mu           sync.Mutex // Protects fields also observed by Next and Counts.
	paths        map[dbus.ObjectPath]Query
	queries      map[Query]dbus.ObjectPath
	seen         map[seenKey]dns.RR
	touched      map[Query]time.Time
	permanent    map[Query]bool
	pendingSeeds int
	native       map[dbus.ObjectPath]bool
	objectLimit  int
	waiting      map[Query]time.Time
	order        []Query
	deferred     uint64
}

// ConnectBrowser opens a local D-Bus connection and verifies a stable running Avahi.
func ConnectBrowser(ctx context.Context, path string, links map[int]observation.Link) (*Browser, error) {
	b, err := newBrowser(links)
	if err != nil {
		return nil, err
	}
	b.bus, err = connectBus(ctx, path)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func newBrowser(links map[int]observation.Link) (*Browser, error) {
	links, err := copyLinks(links)
	if err != nil {
		return nil, err
	}
	var token [16]byte
	if _, err := rand.Read(token[:]); err != nil {
		return nil, err
	}
	return &Browser{epoch: hex.EncodeToString(token[:]), links: links,
		paths: make(map[dbus.ObjectPath]Query), queries: make(map[Query]dbus.ObjectPath),
		seen: make(map[seenKey]dns.RR), touched: make(map[Query]time.Time), permanent: make(map[Query]bool),
		native: make(map[dbus.ObjectPath]bool), objectLimit: maxBrowserObjects, waiting: make(map[Query]time.Time)}, nil
}

func copyLinks(links map[int]observation.Link) (map[int]observation.Link, error) {
	if len(links) == 0 || len(links) > 64 {
		return nil, errors.New("explicit bounded LAN interfaces required")
	}
	links = maps.Clone(links)
	for index, link := range links {
		if index < 1 || link.Source == "" || link.Generation == "" || len(link.Families) == 0 || len(link.Families) > 2 {
			return nil, errors.New("LAN link requires index, identity, generation and families")
		}
		families := slices.Clone(link.Families)
		slices.Sort(families)
		if slices.ContainsFunc(families, func(f int) bool { return f != 4 && f != 6 }) || len(slices.Compact(families)) != len(families) {
			return nil, errors.New("LAN families must be distinct IPv4 or IPv6")
		}
		link.Families = families
		links[index] = link
	}
	return links, nil
}

// Epoch identifies hints that must be discarded together after connection loss.
func (b *Browser) Epoch() string { return b.epoch }

// Err reports a failed observation epoch without exposing device identifiers.
func (b *Browser) Err() error {
	if b.bus == nil {
		return errors.New("avahi browser is not connected")
	}
	return b.bus.err()
}

// Close withdraws all browser ownership and joins the connection monitor.
func (b *Browser) Close() {
	if b.bus != nil {
		b.bus.close()
	}
}

func (b *Browser) normalize(query Query) (Query, error) {
	name, err := localName(query.Name)
	link, ok := b.links[query.Interface]
	if err != nil || !ok || !slices.Contains(link.Families, query.Family) || !observation.Supported(query.Type) {
		return Query{}, errors.New("unapproved Avahi query scope, name or record type")
	}
	query.Name = name
	return query, nil
}

// freeSlots includes prepared browsers until Free is acknowledged, and protects
// declared seeds before their objects exist. Callers hold operations.
func (b *Browser) freeSlots() int {
	return b.objectLimit - len(b.queries) - len(b.native) - b.pendingSeeds
}

// prepare serializes allocations on this private connection. Avahi rejects a
// full client's Prepare before creating an object, so its reply reveals the
// configured limit even when it is smaller than the packaged default.
func (b *Browser) prepare(ctx context.Context, query Query, name string) (dbus.ObjectPath, error) {
	protocol := int32(0)
	if query.Family == 6 {
		protocol = 1
	}
	var path dbus.ObjectPath
	err := b.bus.call(ctx, "/", server2+".RecordBrowserPrepare", int32(query.Interface), protocol, name, uint16(dns.ClassINET), query.Type, uint32(2)).Store(&path)
	var remote dbus.Error
	if errors.As(err, &remote) && strings.HasPrefix(remote.Name, service+".") {
		if remote.Name == service+".TooManyObjectsError" {
			b.objectLimit = len(b.queries) + len(b.native)
			return "", ErrBrowserCapacity
		}
		return "", err // An explicit application refusal allocated no object.
	}
	_, catalogPath := b.paths[path]
	if err == nil && (!path.IsValid() || path == "/" || b.native[path] || catalogPath) {
		err = errors.New("invalid or reused Avahi browser path")
	}
	if err != nil {
		// A missing or malformed Prepare reply can leave an unaccounted object.
		b.bus.fail(errors.New("avahi browser setup failed; discard observation epoch"))
	}
	return path, err
}

// Watch coalesces demand. Distinct excess watches enter a bounded retry queue.
func (b *Browser) Watch(ctx context.Context, query Query) (bool, error) {
	return b.watch(ctx, query, true)
}

func (b *Browser) watch(ctx context.Context, query Query, clientDemand bool) (bool, error) {
	query, err := b.normalize(query)
	if err != nil {
		return false, err
	}
	b.operations.Lock()
	defer b.operations.Unlock()
	if err := b.Err(); err != nil {
		return false, err
	}
	if _, ok := b.queries[query]; ok {
		b.touched[query] = time.Now()
		return true, nil
	}
	// Give the oldest deferred work its turn. Required seed watches already
	// own a reservation and are installed before ordinary demand.
	first := len(b.order) > 0 && b.order[0] == query
	if b.permanent[query] || (b.pendingSeeds == 0 && (len(b.order) == 0 || first) && b.freeSlots() > 0) {
		admitted, err := b.startWatch(ctx, query)
		if first && admitted {
			b.popWaiting()
		}
		if admitted || err != nil || b.permanent[query] {
			return admitted, err
		}
	}
	b.enqueue(query, clientDemand)
	b.mu.Lock()
	b.deferred++
	b.mu.Unlock()
	return false, nil
}

func (b *Browser) enqueue(query Query, clientDemand bool) {
	if _, queued := b.waiting[query]; !queued {
		if len(b.order) >= maxBrowserObjects {
			return
		}
		b.order = append(b.order, query)
		b.waiting[query] = time.Time{} // A dependency alone must still have a live parent.
	}
	if clientDemand {
		b.waiting[query] = time.Now()
	}
}

func (b *Browser) popWaiting() {
	delete(b.waiting, b.order[0])
	b.order[0] = Query{}
	b.order = b.order[1:]
}

func (b *Browser) startWatch(ctx context.Context, query Query) (bool, error) {
	name, err := avahiName(query.Name)
	if err != nil {
		return false, err
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	// A caller may leave while Prepare is in flight. Finish accounting for the
	// result within the D-Bus call deadline; epoch loss closes the transport.
	path, err := b.prepare(context.WithoutCancel(ctx), query, name)
	if errors.Is(err, ErrBrowserCapacity) {
		return false, b.Err()
	}
	if err != nil {
		b.bus.fail(errors.New("avahi browser setup failed; discard observation epoch"))
		return false, err
	}
	// Install routing before Start can deliver its first cached signal.
	b.mu.Lock()
	b.paths[path], b.queries[query], b.touched[query] = query, path, time.Now()
	if b.permanent[query] {
		b.pendingSeeds--
	}
	b.mu.Unlock()
	if err := b.bus.call(context.WithoutCancel(ctx), path, browserInterface+".Start").Err; err != nil {
		b.bus.fail(errors.New("avahi browser start failed; discard observation epoch"))
		return false, err
	}
	return true, b.Err()
}

// WatchNative opens an independent short-lived force-multicast interest. Its
// events are not promoted to Pod hints; native authority still requires wire TTLs.
// Avahi cannot browse ANY keys, so that operation belongs to the raw sender.
func (b *Browser) WatchNative(ctx context.Context, query Query) (func() error, error) {
	link, ok := b.links[query.Interface]
	if !ok || !slices.Contains(link.Families, query.Family) || !dnswire.Name(query.Name) || query.Type == 0 || query.Type == dns.TypeANY {
		return nil, errors.New("unapproved native Avahi query")
	}
	name, err := nativeAvahiName(query.Name)
	if err != nil {
		return nil, err
	}
	b.operations.Lock()
	defer b.operations.Unlock()
	if err := b.Err(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// Leave the next available slot for the oldest deferred catalog interest.
	freeSlots := b.freeSlots()
	if b.pendingSeeds > 0 || freeSlots <= 0 || (len(b.order) > 0 && freeSlots == 1) {
		return nil, ErrBrowserCapacity
	}
	path, err := b.prepare(context.WithoutCancel(ctx), query, name)
	if err != nil {
		return nil, err
	}
	b.mu.Lock()
	b.native[path] = true
	b.mu.Unlock()
	free := func() error {
		if b.Err() != nil {
			return nil // Teardown releases all objects owned by this connection.
		}
		bounded, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer cancel()
		if err := b.bus.call(bounded, path, browserInterface+".Free").Err; err != nil {
			b.bus.fail(errors.New("native Avahi browser release failed"))
			return err
		}
		b.mu.Lock()
		delete(b.native, path)
		b.mu.Unlock()
		return nil
	}
	if err := b.bus.call(ctx, path, browserInterface+".Start").Err; err != nil {
		return nil, errors.Join(err, free())
	}
	return sync.OnceValue(func() error {
		b.operations.Lock()
		defer b.operations.Unlock()
		return free()
	}), nil
}

// Seed installs enumeration and configured interests for this connection epoch.
// Reserve their slots before calls start so incoming hints can be consumed
// concurrently and dependent browsers cannot crowd out the remaining seeds.
func (b *Browser) Seed(ctx context.Context, configured ...config.Bootstrap) error {
	interests := config.BootstrapInterests(configured)
	var queries []Query
	for _, index := range slices.Sorted(maps.Keys(b.links)) {
		for _, family := range b.links[index].Families {
			for _, interest := range interests {
				queries = append(queries, Query{index, family, interest.Name, dns.StringToType[interest.Type]})
			}
		}
	}
	if len(queries) > config.MaxPermanentBrowsers {
		return errors.New("avahi permanent browser budget exceeded")
	}
	b.operations.Lock()
	b.mu.Lock()
	var newSeeds, newObjects int
	for _, query := range queries {
		if !b.permanent[query] {
			newSeeds++
			if b.queries[query] == "" {
				newObjects++
			}
		}
	}
	if len(b.permanent)+newSeeds > config.MaxPermanentBrowsers ||
		newObjects > b.freeSlots() {
		b.mu.Unlock()
		b.operations.Unlock()
		return errors.New("avahi seed browser capacity exceeded")
	}
	b.pendingSeeds += newObjects
	for _, query := range queries {
		b.permanent[query] = true
	}
	b.mu.Unlock()
	b.operations.Unlock()
	for _, query := range queries {
		admitted, err := b.Watch(ctx, query)
		if err != nil {
			return err
		}
		if !admitted {
			return errors.New("avahi seed browser capacity exceeded")
		}
	}
	return nil
}

func dependencies(query Query, rr dns.RR) []Query {
	var target string
	var types []uint16
	switch value := rr.(type) {
	case *dns.PTR:
		target, types = value.Ptr, []uint16{dns.TypeSRV, dns.TypeTXT}
		if query.Name == catalog.Enumeration {
			types = []uint16{dns.TypePTR}
		}
	case *dns.SRV:
		target, types = value.Target, []uint16{dns.TypeA, dns.TypeAAAA}
	}
	var result []Query
	for _, kind := range types {
		result = append(result, Query{query.Interface, query.Family, catalog.NameKey(target), kind})
	}
	return result
}

// Follow browses dependencies on the observation's original interface and family.
func (b *Browser) Follow(ctx context.Context, event Event) error {
	if event.Epoch != b.epoch || !event.Added {
		return nil
	}
	for _, query := range dependencies(event.Query, event.Record.RR) {
		if _, err := b.watch(ctx, query, false); err != nil {
			return err
		}
	}
	return nil
}

// Retire frees only empty, idle browsers that no active record still needs.
func (b *Browser) Retire(ctx context.Context) error {
	b.operations.Lock()
	defer b.operations.Unlock()
	if err := b.Err(); err != nil {
		return err
	}
	b.mu.Lock()
	needed, active := make(map[Query]bool), make(map[dbus.ObjectPath]bool)
	for key, rr := range b.seen {
		active[key.path] = true
		for _, query := range dependencies(b.paths[key.path], rr) {
			needed[query] = true
		}
	}
	var retired []Query
	for query, path := range b.queries {
		if !b.permanent[query] && !needed[query] && !active[path] && time.Since(b.touched[query]) >= watchIdle {
			// Remove routing first so late signals cannot revive a retired watch.
			delete(b.paths, path)
			delete(b.touched, query)
			retired = append(retired, query)
		}
	}
	b.mu.Unlock()
	for _, query := range retired {
		if err := b.bus.call(ctx, b.queries[query], browserInterface+".Free").Err; err != nil {
			b.bus.fail(errors.New("avahi browser retirement failed"))
			return err
		}
		b.mu.Lock()
		delete(b.queries, query)
		b.mu.Unlock()
	}
	return b.retryDeferred(ctx, needed)
}

func (b *Browser) retryDeferred(ctx context.Context, needed map[Query]bool) error {
	// Service a bounded batch on the existing publication tick. A live
	// dependency remains eligible after the ordinary demand window expires.
	retryUntil := time.Now().Add(50 * time.Millisecond)
	for attempts := 0; len(b.order) > 0 && attempts < 8 && time.Now().Before(retryUntil); attempts++ {
		query := b.order[0]
		if b.queries[query] == "" && (needed[query] || time.Since(b.waiting[query]) < watchIdle) {
			if b.pendingSeeds > 0 || b.freeSlots() <= 0 {
				break
			}
			admitted, err := b.startWatch(ctx, query)
			if err != nil {
				return err
			}
			if !admitted {
				break
			}
		}
		b.popWaiting()
	}
	// A live parent can outlast a full retry queue without emitting a new hint.
	for query := range needed {
		if len(b.order) >= maxBrowserObjects {
			break
		}
		if b.queries[query] == "" {
			b.enqueue(query, false)
		}
	}
	return b.Err()
}

// Next returns one admitted hint; failure always takes precedence over queued hints.
func (b *Browser) Next(ctx context.Context) (Event, error) {
	for {
		if err := b.Err(); err != nil {
			return Event{}, err
		}
		select {
		case <-ctx.Done():
			return Event{}, ctx.Err()
		case <-b.bus.failed:
			return Event{}, b.Err()
		case signal := <-b.bus.signals:
			b.mu.Lock()
			event, admitted, err := b.event(signal)
			b.mu.Unlock()
			if err != nil {
				b.bus.fail(errors.New("invalid or overflowing Avahi event stream"))
				return Event{}, err
			}
			if err := b.Err(); err != nil {
				return Event{}, err
			}
			if admitted {
				return event, nil
			}
		}
	}
}

func (b *Browser) event(signal *dbus.Signal) (Event, bool, error) {
	if b.native[signal.Path] {
		if signal.Name == browserInterface+".Failure" {
			return Event{}, false, errors.New("native avahi record browser failed")
		}
		return Event{}, false, nil
	}
	query, ok := b.paths[signal.Path]
	if !ok || !strings.HasPrefix(signal.Name, browserInterface+".") {
		return Event{}, false, nil
	}
	if signal.Name == browserInterface+".Failure" {
		return Event{}, false, errors.New("avahi record browser failed")
	}
	added := signal.Name == browserInterface+".ItemNew"
	if !added && signal.Name != browserInterface+".ItemRemove" {
		return Event{}, false, nil
	}
	var index, protocol int32
	var name string
	var class, kind uint16
	var raw []byte
	var flags uint32
	if err := dbus.Store(signal.Body, &index, &protocol, &name, &class, &kind, &raw, &flags); err != nil {
		return Event{}, false, err
	}
	family := 4
	if protocol == 1 {
		family = 6
	} else if protocol != 0 {
		return Event{}, false, errors.New("invalid Avahi transport family")
	}
	name, err := localName(name)
	if err != nil || int(index) != query.Interface || family != query.Family || name != query.Name || kind != query.Type || class != dns.ClassINET {
		return Event{}, false, errors.New("avahi browser event scope mismatch")
	}
	// A shared enumeration PTR can be LOCAL because our publisher registers the
	// same type. It remains only a hint: independent remote wire evidence is required.
	enumeration := kind == dns.TypePTR && name == catalog.Enumeration
	if flags&(2|16|32) != 0 || flags&8 != 0 && !enumeration || flags&4 == 0 {
		return Event{}, false, nil
	}
	rr, err := rawRecord(name, kind, raw)
	if err != nil {
		return Event{}, false, err
	}
	key := seenKey{signal.Path, (catalog.Answer{RR: rr}).Key()}
	if added {
		b.seen[key] = rr
		if len(b.seen) > catalog.MaxRecords {
			return Event{}, false, errors.New("avahi hint capacity exceeded")
		}
	} else if _, exists := b.seen[key]; !exists {
		return Event{}, false, nil
	} else {
		delete(b.seen, key)
	}
	link := b.links[query.Interface]
	return Event{Epoch: b.epoch, Query: query,
		Record: observation.Record{Source: link.Source, Generation: link.Generation, Family: family, RR: rr},
		Added:  added, Cached: flags&1 != 0}, true, nil
}

// Counts reports resource use without recording queries or device identities.
func (b *Browser) Counts() (watches, hints int, deferred uint64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.queries), len(b.seen), b.deferred
}
