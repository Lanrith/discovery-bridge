package avahi

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/lanrith/discovery-bridge/internal/catalog"
	"github.com/lanrith/discovery-bridge/internal/observation"
	"github.com/miekg/dns"
)

const (
	groupInterface = service + ".EntryGroup"
	publicationTTL = 5 * time.Second
)

// Intent carries a complete admitted group and an absolute Linux monotonic lease.
type Intent struct {
	Interface, Family int
	Deadline          time.Duration
	Records           []catalog.Answer
}

// Goodbye sends only this owner's previously committed record signature.
type Goodbye func(context.Context, int, int, []catalog.Answer) error

type group struct {
	path      dbus.ObjectPath
	records   []catalog.Answer
	deadline  time.Duration
	committed bool
	retiring  bool
	state     byte
	signature []string
}

// Publisher owns one independent Avahi connection. Its lease monitor continues
// while producer reads or reconciliation stall; ownership loss closes D-Bus and
// withdraws the epoch. A fresh connection is required after that failure.
type Publisher struct {
	bus            *bus
	links          map[int]observation.Link
	goodbye        Goodbye
	operations     sync.Mutex
	mu             sync.Mutex
	groups         map[ownerKey]group
	desired        map[ownerKey]*registration
	selected       map[ownerKey]bool
	faults         map[ownerKey]groupFault
	nextAllocation time.Duration
	updates        chan struct{}
	joined         chan struct{}
	done           chan struct{}
}

// ConnectPublisher verifies Avahi and starts independent lease supervision.
func ConnectPublisher(ctx context.Context, path string, links map[int]observation.Link, goodbye Goodbye) (*Publisher, error) {
	links, err := copyLinks(links)
	if err != nil {
		return nil, err
	}
	count := 0
	for _, link := range links {
		count += len(link.Families)
	}
	if count > 12 || goodbye == nil {
		return nil, errors.New("bounded publication links and scoped goodbye sender required")
	}
	b, err := connectBus(ctx, path)
	if err != nil {
		return nil, err
	}
	p := &Publisher{bus: b, links: links, goodbye: goodbye, groups: make(map[ownerKey]group), faults: make(map[ownerKey]groupFault), updates: make(chan struct{}, 1), joined: make(chan struct{}), done: make(chan struct{})}
	go p.monitor()
	go p.maintain(ctx)
	return p, nil
}

// Err reports loss of the independent publication epoch.
func (p *Publisher) Err() error { return p.bus.err() }

// Failed wakes the IPC owner on expiry or Avahi loss.
func (p *Publisher) Failed() <-chan struct{} { return p.bus.failed }

type groupFault struct {
	state byte
	retry time.Duration
}

func (p *Publisher) wake() {
	select {
	case p.updates <- struct{}{}:
	default:
	}
}

// maintain reacts to ownership transitions even while the producer is idle.
// The independent clock monitor can still close a stalled D-Bus transport.
func (p *Publisher) maintain(ctx context.Context) {
	defer close(p.joined)
	for {
		select {
		case <-p.bus.failed:
			return
		case <-p.updates:
			p.operations.Lock()
			if p.Err() == nil {
				if err := p.update(ctx); err != nil {
					p.bus.fail(err)
				}
			}
			p.operations.Unlock()
		}
	}
}

func (p *Publisher) monitor() {
	defer close(p.done)
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	last := catalog.Now().Mono
	for {
		select {
		case <-p.bus.failed:
			return
		case signal := <-p.bus.signals:
			if signal.Name != groupInterface+".StateChanged" {
				continue
			}
			var state int32
			var detail string
			if err := dbus.Store(signal.Body, &state, &detail); err != nil {
				p.bus.fail(errors.New("invalid Avahi publication event"))
				continue
			}
			p.mu.Lock()
			for key, g := range p.groups {
				if g.path != signal.Path || g.retiring {
					continue
				}
				switch state {
				case 0, 1:
					g.state = Pending
				case 2:
					g.state = Established
				case 3, 4:
					code := byte(Failed)
					if state == 3 && key.kind != enumeration {
						code = Collision
					}
					p.faults[key] = groupFault{code, catalog.Now().Mono + time.Second}
					g.state = code
				default:
					p.bus.fail(errors.New("unknown Avahi group state"))
				}
				p.groups[key] = g
				p.wake()
				break
			}
			p.mu.Unlock()
		case <-ticker.C:
			now := catalog.Now().Mono
			invalid := now < 0 || now < last
			last = now
			p.mu.Lock()
			for _, graph := range p.desired {
				invalid = invalid || now >= graph.deadline
			}
			for _, group := range p.groups {
				invalid = invalid || now >= group.deadline
			}
			p.mu.Unlock()
			if invalid {
				p.bus.fail(errors.New("independent publication lease expired"))
			}
		}
	}
}

func signature(records []catalog.Answer) []string {
	result := make([]string, 0, len(records))
	for _, record := range records {
		unique := "0"
		if record.Unique {
			unique = "1"
		}
		result = append(result, fmt.Sprintf("%d/%s/%s/%s", record.RR.Header().Ttl, record.Source, record.Key(), unique))
	}
	slices.Sort(result)
	return result
}

func cloneAnswers(records []catalog.Answer) []catalog.Answer {
	result := slices.Clone(records)
	for i := range result {
		result[i].RR = dns.Copy(result[i].RR)
	}
	return result
}

func (p *Publisher) validate(intents []Intent, now time.Duration) (map[groupKey]Intent, error) {
	if len(intents) > 12 {
		return nil, errors.New("publication group budget exceeded")
	}
	desired := make(map[groupKey]Intent)
	budget := 0
	for _, intent := range intents {
		link, ok := p.links[intent.Interface]
		key := groupKey{intent.Interface, intent.Family}
		if _, duplicate := desired[key]; duplicate || !ok || !slices.Contains(link.Families, intent.Family) || intent.Deadline <= now || intent.Deadline-now > 30*time.Second {
			return nil, errors.New("invalid publication group scope or deadline")
		}
		budget += len(intent.Records)
		if budget > catalog.MaxRecords {
			return nil, errors.New("publication record budget exceeded")
		}
		for _, record := range intent.Records {
			if record.RR == nil || !observation.Supported(record.RR.Header().Rrtype) || !catalog.LocalName(record.RR.Header().Name) {
				return nil, errors.New("invalid admitted publication record")
			}
		}
		intent.Records = cloneAnswers(intent.Records)
		ttl := uint32(1)
		if intent.Deadline-now >= 2*publicationTTL {
			ttl = uint32(publicationTTL / time.Second)
			// Avahi does not age the configured TTL before replying. Stop
			// advertising one whole TTL before the absolute evidence lease:
			// even the last reply then expires by the original deadline.
			// Short leases retain the existing TTL-one behavior. Their smaller
			// TTL must replace the Avahi registration, not just its metadata.
			// Keep another second for supervisor/daemon scheduling, rather than
			// consuming all of the reserve with the client's cache lifetime.
			intent.Deadline -= publicationTTL + time.Second
		}
		for _, record := range intent.Records {
			record.RR.Header().Ttl = ttl
		}
		desired[key] = intent
	}
	return desired, nil
}

// phase runs at most twelve independent groups concurrently. Calls within a
// group retain their order. The old lease bounds removal; the fresh lease then
// bounds creation, so a completed withdrawal cannot constrain its replacement.
func (p *Publisher) phase(ctx context.Context, until time.Duration, operations []func(context.Context) error) error {
	delay := until - catalog.Now().Mono
	if delay <= 0 {
		p.bus.fail(errors.New("publication lease expired before reconciliation"))
		return p.Err()
	}
	bounded, cancel := context.WithTimeout(ctx, min(delay, 3*time.Second))
	defer cancel()
	stop := context.AfterFunc(bounded, func() { p.bus.fail(errors.New("publication reconciliation exceeded lease budget")) })
	defer stop()
	var wg sync.WaitGroup
	var first error
	var failure sync.Once
	work := make(chan func(context.Context) error, len(operations))
	for _, op := range operations {
		work <- op
	}
	close(work)
	for range min(12, len(operations)) {
		wg.Go(func() {
			for op := range work {
				if bounded.Err() != nil {
					return
				}
				if err := op(bounded); err != nil {
					failure.Do(func() { first = err; p.bus.fail(err); cancel() })
					return
				}
			}
		})
	}
	wg.Wait()
	if first != nil {
		return first
	}
	if err := bounded.Err(); err != nil {
		p.bus.fail(err)
	}
	return p.Err()
}

// Reconcile accepts a fresh complete view. Only a new producer submission
// can extend a lease or retry an ordinary registration failure.
func (p *Publisher) Reconcile(ctx context.Context, intents []Intent) error {
	p.operations.Lock()
	defer p.operations.Unlock()
	if err := p.Err(); err != nil {
		return err
	}
	now := catalog.Now().Mono
	scopes, err := p.validate(intents, now)
	if err != nil {
		return err
	}
	valid := make([]Intent, 0, len(scopes))
	for _, intent := range scopes {
		valid = append(valid, intent)
	}
	next := registrations(valid)
	p.mu.Lock()
	for _, graph := range p.desired {
		if now >= graph.deadline {
			p.mu.Unlock()
			p.bus.fail(errors.New("expired publication cannot be renewed"))
			return p.Err()
		}
	}
	for key, fault := range p.faults {
		current := next[key]
		if current == nil || (fault.state == Failed && now >= fault.retry) {
			delete(p.faults, key)
		}
	}
	p.desired = next
	p.selected = p.selectGraphs(groupLimit)
	p.mu.Unlock()
	return p.update(ctx)
}

const groupLimit = 1024

// Reserve a service and its address dependency together. Preserve existing
// services first. Capacity left after services can cover standalone addresses.
func (p *Publisher) selectGraphs(limit int) map[ownerKey]bool {
	selected := make(map[ownerKey]bool)
	keys := ordered(p.desired)
	for _, existing := range []bool{true, false} {
		for _, key := range keys {
			graph := p.desired[key]
			_, active := p.groups[key]
			if key.kind != instance || existing != active || p.faults[key].state != 0 || len(graph.dependencies) != 1 {
				continue
			}
			target := graph.dependencies[0]
			cost := 1
			if !selected[target] {
				cost++
			}
			if p.desired[target] != nil && p.faults[target].state == 0 && len(selected)+cost <= limit {
				selected[target] = true
				selected[key] = true
			}
		}
	}
	for _, key := range keys {
		if len(selected) == limit {
			break
		}
		if p.faults[key].state == 0 && key.kind != instance {
			selected[key] = true
		}
	}
	return selected
}

// ready checks a maximum of three levels (enumeration, instance, address).
// Compare the installed RRset too: a replaced address invalidates its old SRV.
func (p *Publisher) ready(key ownerKey) bool {
	graph := p.desired[key]
	if graph == nil || !p.selected[key] || p.faults[key].state != 0 {
		return false
	}
	if key.kind == host {
		return true
	}
	for _, dep := range graph.dependencies {
		g := p.groups[dep]
		if !g.retiring && g.committed && g.state == Established && p.ready(dep) && slices.Equal(g.signature, p.desired[dep].signature) {
			return true
		}
	}
	return false
}

// Outcomes is bounded by the admitted record count. Commit is pending until
// Avahi has reported ESTABLISHED for this object and its dependencies.
func (p *Publisher) Outcomes() (string, time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	var result strings.Builder
	var until time.Duration
	for _, key := range ordered(p.desired) {
		if deadline := p.desired[key].deadline; until == 0 || deadline < until {
			until = deadline
		}
		code := byte(Pending)
		if f := p.faults[key]; f.state != 0 {
			code = f.state
		} else if g := p.groups[key]; g.state == Established && !g.retiring && g.committed && p.ready(key) {
			code = Established
		}
		result.WriteByte(code)
	}
	return result.String(), until
}

func (p *Publisher) update(ctx context.Context) error {
	deadline := catalog.Now().Mono + 3*time.Second
	var remove []func(context.Context) error
	p.mu.Lock()
	for key, g := range p.groups {
		graph := p.desired[key]
		if !g.retiring && p.ready(key) && g.state != Failed && g.state != Collision && slices.Equal(g.signature, graph.signature) {
			g.deadline = graph.deadline
			p.groups[key] = g
			continue
		}
		deadline = min(deadline, g.deadline)
		// Ignore signals during Reset but retain the goodbye signature until
		// cleanup succeeds. Close can retry it if the bus disappears.
		g.retiring = true
		p.groups[key] = g
		remove = append(remove, func(ctx context.Context) error {
			if err := p.bus.call(ctx, g.path, groupInterface+".Reset").Err; err != nil {
				return err
			}
			if err := p.bus.call(ctx, g.path, groupInterface+".Free").Err; err != nil {
				return err
			}
			if g.committed {
				if err := p.goodbye(ctx, key.index, key.family, g.records); err != nil {
					return err
				}
			}
			p.mu.Lock()
			delete(p.groups, key)
			p.mu.Unlock()
			return nil
		})
	}
	p.mu.Unlock()
	if err := p.phase(ctx, deadline, remove); err != nil {
		return err
	}

	deadline = catalog.Now().Mono + 3*time.Second
	var add []func(context.Context) error
	p.mu.Lock()
	if catalog.Now().Mono < p.nextAllocation {
		p.mu.Unlock()
		return p.Err()
	}
	for _, key := range ordered(p.desired) {
		graph := p.desired[key]
		deadline = min(deadline, graph.deadline)
		if _, exists := p.groups[key]; exists || !p.ready(key) {
			continue
		}
		add = append(add, func(ctx context.Context) error { return p.register(ctx, key, graph) })
		// Bound each pass on a busy bus. Later acknowledgements and fresh
		// submissions continue admission without blocking producer renewal.
		if len(add) == 12 {
			break
		}
	}
	p.mu.Unlock()
	return p.phase(ctx, deadline, add)
}

func (p *Publisher) register(ctx context.Context, key ownerKey, graph *registration) error {
	var path dbus.ObjectPath
	if err := p.bus.call(ctx, "/", server+".EntryGroupNew").Store(&path); err != nil {
		return p.registrationError(key, err, false)
	}
	if !path.IsValid() || path == "/" {
		return errors.New("invalid Avahi entry group path")
	}
	p.mu.Lock()
	p.groups[key] = group{path: path, records: graph.records, signature: graph.signature, deadline: graph.deadline, state: Pending}
	p.mu.Unlock()
	protocol := int32(0)
	if key.family == 6 {
		protocol = 1
	}
	for _, record := range graph.records {
		name, err := avahiName(record.RR.Header().Name)
		if err != nil {
			return err
		}
		raw, err := rdata(record.RR)
		if err != nil {
			return err
		}
		flags := uint32(0)
		if record.Unique {
			flags = 9
		}
		if err := p.bus.call(ctx, path, groupInterface+".AddRecord", int32(key.index), protocol, flags, name, uint16(dns.ClassINET), record.RR.Header().Rrtype, record.RR.Header().Ttl, raw).Err; err != nil {
			return p.registrationError(key, err, record.Unique)
		}
	}
	// An asynchronous dependency loss may arrive while AddRecord is running.
	// Leave this object uncommitted for the independent withdrawal worker.
	p.mu.Lock()
	if !p.ready(key) {
		g := p.groups[key]
		g.retiring = true
		p.groups[key] = g
		p.mu.Unlock()
		p.wake()
		return nil
	}
	p.mu.Unlock()
	if err := p.bus.call(ctx, path, groupInterface+".Commit").Err; err != nil {
		return p.registrationError(key, err, key.kind != enumeration)
	}
	p.mu.Lock()
	g := p.groups[key]
	g.committed = true
	p.groups[key] = g
	p.mu.Unlock()
	return nil
}

func (p *Publisher) registrationError(key ownerKey, err error, unique bool) error {
	var remote dbus.Error
	if !errors.As(err, &remote) || (!strings.HasPrefix(remote.Name, service+".") && remote.Name != busInterface+".Error.Failed") {
		return err
	}
	code := byte(Failed)
	if unique && remote.Name == service+".CollisionError" {
		code = Collision
	}
	p.mu.Lock()
	retry := catalog.Now().Mono + time.Second
	p.faults[key] = groupFault{code, retry}
	if remote.Name == service+".TooManyObjectsError" {
		p.nextAllocation = retry
	}
	p.mu.Unlock()
	p.wake()
	return nil
}

// Clear withdraws this producer's complete publication while keeping healthy Avahi.
func (p *Publisher) Clear(ctx context.Context) error { return p.Reconcile(ctx, nil) }

// Close drops Avahi ownership first, sends scoped goodbyes for committed groups,
// and joins the independent monitor. Goodbye failures cannot keep ownership alive.
func (p *Publisher) Close(ctx context.Context) error {
	p.bus.close()
	<-p.done
	<-p.joined
	p.operations.Lock()
	defer p.operations.Unlock()
	p.mu.Lock()
	groups := p.groups
	p.groups = make(map[ownerKey]group)
	p.mu.Unlock()
	var errs []error
	for key, group := range groups {
		if group.committed {
			errs = append(errs, p.goodbye(ctx, key.index, key.family, group.records))
		}
	}
	return errors.Join(errs...)
}

// Counts reports publication use without device identifiers.
func (p *Publisher) Counts() (groups, records int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, group := range p.groups {
		records += len(group.records)
	}
	return len(p.groups), records
}
