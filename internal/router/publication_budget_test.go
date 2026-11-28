package router

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/lanrith/discovery-bridge/internal/avahi"
	"github.com/lanrith/discovery-bridge/internal/catalog"
	"github.com/lanrith/discovery-bridge/internal/gateway"
	"github.com/lanrith/discovery-bridge/internal/native"
	"github.com/lanrith/discovery-bridge/internal/observation"
	"github.com/lanrith/discovery-bridge/internal/policy"
	"github.com/lanrith/discovery-bridge/internal/publication"
	"github.com/lanrith/discovery-bridge/internal/state"
	"github.com/miekg/dns"
)

func tenDestinations() map[int]observation.Link {
	links := map[int]observation.Link{}
	for i := range 5 {
		links[i+1] = observation.Link{Source: fmt.Sprintf("lan-%d", i+1), Generation: "epoch", Families: []int{4, 6}}
	}
	return links
}

func budgetCollector(t *testing.T) *collector {
	t.Helper()
	ids, err := state.Open(t.Context(), filepath.Join(t.TempDir(), "aliases.db"), "alias")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ids.Close() })
	return &collector{identities: ids}
}

func acceptedFrame(t *testing.T, links map[int]observation.Link, groups []avahi.Intent, now time.Duration) {
	t.Helper()
	boot := strings.Repeat("a", 36)
	data, err := publication.Frame(boot, 1, now, groups)
	if err != nil || len(data) > publication.MaxFrame {
		t.Fatal("invalid encoded frame", len(data), err)
	}
	// The producer tests independently verify SQLite ownership. Check the
	// receiving peer's strict whole-graph, TTL, source and replay validation.
	peer := publication.Admission{Boot: boot, Links: links, Owns: func(string) (bool, error) { return true, nil }}
	if _, _, err := peer.Decode(data, now, 0); err != nil {
		t.Fatal(err)
	}
}

func TestPublicationLimitPreservesFeedNativeAndFreshAdmission(t *testing.T) {
	c := budgetCollector(t)
	now := catalog.Now()
	links := tenDestinations()
	scopes, err := policy.New(map[string][]string{"lan-1": {"192.0.2.0/24"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	feed, err := gateway.NewFeed(t.Context(), scopes, filepath.Join(t.TempDir(), "generation"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = feed.Close() })
	resolver, err := native.New("epoch", map[string][]netip.Prefix{"lan-1": scopes.Effective("lan-1")},
		func(context.Context, native.Question) (func() error, error) {
			return nil, errors.New("unexpected cold question")
		})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(resolver.Close)
	c.current = &collectorEpoch{native: resolver}
	c.feed = feed
	records := []catalog.Record{}
	for i := range 410 {
		name := fmt.Sprintf("device-%03d.local.", i)
		records = append(records, catalog.Record{ID: name, Name: name, Type: "A", Data: "192.0.2.25", Source: "lan-1", Expires: now.Wall.Add(20 * time.Second)})
	}
	for _, size := range []int{409, 410} {
		feedRecords, groups, err := c.views(t.Context(), records[:size], links, now)
		if err != nil || len(groups) != 10 || len(feedRecords) != size {
			t.Fatal(size, len(groups), len(feedRecords), err)
		}
		acceptedFrame(t, links, groups, now.Mono)
		for _, group := range groups {
			if len(group.Records) != 409 {
				t.Fatal("record ceiling per pair", len(group.Records))
			}
		}
		if err := feed.Publish(podView(feedRecords, now.Wall), now.Wall, now); err != nil {
			t.Fatal(err)
		}
		node := catalog.NewNodeFeed(scopes, nil)
		nonce, err := node.BeginRequest()
		if err != nil {
			t.Fatal(err)
		}
		data, err := feed.Read(nonce, now)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = node.Accept(data, now); err != nil {
			t.Fatal(err)
		}
		target := records[size-1]
		if !strings.Contains(string(data), target.Name) {
			t.Fatal("fresh workload record missing", size)
		}
		rr, err := target.RR(20)
		if err != nil {
			t.Fatal(err)
		}
		if err = resolver.Ingest([]observation.Record{{Source: "lan-1", Generation: "epoch", Family: 4, RR: rr}}, now.Mono); err != nil {
			t.Fatal(err)
		}
		result, err := c.Query(t.Context(), native.Question{Source: "lan-1", DNS: dns.Question{Name: target.Name, Qtype: dns.TypeA, Qclass: dns.ClassINET}})
		if err != nil || len(result.Records) != 1 {
			t.Fatal(result, err)
		}
	}
	_, oldAlias, _ := c.identities.Alias(t.Context(), "lan-1", records[0].Name, false)
	_, waitingAlias, _ := c.identities.Alias(t.Context(), "lan-1", records[409].Name, false)
	if !c.publication.admitted["host/"+catalog.NameKey(oldAlias)] || c.publication.admitted["host/"+catalog.NameKey(waitingAlias)] ||
		c.publication.deferredRecords < 10 || c.publication.deferredGraphs == 0 {
		t.Fatal("retention or deferred counts")
	}
	records[0].Expires = now.Wall
	slices.Reverse(records)
	_, groups, err := c.views(t.Context(), records, links, now)
	if err != nil {
		t.Fatal(err)
	}
	if c.publication.admitted["host/"+catalog.NameKey(oldAlias)] || !c.publication.admitted["host/"+catalog.NameKey(waitingAlias)] {
		t.Fatal("expired graph retained its slot")
	}
	for _, group := range groups {
		if slices.ContainsFunc(group.Records, func(a catalog.Answer) bool { return catalog.NameKey(a.RR.Header().Name) == catalog.NameKey(oldAlias) }) {
			t.Fatal("expired data was published")
		}
	}
	acceptedFrame(t, links, groups, now.Mono)
	c.withdraw(c.current)
	_, err = c.Query(t.Context(), native.Question{Source: "lan-1", DNS: dns.Question{Name: "device-409.local.", Qtype: dns.TypeA, Qclass: dns.ClassINET}})
	if !errors.Is(err, native.ErrUnavailable) {
		t.Fatal("withdrawn native session remained available", err)
	}
	node := catalog.NewNodeFeed(scopes, nil)
	nonce, err := node.BeginRequest()
	if err != nil {
		t.Fatal(err)
	}
	data, err := feed.Read(nonce, now)
	if err != nil || strings.Contains(string(data), "device-409.local.") {
		t.Fatal("withdrawal retained workload evidence", err)
	}

}

func TestByteBudgetAdmitsCompleteServicesWithSharedAddresses(t *testing.T) {
	c := budgetCollector(t)
	now := catalog.Now()
	links := tenDestinations()
	records := []catalog.Record{}
	add := func(name, typ, data string) {
		records = append(records, catalog.Record{ID: fmt.Sprint(len(records)), Name: name, Type: typ, Data: data, Source: "lan-1", Expires: now.Wall.Add(25 * time.Second)})
	}
	add(catalog.Enumeration, "PTR", "_printer._tcp.local.")
	add("shared.local.", "A", "192.0.2.62")
	add("shared.local.", "AAAA", "2001:db8::62")
	for i := range 40 {
		instance := fmt.Sprintf("device-%02d._printer._tcp.local.", i)
		add("_printer._tcp.local.", "PTR", instance)
		add("_ink._sub._printer._tcp.local.", "PTR", instance)
		add(instance, "SRV", "0 0 1234 shared.local.")
		add(instance, "TXT", strings.TrimSpace(strings.Repeat("\""+strings.Repeat("<", 200)+"\" ", 8)))
	}
	output, groups, err := c.views(t.Context(), records, links, now)
	if err != nil || len(output) != len(records) || c.publication.deferredGraphs == 0 {
		t.Fatal(len(output), c.publication, err)
	}
	if len(groups) != 10 {
		t.Fatal("missing approved destination")
	}
	for _, group := range groups {
		services, subtypes := 0, 0
		for _, a := range group.Records {
			ptr, ok := a.RR.(*dns.PTR)
			if !ok || catalog.NameKey(ptr.Hdr.Name) == catalog.Enumeration {
				continue
			}
			if strings.HasPrefix(ptr.Hdr.Name, "_ink.") {
				subtypes++
			} else {
				services++
			}
			if deps := catalog.Additionals(a, group.Records); len(deps) != 4 {
				t.Fatal("incomplete graph", ptr, len(deps))
			}
		}
		if services < 1 || services >= 40 || services != subtypes {
			t.Fatal("partial service", services, subtypes)
		}
	}
	acceptedFrame(t, links, groups, now.Mono)
}

func TestSharedTypeAdmissionHasStableSource(t *testing.T) {
	now := time.Now()
	records := []catalog.Record{
		{ID: "one", Source: "lan-b", Name: catalog.Enumeration, Type: "PTR", Data: "_test._udp.local.", Expires: now.Add(20 * time.Second)},
		{ID: "two", Source: "lan-a", Name: catalog.Enumeration, Type: "PTR", Data: "_test._udp.local.", Expires: now.Add(20 * time.Second)},
	}
	for range 32 {
		slices.Reverse(records)
		view := podView(records, now)
		if len(view) != 1 || view[0].Source != "lan-a" {
			t.Fatal("unstable shared enumeration", view)
		}
	}
}
