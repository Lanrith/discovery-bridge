package router

import (
	"cmp"
	"maps"
	"math"
	"slices"
	"strings"
	"time"

	"github.com/lanrith/discovery-bridge/internal/avahi"
	"github.com/lanrith/discovery-bridge/internal/catalog"
	"github.com/lanrith/discovery-bridge/internal/observation"
	"github.com/lanrith/discovery-bridge/internal/publication"
	"github.com/miekg/dns"
)

type publicationCounts struct {
	admitted                        map[string]bool
	deferredGraphs, deferredRecords int
}

type serviceGraph struct {
	key      string
	source   string
	original bool
	parts    [][]int // Encoded records, shared host RRsets, and shared type enumeration.
}

// publicationGraphs operates on the already validated, owned alias view. All
// PTRs (including subtypes) for an instance depend on its full SRV/TXT/address set.
func publicationGraphs(aliases, originals []catalog.Answer) []serviceGraph {
	hosts, services := map[string][]int{}, map[string][]int{}
	hostFor, typeFor := map[string]string{}, map[string]string{}
	enumerations := map[string]int{}
	for i, answer := range aliases {
		name := catalog.NameKey(answer.RR.Header().Name)
		switch rr := answer.RR.(type) {
		case *dns.A, *dns.AAAA:
			hosts[name] = append(hosts[name], i)
		case *dns.SRV:
			services[name] = append(services[name], i)
			hostFor[name] = catalog.NameKey(rr.Target)
			suffix, _ := dns.NextLabel(name, 0)
			typeFor[name] = name[suffix:]
		case *dns.TXT:
			services[name] = append(services[name], i)
		case *dns.PTR:
			target := catalog.NameKey(rr.Ptr)
			if name == catalog.Enumeration {
				enumerations[target] = i
			} else {
				services[target] = append(services[target], i)
			}
		}
	}
	var graphs []serviceGraph
	usedHosts, usedTypes := map[string]bool{}, map[string]bool{}
	for name, service := range services {
		host, typ := hostFor[name], typeFor[name]
		g := serviceGraph{key: "service/" + name, source: aliases[service[0]].Source,
			parts: [][]int{service, hosts[host]}}
		usedHosts[host] = true
		if i, ok := enumerations[typ]; ok {
			g.parts = append(g.parts, []int{i})
			usedTypes[typ] = true
		}
		graphs = append(graphs, g)
	}
	for name, records := range hosts {
		if !usedHosts[name] {
			graphs = append(graphs, serviceGraph{key: "host/" + name, source: aliases[records[0]].Source, parts: [][]int{records}})
		}
	}
	for typ, i := range enumerations {
		if !usedTypes[typ] {
			graphs = append(graphs, serviceGraph{key: "type/" + typ, source: aliases[i].Source, parts: [][]int{{i}}})
		}
	}
	originalSets := map[string][]int{}
	for i, answer := range originals {
		key := answer.Source + "\x00" + catalog.NameKey(answer.RR.Header().Name)
		originalSets[key] = append(originalSets[key], len(aliases)+i)
	}
	for key, records := range originalSets {
		graphs = append(graphs, serviceGraph{key: "original/" + key, source: originals[records[0]-len(aliases)].Source,
			original: true, parts: [][]int{records}})
	}
	return graphs
}

func admitPublication(aliases, originals []catalog.Answer, links map[int]observation.Link, now time.Duration,
	previous map[string]bool, optionalSource string) ([]avahi.Intent, publicationCounts, error) {
	counts := publicationCounts{admitted: map[string]bool{}}
	answers := slices.Concat(aliases, originals)
	var intents []avahi.Intent
	for _, i := range slices.Sorted(maps.Keys(links)) {
		for _, family := range slices.Sorted(slices.Values(links[i].Families)) {
			intents = append(intents, avahi.Intent{Interface: i, Family: family})
		}
	}
	// Reserve the maximum sequence width, UUID, and a full JSON float for
	// every monotonic stamp, including the send-time issued field.
	envelope, err := publication.Frame(strings.Repeat("0", 36), math.MaxInt64-1, 0, intents)
	if err != nil {
		return nil, counts, err
	}
	bytesLeft := publication.MaxFrame - len(envelope) - 23*(1+len(intents))
	slotsLeft := catalog.MaxRecords
	sizes := make([]int, len(answers))
	for i, answer := range answers {
		sizes[i], err = publication.RecordBytes(answer)
		if err != nil {
			return nil, counts, err
		}
	}
	graphs := publicationGraphs(aliases, originals)
	priority := func(g serviceGraph) int {
		n := 0
		if g.original {
			n += 4
		}
		if g.source == optionalSource {
			n += 2
		}
		if !previous[g.key] {
			n++
		}
		return n
	}
	slices.SortFunc(graphs, func(a, b serviceGraph) int {
		if n := cmp.Compare(priority(a), priority(b)); n != 0 {
			return n
		}
		return strings.Compare(a.key, b.key)
	})
	onLinks := make(map[string]int)
	for _, target := range intents {
		onLinks[links[target.Interface].Source]++
	}
	admitted := make([]bool, len(answers))
	for _, g := range graphs {
		fanout := len(intents)
		if g.original {
			fanout -= onLinks[g.source]
		}
		if fanout == 0 {
			continue
		}
		var slots, bytes int
		for _, part := range g.parts {
			for _, i := range part {
				if !admitted[i] {
					slots++
					bytes += sizes[i]
				}
			}
		}
		slots, bytes = slots*fanout, bytes*fanout
		if slots > slotsLeft || bytes > bytesLeft {
			counts.deferredGraphs++
			continue
		}
		slotsLeft -= slots
		bytesLeft -= bytes
		for _, part := range g.parts {
			for _, i := range part {
				admitted[i] = true
			}
		}
		counts.admitted[g.key] = true
	}
	for j := range intents {
		target := &intents[j]
		ttl := uint32(catalog.MaxTTL)
		for i, answer := range answers {
			if i >= len(aliases) && answer.Source == links[target.Interface].Source {
				continue
			}
			if !admitted[i] {
				counts.deferredRecords++
				continue
			}
			target.Records = append(target.Records, answer)
			ttl = min(ttl, answer.RR.Header().Ttl)
		}
		target.Deadline = now + time.Duration(ttl)*time.Second
	}
	return slices.DeleteFunc(intents, func(i avahi.Intent) bool { return len(i.Records) == 0 }), counts, nil
}
