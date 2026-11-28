package avahi

import (
	"cmp"
	"slices"
	"time"

	"github.com/lanrith/discovery-bridge/internal/catalog"
	"github.com/miekg/dns"
)

// Outcome codes identify independently owned registrations in a receipt.
const (
	Pending     = 'P'
	Established = 'E'
	Failed      = 'F'
	Collision   = 'C'
)

type groupKey struct{ index, family int }

const (
	host = iota
	instance
	enumeration
)

type ownerKey struct {
	groupKey
	kind int
	name string
}

type registration struct {
	records      []catalog.Answer
	signature    []string
	dependencies []ownerKey // A service needs its host; a type needs any live instance.
	deadline     time.Duration
}

func ownerOf(scope groupKey, rr dns.RR) ownerKey {
	name := catalog.NameKey(rr.Header().Name)
	switch rr := rr.(type) {
	case *dns.PTR:
		if name == catalog.Enumeration {
			return ownerKey{scope, enumeration, catalog.NameKey(rr.Ptr)}
		}
		return ownerKey{scope, instance, catalog.NameKey(rr.Ptr)}
	case *dns.SRV, *dns.TXT:
		return ownerKey{scope, instance, name}
	default:
		return ownerKey{scope, host, name}
	}
}

func registrations(intents []Intent) map[ownerKey]*registration {
	result := make(map[ownerKey]*registration)
	for _, intent := range intents {
		scope := groupKey{intent.Interface, intent.Family}
		types := make(map[string][]ownerKey)
		for _, record := range intent.Records {
			key := ownerOf(scope, record.RR)
			graph := result[key]
			if graph == nil {
				graph = &registration{deadline: intent.Deadline}
				result[key] = graph
			}
			graph.records = append(graph.records, record)
			switch rr := record.RR.(type) {
			case *dns.SRV:
				graph.dependencies = []ownerKey{{scope, host, catalog.NameKey(rr.Target)}}
			case *dns.PTR:
				if key.kind == instance {
					name := catalog.NameKey(rr.Hdr.Name)
					types[name] = append(types[name], key)
				}
			}
		}
		for name, instances := range types {
			if graph := result[ownerKey{scope, enumeration, name}]; graph != nil {
				graph.dependencies = instances
			}
		}
	}
	for _, graph := range result {
		graph.signature = signature(graph.records)
	}
	return result
}

func ordered[V any](graphs map[ownerKey]V) []ownerKey {
	keys := make([]ownerKey, 0, len(graphs))
	for key := range graphs {
		keys = append(keys, key)
	}
	slices.SortFunc(keys, func(a, b ownerKey) int {
		return cmp.Or(cmp.Compare(a.index, b.index), cmp.Compare(a.family, b.family), cmp.Compare(a.kind, b.kind), cmp.Compare(a.name, b.name))
	})
	return keys
}

// ReceiptOwners returns canonical unique owners in protocol order. An empty
// name denotes a shared enumeration PTR which cannot rotate an identity.
func ReceiptOwners(intents []Intent) []string {
	owners := make(map[ownerKey]bool)
	for _, intent := range intents {
		for _, record := range intent.Records {
			owners[ownerOf(groupKey{intent.Interface, intent.Family}, record.RR)] = true
		}
	}
	keys := ordered(owners)
	names := make([]string, len(keys))
	for i, key := range keys {
		if key.kind != enumeration {
			names[i] = key.name
		}
	}
	return names
}
