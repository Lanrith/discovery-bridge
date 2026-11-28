package router

import (
	"context"
	"encoding/json"
	"math"
	"slices"
	"strings"
	"time"

	"github.com/lanrith/discovery-bridge/internal/avahi"
	"github.com/lanrith/discovery-bridge/internal/catalog"
	"github.com/lanrith/discovery-bridge/internal/observation"
	"github.com/miekg/dns"
)

// views accounts for feed and multicast capacity independently.
func (c *collector) views(ctx context.Context, native []catalog.Record, links map[int]observation.Link, now catalog.Moment) ([]catalog.Record, []avahi.Intent, error) {
	records := native
	optionalSource := ""
	if optional := c.services.Records(now); len(optional) > 0 && len(native)+len(optional) <= catalog.MaxRecords {
		combined := append(slices.Clone(native), optional...)
		rendered := c.translator.Render(combined, now)
		value := catalog.Snapshot{Schema: 2, Epoch: strings.Repeat("0", 32), Revision: math.MaxInt64,
			Issued: now.Wall, Until: now.Wall.Add(catalog.Lease), Records: rendered}
		data, err := json.Marshal(value)
		if err != nil {
			return nil, nil, err
		}
		if len(rendered) <= catalog.MaxRecords && len(data) <= catalog.MaxBytes {
			records, optionalSource = combined, optional[0].Source
		}
	}
	groups, err := c.lanGroups(ctx, c.translator.Render(records, now), links, now, optionalSource)
	return records, groups, err
}

// podView preserves coherent original names as shared answers. The bridge has
// not probed ownership inside the pod and never advertises the pod itself.
func podView(records []catalog.Record, now time.Time) []catalog.Answer {
	authority := catalog.Authority{IDs: make(map[string]bool)}
	values := make([]catalog.TimedRecord, 0, len(records))
	for _, record := range records {
		if ttl := min(record.Expires.Sub(now)/time.Second, catalog.MaxTTL); ttl > 0 {
			authority.IDs[record.ID] = true
			values = append(values, catalog.TimedRecord{Record: record, TTL: uint32(ttl)})
		}
	}
	return catalog.ResponseView(values, authority)
}

// lanGroups reserves the reconciliation and frame-age budgets before compiling
// dependencies. Original hostnames appear only on links other than their origin.
func (c *collector) lanGroups(ctx context.Context, records []catalog.Record, links map[int]observation.Link, now catalog.Moment, optionalSource string) ([]avahi.Intent, error) {
	live := make([]catalog.Record, 0, len(records))
	for _, record := range records {
		if record.Expires.Sub(now.Wall) >= 5*time.Second {
			live = append(live, record)
		}
	}
	aliases, err := c.identities.Compile(ctx, live, now.Wall)
	if err != nil {
		return nil, err
	}
	var hosts []catalog.Answer
	for _, answer := range podView(live, now.Wall) {
		kind := answer.RR.Header().Rrtype
		if kind != dns.TypeA && kind != dns.TypeAAAA {
			continue
		}
		owned, err := c.identities.OwnsHost(ctx, answer.Source, answer.RR.Header().Name)
		if err != nil {
			return nil, err
		}
		if owned {
			answer.Unique = true
			hosts = append(hosts, answer)
		}
	}
	groups, next, err := admitPublication(aliases, hosts, links, now.Mono, c.publication.admitted, optionalSource)
	if err == nil {
		c.publication = next
	}
	return groups, err
}
