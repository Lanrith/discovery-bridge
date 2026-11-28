package state

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/lanrith/discovery-bridge/internal/catalog"
	"github.com/miekg/dns"
)

// OwnsHost distinguishes an observed original hostname from reserved aliases.
func (s *Identities) OwnsHost(ctx context.Context, source, name string) (bool, error) {
	if len(dns.SplitDomainName(name)) != 2 || !catalog.LocalName(dns.Fqdn(name)) {
		return false, nil
	}
	wire, err := canonicalWire(name)
	if err != nil {
		return false, err
	}
	var owned bool
	err = s.db.QueryRowContext(ctx, `SELECT
	 EXISTS(SELECT 1 FROM identities WHERE source=? AND original=?) AND
	 NOT EXISTS(SELECT 1 FROM reservations WHERE name=?)`, source, wire, wire).Scan(&owned)
	return owned, err
}

// RotateAlias reserves a replacement while retaining the retired reservation.
func (s *Identities) RotateAlias(ctx context.Context, alias string) (string, error) {
	source, name, err := s.Original(ctx, alias)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	_, replacement, err := s.Alias(ctx, source, name, true)
	return replacement, err
}

// Compile builds coherent source-scoped aliases without extending source expiry.
func (s *Identities) Compile(ctx context.Context, records []catalog.Record, now time.Time) ([]catalog.Answer, error) {
	if len(records) > catalog.MaxRecords {
		return nil, errors.New("alias record limit")
	}
	aliases := make(map[string]string)
	for _, r := range records {
		if r.Type == "A" || r.Type == "AAAA" || r.Type == "SRV" || r.Type == "TXT" {
			_, alias, err := s.Alias(ctx, r.Source, r.Name, false)
			if err != nil {
				return nil, err
			}
			aliases[r.Source+"\x00"+catalog.NameKey(r.Name)] = alias
		}
	}
	authority := catalog.Authority{IDs: make(map[string]bool), Unique: make(map[catalog.RRSet]bool)}
	values := make([]catalog.TimedRecord, 0, len(records))
	for _, r := range records {
		if ttl := min(r.Expires.Sub(now)/time.Second, catalog.MaxTTL); ttl > 0 {
			rr, err := r.RR(uint32(ttl))
			if err != nil {
				return nil, err
			}
			alias := func(name string) string {
				if replacement, ok := aliases[r.Source+"\x00"+catalog.NameKey(name)]; ok {
					return replacement
				}
				return name
			}
			rr.Header().Name = alias(rr.Header().Name)
			switch value := rr.(type) {
			case *dns.PTR:
				value.Ptr = alias(value.Ptr)
			case *dns.SRV:
				value.Target = alias(value.Target)
			}
			r.Name = rr.Header().Name
			r.Data = strings.TrimPrefix(rr.String(), rr.Header().String())
			authority.IDs[r.ID] = true
			if r.Type != "PTR" {
				authority.Unique[(catalog.Answer{RR: rr}).Set()] = true
			}
			values = append(values, catalog.TimedRecord{Record: r, TTL: uint32(ttl)})
		}
	}
	return catalog.ResponseView(values, authority), nil
}
