// Package translation samples existing immutable TAYGA instances without
// allocating mappings, changing routes or controlling services.
package translation

import (
	"errors"
	"net/netip"
	"slices"
	"strings"

	"github.com/lanrith/discovery-bridge/internal/catalog"
	"github.com/lanrith/discovery-bridge/internal/config"
	"github.com/lanrith/discovery-bridge/internal/policy"
)

func parseConfig(data []byte, profile config.Translator, spaces catalog.Translation, nat46 bool) (map[netip.Addr]netip.Addr, error) {
	if len(data) == 0 || len(data) > 65536 {
		return nil, errors.New("translator configuration size")
	}
	for _, b := range data {
		if b >= 128 || b == 0 {
			return nil, errors.New("translator configuration must be ASCII")
		}
	}
	expected := map[string]string{
		"tun-device": profile.Interface, "ipv4-addr": profile.IPv4,
		"ipv6-addr": profile.IPv6, "prefix": profile.Prefix, "data-dir": profile.DataDirectory,
	}
	if !nat46 {
		expected["dynamic-pool"], expected["udp-cksum-mode"] = profile.DynamicPool, "calc"
	}
	seen := make(map[string]bool)
	maps, aliases := make(map[netip.Addr]netip.Addr), make(map[netip.Addr]bool)
	pool := spaces.Pool.String()
	reserved := spaces.Reserved
	if !nat46 {
		pool = profile.DynamicPool
		reserved = []netip.Addr{netip.MustParseAddr(profile.IPv4)} // New validates the immutable profile.
	}
	aliasPolicy, err := policy.New(map[string][]string{"alias": {pool}}, nil)
	if err != nil {
		return nil, err
	}
	prefix := netip.MustParsePrefix(profile.Prefix) // New validates operator settings.
	for line := range strings.SplitSeq(string(data), "\n") {
		line, _, _ = strings.Cut(line, "#")
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if len(fields) == 3 && fields[0] == "map" {
			alias, err4 := netip.ParseAddr(fields[1])
			target, err6 := netip.ParseAddr(fields[2])
			if err4 != nil || err6 != nil || aliasPolicy.CheckAddress("alias", alias) != nil || slices.Contains(reserved, alias) || !target.Is6() || target.Is4In6() || target.Zone() != "" || !target.IsGlobalUnicast() || target.IsLinkLocalUnicast() || prefix.Contains(target) || spaces.NAT64.Contains(target) || aliases[alias] || maps[target].IsValid() || len(maps) >= catalog.MaxRecords {
				return nil, errors.New("invalid or duplicate static translator map")
			}
			maps[target], aliases[alias] = alias, true
			continue
		}
		if len(fields) != 2 || expected[fields[0]] == "" || seen[fields[0]] || expected[fields[0]] != fields[1] {
			return nil, errors.New("unsupported or mismatched translator directive")
		}
		seen[fields[0]] = true
	}
	// Static NAT46 has no allocator state. Accept its absent data-dir while
	// still checking the exact configured path when an older image includes it.
	required := len(expected)
	if nat46 && !seen["data-dir"] {
		required--
	}
	if len(seen) != required || nat46 && len(maps) == 0 {
		return nil, errors.New("incomplete immutable translator profile")
	}
	return maps, nil
}
