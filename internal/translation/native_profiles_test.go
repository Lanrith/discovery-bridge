package translation

import (
	"strings"
	"testing"
)

func TestNativeTranslatorProfiles(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		text    string
		nat46   bool
		allowed bool
	}{
		{"static NAT46 without allocation state", strings.ReplaceAll(config46, "data-dir /var/lib/translator46\n", ""), true, true},
		{"static NAT46 wrong optional path", strings.ReplaceAll(config46, "/var/lib/translator46", "/var/lib/other"), true, false},
		{"native NAT64 stable source", config64 + "map 203.0.113.200 2001:db8:1::84\n", false, true},
		{"native NAT64 duplicate source", config64 + "map 203.0.113.200 2001:db8:1::84\nmap 203.0.113.201 2001:db8:1::84\n", false, false},
		{"native NAT64 duplicate alias", config64 + "map 203.0.113.200 2001:db8:1::84\nmap 203.0.113.200 2001:db8:1::85\n", false, false},
		{"native NAT64 control alias", config64 + "map 203.0.113.1 2001:db8:1::84\n", false, false},
		{"native NAT64 foreign pool", config64 + "map 198.51.100.200 2001:db8:1::84\n", false, false},
		{"native NAT64 missing state", strings.ReplaceAll(config64, "data-dir /var/lib/translator64\n", ""), false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := fixture(t)
			profile := s.settings.NAT64
			if tc.nat46 {
				profile = s.settings.NAT46
			}
			_, err := parseConfig([]byte(tc.text), *profile, s.spaces, tc.nat46)
			if (err == nil) != tc.allowed {
				t.Fatalf("allowed=%t: %v", tc.allowed, err)
			}
		})
	}
}
