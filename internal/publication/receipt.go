package publication

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/lanrith/discovery-bridge/internal/avahi"
	"github.com/lanrith/discovery-bridge/internal/observation"
)

const hello = "RECEIPTS/1 "

// Receipt is a read-only observation of an admitted snapshot. The state string
// contains one byte per graph in avahi.ReceiptOwners order.
type Receipt struct {
	Until     time.Duration `json:"until_ns"`
	Sequence  int64         `json:"sequence"`
	Collector string        `json:"collector"`
	Publisher string        `json:"publisher"`
	States    string        `json:"states"`
}

func token(value string) bool {
	raw, err := hex.DecodeString(value)
	return err == nil && len(raw) == 16
}

func publisherGeneration(links map[int]observation.Link) string {
	h := sha256.New()
	for _, index := range slices.Sorted(maps.Keys(links)) {
		_, _ = fmt.Fprintf(h, "%d/%q\n", index, links[index].Generation)
	}
	return hex.EncodeToString(h.Sum(nil)[:16])
}

func (r Receipt) validate(c *Client, intents []avahi.Intent, now time.Duration) ([]string, error) {
	if r.Sequence != c.sequence || r.Collector != c.collector || r.Publisher != c.publisher {
		return nil, errors.New("publication receipt belongs to another submission or generation")
	}
	if (r.States != "" && now >= r.Until) || (r.States == "" && r.Until != 0) {
		return nil, errors.New("publication receipt outside supervised lease")
	}
	for _, intent := range intents {
		if now >= intent.Deadline || (len(intent.Records) > 0 && r.Until > intent.Deadline+time.Microsecond) {
			return nil, errors.New("publication receipt arrived after lease expiry")
		}
	}
	names := avahi.ReceiptOwners(intents)
	if len(names) != len(r.States) {
		return nil, errors.New("publication receipt graph count mismatch")
	}
	conflicts := make(map[string]bool)
	for i := range len(r.States) {
		switch r.States[i] {
		case avahi.Established, avahi.Pending, avahi.Failed:
		case avahi.Collision:
			if names[i] == "" {
				return nil, errors.New("shared record cannot claim name collision")
			}
			conflicts[names[i]] = true
		default:
			return nil, errors.New("unknown publication outcome")
		}
	}
	return slices.Sorted(maps.Keys(conflicts)), nil
}

// Counts returns only bounded aggregate outcomes suitable for the collector log.
func (r Receipt) Counts() [4]int {
	return [4]int{strings.Count(r.States, "E"), strings.Count(r.States, "P"), strings.Count(r.States, "F"), strings.Count(r.States, "C")}
}
