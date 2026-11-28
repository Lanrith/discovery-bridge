package avahi

import (
	"github.com/godbus/dbus/v5"
	"github.com/lanrith/discovery-bridge/internal/catalog"
	"testing"
)

func TestObjectBudgetRetainsIndependentGraphsAndSharedAddress(t *testing.T) {
	scope := groupKey{2, 4}
	a, b, c := ownerKey{scope, instance, "a"}, ownerKey{scope, instance, "b"}, ownerKey{scope, instance, "c"}
	x, y := ownerKey{scope, host, "x"}, ownerKey{scope, host, "y"}
	p := Publisher{desired: map[ownerKey]*registration{x: {}, y: {}, a: {dependencies: []ownerKey{x}}, b: {dependencies: []ownerKey{x}}, c: {dependencies: []ownerKey{y}}},
		groups: map[ownerKey]group{c: {state: Established}, y: {state: Established}}, faults: map[ownerKey]groupFault{}}
	selected := p.selectGraphs(3)
	if len(selected) > 3 || !selected[c] || !selected[y] || selected[a] || selected[b] {
		t.Fatal("budget displaced a live pair or split a new pair", selected)
	}
	p.faults[c] = groupFault{state: Collision}
	selected = p.selectGraphs(3)
	if len(selected) != 3 || !selected[a] || !selected[b] || !selected[x] {
		t.Fatal("colliding name reserved another service's capacity", selected)
	}
}

func TestPublisherClassifiesRegistrationErrorsAndBoundsQuotaRetry(t *testing.T) {
	key := ownerKey{groupKey{2, 4}, host, "original.local."}
	for _, test := range []struct {
		name   string
		unique bool
		state  byte
	}{
		{service + ".CollisionError", true, Collision}, {service + ".CollisionError", false, Failed},
		{service + ".TooManyObjectsError", false, Failed}, {busInterface + ".Error.Failed", true, Failed},
	} {
		p := Publisher{faults: make(map[ownerKey]groupFault), updates: make(chan struct{}, 1)}
		if err := p.registrationError(key, dbus.Error{Name: test.name}, test.unique); err != nil {
			t.Fatal(err)
		}
		if p.faults[key].state != test.state || p.faults[key].retry <= catalog.Now().Mono {
			t.Fatal(test, p.faults[key])
		}
		if (test.name == service+".TooManyObjectsError") != (p.nextAllocation > catalog.Now().Mono) {
			t.Fatal("incorrect client quota backoff", test)
		}
	}
	p := Publisher{}
	if err := p.registrationError(key, dbus.Error{Name: busInterface + ".Error.NoReply"}, false); err == nil {
		t.Fatal("unknown ownership after timeout treated as local failure")
	}
}
