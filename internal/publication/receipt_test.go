package publication

import (
	"bufio"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lanrith/discovery-bridge/internal/avahi"
	"github.com/lanrith/discovery-bridge/internal/catalog"
)

func TestReceiptsBoundSequenceGenerationsAndLease(t *testing.T) {
	path, owner := startServer(t, uint32(os.Geteuid()))
	c, err := DialGeneration(t.Context(), path, "test-boot", strings.Repeat("a", 32))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	now := catalog.Now().Mono
	intents := []avahi.Intent{{Interface: 2, Family: 4, Records: publicationAnswers(t), Deadline: now + 20*time.Second}}
	owner.mu.Lock()
	owner.outcomes = "ECF"
	owner.until = now + 10*time.Second
	owner.mu.Unlock()
	var conflict *Conflict
	if err := c.Send(t.Context(), intents); !errors.As(err, &conflict) || len(conflict.Names) != 1 || conflict.Names[0] != "alias._example._tcp.local." {
		t.Fatal("misattributed receipt", err, conflict)
	}
	r := c.LastReceipt()
	for _, mutate := range []func(*Receipt){
		func(r *Receipt) { r.Sequence-- }, func(r *Receipt) { r.Collector = strings.Repeat("d", 32) }, func(r *Receipt) { r.Publisher = strings.Repeat("d", 32) }, func(r *Receipt) { r.States = "EEE?" }, func(r *Receipt) { r.States = "EEC" }, func(r *Receipt) { r.States = "EE?" }, func(r *Receipt) { r.Until = now }, func(r *Receipt) { r.Until = now + 21*time.Second },
	} {
		bad := r
		mutate(&bad)
		if _, err := bad.validate(c, intents, now); err == nil {
			t.Fatalf("accepted invalid receipt %#v", bad)
		}
	}
	if _, err := r.validate(c, intents, r.Until); err == nil {
		t.Fatal("delayed receipt renewed a lease")
	}
	owner.mu.Lock()
	owner.outcomes = "PEE"
	owner.mu.Unlock()
	if err := c.Send(t.Context(), intents); err != nil {
		t.Fatal("independent publication session lost", err)
	}
	if _, err := r.validate(c, intents, now); err == nil {
		t.Fatal("previous sequence reused")
	}
}

// This peer follows the v0.1.11 wire contract, including its broad CONFLICT.
func TestReceiptProducerWithLegacyPublisher(t *testing.T) {
	dir, err := os.MkdirTemp("", "pub-v1-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "bus")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	done := make(chan error, 1)
	go func() {
		first, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		_, err = bufio.NewReader(first).ReadString('\n')
		_ = first.Close()
		if err != nil {
			done <- err
			return
		}
		second, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		defer func() { _ = second.Close() }()
		reader := bufio.NewReader(second)
		var sequence int64
		for _, reply := range []string{"OK\n", "OK\n", `CONFLICT ["a.local.","b.local."]` + "\n"} {
			payload, err := frameLine(reader)
			if err != nil {
				done <- err
				return
			}
			sequence, _, err = admissionFixture().Decode(payload, catalog.Now().Mono, sequence)
			if err != nil {
				done <- err
				return
			}
			if _, err = second.Write([]byte(reply)); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	c, err := DialGeneration(context.Background(), path, "test-boot", strings.Repeat("b", 32))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if err := c.Send(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	var conflict *Conflict
	if err := c.Send(t.Context(), nil); err == nil || errors.As(err, &conflict) {
		t.Fatal("legacy group conflict mutated identity")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestLegacyProducerPartialResultClosesWithoutIdentityMutation(t *testing.T) {
	path, owner := startServer(t, uint32(os.Geteuid()))
	connection, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = connection.Close() }()
	if err := connection.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	now := catalog.Now().Mono
	owner.mu.Lock()
	owner.outcomes = "ECE"
	owner.until = now + 10*time.Second
	owner.mu.Unlock()
	payload, err := Frame("test-boot", 1, now, []avahi.Intent{{Interface: 2, Family: 4, Deadline: now + 20*time.Second, Records: publicationAnswers(t)}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Write(payload); err != nil {
		t.Fatal(err)
	}
	if reply, err := bufio.NewReader(connection).ReadString('\n'); err == nil || reply != "" {
		t.Fatal("partial publication acknowledged or rotated identity on legacy peer", reply, err)
	}
}
