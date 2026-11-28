package publication

import (
	"bufio"
	"context"
	"errors"
	"io"
	"math"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/lanrith/discovery-bridge/internal/avahi"
	"github.com/lanrith/discovery-bridge/internal/catalog"
	"github.com/lanrith/discovery-bridge/internal/jsonwire"
)

// Conflict reports unique names that the collector must resolve before retrying.
type Conflict struct{ Names []string }

func (c *Conflict) Error() string { return "Avahi publication conflict" }

// Client owns one local publication producer session and strictly increasing sequence.
type Client struct {
	mu                   sync.Mutex
	connection           net.Conn
	reader               *bufio.Reader
	boot                 string
	sequence             int64
	collector, publisher string
	last                 Receipt
}

// Dial opens only an explicit absolute Unix socket; no TCP transport is accepted.
func Dial(ctx context.Context, path, boot string) (*Client, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) > 107 || boot == "" {
		return nil, errors.New("local publisher path and boot identity required")
	}
	bounded, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	connection, err := (&net.Dialer{}).DialContext(bounded, "unix", path)
	if err != nil {
		return nil, err
	}
	return &Client{connection: connection, reader: bufio.NewReaderSize(connection, 64*1024), boot: boot}, nil
}

// DialGeneration negotiates receipts before sending any publication. A pinned
// pre-receipt publisher rejects the greeting and closes without applying it.
func DialGeneration(ctx context.Context, path, boot, generation string) (*Client, error) {
	if !token(generation) {
		return nil, errors.New("invalid collector topology generation")
	}
	c, err := Dial(ctx, path, boot)
	if err != nil {
		return nil, err
	}
	bounded, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	until, _ := bounded.Deadline()
	if err = c.connection.SetDeadline(until); err == nil {
		_, err = io.WriteString(c.connection, hello+generation+"\n")
	}
	var line []byte
	if err == nil {
		line, err = frameLine(c.reader)
	}
	if err == nil {
		fields := strings.Fields(string(line))
		if len(fields) == 3 && fields[0] == "RECEIPTS/1" && fields[1] == generation && token(fields[2]) {
			c.collector, c.publisher = generation, fields[2]
			return c, nil
		}
		err = errors.New("invalid publisher receipt greeting")
	}
	_ = c.Close()
	if !errors.Is(err, io.EOF) && !errors.Is(err, syscall.ECONNRESET) {
		return nil, err
	}
	// Authenticate legacy behavior with an empty harmless frame. The old
	// handler can still be finishing cleanup as it closes the first socket.
	for bounded.Err() == nil {
		legacy, dialErr := Dial(bounded, path, boot)
		if dialErr != nil {
			return nil, dialErr
		}
		if err = legacy.Send(bounded, nil); err == nil {
			return legacy, nil
		}
		_ = legacy.Close()
		select {
		case <-bounded.Done():
			return nil, bounded.Err()
		case <-time.After(25 * time.Millisecond):
		}
	}
	return nil, bounded.Err()
}

// LastReceipt returns the validated receipt for the most recent submission.
func (c *Client) LastReceipt() Receipt {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.last
}

// Send transfers a complete snapshot and waits at most three seconds for admission.
func (c *Client) Send(ctx context.Context, intents []avahi.Intent) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if c.sequence >= math.MaxInt64-1 {
		return errors.New("publication sequence exhausted")
	}
	deadline := time.Now().Add(3 * time.Second)
	if until, ok := ctx.Deadline(); ok && until.Before(deadline) {
		deadline = until
	}
	if err := c.connection.SetDeadline(deadline); err != nil {
		return err
	}
	stop := context.AfterFunc(ctx, func() { _ = c.connection.Close() })
	defer stop()
	c.sequence++
	payload, err := Frame(c.boot, c.sequence, catalog.Now().Mono, intents)
	if err != nil {
		return err
	}
	if n, err := c.connection.Write(payload); err != nil || n != len(payload) {
		return errors.Join(err, io.ErrShortWrite)
	}
	reply, err := frameLine(c.reader)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if c.publisher == "" {
		if string(reply) == "OK\n" {
			return nil
		}
		// Earlier group-wide CONFLICT lists cannot attribute a name. Reconnect
		// for fresh evidence without changing any persistent reservations.
		return errors.New("legacy publisher rejected snapshot")
	}
	var receipt Receipt
	if err := jsonwire.Decode(reply, MaxFrame, &receipt); err != nil {
		return err
	}
	names, err := receipt.validate(c, intents, catalog.Now().Mono)
	if err != nil {
		return err
	}
	c.last = receipt
	if len(names) > 0 {
		return &Conflict{Names: names}
	}
	return nil
}

// Close releases the producer; the independent owner withdraws its publications.
func (c *Client) Close() error { return c.connection.Close() }
