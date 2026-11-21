package whois

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

// DefaultIANAAddr is the bootstrap WHOIS server. Every lookup starts here;
// IANA answers with the server responsible for the queried TLD or IP block.
const DefaultIANAAddr = "whois.iana.org:43"

// DefaultMaxHops caps referral chasing so a referral loop (or a server
// that keeps bouncing between two registries) terminates.
const DefaultMaxHops = 5

// Client performs WHOIS lookups. The zero value is usable: timeouts and
// the bootstrap server fall back to their defaults.
type Client struct {
	// DialTimeout bounds establishing a TCP connection. Default 5s.
	DialTimeout time.Duration
	// ReadTimeout bounds a whole query once connected. Default 10s.
	ReadTimeout time.Duration
	// MaxHops caps referral chasing. Default 5.
	MaxHops int
	// IANAAddr is the bootstrap server, host:port. Default whois.iana.org:43.
	IANAAddr string
	// Dial, when set, replaces the default dialer. Tests use it to point
	// the client at local mock servers; production code leaves it nil.
	Dial func(ctx context.Context, network, address string) (net.Conn, error)
}

func (c *Client) dialTimeout() time.Duration {
	if c.DialTimeout > 0 {
		return c.DialTimeout
	}
	return 5 * time.Second
}

func (c *Client) readTimeout() time.Duration {
	if c.ReadTimeout > 0 {
		return c.ReadTimeout
	}
	return 10 * time.Second
}

func (c *Client) maxHops() int {
	if c.MaxHops > 0 {
		return c.MaxHops
	}
	return DefaultMaxHops
}

func (c *Client) ianaAddr() string {
	if c.IANAAddr != "" {
		return c.IANAAddr
	}
	return DefaultIANAAddr
}

func (c *Client) dial(ctx context.Context, address string) (net.Conn, error) {
	if c.Dial != nil {
		return c.Dial(ctx, "tcp", address)
	}
	d := net.Dialer{Timeout: c.dialTimeout()}
	return d.DialContext(ctx, "tcp", address)
}

// QueryServer sends one raw WHOIS query to a single server (host or
// host:port — port 43 is assumed when omitted) and returns the server's
// full response. The query is sent terminated with CRLF, per RFC 3912,
// and the response is read until the server closes the connection.
func (c *Client) QueryServer(ctx context.Context, server, query string) (string, error) {
	addr := server
	if _, _, err := net.SplitHostPort(server); err != nil {
		addr = net.JoinHostPort(server, "43")
	}

	ctx, cancel := context.WithTimeout(ctx, c.readTimeout())
	defer cancel()

	conn, err := c.dial(ctx, addr)
	if err != nil {
		return "", fmt.Errorf("dial %s: %w", addr, err)
	}
	defer conn.Close()

	// The whole query (write + read) must finish before the deadline, so
	// a server that accepts the connection and then goes silent fails
	// fast instead of hanging the lookup.
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	if _, err := fmt.Fprintf(conn, "%s\r\n", query); err != nil {
		return "", fmt.Errorf("write query to %s: %w", addr, err)
	}
	// Half-close the write side: some servers wait for EOF before
	// answering. TCPConn supports it; other conns just skip it.
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
	}

	raw, err := io.ReadAll(conn)
	if err != nil && !errors.Is(err, io.EOF) {
		return "", fmt.Errorf("read response from %s: %w", addr, err)
	}
	return string(raw), nil
}

// Lookup queries a domain or IP address, following referrals from IANA
// down to the responsible registry and registrar. The returned Record
// merges every hop's parsed response, with the deepest hop winning for
// scalar fields and list fields unioned.
func (c *Client) Lookup(ctx context.Context, query string) (*Record, error) {
	query = strings.TrimSpace(query)
	if query == "" {
		return nil, errors.New("whois: empty query")
	}

	merged := &Record{Query: query}
	addr := c.ianaAddr()
	for hop := 0; hop <= c.maxHops(); hop++ {
		raw, err := c.QueryServer(ctx, addr, query)
		if err != nil {
			return nil, err
		}
		merged.ServersQueried = append(merged.ServersQueried, addr)
		merged.Raw = raw
		mergeRecord(merged, Parse(raw))

		if merged.Available {
			return merged, nil
		}
		next := ReferralServer(raw)
		if next == "" {
			return merged, nil
		}
		addr = next
	}
	return nil, fmt.Errorf("whois: referral chain for %q exceeded %d hops", query, c.maxHops())
}

// LookupMany looks up every query concurrently with at most workers
// goroutines and returns the results in the same order as the input, so
// callers can line results up with a domains file. A per-query failure is
// reported in that query's Result, not by aborting the batch.
func (c *Client) LookupMany(ctx context.Context, queries []string, workers int) []*Result {
	if workers < 1 {
		workers = 1
	}
	results := make([]*Result, len(queries))
	jobs := make(chan int)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				rec, err := c.Lookup(ctx, queries[i])
				results[i] = &Result{Record: rec, Err: err}
			}
		}()
	}
	for i := range queries {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	return results
}

// mergeRecord folds src into dst. Scalar fields are overwritten only when
// src has a value (the deeper hop is more authoritative); list fields are
// unioned, keeping first-seen order.
func mergeRecord(dst, src *Record) {
	if src.Available {
		dst.Available = true
	}
	if src.Registrar != "" {
		dst.Registrar = src.Registrar
	}
	if src.WhoisServer != "" {
		dst.WhoisServer = src.WhoisServer
	}
	if src.Created != nil {
		dst.Created = src.Created
	}
	if src.Updated != nil {
		dst.Updated = src.Updated
	}
	if src.Expires != nil {
		dst.Expires = src.Expires
	}
	if src.RegistrantOrg != "" {
		dst.RegistrantOrg = src.RegistrantOrg
	}
	if src.NetRange != "" {
		dst.NetRange = src.NetRange
	}
	if src.Country != "" {
		dst.Country = src.Country
	}
	dst.NameServers = union(dst.NameServers, src.NameServers)
	dst.Status = union(dst.Status, src.Status)
}

func union(a, b []string) []string {
	seen := make(map[string]struct{}, len(a)+len(b))
	out := a[:len(a):len(a)]
	for _, v := range a {
		seen[v] = struct{}{}
	}
	for _, v := range b {
		if _, ok := seen[v]; !ok {
			seen[v] = struct{}{}
			out = append(out, v)
		}
	}
	return out
}
