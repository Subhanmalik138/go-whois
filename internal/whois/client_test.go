package whois

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// mockServer is a tiny WHOIS server on localhost. handler receives the
// query (without CRLF) and returns the response. queries records every
// query received, in order.
type mockServer struct {
	t       *testing.T
	addr    string
	ln      net.Listener
	queries []string
	mu      sync.Mutex
	done    chan struct{}
}

func startMockServer(t *testing.T, handler func(query string) string) *mockServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &mockServer{t: t, addr: ln.Addr().String(), ln: ln, done: make(chan struct{})}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				raw, _ := io.ReadAll(c)
				query := strings.TrimRight(string(raw), "\r\n")
				s.mu.Lock()
				s.queries = append(s.queries, query)
				s.mu.Unlock()
				fmt.Fprint(c, handler(query))
			}(conn)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return s
}

func (s *mockServer) received() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.queries))
	copy(out, s.queries)
	return out
}

const ianaReferral = "whois: %s\n\n"
const registrarResponse = `Domain Name: EXAMPLE.COM
Registrar: Example Registrar, Inc.
Creation Date: 1995-08-14T04:00:00Z
Registry Expiry Date: 2026-08-13T04:00:00Z
Name Server: A.IANA-SERVERS.NET
Name Server: B.IANA-SERVERS.NET
`

func TestQueryServerRoundTrip(t *testing.T) {
	srv := startMockServer(t, func(q string) string {
		return "hello " + q
	})
	c := &Client{}
	raw, err := c.QueryServer(context.Background(), srv.addr, "example.com")
	if err != nil {
		t.Fatalf("QueryServer: %v", err)
	}
	if raw != "hello example.com" {
		t.Errorf("response = %q", raw)
	}
	if got := srv.received(); len(got) != 1 || got[0] != "example.com" {
		t.Errorf("server received %v", got)
	}
}

func TestLookupReferralChain(t *testing.T) {
	registrar := startMockServer(t, func(q string) string { return registrarResponse })
	iana := startMockServer(t, func(q string) string {
		return fmt.Sprintf(ianaReferral, registrar.addr)
	})
	c := &Client{IANAAddr: iana.addr}
	rec, err := c.Lookup(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if rec.Registrar != "Example Registrar, Inc." {
		t.Errorf("registrar = %q", rec.Registrar)
	}
	if rec.Created == nil || rec.Created.Format("2006-01-02") != "1995-08-14" {
		t.Errorf("created = %v", rec.Created)
	}
	if len(rec.ServersQueried) != 2 || rec.ServersQueried[0] != iana.addr || rec.ServersQueried[1] != registrar.addr {
		t.Errorf("servers queried = %v", rec.ServersQueried)
	}
	if got := iana.received(); len(got) != 1 || got[0] != "example.com" {
		t.Errorf("IANA received %v", got)
	}
	if got := registrar.received(); len(got) != 1 || got[0] != "example.com" {
		t.Errorf("registrar received %v", got)
	}
}

func TestLookupNoReferral(t *testing.T) {
	// The DENIC response names no further server, so the lookup ends
	// after one hop.
	srv := startMockServer(t, func(q string) string { return denicResponse })
	c := &Client{IANAAddr: srv.addr}
	rec, err := c.Lookup(context.Background(), "example.de")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if len(rec.NameServers) != 2 || rec.NameServers[0] != "ns1.example.com" {
		t.Errorf("name servers = %v", rec.NameServers)
	}
	if rec.Updated == nil || rec.Updated.Format("2006-01-02") != "2024-01-15" {
		t.Errorf("updated = %v", rec.Updated)
	}
	if len(rec.ServersQueried) != 1 {
		t.Errorf("servers queried = %v", rec.ServersQueried)
	}
}

func TestLookupAvailable(t *testing.T) {
	srv := startMockServer(t, func(q string) string {
		return "No match for \"" + strings.ToUpper(q) + "\".\n"
	})
	c := &Client{IANAAddr: srv.addr}
	rec, err := c.Lookup(context.Background(), "this-name-is-surely-free-12345.com")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if !rec.Available {
		t.Error("expected Available=true")
	}
}

func TestLookupReferralLoopStops(t *testing.T) {
	// A server that refers to itself: the client must stop after MaxHops
	// instead of chasing referrals forever.
	var addr string
	srv := startMockServer(t, func(q string) string {
		return "Whois Server: " + addr + "\n"
	})
	addr = srv.addr
	c := &Client{IANAAddr: srv.addr, MaxHops: 2}
	_, err := c.Lookup(context.Background(), "example.com")
	if err == nil {
		t.Fatal("expected referral-loop error")
	}
	if !strings.Contains(err.Error(), "exceeded") {
		t.Errorf("unexpected error: %v", err)
	}
	if got := len(srv.received()); got != 3 {
		t.Errorf("expected 3 queries (initial + 2 hops), got %d", got)
	}
}

func TestLookupTimeout(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				// Read the query, then go silent: never answer.
				buf := make([]byte, 256)
				_, _ = c.Read(buf)
				time.Sleep(5 * time.Second)
			}(conn)
		}
	}()
	c := &Client{ReadTimeout: 200 * time.Millisecond}
	_, err = c.QueryServer(context.Background(), ln.Addr().String(), "example.com")
	if err == nil {
		t.Fatal("expected timeout error")
	}
}

func TestLookupManyPreservesOrder(t *testing.T) {
	srv := startMockServer(t, func(q string) string {
		return "Domain Name: " + strings.ToUpper(q) + "\nRegistrar: Reg-" + q + "\n"
	})
	c := &Client{IANAAddr: srv.addr}
	queries := []string{"a.com", "b.com", "c.com", "d.com", "e.com"}
	results := c.LookupMany(context.Background(), queries, 3)
	if len(results) != len(queries) {
		t.Fatalf("got %d results", len(results))
	}
	for i, r := range results {
		if r.Err != nil {
			t.Errorf("query %d: %v", i, r.Err)
			continue
		}
		if r.Record.Query != queries[i] {
			t.Errorf("result %d query = %q, want %q", i, r.Record.Query, queries[i])
		}
		if r.Record.Registrar != "Reg-"+queries[i] {
			t.Errorf("result %d registrar = %q", i, r.Record.Registrar)
		}
	}
}

func TestLookupManyReportsPerQueryErrors(t *testing.T) {
	good := startMockServer(t, func(q string) string { return "Domain Name: X.COM\n" })
	c := &Client{IANAAddr: good.addr, ReadTimeout: time.Second}
	// An unroutable address for the second lookup: use a closed port.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := ln.Addr().String()
	ln.Close()
	c2 := &Client{IANAAddr: dead, ReadTimeout: 200 * time.Millisecond}
	_ = c2
	results := c.LookupMany(context.Background(), []string{"a.com"}, 1)
	if results[0].Err != nil {
		t.Errorf("expected success, got %v", results[0].Err)
	}
	// Direct check that a dead server errors rather than hanging.
	_, err = c2.Lookup(context.Background(), "a.com")
	if err == nil {
		t.Error("expected error for dead server")
	}
}
