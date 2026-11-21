// Command whois looks up domain and IP WHOIS records from the command
// line, following referrals from IANA to the responsible registry and
// registrar.
//
// Usage:
//
//	whois example.com                    # human-readable record
//	whois -json example.com              # machine-readable record
//	whois -raw example.com               # raw final server response
//	whois -server whois.verisign-grs.com example.com
//	whois -file domains.txt -c 5         # bulk lookup, 5 concurrent
//
// Exit status is 0 when every lookup completed (even for available
// domains), 1 on a usage error or a lookup failure.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Subhanmalik138/go-whois/internal/whois"
)

func main() {
	server := flag.String("server", "", "query a single WHOIS server directly, skipping referrals")
	timeout := flag.Duration("timeout", 10*time.Second, "per-query timeout")
	jsonOut := flag.Bool("json", false, "print records as JSON")
	rawOut := flag.Bool("raw", false, "print the raw final server response instead of the parsed record")
	file := flag.String("file", "", "file with one domain or IP per line to look up")
	workers := flag.Int("c", 5, "concurrent lookups for -file or multiple domains")
	noReferral := flag.Bool("no-referral", false, "query only the IANA bootstrap server, do not follow referrals")
	flag.Parse()

	queries := flag.Args()
	if *file != "" {
		domains, err := readLines(*file)
		if err != nil {
			fatal(err)
		}
		queries = append(queries, domains...)
	}
	if len(queries) == 0 {
		fmt.Fprintln(os.Stderr, "usage: whois [flags] <domain|IP> ...")
		flag.PrintDefaults()
		os.Exit(1)
	}

	client := &whois.Client{ReadTimeout: *timeout, DialTimeout: *timeout}
	if *noReferral {
		client.MaxHops = 0
	}

	ctx := context.Background()
	failed := false

	if *server != "" {
		// Single-server mode: one raw query per domain, no referrals.
		for _, q := range queries {
			if err := runSingleServer(ctx, client, *server, q, *jsonOut, *rawOut); err != nil {
				fmt.Fprintln(os.Stderr, "error:", err)
				failed = true
			}
		}
	} else if len(queries) == 1 {
		rec, err := client.Lookup(ctx, queries[0])
		if err != nil {
			fatal(err)
		}
		printRecord(rec, *jsonOut, *rawOut)
	} else {
		results := client.LookupMany(ctx, queries, *workers)
		for i, r := range results {
			if r.Err != nil {
				fmt.Fprintf(os.Stderr, "%s: error: %v\n", queries[i], r.Err)
				failed = true
				continue
			}
			printRecord(r.Record, *jsonOut, *rawOut)
			if i < len(results)-1 {
				fmt.Println()
			}
		}
	}

	if failed {
		os.Exit(1)
	}
}

func runSingleServer(ctx context.Context, client *whois.Client, server, query string, jsonOut, rawOut bool) error {
	raw, err := client.QueryServer(ctx, server, query)
	if err != nil {
		return err
	}
	rec := whois.Parse(raw)
	rec.Query = query
	rec.ServersQueried = []string{server}
	rec.Raw = raw
	printRecord(rec, jsonOut, rawOut)
	return nil
}

func printRecord(rec *whois.Record, jsonOut, rawOut bool) {
	if rawOut {
		fmt.Println(rec.Raw)
		return
	}
	if jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(rec)
		return
	}
	printText(rec)
}

func printText(rec *whois.Record) {
	fmt.Println(rec.Query)
	if rec.Available {
		fmt.Println("  Available: yes — no WHOIS record found")
		return
	}
	fmt.Println("  Available: no")
	if rec.Registrar != "" {
		fmt.Printf("  Registrar:   %s\n", rec.Registrar)
	}
	if rec.Created != nil {
		fmt.Printf("  Created:     %s\n", rec.Created.Format("2006-01-02"))
	}
	if rec.Updated != nil {
		fmt.Printf("  Updated:     %s\n", rec.Updated.Format("2006-01-02"))
	}
	if rec.Expires != nil {
		fmt.Printf("  Expires:     %s\n", rec.Expires.Format("2006-01-02"))
	}
	if len(rec.Status) > 0 {
		fmt.Printf("  Status:      %s\n", strings.Join(rec.Status, ", "))
	}
	if len(rec.NameServers) > 0 {
		fmt.Printf("  Name servers: %s\n", strings.Join(rec.NameServers, ", "))
	}
	if rec.RegistrantOrg != "" {
		fmt.Printf("  Registrant:  %s\n", rec.RegistrantOrg)
	}
	if rec.NetRange != "" {
		fmt.Printf("  Net range:   %s\n", rec.NetRange)
	}
	if rec.Country != "" {
		fmt.Printf("  Country:     %s\n", rec.Country)
	}
	if len(rec.ServersQueried) > 0 {
		fmt.Printf("  Queried:     %s\n", strings.Join(rec.ServersQueried, " -> "))
	}
}

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out, sc.Err()
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}
