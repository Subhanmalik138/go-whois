# go-whois

A WHOIS client library and CLI in Go. It speaks the WHOIS protocol
(RFC 3912) directly — raw queries over TCP port 43 — follows referrals
from IANA down to the responsible registry and registrar, and parses the
flat key-value responses into a structured record.

```sh
$ whois example.com
example.com
  Available: no
  Registrar:   Example Registrar, Inc.
  Created:     1995-08-14
  Expires:     2026-08-13
  Status:      clientDeleteProhibited, clientTransferProhibited
  Name servers: a.iana-servers.net, b.iana-servers.net
  Queried:     whois.iana.org:43 -> whois.verisign-grs.com:43
```

## Why this exists

Every `whois` you have used shells out to a system binary or leans on a
library that only talks to one hardcoded server. The interesting part of
WHOIS is the referral chain: IANA knows which registry owns a TLD, the
registry knows which registrar owns a name, and only the registrar holds
the full record. This client walks that chain, merges each hop's
response, and hands you one record — plus the chain it followed, so you
can see exactly where each fact came from.

## Design decisions

- **Referral chasing from IANA, not a TLD table.** A hardcoded map of
  TLD → server rots the moment a new TLD launches or a registry moves.
  Asking IANA first always returns the current authority, and the hop
  limit (default 5) bounds referral loops.
- **Merge, don't overwrite.** Each hop's response is parsed and merged
  into one record: the deepest hop wins for scalar fields (dates,
  registrar), list fields (name servers, statuses) are unioned. A
  registry that omits a field the registrar publishes still yields a
  complete record.
- **Tolerant parsing, strict dates.** Registries disagree on field names
  ("Creation Date", "Created On", "Registered on") and date formats
  (RFC 3339, `14-Aug-1999`, `20260813`, ...). The parser normalises
  keys and tries a list of layouts; a date it cannot parse is left
  empty rather than guessed.
- **Standard library only, no network in tests.** Tests run against
  mock WHOIS servers on localhost, including a referral chain,
  a referral loop, a silent server (timeout), and bulk lookups — so
  `go test ./...` works offline and deterministically.

## Install

```sh
go install github.com/Subhanmalik138/go-whois/cmd/whois@latest
```

Requires Go 1.23+.

## Usage

```sh
whois example.com                    # human-readable record
whois -json example.com              # machine-readable record
whois -raw example.com               # raw final server response
whois -server whois.verisign-grs.com example.com   # one server, no referrals
whois -no-referral example.com       # ask IANA only
whois -file domains.txt -c 5         # bulk lookup, 5 concurrent
whois example.com example.org       # several domains, results in order
```

Flags:

| Flag | Default | Meaning |
| ---- | ------- | ------- |
| `-server` | — | Query a single WHOIS server directly, skipping referrals |
| `-timeout` | 10s | Per-query timeout (dial + read) |
| `-json` | false | Print records as indented JSON |
| `-raw` | false | Print the raw final response instead of the parsed record |
| `-file` | — | File with one domain or IP per line (`#` comments skipped) |
| `-c` | 5 | Concurrent lookups for `-file` or multiple domains |
| `-no-referral` | false | Query only the IANA bootstrap server |

Exit status is 0 when every lookup completed (an available domain is a
successful lookup, not an error) and 1 on a usage error or lookup failure.

## Library use

```go
client := &whois.Client{} // sensible defaults: 5s dial, 10s read, 5 hops
rec, err := client.Lookup(ctx, "example.com")
if err != nil { ... }
fmt.Println(rec.Registrar, rec.Expires)

// Bulk, order-preserving, per-query errors in Result.Err:
results := client.LookupMany(ctx, []string{"a.com", "b.com"}, 4)

// One raw query against a known server:
raw, err := client.QueryServer(ctx, "whois.verisign-grs.com", "example.com")
```

## Tests

```sh
go test ./...
go vet ./...
```

Tests cover Verisign/Nominet/DENIC response styles, eleven date
formats, availability detection, referral chains and loops, timeouts,
and order-preserving bulk lookups — all against local mock servers,
no live network needed.

## License

MIT — see [LICENSE](LICENSE).
