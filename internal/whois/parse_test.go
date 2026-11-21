package whois

import (
	"strings"
	"testing"
	"time"
)

// A Verisign-style .com response — the most common shape in the wild.
const verisignResponse = `   Domain Name: EXAMPLE.COM
   Registry Domain ID: 2336799_DOMAIN_COM-VRSN
   Registrar WHOIS Server: whois.example-registrar.com
   Registrar URL: http://www.example-registrar.com
   Updated Date: 2024-08-14T07:02:34Z
   Creation Date: 1995-08-14T04:00:00Z
   Registry Expiry Date: 2026-08-13T04:00:00Z
   Registrar: Example Registrar, Inc.
   Registrar IANA ID: 123
   Domain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited
   Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
   Name Server: A.IANA-SERVERS.NET
   Name Server: B.IANA-SERVERS.NET
   DNSSEC: unsigned
`

// A Nominet-style .uk response: indented keys, bare name-server lines,
// "Registered on" phrasing.
const nominetResponse = `    Domain name:
        example.co.uk

    Registrar:
        Example Registrar Ltd [Tag = EXAMPLE]

    Relevant dates:
        Registered on: 14-Aug-1999
        Expiry date:  14-Aug-2026
        Last updated:  01-Jul-2025

    Registration status:
        Registered until expiry date.

    Name servers:
        ns1.example.com
        ns2.example.com
`

// A DENIC-style .de response: terse keys, no registrar block.
const denicResponse = `Domain: example.de
Nserver: ns1.example.com
Nserver: ns2.example.com
Status: connect
Changed: 2024-01-15T10:00:00+01:00
`

func TestParseVerisign(t *testing.T) {
	rec := Parse(verisignResponse)
	if rec.Available {
		t.Fatal("registered domain reported available")
	}
	if rec.Registrar != "Example Registrar, Inc." {
		t.Errorf("registrar = %q", rec.Registrar)
	}
	if rec.WhoisServer != "whois.example-registrar.com" {
		t.Errorf("whois server = %q", rec.WhoisServer)
	}
	checkDate(t, "created", rec.Created, time.Date(1995, 8, 14, 4, 0, 0, 0, time.UTC))
	checkDate(t, "updated", rec.Updated, time.Date(2024, 8, 14, 7, 2, 34, 0, time.UTC))
	checkDate(t, "expires", rec.Expires, time.Date(2026, 8, 13, 4, 0, 0, 0, time.UTC))
	if len(rec.Status) != 2 || rec.Status[0] != "clientDeleteProhibited" || rec.Status[1] != "clientTransferProhibited" {
		t.Errorf("status = %v", rec.Status)
	}
	if len(rec.NameServers) != 2 || rec.NameServers[0] != "a.iana-servers.net" || rec.NameServers[1] != "b.iana-servers.net" {
		t.Errorf("name servers = %v", rec.NameServers)
	}
}

func TestParseNominet(t *testing.T) {
	rec := Parse(nominetResponse)
	if rec.Available {
		t.Fatal("registered domain reported available")
	}
	checkDate(t, "created", rec.Created, time.Date(1999, 8, 14, 0, 0, 0, 0, time.UTC))
	checkDate(t, "expires", rec.Expires, time.Date(2026, 8, 14, 0, 0, 0, 0, time.UTC))
	checkDate(t, "updated", rec.Updated, time.Date(2025, 7, 1, 0, 0, 0, 0, time.UTC))
	if len(rec.NameServers) != 2 || rec.NameServers[0] != "ns1.example.com" {
		t.Errorf("bare name-server lines not parsed: %v", rec.NameServers)
	}
}

func TestParseDenic(t *testing.T) {
	rec := Parse(denicResponse)
	checkDate(t, "updated", rec.Updated, time.Date(2024, 1, 15, 10, 0, 0, 0, time.FixedZone("", 3600)))
	if len(rec.NameServers) != 2 || rec.NameServers[0] != "ns1.example.com" {
		t.Errorf("nserver lines not parsed: %v", rec.NameServers)
	}
	if len(rec.Status) != 1 || rec.Status[0] != "connect" {
		t.Errorf("status = %v", rec.Status)
	}
}

func checkDate(t *testing.T, name string, got *time.Time, want time.Time) {
	t.Helper()
	if got == nil {
		t.Fatalf("%s is nil, want %v", name, want)
	}
	if !got.Equal(want) {
		t.Errorf("%s = %v, want %v", name, *got, want)
	}
}

func TestParseDateFormats(t *testing.T) {
	cases := map[string]time.Time{
		"1995-08-14T04:00:00Z":               time.Date(1995, 8, 14, 4, 0, 0, 0, time.UTC),
		"1995-08-14T04:00:00.000Z":           time.Date(1995, 8, 14, 4, 0, 0, 0, time.UTC),
		"2024-01-15T10:00:00+01:00":          time.Date(2024, 1, 15, 10, 0, 0, 0, time.FixedZone("", 3600)),
		"14-Aug-1999":                        time.Date(1999, 8, 14, 0, 0, 0, 0, time.UTC),
		"14-aug-1999":                        time.Date(1999, 8, 14, 0, 0, 0, 0, time.UTC),
		"2026-08-13":                         time.Date(2026, 8, 13, 0, 0, 0, 0, time.UTC),
		"2026-08-13 04:00:00":                time.Date(2026, 8, 13, 4, 0, 0, 0, time.UTC),
		"2026.08.13":                         time.Date(2026, 8, 13, 0, 0, 0, 0, time.UTC),
		"20260813":                           time.Date(2026, 8, 13, 0, 0, 0, 0, time.UTC),
		"Aug 13 2026":                        time.Date(2026, 8, 13, 0, 0, 0, 0, time.UTC),
		"2026-08-13T04:00:00Z (in 100 days)": time.Date(2026, 8, 13, 4, 0, 0, 0, time.UTC),
	}
	for in, want := range cases {
		got, ok := parseDate(in)
		if !ok {
			t.Errorf("parseDate(%q): not parsed", in)
			continue
		}
		if !got.Equal(want) {
			t.Errorf("parseDate(%q) = %v, want %v", in, got, want)
		}
	}
	if _, ok := parseDate("not a date"); ok {
		t.Error("parseDate accepted garbage")
	}
}

func TestParseAvailability(t *testing.T) {
	cases := []struct {
		raw  string
		want bool
	}{
		{"No match for \"EXAMPLE-NOT-REGISTERED.COM\".\n", true},
		{"% No entries found.\n", true},
		{"Domain not found.\n", true},
		{"Status: free\n", true},
		{"No data found\n", true},
		{verisignResponse, false},
		{"Domain Name: EXAMPLE.COM\nRegistrar: Example\n", false},
		// "not found" inside a disclaimer must not misfire.
		{"Domain Name: EXAMPLE.COM\nNote: if this record is not found contact support.\n", false},
	}
	for _, tc := range cases {
		if got := Parse(tc.raw).Available; got != tc.want {
			t.Errorf("Parse(%q).Available = %v, want %v", firstLine(tc.raw), got, tc.want)
		}
	}
}

func firstLine(s string) string {
	if i := strings.Index(s, "\n"); i >= 0 {
		return s[:i]
	}
	return s
}

func TestParseNameServerNormalisation(t *testing.T) {
	raw := "Name Server: NS1.EXAMPLE.COM.\nName Server: ns1.example.com\nName Server: ns2.example.com 192.0.2.53\nName Server: 192.0.2.1\n"
	rec := Parse(raw)
	want := []string{"ns1.example.com", "ns2.example.com"}
	if len(rec.NameServers) != len(want) {
		t.Fatalf("name servers = %v, want %v", rec.NameServers, want)
	}
	for i, w := range want {
		if rec.NameServers[i] != w {
			t.Errorf("name servers[%d] = %q, want %q", i, rec.NameServers[i], w)
		}
	}
}

func TestParseIPResponse(t *testing.T) {
	raw := "NetRange:       8.8.8.0 - 8.8.8.255\nCIDR:           8.8.8.0/24\nOrgName:        Google LLC\nCountry:        US\nReferralServer: whois://whois.arin.net\n"
	rec := Parse(raw)
	if rec.NetRange != "8.8.8.0/24" {
		t.Errorf("net range = %q", rec.NetRange)
	}
	if rec.RegistrantOrg != "Google LLC" {
		t.Errorf("org = %q", rec.RegistrantOrg)
	}
	if rec.Country != "US" {
		t.Errorf("country = %q", rec.Country)
	}
}

func TestReferralServer(t *testing.T) {
	cases := []struct {
		raw  string
		want string
	}{
		{"Whois Server: whois.example-registrar.com\n", "whois.example-registrar.com:43"},
		{"whois: whois.verisign-grs.com\n", "whois.verisign-grs.com:43"},
		{"ReferralServer: whois://whois.arin.net\n", "whois.arin.net:43"},
		{"ReferralServer: whois://whois.ripe.net:43\n", "whois.ripe.net:43"},
		{"Domain Name: EXAMPLE.COM\n", ""},
		{"", ""},
	}
	for _, tc := range cases {
		if got := ReferralServer(tc.raw); got != tc.want {
			t.Errorf("ReferralServer(%q) = %q, want %q", tc.raw, got, tc.want)
		}
	}
}
