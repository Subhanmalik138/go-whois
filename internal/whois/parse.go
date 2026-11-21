package whois

import (
	"strings"
	"time"
)

// dateLayouts are the formats registries actually emit, in rough order of
// frequency. time.Parse matches month names case-insensitively, which
// covers "14-Aug-1999" and "14-aug-1999" alike.
var dateLayouts = []string{
	time.RFC3339Nano,
	time.RFC3339,
	"2006-01-02T15:04:05Z07:00",
	"2006-01-02 15:04:05",
	"2006-01-02",
	"02-Jan-2006",
	"02 Jan 2006",
	"02-Jan-2006 15:04:05",
	"2006.01.02",
	"20060102",
	"Jan 02 2006",
	"Mon Jan 2 15:04:05 MST 2006",
	"2006-01-02T15:04:05",
}

// parseDate parses a registry date, tolerating the trailing parenthetical
// remarks some registries append ("2026-08-13T04:00:00Z (in 265 days)")
// and the occasional "UTC"/"GMT" suffix.
func parseDate(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, " ("); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	s = strings.TrimSuffix(s, " UTC")
	s = strings.TrimSuffix(s, " GMT")
	if s == "" {
		return time.Time{}, false
	}
	for _, layout := range dateLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// notFoundMarkers are substrings that, in a WHOIS response body, mean the
// queried name is not registered. Matching is case-insensitive and kept to
// phrases registries actually emit, so a "not found" inside a help text or
// a legal disclaimer does not misfire on a registered domain.
var notFoundMarkers = []string{
	"no match for",
	"no entries found",
	"no data found",
	"no object found",
	"domain not found",
	"not found:",
	"status: free",
	"is free",
	"available for registration",
	"no match",
	"nothing found",
}

// IsAvailable reports whether a raw WHOIS response says the queried name
// is unregistered.
func IsAvailable(raw string) bool {
	lower := strings.ToLower(raw)
	for _, m := range notFoundMarkers {
		if strings.Contains(lower, m) {
			return true
		}
	}
	return false
}

// ReferralServer extracts the next WHOIS server from a response: the
// "Whois Server" field registries publish, or the RIR-style
// "ReferralServer: whois://..." field. The returned value is host:port,
// with port 43 assumed. It returns "" when the response names no referral.
func ReferralServer(raw string) string {
	for _, line := range strings.Split(raw, "\n") {
		key, val, ok := splitField(line)
		if !ok {
			continue
		}
		switch key {
		case "registrar whois server", "whois server", "whois":
			return ensurePort(strings.TrimSpace(val))
		case "referralserver":
			val = strings.TrimSpace(val)
			val = strings.TrimPrefix(val, "whois://")
			val = strings.TrimSuffix(val, "/")
			return ensurePort(val)
		}
	}
	return ""
}

func ensurePort(host string) string {
	if host == "" {
		return ""
	}
	if strings.Contains(host, ":") {
		return host
	}
	return host + ":43"
}

// splitField splits one "Key: value" line. Keys are normalised to lower
// case with collapsed whitespace so "Registry Expiry Date", "registry
// expiry date" and "Registry  Expiry  Date" all match.
func splitField(line string) (key, val string, ok bool) {
	i := strings.Index(line, ":")
	if i < 0 {
		return "", "", false
	}
	key = normaliseKey(line[:i])
	val = strings.TrimSpace(line[i+1:])
	if key == "" {
		return "", "", false
	}
	return key, val, true
}

func normaliseKey(s string) string {
	return strings.Join(strings.Fields(strings.ToLower(s)), " ")
}

// Parse turns a raw WHOIS response into a Record. It tolerates the three
// response styles in the wild: Verisign-style "Key: Value" lines, Nominet
// indented blocks (bare value lines under a "Name servers:" header), and
// DENIC-style terse keys ("Nserver:", "Changed:"). Unknown fields are
// ignored; a field the parser cannot understand simply stays empty.
func Parse(raw string) *Record {
	rec := &Record{}
	lastKey := ""
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimRight(line, "\r")
		key, val, ok := splitField(line)
		if !ok {
			// A bare line is a continuation value for the previous key —
			// how Nominet lists name servers under "Name servers:".
			if lastKey == "name servers" || lastKey == "name server" {
				if ns := normaliseNameServer(strings.TrimSpace(line)); ns != "" {
					rec.NameServers = appendUnique(rec.NameServers, ns)
				}
			}
			continue
		}
		lastKey = key
		switch key {
		case "registrar", "sponsoring registrar", "registrar name":
			rec.Registrar = val
		case "registrar whois server", "whois server":
			rec.WhoisServer = val
		case "creation date", "created on", "registered on", "registration date", "created":
			if t, ok := parseDate(val); ok {
				rec.Created = &t
			}
		case "updated date", "last updated", "last modified", "changed":
			if t, ok := parseDate(val); ok {
				rec.Updated = &t
			}
		case "registry expiry date", "registrar registration expiration date",
			"expiration date", "expiry date", "expire date", "paid-till", "expire":
			if t, ok := parseDate(val); ok {
				rec.Expires = &t
			}
		case "name server", "nserver", "nameservers", "name servers":
			for _, ns := range strings.Fields(val) {
				if ns = normaliseNameServer(ns); ns != "" {
					rec.NameServers = appendUnique(rec.NameServers, ns)
				}
			}
		case "domain status", "status":
			// Statuses carry a trailing EPP URL: keep only the code.
			if code := strings.Fields(val); len(code) > 0 {
				rec.Status = appendUnique(rec.Status, code[0])
			}
		case "registrant organization", "registrant organisation", "org", "orgname", "org-name", "registrant":
			rec.RegistrantOrg = val
		case "netrange", "cidr":
			rec.NetRange = val
		case "country":
			rec.Country = val
		}
	}
	rec.Available = IsAvailable(raw)
	return rec
}

// normaliseNameServer lower-cases a name server, strips a trailing dot and
// any trailing IP address ("ns1.example.com 192.0.2.1" -> "ns1.example.com").
// It returns "" for values that are not hostnames.
func normaliseNameServer(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimSuffix(s, ".")
	if s == "" || !strings.Contains(s, ".") {
		return ""
	}
	// Guard against "192.0.2.1"-style values slipping through as names.
	if isIPLiteral(s) {
		return ""
	}
	return s
}

func isIPLiteral(s string) bool {
	for _, c := range s {
		if (c < '0' || c > '9') && c != '.' && c != ':' {
			return false
		}
	}
	return true
}

func appendUnique(list []string, v string) []string {
	for _, e := range list {
		if e == v {
			return list
		}
	}
	return append(list, v)
}
