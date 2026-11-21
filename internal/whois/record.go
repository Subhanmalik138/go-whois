// Package whois implements a WHOIS (RFC 3912) client: raw queries over TCP
// port 43, referral chasing from IANA down to the responsible registry or
// registrar, and structured parsing of the flat key-value responses those
// servers return.
//
// A lookup starts at whois.iana.org, which answers with the server
// responsible for the queried TLD or IP block; the client follows the
// "Whois Server" referral, usually to a registry, which in turn may refer
// to a registrar. Each hop's response is parsed and merged, with the
// deepest (most authoritative) hop winning for scalar fields.
//
// The package is standard library only and safe for concurrent use: a
// Client holds no per-query state.
package whois

import "time"

// Record is the structured result of a WHOIS lookup. Dates are pointers
// because registries disagree on which dates they publish — a missing date
// is nil, not the zero time.
type Record struct {
	// Query is the domain or IP address that was looked up.
	Query string `json:"query"`
	// Available reports whether the registry says the name is unregistered.
	Available bool `json:"available"`
	// Registrar is the sponsoring registrar, when the response names one.
	Registrar string `json:"registrar,omitempty"`
	// WhoisServer is the registrar WHOIS server named in the response.
	WhoisServer string `json:"whois_server,omitempty"`
	// Created, Updated and Expires are the lifecycle dates, when published.
	Created *time.Time `json:"created,omitempty"`
	Updated *time.Time `json:"updated,omitempty"`
	Expires *time.Time `json:"expires,omitempty"`
	// NameServers lists the delegated name servers, lower-cased, no
	// trailing dot.
	NameServers []string `json:"name_servers,omitempty"`
	// Status lists the EPP domain statuses (clientTransferProhibited, ...).
	Status []string `json:"status,omitempty"`
	// RegistrantOrg is the registrant organisation, when published.
	RegistrantOrg string `json:"registrant_org,omitempty"`
	// NetRange is the address block, for IP lookups (e.g. "8.8.8.0/24").
	NetRange string `json:"net_range,omitempty"`
	// Country is the two-letter country code, for IP lookups.
	Country string `json:"country,omitempty"`
	// ServersQueried is the referral chain actually followed, in order.
	ServersQueried []string `json:"servers_queried"`
	// Raw is the full text of the final (deepest) server's response.
	Raw string `json:"raw,omitempty"`
}

// Result pairs a Record with the error its lookup produced, so bulk
// lookups can report per-domain failures without aborting the batch.
type Result struct {
	Record *Record
	Err    error
}
