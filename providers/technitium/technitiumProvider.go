package technitium

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/DNSControl/dnscontrol/v4/models"
	"github.com/DNSControl/dnscontrol/v4/pkg/providers"
)

/*
Technitium DNS Server provider:

Info required in `creds.json`:
   - api_url    Base URL of the Technitium DNS Server web console/API, e.g. https://dns.example.com:5380
   - api_token  A non-expiring API token created via the "Create API Token" call, or the
                Administration -> Sessions page of the web console.

Technitium is self-hosted, so - unlike a SaaS DNS provider - DNSControl does not
know what nameservers the operator's zones are actually served from. The
nameservers to report to a registrar are given as a "default_ns" metadata
field, the same pattern used by the BIND and PowerDNS providers:

  var DSP_TECHNITIUM = NewDnsProvider("technitium", {
      default_ns: ["ns1.example.com.", "ns2.example.com."],
  });

The records API addresses one record value at a time and identifies it by its
current field values rather than an opaque ID (e.g. the current ipAddress of
an A record, or the current preference and exchange of an MX record), with a
parallel set of "new"-prefixed fields for the value it is changing to. This
provider therefore uses diff2.ByRecord(), and a CHANGE correction carries both
the old record (to identify it) and the new one (to supply the new values).
See convert.go and records.go.

The SOA record and the DNSSEC-related records of a signed zone (RRSIG, DNSKEY,
NSEC, NSEC3, NSEC3PARAM) are maintained by the server itself and cannot be
written through the records API, so they are left out of the zone contents.
Unlike some hosted DNS providers, Technitium does not manage the zone's own
NS records for you: it is a full authoritative server, so the apex NS set is
just like any other record set and is managed normally.
*/

var features = providers.DocumentationNotes{
	// The default for unlisted capabilities is 'Cannot'.
	// See providers/capabilities.go for the entire list of capabilities.
	providers.CanAutoDNSSEC:          providers.Unimplemented("DNSSEC is managed via the zone's DNSSEC settings outside DNSControl"),
	providers.CanConcur:              providers.Unimplemented(),
	providers.CanGetZones:            providers.Can(),
	providers.CanUseAlias:            providers.Can("Technitium calls this record type ANAME"),
	providers.CanUseCAA:              providers.Can(),
	providers.CanUseDHCID:            providers.Cannot(),
	providers.CanUseDNAME:            providers.Can(),
	providers.CanUseDNSKEY:           providers.Cannot("DNSKEY records are managed by the zone's DNSSEC settings"),
	providers.CanUseDS:               providers.Can(),
	providers.CanUseHTTPS:            providers.Can("Automatic Hints (ipv4hint/ipv6hint=auto) are not supported"),
	providers.CanUseLOC:              providers.Cannot(),
	providers.CanUseNAPTR:            providers.Can(),
	providers.CanUseOPENPGPKEY:       providers.Cannot(),
	providers.CanUsePTR:              providers.Can(),
	providers.CanUseRP:               providers.Cannot(),
	providers.CanUseSMIMEA:           providers.Cannot(),
	providers.CanUseSOA:              providers.Cannot("The SOA record is managed by the server"),
	providers.CanUseSRV:              providers.Can(),
	providers.CanUseSSHFP:            providers.Can(),
	providers.CanUseSVCB:             providers.Can("Automatic Hints (ipv4hint/ipv6hint=auto) are not supported"),
	providers.CanUseTLSA:             providers.Can(),
	providers.DocCreateDomains:       providers.Can(),
	providers.DocDualHost:            providers.Can(),
	providers.DocOfficiallySupported: providers.Cannot(),
}

// technitiumProvider represents the Technitium DNS Server DNSServiceProvider.
type technitiumProvider struct {
	client      *apiClient
	nameservers []*models.Nameserver
}

func init() {
	const providerName = "TECHNITIUM"
	const providerMaintainer = "@caraar12345"
	fns := providers.DspFuncs{
		Initializer:   newTechnitium,
		RecordAuditor: AuditRecords,
	}
	providers.RegisterDomainServiceProviderType(providerName, fns, features)
	providers.RegisterMaintainer(providerName, providerMaintainer)
	providers.RegisterDefaultTTL(providerName, defaultTTL)

	providers.RegisterCredsMetadata(providerName, providers.CredsMetadata{
		DisplayName: "Technitium DNS Server",
		Kind:        providers.KindDNS,
		DocsURL:     "https://docs.dnscontrol.org/provider/technitium",
		PortalURL:   "https://technitium.com/dns/",
		Notes:       "Self-hosted. api_url points at your own server; api_token is created via the server's Create API Token call or Sessions page.",
		Fields: []providers.CredsField{
			{
				Key:      "api_url",
				Label:    "API base URL",
				Help:     "Base URL of the Technitium DNS Server web console, e.g. https://dns.example.com:5380",
				Required: true,
			},
			{
				Key:      "api_token",
				Label:    "API token",
				Help:     "A non-expiring API token with permission to view and modify the zones DNSControl manages.",
				Secret:   true,
				Required: true,
			},
		},
	})
}

// newTechnitium builds a provider from the entry in creds.json and the
// per-provider metadata passed to NewDnsProvider() in dnsconfig.js.
func newTechnitium(settings map[string]string, metadata json.RawMessage) (providers.DNSServiceProvider, error) {
	apiURL := settings["api_url"]
	if apiURL == "" {
		return nil, errors.New("missing TECHNITIUM api_url")
	}

	token := settings["api_token"]
	if token == "" {
		return nil, errors.New("missing TECHNITIUM api_token")
	}

	var meta struct {
		DefaultNS []string `json:"default_ns"`
	}
	if len(metadata) != 0 {
		if err := json.Unmarshal(metadata, &meta); err != nil {
			return nil, err
		}
	}

	nss := make([]string, len(meta.DefaultNS))
	for i, ns := range meta.DefaultNS {
		if ns == "" {
			return nil, fmt.Errorf("empty string in default_ns[%d]", i)
		}
		nss[i] = strings.TrimSuffix(ns, ".")
	}
	nameservers, err := models.ToNameservers(nss)
	if err != nil {
		return nil, err
	}

	return &technitiumProvider{
		client:      newAPIClient(apiURL, token),
		nameservers: nameservers,
	}, nil
}

// GetNameservers returns the nameservers configured for the provider via the
// default_ns metadata field.
func (c *technitiumProvider) GetNameservers(string) ([]*models.Nameserver, error) {
	return c.nameservers, nil
}
