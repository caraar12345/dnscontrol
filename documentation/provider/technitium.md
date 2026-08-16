## Configuration

To use this provider, add an entry to `creds.json` with `TYPE` set to
`TECHNITIUM` along with the base URL of your
[Technitium DNS Server](https://technitium.com/dns/) and an API token.

Example:

{% code title="creds.json" %}
```json
{
  "technitium": {
    "TYPE": "TECHNITIUM",
    "api_url": "https://dns.example.com:5380",
    "api_token": "your-api-token"
  }
}
```
{% endcode %}

You can also use environment variables:

```shell
export TECHNITIUM_API_URL=https://dns.example.com:5380
export TECHNITIUM_API_TOKEN=XXXXXXXXX
```

{% code title="creds.json" %}
```json
{
  "technitium": {
    "TYPE": "TECHNITIUM",
    "api_url": "$TECHNITIUM_API_URL",
    "api_token": "$TECHNITIUM_API_TOKEN"
  }
}
```
{% endcode %}

## Metadata

Technitium is self-hosted, so - unlike a SaaS DNS provider - DNSControl has no
way to know what nameservers your zones are actually served from. Tell it with
the `default_ns` metadata field on `NewDnsProvider()`:

{% code title="dnsconfig.js" %}
```javascript
var DSP_TECHNITIUM = NewDnsProvider("technitium", {
  default_ns: ["ns1.example.com.", "ns2.example.com."],
});
```
{% endcode %}

## Usage

An example configuration:

{% code title="dnsconfig.js" %}
```javascript
var REG_NONE = NewRegistrar("none");
var DSP_TECHNITIUM = NewDnsProvider("technitium", {
  default_ns: ["ns1.example.com.", "ns2.example.com."],
});

D("example.com", REG_NONE, DnsProvider(DSP_TECHNITIUM),
    A("@", "203.0.113.10"),
    A("www", "203.0.113.10"),
    AAAA("@", "2001:db8::1"),
    CNAME("blog", "example.github.io."),
    MX("@", 10, "mail.example.com."),
    TXT("@", "v=spf1 -all"),
    CAA("@", "issue", "letsencrypt.org"),
    SRV("_sip._tcp", 10, 60, 5060, "sip.example.com."),
);
```
{% endcode %}

## Activation

DNSControl talks to the
[Technitium DNS Server HTTP API](https://github.com/TechnitiumSoftware/DnsServer/blob/master/APIDOCS.md),
which needs a non-expiring API token.

1. Sign in to the web console.
2. Go to **Administration** -> **Sessions**, or call the `/api/user/createToken`
   API directly, to create a non-expiring API token for the account DNSControl
   will use.
3. Grant the account permission to view and modify the zones DNSControl will
   manage.
4. Put the server's base URL and the token in `creds.json` as shown above.

## Supported record types

| Name   | Description |
| ------ | ----------- |
| A      | IPv4 address record |
| AAAA   | IPv6 address record |
| ALIAS  | Alias record. Technitium calls this record type `ANAME`. |
| CAA    | Certification Authority Authorization record |
| CNAME  | Canonical name (alias) record |
| DNAME  | Delegation name record |
| DS     | Delegation signer record |
| HTTPS  | HTTPS service binding record |
| MX     | Mail exchange record |
| NAPTR  | Naming Authority Pointer record |
| NS     | Name server record |
| PTR    | Pointer record |
| SRV    | Service record |
| SSHFP  | SSH fingerprint record |
| SVCB   | Service binding record |
| [`TECHNITIUM_APP`](../language-reference/domain-modifiers/TECHNITIUM_APP.md) | Hands the query off to an installed DNS app, such as Split Horizon. Technitium calls this record type `APP`. |
| TLSA   | TLSA record |
| TXT    | Text record |

No other record type is supported.

## New domains

If a domain does not exist on the Technitium server, DNSControl will add it as
a Primary zone with the `push` command.

## Limitations

### Zone apex

Technitium is a full authoritative server, not a hosted platform that manages
delegation for you, so unlike many DNS providers the apex `NS` record set is a
normal record set: DNSControl can add, change or remove it like any other
record, and dual-hosting a zone with a second DNS provider is supported.

### SOA and DNSSEC records

The `SOA` record and the DNSSEC records of a signed zone (`RRSIG`, `DNSKEY`,
`NSEC`, `NSEC3`, `NSEC3PARAM`) are maintained by the server and cannot be
written through the records API, so DNSControl leaves them alone. They are not
reported by `dnscontrol get-zones`, and `AUTODNSSEC_ON` is not implemented -
DNSSEC is switched on per zone from the web console or the DNSSEC-specific API
calls, outside of DNSControl.

### SVCB and HTTPS automatic hints

Technitium can compute the `ipv4hint`/`ipv6hint` SVCB parameter for you
(Automatic Hints), but it always reports back the resolved address rather than
the fact that the value is auto-computed. DNSControl cannot tell that address
apart from a manually set one, so a config asking for the automatic hint would
never converge; `dnscontrol check` rejects `ipv4hint=auto` and
`ipv6hint=auto` up front instead.

### APP records

Technitium's proprietary `APP` record type hands a query off to an installed
[DNS app](https://blog.technitium.com/2021/03/creating-and-running-dns-apps-on.html)
(for example, the Split Horizon app included with Technitium) instead of
answering it directly. It has no equivalent in DNSControl's record types, so
it's exposed as the provider-specific
[`TECHNITIUM_APP`](../language-reference/domain-modifiers/TECHNITIUM_APP.md)
pseudo-type. Only one `APP` record can exist at a label, and Technitium does
not check it against any `A`/`AAAA` records also present there - those take
precedence, so remove them if the app is meant to answer the query.

### Concurrent operations

Zone data is not gathered concurrently. The provider has not been verified for
concurrent use.

## Feature Summary

<!-- provider-features-start -->
- Provider Type
  - [Official Support](../provider/index.md#providers-with-official-support): ❌
  - DNS Provider: ✅
  - Registrar: ❌
- Provider API
  - [Concurrency Verified](../advanced-features/concurrency-verified.md): ❔
  - [dual host](../advanced-features/dual-host.md): ✅
  - create-domains: ✅
  - [get-zones](../commands/get-zones.md): ✅
- DNS extensions
  - [`ALIAS`](../language-reference/domain-modifiers/ALIAS.md): ✅
  - [`DNAME`](../language-reference/domain-modifiers/DNAME.md): ✅
  - [`LOC`](../language-reference/domain-modifiers/LOC.md): ❌
  - [`PTR`](../language-reference/domain-modifiers/PTR.md): ✅
  - [`SOA`](../language-reference/domain-modifiers/SOA.md): ❌
- Service discovery
  - [`DHCID`](../language-reference/domain-modifiers/DHCID.md): ❌
  - [`NAPTR`](../language-reference/domain-modifiers/NAPTR.md): ✅
  - [`SRV`](../language-reference/domain-modifiers/SRV.md): ✅
  - [`SVCB`](../language-reference/domain-modifiers/SVCB.md): ✅
- Security
  - [`CAA`](../language-reference/domain-modifiers/CAA.md): ✅
  - [`HTTPS`](../language-reference/domain-modifiers/HTTPS.md): ✅
  - [`SMIMEA`](../language-reference/domain-modifiers/SMIMEA.md): ❌
  - [`SSHFP`](../language-reference/domain-modifiers/SSHFP.md): ✅
  - [`TLSA`](../language-reference/domain-modifiers/TLSA.md): ✅
- DNSSEC
  - [`AUTODNSSEC`](../language-reference/domain-modifiers/AUTODNSSEC_ON.md): ❔
  - [`DNSKEY`](../language-reference/domain-modifiers/DNSKEY.md): ❌
  - [`DS`](../language-reference/domain-modifiers/DS.md): ✅
<!-- provider-features-end -->
