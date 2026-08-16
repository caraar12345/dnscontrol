package technitium

import (
	"fmt"
	"strings"

	"github.com/DNSControl/dnscontrol/v4/models"
	"github.com/DNSControl/dnscontrol/v4/pkg/rejectif"
)

// AuditRecords returns a list of errors corresponding to the records
// that aren't supported by this provider.  If all records are
// supported, an empty list is returned.
func AuditRecords(records []*models.RecordConfig) []error {
	a := rejectif.Auditor{}

	a.TypesSupported([]string{
		"A", "AAAA", "ALIAS", "CAA", "CNAME", "DNAME", "DS", "HTTPS",
		"MX", "NAPTR", "NS", "PTR", "SRV", "SSHFP", "SVCB", "TECHNITIUM_APP",
		"TLSA", "TXT",
	}) // Last verified 2026-08-16.

	a.Add("TXT", rejectif.TxtIsEmpty) // Last verified 2026-08-08.

	// Technitium can compute the ipv4hint/ipv6hint SVCB parameter itself
	// (Automatic Hints), but it does so by writing the resolved address into
	// the record and never reports back that the value is auto-computed. A
	// SvcParams of "ipv4hint=auto" would therefore read back as a literal
	// address on every run, which this provider cannot tell apart from a real
	// edit. Rejecting it up front avoids planning a correction that can never
	// converge. Last verified 2026-08-08.
	a.Add("SVCB", rejectAutoSvcbHint)
	a.Add("HTTPS", rejectAutoSvcbHint)

	return a.Audit(records)
}

// rejectAutoSvcbHint rejects an SVCB/HTTPS record whose SvcParams asks for
// Technitium's Automatic Hints feature, which this provider does not
// implement.
func rejectAutoSvcbHint(rc *models.RecordConfig) error {
	for _, field := range strings.Fields(rc.SvcParams) {
		key, value, _ := strings.Cut(field, "=")
		if (key == "ipv4hint" || key == "ipv6hint") && value == "auto" {
			return fmt.Errorf("%s=auto is not supported", key)
		}
	}
	return nil
}
