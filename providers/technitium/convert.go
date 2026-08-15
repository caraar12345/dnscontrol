package technitium

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/DNSControl/dnscontrol/v4/models"
)

// toFQDN turns a hostname Technitium returned into an absolute name (trailing
// dot). Technitium's API always returns an already-fully-qualified hostname
// but omits the trailing dot; DNSControl's CanonicalizeTargets() runs over
// every provider's GetZoneRecords() result and uses the trailing dot as the
// only signal that a hostname is already absolute; a dotless value is
// (wrongly, here) treated as a shortname and has the zone's origin appended
// to it a second time. See dnsutil.AddOrigin() and models.CanonicalizeTargets().
func toFQDN(name string) string {
	if name == "" || strings.HasSuffix(name, ".") {
		return name
	}
	return name + "."
}

// fromFQDN is the reverse of toFQDN: by the time a correction is built,
// CanonicalizeTargets() has made every hostname target absolute (trailing
// dot), but Technitium's own API never includes one, so it is stripped again
// before the value is sent back. The bare root "." (used by NAPTR to mean
// "no replacement") is left alone: it is the whole name, not a suffix to trim.
func fromFQDN(name string) string {
	if name == "." {
		return name
	}
	return strings.TrimSuffix(name, ".")
}

// toRecordConfig converts one record of a GET /api/zones/records/get
// response to a RecordConfig. rec.Name is the record's FQDN, not a name
// relative to the zone.
func toRecordConfig(rec apiRecord, origin string) (*models.RecordConfig, error) {
	rc := &models.RecordConfig{
		Type:     rec.Type,
		TTL:      rec.TTL,
		Original: rec,
	}
	rc.SetLabelFromFQDN(rec.Name, origin)

	switch rec.Type {
	case "A", "AAAA":
		var d struct {
			IPAddress string `json:"ipAddress"`
		}
		if err := json.Unmarshal(rec.RData, &d); err != nil {
			return nil, err
		}
		return rc, rc.SetTarget(d.IPAddress)

	case "NS":
		var d struct {
			NameServer string `json:"nameServer"`
		}
		if err := json.Unmarshal(rec.RData, &d); err != nil {
			return nil, err
		}
		return rc, rc.SetTarget(toFQDN(d.NameServer))

	case "CNAME":
		var d struct {
			CName string `json:"cname"`
		}
		if err := json.Unmarshal(rec.RData, &d); err != nil {
			return nil, err
		}
		return rc, rc.SetTarget(toFQDN(d.CName))

	case "PTR":
		var d struct {
			PtrName string `json:"ptrName"`
		}
		if err := json.Unmarshal(rec.RData, &d); err != nil {
			return nil, err
		}
		return rc, rc.SetTarget(toFQDN(d.PtrName))

	case "DNAME":
		var d struct {
			DName string `json:"dname"`
		}
		if err := json.Unmarshal(rec.RData, &d); err != nil {
			return nil, err
		}
		return rc, rc.SetTarget(toFQDN(d.DName))

	// ANAME is Technitium's proprietary equivalent of DNSControl's ALIAS. The
	// type is left as "ANAME": GetZoneRecordsCorrections renames the desired
	// side from "ALIAS" to "ANAME" before diffing, so both sides need to agree
	// on the wire name for diff2 to compare them as the same record.
	case "ANAME":
		var d struct {
			AName string `json:"aname"`
		}
		if err := json.Unmarshal(rec.RData, &d); err != nil {
			return nil, err
		}
		return rc, rc.SetTarget(toFQDN(d.AName))

	case "MX":
		var d struct {
			Exchange   string `json:"exchange"`
			Preference uint16 `json:"preference"`
		}
		if err := json.Unmarshal(rec.RData, &d); err != nil {
			return nil, err
		}
		return rc, rc.SetTargetMX(d.Preference, toFQDN(d.Exchange))

	case "TXT":
		var d struct {
			CharacterStrings []string `json:"characterStrings"`
		}
		if err := json.Unmarshal(rec.RData, &d); err != nil {
			return nil, err
		}
		return rc, rc.SetTargetTXTs(d.CharacterStrings)

	case "SRV":
		var d struct {
			Priority uint16 `json:"priority"`
			Weight   uint16 `json:"weight"`
			Port     uint16 `json:"port"`
			Target   string `json:"target"`
		}
		if err := json.Unmarshal(rec.RData, &d); err != nil {
			return nil, err
		}
		return rc, rc.SetTargetSRV(d.Priority, d.Weight, d.Port, toFQDN(d.Target))

	case "CAA":
		var d struct {
			Flags uint8  `json:"flags"`
			Tag   string `json:"tag"`
			Value string `json:"value"`
		}
		if err := json.Unmarshal(rec.RData, &d); err != nil {
			return nil, err
		}
		return rc, rc.SetTargetCAA(d.Flags, d.Tag, d.Value)

	case "NAPTR":
		var d struct {
			Order       uint16 `json:"naptrOrder"`
			Preference  uint16 `json:"naptrPreference"`
			Flags       string `json:"naptrFlags"`
			Services    string `json:"naptrServices"`
			Regexp      string `json:"naptrRegexp"`
			Replacement string `json:"naptrReplacement"`
		}
		if err := json.Unmarshal(rec.RData, &d); err != nil {
			return nil, err
		}
		return rc, rc.SetTargetNAPTR(d.Order, d.Preference, d.Flags, d.Services, d.Regexp, toFQDN(d.Replacement))

	case "SVCB", "HTTPS":
		var d struct {
			SvcPriority   uint16 `json:"svcPriority"`
			SvcTargetName string `json:"svcTargetName"`
			SvcParams     string `json:"svcParams"`
		}
		if err := json.Unmarshal(rec.RData, &d); err != nil {
			return nil, err
		}
		rc.SvcPriority = d.SvcPriority
		rc.SvcParams = svcParamsFromTechnitium(d.SvcParams)
		return rc, rc.SetTarget(toFQDN(d.SvcTargetName))

	case "TLSA":
		var d struct {
			CertificateUsage           string `json:"tlsaCertificateUsage"`
			Selector                   string `json:"tlsaSelector"`
			MatchingType               string `json:"tlsaMatchingType"`
			CertificateAssociationData string `json:"tlsaCertificateAssociationData"`
		}
		if err := json.Unmarshal(rec.RData, &d); err != nil {
			return nil, err
		}
		usage, err := valueFor(tlsaCertificateUsageNames, d.CertificateUsage)
		if err != nil {
			return nil, fmt.Errorf("TLSA certificate usage: %w", err)
		}
		selector, err := valueFor(tlsaSelectorNames, d.Selector)
		if err != nil {
			return nil, fmt.Errorf("TLSA selector: %w", err)
		}
		matchingType, err := valueFor(tlsaMatchingTypeNames, d.MatchingType)
		if err != nil {
			return nil, fmt.Errorf("TLSA matching type: %w", err)
		}
		return rc, rc.SetTargetTLSA(usage, selector, matchingType, d.CertificateAssociationData)

	case "DS":
		var d struct {
			KeyTag     uint16 `json:"keyTag"`
			Algorithm  string `json:"algorithm"`
			DigestType string `json:"digestType"`
			Digest     string `json:"digest"`
		}
		if err := json.Unmarshal(rec.RData, &d); err != nil {
			return nil, err
		}
		algorithm, err := valueFor(dsAlgorithmNames, d.Algorithm)
		if err != nil {
			return nil, fmt.Errorf("DS algorithm: %w", err)
		}
		digestType, err := valueFor(dsDigestTypeNames, d.DigestType)
		if err != nil {
			return nil, fmt.Errorf("DS digest type: %w", err)
		}
		return rc, rc.SetTargetDS(d.KeyTag, algorithm, digestType, d.Digest)

	case "SSHFP":
		var d struct {
			Algorithm       string `json:"sshfpAlgorithm"`
			FingerprintType string `json:"sshfpFingerprintType"`
			Fingerprint     string `json:"sshfpFingerprint"`
		}
		if err := json.Unmarshal(rec.RData, &d); err != nil {
			return nil, err
		}
		algorithm, err := valueFor(sshfpAlgorithmNames, d.Algorithm)
		if err != nil {
			return nil, fmt.Errorf("SSHFP algorithm: %w", err)
		}
		fingerprintType, err := valueFor(sshfpFingerprintTypeNames, d.FingerprintType)
		if err != nil {
			return nil, fmt.Errorf("SSHFP fingerprint type: %w", err)
		}
		return rc, rc.SetTargetSSHFP(algorithm, fingerprintType, d.Fingerprint)

	default:
		return nil, fmt.Errorf("unsupported record type %q", rec.Type)
	}
}

// currentParams returns the query parameters that describe rc using
// Technitium's unprefixed field names. This is what Add uses for the record
// being created, what Delete uses to identify the record being removed, and
// what Update uses to identify the record being changed.
func currentParams(rc *models.RecordConfig) (url.Values, error) {
	v := url.Values{}

	switch rc.Type {
	case "A", "AAAA":
		v.Set("ipAddress", rc.GetTargetField())

	case "NS":
		v.Set("nameServer", fromFQDN(rc.GetTargetField()))

	case "CNAME":
		v.Set("cname", fromFQDN(rc.GetTargetField()))

	case "PTR":
		v.Set("ptrName", fromFQDN(rc.GetTargetField()))

	case "DNAME":
		v.Set("dname", fromFQDN(rc.GetTargetField()))

	case "ANAME":
		v.Set("aname", fromFQDN(rc.GetTargetField()))

	case "MX":
		v.Set("exchange", fromFQDN(rc.GetTargetField()))
		v.Set("preference", strconv.Itoa(int(rc.MxPreference)))

	case "TXT":
		v.Set("text", rc.GetTargetTXTJoined())

	case "SRV":
		v.Set("priority", strconv.Itoa(int(rc.SrvPriority)))
		v.Set("weight", strconv.Itoa(int(rc.SrvWeight)))
		v.Set("port", strconv.Itoa(int(rc.SrvPort)))
		v.Set("target", fromFQDN(rc.GetTargetField()))

	case "CAA":
		v.Set("flags", strconv.Itoa(int(rc.CaaFlag)))
		v.Set("tag", rc.CaaTag)
		v.Set("value", rc.GetTargetField())

	case "NAPTR":
		v.Set("naptrOrder", strconv.Itoa(int(rc.NaptrOrder)))
		v.Set("naptrPreference", strconv.Itoa(int(rc.NaptrPreference)))
		v.Set("naptrFlags", rc.NaptrFlags)
		v.Set("naptrServices", rc.NaptrService)
		v.Set("naptrRegexp", rc.NaptrRegexp)
		v.Set("naptrReplacement", fromFQDN(rc.GetTargetField()))

	case "SVCB", "HTTPS":
		v.Set("svcPriority", strconv.Itoa(int(rc.SvcPriority)))
		v.Set("svcTargetName", fromFQDN(rc.GetTargetField()))
		v.Set("svcParams", svcParamsToTechnitium(rc.SvcParams))

	case "TLSA":
		usage, err := nameFor(tlsaCertificateUsageNames, rc.TlsaUsage)
		if err != nil {
			return nil, fmt.Errorf("TLSA certificate usage: %w", err)
		}
		selector, err := nameFor(tlsaSelectorNames, rc.TlsaSelector)
		if err != nil {
			return nil, fmt.Errorf("TLSA selector: %w", err)
		}
		matchingType, err := nameFor(tlsaMatchingTypeNames, rc.TlsaMatchingType)
		if err != nil {
			return nil, fmt.Errorf("TLSA matching type: %w", err)
		}
		v.Set("tlsaCertificateUsage", usage)
		v.Set("tlsaSelector", selector)
		v.Set("tlsaMatchingType", matchingType)
		v.Set("tlsaCertificateAssociationData", rc.GetTargetField())

	case "DS":
		algorithm, err := nameFor(dsAlgorithmNames, rc.DsAlgorithm)
		if err != nil {
			return nil, fmt.Errorf("DS algorithm: %w", err)
		}
		digestType, err := nameFor(dsDigestTypeNames, rc.DsDigestType)
		if err != nil {
			return nil, fmt.Errorf("DS digest type: %w", err)
		}
		v.Set("keyTag", strconv.Itoa(int(rc.DsKeyTag)))
		v.Set("algorithm", algorithm)
		v.Set("digestType", digestType)
		v.Set("digest", rc.DsDigest)

	case "SSHFP":
		algorithm, err := nameFor(sshfpAlgorithmNames, rc.SshfpAlgorithm)
		if err != nil {
			return nil, fmt.Errorf("SSHFP algorithm: %w", err)
		}
		fingerprintType, err := nameFor(sshfpFingerprintTypeNames, rc.SshfpFingerprint)
		if err != nil {
			return nil, fmt.Errorf("SSHFP fingerprint type: %w", err)
		}
		v.Set("sshfpAlgorithm", algorithm)
		v.Set("sshfpFingerprintType", fingerprintType)
		v.Set("sshfpFingerprint", rc.GetTargetField())

	default:
		return nil, fmt.Errorf("unsupported record type %q", rc.Type)
	}

	return v, nil
}

// newValueParams returns the "new"-prefixed query parameters Update uses to
// carry the values a record is changing to. CNAME and DNAME are not included:
// a label can hold only one of either, so Update identifies the record by
// domain and type alone and currentParams already carries the (only) field
// as the value to set.
//
// NAPTR's new-value fields are named naptrNew* rather than newNaptr*, and
// ANAME's is newAName rather than newAname; both are exactly as documented in
// the Technitium API, not typos introduced here.
func newValueParams(rc *models.RecordConfig) (url.Values, error) {
	v := url.Values{}

	switch rc.Type {
	case "A", "AAAA":
		v.Set("newIpAddress", rc.GetTargetField())

	case "NS":
		v.Set("newNameServer", fromFQDN(rc.GetTargetField()))

	case "PTR":
		v.Set("newPtrName", fromFQDN(rc.GetTargetField()))

	case "ANAME":
		v.Set("newAName", fromFQDN(rc.GetTargetField()))

	case "MX":
		v.Set("newExchange", fromFQDN(rc.GetTargetField()))
		v.Set("newPreference", strconv.Itoa(int(rc.MxPreference)))

	case "TXT":
		v.Set("newText", rc.GetTargetTXTJoined())

	case "SRV":
		v.Set("newPriority", strconv.Itoa(int(rc.SrvPriority)))
		v.Set("newWeight", strconv.Itoa(int(rc.SrvWeight)))
		v.Set("newPort", strconv.Itoa(int(rc.SrvPort)))
		v.Set("newTarget", fromFQDN(rc.GetTargetField()))

	case "CAA":
		v.Set("newFlags", strconv.Itoa(int(rc.CaaFlag)))
		v.Set("newTag", rc.CaaTag)
		v.Set("newValue", rc.GetTargetField())

	case "NAPTR":
		v.Set("naptrNewOrder", strconv.Itoa(int(rc.NaptrOrder)))
		v.Set("naptrNewPreference", strconv.Itoa(int(rc.NaptrPreference)))
		v.Set("naptrNewFlags", rc.NaptrFlags)
		v.Set("naptrNewServices", rc.NaptrService)
		v.Set("naptrNewRegexp", rc.NaptrRegexp)
		v.Set("naptrNewReplacement", fromFQDN(rc.GetTargetField()))

	case "SVCB", "HTTPS":
		v.Set("newSvcPriority", strconv.Itoa(int(rc.SvcPriority)))
		v.Set("newSvcTargetName", fromFQDN(rc.GetTargetField()))
		v.Set("newSvcParams", svcParamsToTechnitium(rc.SvcParams))

	case "TLSA":
		usage, err := nameFor(tlsaCertificateUsageNames, rc.TlsaUsage)
		if err != nil {
			return nil, fmt.Errorf("TLSA certificate usage: %w", err)
		}
		selector, err := nameFor(tlsaSelectorNames, rc.TlsaSelector)
		if err != nil {
			return nil, fmt.Errorf("TLSA selector: %w", err)
		}
		matchingType, err := nameFor(tlsaMatchingTypeNames, rc.TlsaMatchingType)
		if err != nil {
			return nil, fmt.Errorf("TLSA matching type: %w", err)
		}
		v.Set("newTlsaCertificateUsage", usage)
		v.Set("newTlsaSelector", selector)
		v.Set("newTlsaMatchingType", matchingType)
		v.Set("newTlsaCertificateAssociationData", rc.GetTargetField())

	case "DS":
		algorithm, err := nameFor(dsAlgorithmNames, rc.DsAlgorithm)
		if err != nil {
			return nil, fmt.Errorf("DS algorithm: %w", err)
		}
		digestType, err := nameFor(dsDigestTypeNames, rc.DsDigestType)
		if err != nil {
			return nil, fmt.Errorf("DS digest type: %w", err)
		}
		v.Set("newKeyTag", strconv.Itoa(int(rc.DsKeyTag)))
		v.Set("newAlgorithm", algorithm)
		v.Set("newDigestType", digestType)
		v.Set("newDigest", rc.DsDigest)

	case "SSHFP":
		algorithm, err := nameFor(sshfpAlgorithmNames, rc.SshfpAlgorithm)
		if err != nil {
			return nil, fmt.Errorf("SSHFP algorithm: %w", err)
		}
		fingerprintType, err := nameFor(sshfpFingerprintTypeNames, rc.SshfpFingerprint)
		if err != nil {
			return nil, fmt.Errorf("SSHFP fingerprint type: %w", err)
		}
		v.Set("newSshfpAlgorithm", algorithm)
		v.Set("newSshfpFingerprintType", fingerprintType)
		v.Set("newSshfpFingerprint", rc.GetTargetField())

	default:
		return nil, fmt.Errorf("unsupported record type %q", rc.Type)
	}

	return v, nil
}

// updateParams returns the parameters for a Technitium update call: the
// fields identifying old (the record being replaced) plus the new-value
// fields for new. Both records share the same label and type - see the
// comment on diff2.ByRecord's CHANGE semantics in records.go.
func updateParams(old, current *models.RecordConfig) (url.Values, error) {
	if current.Type == "CNAME" || current.Type == "DNAME" {
		// Only one value can exist at the label, so Technitium identifies the
		// record by domain and type alone; the single field doubles as the new
		// value to set.
		return currentParams(current)
	}

	v, err := currentParams(old)
	if err != nil {
		return nil, err
	}
	newValues, err := newValueParams(current)
	if err != nil {
		return nil, err
	}
	for key, vals := range newValues {
		v[key] = vals
	}
	return v, nil
}

// svcParamsToTechnitium converts DNSControl's SvcParams ("key=value
// key2=value2", space separated) to Technitium's format (a flat pipe
// separated list: "key|value|key2|value2").
func svcParamsToTechnitium(params string) string {
	fields := strings.Fields(params)
	if len(fields) == 0 {
		return ""
	}

	parts := make([]string, 0, len(fields)*2)
	for _, field := range fields {
		key, value, _ := strings.Cut(field, "=")
		parts = append(parts, key, value)
	}
	return strings.Join(parts, "|")
}

// svcParamsFromTechnitium is the reverse of svcParamsToTechnitium.
func svcParamsFromTechnitium(params string) string {
	if params == "" {
		return ""
	}

	parts := strings.Split(params, "|")
	fields := make([]string, 0, len(parts)/2)
	for i := 0; i+1 < len(parts); i += 2 {
		fields = append(fields, parts[i]+"="+parts[i+1])
	}
	return strings.Join(fields, " ")
}
