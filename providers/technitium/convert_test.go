package technitium

import (
	"net/url"
	"testing"

	"github.com/DNSControl/dnscontrol/v4/models"
)

const testOrigin = "example.com"

// TestRecordRoundTrip reads a record the way the API returns it, converts it
// back into the params an update would send, and checks that nothing was
// lost or renamed along the way.
func TestRecordRoundTrip(t *testing.T) {
	tests := []struct {
		name   string
		stored apiRecord
		verify func(t *testing.T, rc *models.RecordConfig, params url.Values)
	}{
		{
			name:   "A",
			stored: apiRecord{Name: "www.example.com", Type: "A", TTL: 300, RData: []byte(`{"ipAddress":"203.0.113.10"}`)},
		},
		{
			name:   "CNAME",
			stored: apiRecord{Name: "alias.example.com", Type: "CNAME", TTL: 300, RData: []byte(`{"cname":"www.example.net"}`)},
		},
		{
			name:   "MX splits off the preference",
			stored: apiRecord{Name: "example.com", Type: "MX", TTL: 300, RData: []byte(`{"exchange":"mail.example.net","preference":10}`)},
			verify: func(t *testing.T, rc *models.RecordConfig, params url.Values) {
				if params.Get("preference") != "10" {
					t.Errorf("preference = %q, want 10", params.Get("preference"))
				}
			},
		},
		{
			name:   "SRV splits off priority, weight and port",
			stored: apiRecord{Name: "_sip._tcp.example.com", Type: "SRV", TTL: 300, RData: []byte(`{"priority":10,"weight":60,"port":5060,"target":"sip.example.net"}`)},
			verify: func(t *testing.T, rc *models.RecordConfig, params url.Values) {
				if params.Get("priority") != "10" || params.Get("weight") != "60" || params.Get("port") != "5060" {
					t.Errorf("srv fields = %v", params)
				}
			},
		},
		{
			name:   "CAA splits off the flags and the tag",
			stored: apiRecord{Name: "example.com", Type: "CAA", TTL: 300, RData: []byte(`{"flags":0,"tag":"issue","value":"letsencrypt.org"}`)},
			verify: func(t *testing.T, rc *models.RecordConfig, params url.Values) {
				if params.Get("tag") != "issue" || params.Get("flags") != "0" {
					t.Errorf("caa fields = %v", params)
				}
			},
		},
		{
			name:   "DS translates the enum names to numbers and back",
			stored: apiRecord{Name: "child.example.com", Type: "DS", TTL: 300, RData: []byte(`{"keyTag":12345,"algorithm":"RSASHA256","digestType":"SHA256","digest":"2bb183af"}`)},
			verify: func(t *testing.T, rc *models.RecordConfig, params url.Values) {
				if rc.DsAlgorithm != 8 || rc.DsDigestType != 2 {
					t.Errorf("DsAlgorithm = %d, DsDigestType = %d, want 8, 2", rc.DsAlgorithm, rc.DsDigestType)
				}
				if params.Get("algorithm") != "RSASHA256" || params.Get("digestType") != "SHA256" {
					t.Errorf("ds fields = %v", params)
				}
			},
		},
		{
			name:   "SSHFP translates the enum names to numbers and back",
			stored: apiRecord{Name: "example.com", Type: "SSHFP", TTL: 300, RData: []byte(`{"sshfpAlgorithm":"ECDSA","sshfpFingerprintType":"SHA256","sshfpFingerprint":"abcdef"}`)},
			verify: func(t *testing.T, rc *models.RecordConfig, params url.Values) {
				if rc.SshfpAlgorithm != 3 || rc.SshfpFingerprint != 2 {
					t.Errorf("SshfpAlgorithm = %d, SshfpFingerprint = %d, want 3, 2", rc.SshfpAlgorithm, rc.SshfpFingerprint)
				}
				if params.Get("sshfpAlgorithm") != "ECDSA" || params.Get("sshfpFingerprintType") != "SHA256" {
					t.Errorf("sshfp fields = %v", params)
				}
			},
		},
		{
			name:   "TLSA translates the enum names to numbers and back",
			stored: apiRecord{Name: "_443._tcp.example.com", Type: "TLSA", TTL: 300, RData: []byte(`{"tlsaCertificateUsage":"DANE-EE","tlsaSelector":"SPKI","tlsaMatchingType":"SHA2-256","tlsaCertificateAssociationData":"abcdef"}`)},
			verify: func(t *testing.T, rc *models.RecordConfig, params url.Values) {
				if rc.TlsaUsage != 3 || rc.TlsaSelector != 1 || rc.TlsaMatchingType != 1 {
					t.Errorf("tlsa fields = %d %d %d, want 3 1 1", rc.TlsaUsage, rc.TlsaSelector, rc.TlsaMatchingType)
				}
			},
		},
		{
			name:   "NAPTR",
			stored: apiRecord{Name: "example.com", Type: "NAPTR", TTL: 300, RData: []byte(`{"naptrOrder":100,"naptrPreference":10,"naptrFlags":"u","naptrServices":"E2U+sip","naptrRegexp":"!^.*$!sip:info@example.com!","naptrReplacement":"."}`)},
			verify: func(t *testing.T, rc *models.RecordConfig, params url.Values) {
				if params.Get("naptrServices") != "E2U+sip" {
					t.Errorf("naptrServices = %q, want E2U+sip", params.Get("naptrServices"))
				}
			},
		},
		{
			name:   "SVCB translates pipe separated params to the DNSControl form",
			stored: apiRecord{Name: "example.com", Type: "SVCB", TTL: 300, RData: []byte(`{"svcPriority":1,"svcTargetName":"svc.example.net","svcParams":"alpn|h2,h3|port|53443"}`)},
			verify: func(t *testing.T, rc *models.RecordConfig, params url.Values) {
				if rc.SvcParams != "alpn=h2,h3 port=53443" {
					t.Errorf("SvcParams = %q, want %q", rc.SvcParams, "alpn=h2,h3 port=53443")
				}
				if params.Get("svcParams") != "alpn|h2,h3|port|53443" {
					t.Errorf("svcParams = %q, want alpn|h2,h3|port|53443", params.Get("svcParams"))
				}
			},
		},
		{
			name:   "TXT joins the character-strings",
			stored: apiRecord{Name: "example.com", Type: "TXT", TTL: 300, RData: []byte(`{"characterStrings":["v=spf1 ","-all"]}`)},
			verify: func(t *testing.T, rc *models.RecordConfig, params url.Values) {
				if rc.GetTargetTXTJoined() != "v=spf1 -all" {
					t.Errorf("TXT value = %q, want %q", rc.GetTargetTXTJoined(), "v=spf1 -all")
				}
			},
		},
		{
			name:   "ANAME keeps the wire type name",
			stored: apiRecord{Name: "example.com", Type: "ANAME", TTL: 300, RData: []byte(`{"aname":"target.example.net"}`)},
			verify: func(t *testing.T, rc *models.RecordConfig, params url.Values) {
				if rc.Type != "ANAME" {
					t.Errorf("Type = %q, want ANAME", rc.Type)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rc, err := toRecordConfig(tt.stored, testOrigin)
			if err != nil {
				t.Fatalf("toRecordConfig() error = %v", err)
			}
			if rc.TTL != tt.stored.TTL {
				t.Errorf("TTL = %d, want %d", rc.TTL, tt.stored.TTL)
			}

			params, err := currentParams(rc)
			if err != nil {
				t.Fatalf("currentParams() error = %v", err)
			}
			if tt.verify != nil {
				tt.verify(t, rc, params)
			}
		})
	}
}

func TestUpdateParamsCnameHasNoCurrentField(t *testing.T) {
	old := &models.RecordConfig{Type: "CNAME", TTL: 300}
	old.SetLabel("alias", testOrigin)
	if err := old.SetTarget("old.example.net."); err != nil {
		t.Fatalf("SetTarget() error = %v", err)
	}

	current := &models.RecordConfig{Type: "CNAME", TTL: 300}
	current.SetLabel("alias", testOrigin)
	if err := current.SetTarget("new.example.net."); err != nil {
		t.Fatalf("SetTarget() error = %v", err)
	}

	params, err := updateParams(old, current)
	if err != nil {
		t.Fatalf("updateParams() error = %v", err)
	}
	if got := params.Get("cname"); got != "new.example.net." {
		t.Errorf("cname = %q, want %q", got, "new.example.net.")
	}
	if params.Has("newCname") {
		t.Errorf("update params should not carry a newCname field: %v", params)
	}
}

func TestUpdateParamsCarriesOldAndNewValues(t *testing.T) {
	old := &models.RecordConfig{Type: "A", TTL: 300}
	old.SetLabel("www", testOrigin)
	if err := old.SetTarget("203.0.113.10"); err != nil {
		t.Fatalf("SetTarget() error = %v", err)
	}

	current := &models.RecordConfig{Type: "A", TTL: 300}
	current.SetLabel("www", testOrigin)
	if err := current.SetTarget("203.0.113.20"); err != nil {
		t.Fatalf("SetTarget() error = %v", err)
	}

	params, err := updateParams(old, current)
	if err != nil {
		t.Fatalf("updateParams() error = %v", err)
	}
	if params.Get("ipAddress") != "203.0.113.10" {
		t.Errorf("ipAddress = %q, want the old value 203.0.113.10", params.Get("ipAddress"))
	}
	if params.Get("newIpAddress") != "203.0.113.20" {
		t.Errorf("newIpAddress = %q, want the new value 203.0.113.20", params.Get("newIpAddress"))
	}
}

func TestSvcParamsConversion(t *testing.T) {
	tests := []struct {
		dnscontrol string
		technitium string
	}{
		{"", ""},
		{"alpn=h2,h3", "alpn|h2,h3"},
		{"alpn=h2,h3 port=53443", "alpn|h2,h3|port|53443"},
	}

	for _, tt := range tests {
		if got := svcParamsToTechnitium(tt.dnscontrol); got != tt.technitium {
			t.Errorf("svcParamsToTechnitium(%q) = %q, want %q", tt.dnscontrol, got, tt.technitium)
		}
		if got := svcParamsFromTechnitium(tt.technitium); got != tt.dnscontrol {
			t.Errorf("svcParamsFromTechnitium(%q) = %q, want %q", tt.technitium, got, tt.dnscontrol)
		}
	}
}
