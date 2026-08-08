package technitium

import (
	"testing"

	"github.com/DNSControl/dnscontrol/v4/models"
)

func TestAuditRecords(t *testing.T) {
	tests := []struct {
		name      string
		record    *models.RecordConfig
		wantCount int
	}{
		{
			name:      "a TXT record with content is fine",
			record:    makeRecord(t, "TXT", "@", "v=spf1 -all"),
			wantCount: 0,
		},
		{
			name:      "an empty TXT record is rejected",
			record:    auditTXT(t, ""),
			wantCount: 1,
		},
		{
			name:      "a LOC record is not a type this provider supports",
			record:    &models.RecordConfig{Type: "LOC"},
			wantCount: 1,
		},
		{
			name:      "an SVCB record with a literal value is fine",
			record:    auditSVCB(t, "alpn=h2,h3 ipv4hint=203.0.113.10"),
			wantCount: 0,
		},
		{
			name:      "an SVCB record asking for an automatic hint is rejected",
			record:    auditSVCB(t, "alpn=h2,h3 ipv4hint=auto"),
			wantCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errs := AuditRecords([]*models.RecordConfig{tt.record})
			if len(errs) != tt.wantCount {
				t.Errorf("AuditRecords() returned %d errors, want %d: %v", len(errs), tt.wantCount, errs)
			}
		})
	}
}

func auditTXT(t *testing.T, target string) *models.RecordConfig {
	t.Helper()

	rc := &models.RecordConfig{Type: "TXT"}
	rc.SetLabel("@", testOrigin)
	if err := rc.SetTargetTXT(target); err != nil {
		t.Fatalf("SetTargetTXT() error = %v", err)
	}
	return rc
}

func auditSVCB(t *testing.T, params string) *models.RecordConfig {
	t.Helper()

	rc := &models.RecordConfig{Type: "SVCB", SvcParams: params}
	rc.SetLabel("@", testOrigin)
	if err := rc.SetTarget("svc.example.net."); err != nil {
		t.Fatalf("SetTarget() error = %v", err)
	}
	return rc
}

func makeRecord(t *testing.T, rtype, label, target string) *models.RecordConfig {
	t.Helper()

	rc := &models.RecordConfig{Type: rtype}
	rc.SetLabel(label, testOrigin)
	if err := rc.PopulateFromString(rtype, target, testOrigin); err != nil {
		t.Fatalf("PopulateFromString() error = %v", err)
	}
	return rc
}
