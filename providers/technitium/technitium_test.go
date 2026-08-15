package technitium

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/DNSControl/dnscontrol/v4/models"
)

func TestGetZoneRecords(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/zones/records/get":
			_, _ = w.Write([]byte(`{"response":{"zone":{"name":"example.com","type":"Primary"},"records":[
				{"disabled":false,"name":"example.com","type":"SOA","ttl":3600,"rData":{"primaryNameServer":"ns1.example.com","responsiblePerson":"hostadmin.example.com","serial":1,"refresh":3600,"retry":300,"expire":604800,"minimum":3600}},
				{"disabled":false,"name":"example.com","type":"NS","ttl":3600,"rData":{"nameServer":"ns1.example.com"}},
				{"disabled":false,"name":"www.example.com","type":"A","ttl":300,"rData":{"ipAddress":"203.0.113.10"}}
			]},"status":"ok"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	p := testProvider(server.URL)
	recs, err := p.GetZoneRecords(&models.DomainConfig{Name: "example.com"})
	if err != nil {
		t.Fatalf("GetZoneRecords() error = %v", err)
	}

	// The SOA record is maintained by the server and must not be reported; the
	// apex NS record is a normal, DNSControl-managed record on Technitium and
	// must be.
	if len(recs) != 2 {
		t.Fatalf("GetZoneRecords() returned %d records, want 2: %v", len(recs), recs)
	}
	if recs[0].Type != "NS" || recs[0].GetLabel() != "@" {
		t.Errorf("first record = %s %s, want NS @", recs[0].Type, recs[0].GetLabel())
	}
	if recs[1].Type != "A" || recs[1].GetTargetField() != "203.0.113.10" {
		t.Errorf("second record = %s %s, want A 203.0.113.10", recs[1].Type, recs[1].GetTargetField())
	}
}

// TestGetZoneRecordsCorrectionsNoFalseDiffOnAbsoluteHostnames reproduces a
// report from real-world use: Technitium's API returns an MX/CNAME/SRV target
// that is already absolute but without the trailing dot DNSControl uses to
// recognize that, and models.CanonicalizeTargets() - which the framework runs
// on both existing and desired records before diffing, outside this package -
// would otherwise treat the dotless value as a shortname and append the
// zone's origin to it a second time, turning a no-op run into a bogus MODIFY.
func TestGetZoneRecordsCorrectionsNoFalseDiffOnAbsoluteHostnames(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/zones/records/get":
			_, _ = w.Write([]byte(`{"response":{"zone":{"name":"example.com","type":"Primary"},"records":[
				{"disabled":false,"name":"svc.example.com","type":"MX","ttl":300,"rData":{"exchange":"mail.svc.example.com","preference":10}},
				{"disabled":false,"name":"autoconfig.mail.svc.example.com","type":"CNAME","ttl":300,"rData":{"cname":"mail.svc.example.com"}}
			]},"status":"ok"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	p := testProvider(server.URL)
	existing, err := p.GetZoneRecords(&models.DomainConfig{Name: "example.com"})
	if err != nil {
		t.Fatalf("GetZoneRecords() error = %v", err)
	}

	mx := &models.RecordConfig{Type: "MX", TTL: 300}
	mx.SetLabel("svc", "example.com")
	if err := mx.SetTargetMX(10, "mail.svc.example.com."); err != nil {
		t.Fatalf("SetTargetMX() error = %v", err)
	}
	cname := &models.RecordConfig{Type: "CNAME", TTL: 300}
	cname.SetLabel("autoconfig.mail.svc", "example.com")
	if err := cname.SetTarget("mail.svc.example.com."); err != nil {
		t.Fatalf("SetTarget() error = %v", err)
	}
	dc := &models.DomainConfig{Name: "example.com", Records: models.Records{mx, cname}}

	// The framework runs this on both sides before calling
	// GetZoneRecordsCorrections; simulate that here rather than duplicating
	// diff2's own machinery.
	models.CanonicalizeTargets(existing, dc.Name)
	models.CanonicalizeTargets(dc.Records, dc.Name)

	_, changeCount, err := p.GetZoneRecordsCorrections(dc, existing)
	if err != nil {
		t.Fatalf("GetZoneRecordsCorrections() error = %v", err)
	}
	if changeCount != 0 {
		t.Errorf("GetZoneRecordsCorrections() reported %d changes for identical records, want 0 (existing: %s, %s)",
			changeCount, existing[0].GetTargetField(), existing[1].GetTargetField())
	}
}

func TestEnsureZoneExists(t *testing.T) {
	var created []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/zones/create":
			created = append(created, r.URL.Query().Get("zone"))
			_, _ = w.Write([]byte(`{"response":{"domain":"new.example.com"},"status":"ok"}`))
		case "/api/zones/list":
			_, _ = w.Write([]byte(`{"response":{"zones":[{"name":"example.com","type":"Primary"}],"pageNumber":1,"totalPages":1,"totalZones":1},"status":"ok"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	p := testProvider(server.URL)
	if err := p.EnsureZoneExists(&models.DomainConfig{Name: "example.com"}); err != nil {
		t.Fatalf("EnsureZoneExists() error = %v", err)
	}
	if len(created) != 0 {
		t.Errorf("an existing zone was created again: %v", created)
	}

	if err := p.EnsureZoneExists(&models.DomainConfig{Name: "new.example.com"}); err != nil {
		t.Fatalf("EnsureZoneExists() error = %v", err)
	}
	if len(created) != 1 || created[0] != "new.example.com" {
		t.Errorf("created = %v, want [new.example.com]", created)
	}
}

func TestGetNameservers(t *testing.T) {
	p := &technitiumProvider{}
	nameservers, err := models.ToNameservers([]string{"ns1.example.com", "ns2.example.com"})
	if err != nil {
		t.Fatalf("ToNameservers() error = %v", err)
	}
	p.nameservers = nameservers

	got, err := p.GetNameservers("example.com")
	if err != nil {
		t.Fatalf("GetNameservers() error = %v", err)
	}
	if len(got) != 2 || got[0].Name != "ns1.example.com" {
		t.Errorf("GetNameservers() = %v, want ns1.example.com, ns2.example.com", got)
	}
}

func testProvider(baseURL string) *technitiumProvider {
	return &technitiumProvider{
		client: newAPIClient(baseURL, "not-a-real-token"),
	}
}
