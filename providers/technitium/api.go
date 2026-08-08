package technitium

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// defaultTTL is the TTL Technitium gives a record that is created without one.
const defaultTTL = 3600

// apiClient is a thin wrapper around the Technitium DNS Server HTTP API.
type apiClient struct {
	baseURL    string
	apiToken   string
	httpClient *http.Client
}

// apiEnvelope is the envelope every response is wrapped in.
type apiEnvelope struct {
	Response     json.RawMessage `json:"response"`
	Status       string          `json:"status"`
	ErrorMessage string          `json:"errorMessage"`
	StackTrace   string          `json:"stackTrace"`
	InnerError   string          `json:"innerErrorMessage"`
}

// apiError is returned when the server answers with status "error" or
// "invalid-token".
type apiError struct {
	Status  string
	Message string
}

func (e *apiError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("TECHNITIUM: API error: %s", e.Status)
	}
	return fmt.Sprintf("TECHNITIUM: API error: %s", e.Message)
}

// apiZone is a zone as returned by the zone list and record endpoints.
type apiZone struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

// apiZoneListResponse is the response of GET /api/zones/list.
type apiZoneListResponse struct {
	Zones      []apiZone `json:"zones"`
	PageNumber int       `json:"pageNumber"`
	TotalPages int       `json:"totalPages"`
	TotalZones int       `json:"totalZones"`
}

// apiRecord is one record as returned by GET /api/zones/records/get. Name is
// the record's fully qualified domain name, not a name relative to the zone.
type apiRecord struct {
	Disabled bool            `json:"disabled"`
	Name     string          `json:"name"`
	Type     string          `json:"type"`
	TTL      uint32          `json:"ttl"`
	RData    json.RawMessage `json:"rData"`
}

// apiRecordsResponse is the response of GET /api/zones/records/get.
type apiRecordsResponse struct {
	Zone    apiZone     `json:"zone"`
	Records []apiRecord `json:"records"`
}

func newAPIClient(baseURL, token string) *apiClient {
	return &apiClient{
		baseURL:  strings.TrimSuffix(baseURL, "/"),
		apiToken: token,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// listZones returns every zone the API token can see, optionally filtered by
// Technitium zone type.
func (c *apiClient) listZones(filterType string) ([]apiZone, error) {
	query := url.Values{}
	if filterType != "" {
		query.Set("filterType", filterType)
	}

	var all []apiZone
	for page := 1; ; page++ {
		query.Set("pageNumber", fmt.Sprintf("%d", page))

		var resp apiZoneListResponse
		if err := c.get("/api/zones/list", query, &resp); err != nil {
			return nil, err
		}
		all = append(all, resp.Zones...)
		if page >= resp.TotalPages {
			return all, nil
		}
	}
}

// zoneExists reports whether a zone of the given name exists.
func (c *apiClient) zoneExists(name string) (bool, error) {
	zones, err := c.listZones("Primary")
	if err != nil {
		return false, err
	}
	for _, z := range zones {
		if z.Name == name {
			return true, nil
		}
	}
	return false, nil
}

// createZone creates a new Primary zone.
func (c *apiClient) createZone(name string) error {
	query := url.Values{
		"zone": {name},
		"type": {"Primary"},
	}
	return c.get("/api/zones/create", query, nil)
}

// getZoneRecords returns every record in the zone, including those managed
// by Technitium itself (SOA, DNSSEC records, and so on).
func (c *apiClient) getZoneRecords(zone string) ([]apiRecord, error) {
	query := url.Values{
		"domain":   {zone},
		"zone":     {zone},
		"listZone": {"true"},
	}
	var resp apiRecordsResponse
	if err := c.get("/api/zones/records/get", query, &resp); err != nil {
		return nil, err
	}
	return resp.Records, nil
}

// addRecord adds a record to a zone. params carries the type-specific fields.
func (c *apiClient) addRecord(zone, domain, rtype string, ttl uint32, params url.Values) error {
	query := cloneValues(params)
	query.Set("domain", domain)
	query.Set("zone", zone)
	query.Set("type", rtype)
	query.Set("ttl", fmt.Sprintf("%d", ttl))
	return c.get("/api/zones/records/add", query, nil)
}

// updateRecord updates a record in a zone. params carries both the current
// (identifying) fields and the new-value fields.
func (c *apiClient) updateRecord(zone, domain, rtype string, ttl uint32, params url.Values) error {
	query := cloneValues(params)
	query.Set("domain", domain)
	query.Set("zone", zone)
	query.Set("type", rtype)
	query.Set("ttl", fmt.Sprintf("%d", ttl))
	return c.get("/api/zones/records/update", query, nil)
}

// deleteRecord removes a record from a zone. params carries the fields that
// identify which value to remove from the label's record set.
func (c *apiClient) deleteRecord(zone, domain, rtype string, params url.Values) error {
	query := cloneValues(params)
	query.Set("domain", domain)
	query.Set("zone", zone)
	query.Set("type", rtype)
	return c.get("/api/zones/records/delete", query, nil)
}

func cloneValues(v url.Values) url.Values {
	out := make(url.Values, len(v))
	for k, vs := range v {
		out[k] = append([]string(nil), vs...)
	}
	return out
}

// get performs a GET request against the API, unwrapping the response
// envelope into result. Technitium accepts POST for the same calls, but
// every call this provider makes is idempotent to retry, so GET is used
// throughout for simplicity.
func (c *apiClient) get(path string, query url.Values, result any) error {
	u := c.baseURL + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}

	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.apiToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var envelope apiEnvelope
	if err := json.Unmarshal(body, &envelope); err != nil {
		return fmt.Errorf("TECHNITIUM: could not parse API response: %w", err)
	}

	switch envelope.Status {
	case "ok":
		if result == nil || len(envelope.Response) == 0 {
			return nil
		}
		return json.Unmarshal(envelope.Response, result)
	case "invalid-token":
		return &apiError{Status: envelope.Status, Message: "the API token was rejected"}
	case "2fa-required":
		return &apiError{Status: envelope.Status, Message: "the API token requires two-factor authentication, which this provider does not support"}
	default:
		msg := envelope.ErrorMessage
		if envelope.InnerError != "" {
			msg = fmt.Sprintf("%s (%s)", msg, envelope.InnerError)
		}
		return &apiError{Status: envelope.Status, Message: msg}
	}
}
