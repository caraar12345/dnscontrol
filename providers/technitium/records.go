package technitium

import (
	"fmt"

	"github.com/DNSControl/dnscontrol/v4/models"
	"github.com/DNSControl/dnscontrol/v4/pkg/diff2"
	"github.com/DNSControl/dnscontrol/v4/pkg/printer"
)

// managedByServer are record types that Technitium generates and maintains
// itself: the SOA, and the DNSSEC records of a signed zone. None of them can
// be written through the records API, so reporting them would make every run
// plan a change it cannot apply.
var managedByServer = map[string]bool{
	"SOA":        true,
	"RRSIG":      true,
	"DNSKEY":     true,
	"NSEC":       true,
	"NSEC3":      true,
	"NSEC3PARAM": true,
}

// GetZoneRecords gets the records of a zone and returns them in RecordConfig format.
func (c *technitiumProvider) GetZoneRecords(dc *models.DomainConfig) (models.Records, error) {
	nativeRecs, err := c.client.getZoneRecords(dc.Name)
	if err != nil {
		return nil, err
	}

	recs := make(models.Records, 0, len(nativeRecs))
	for _, nativeRec := range nativeRecs {
		if managedByServer[nativeRec.Type] {
			continue
		}

		rc, err := toRecordConfig(nativeRec, dc.Name)
		if err != nil {
			printer.Warnf("TECHNITIUM: ignoring unsupported record type %s at %s: %v\n", nativeRec.Type, nativeRec.Name, err)
			continue
		}
		recs = append(recs, rc)
	}

	return recs, nil
}

// GetZoneRecordsCorrections returns a list of corrections that will turn existing records into dc.Records.
func (c *technitiumProvider) GetZoneRecordsCorrections(dc *models.DomainConfig, existing models.Records) ([]*models.Correction, int, error) {
	// Technitium calls DNSControl's ALIAS record type ANAME. Renaming the
	// desired side here, before diffing, means both sides use the same type
	// name and diff2 can compare them as the same record; toRecordConfig does
	// the same on the existing side (see convert.go).
	for _, rec := range dc.Records {
		if rec.Type == "ALIAS" {
			rec.ChangeType("ANAME", dc.Name)
		}
	}

	instructions, actualChangeCount, err := diff2.ByRecord(existing, dc, nil)
	if err != nil {
		return nil, 0, err
	}

	var corrections []*models.Correction
	for _, inst := range instructions {
		switch inst.Type {
		case diff2.REPORT:
			corrections = append(corrections, inst.CreateMessage())

		case diff2.CREATE:
			newRec := inst.New[0]
			params, err := currentParams(newRec)
			if err != nil {
				return nil, 0, err
			}
			corrections = append(corrections, inst.CreateCorrection(func() error {
				return c.client.addRecord(dc.Name, newRec.GetLabelFQDN(), newRec.Type, newRec.TTL, params)
			}))

		case diff2.CHANGE:
			// ByRecord's CHANGE always pairs an old and a new record that share
			// the same label and type; only the record's own fields (and
			// possibly the TTL) differ. See diff2.ByRecord's doc comment.
			oldRec, newRec := inst.Old[0], inst.New[0]
			params, err := updateParams(oldRec, newRec)
			if err != nil {
				return nil, 0, err
			}
			corrections = append(corrections, inst.CreateCorrection(func() error {
				return c.client.updateRecord(dc.Name, newRec.GetLabelFQDN(), newRec.Type, newRec.TTL, params)
			}))

		case diff2.DELETE:
			oldRec := inst.Old[0]
			params, err := currentParams(oldRec)
			if err != nil {
				return nil, 0, err
			}
			corrections = append(corrections, inst.CreateCorrection(func() error {
				return c.client.deleteRecord(dc.Name, oldRec.GetLabelFQDN(), oldRec.Type, params)
			}))

		default:
			panic(fmt.Sprintf("unhandled inst.Type %s", inst.Type))
		}
	}

	return corrections, actualChangeCount, nil
}
