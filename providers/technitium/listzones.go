package technitium

import (
	"fmt"

	"github.com/DNSControl/dnscontrol/v4/models"
	"github.com/DNSControl/dnscontrol/v4/pkg/printer"
)

// ListZones returns every Primary zone the API token can see.
func (c *technitiumProvider) ListZones() ([]string, error) {
	zones, err := c.client.listZones("Primary")
	if err != nil {
		return nil, err
	}

	names := make([]string, 0, len(zones))
	for _, z := range zones {
		names = append(names, z.Name)
	}

	return names, nil
}

// EnsureZoneExists creates the zone as a Primary zone if the server does not have it yet.
func (c *technitiumProvider) EnsureZoneExists(dc *models.DomainConfig) error {
	exists, err := c.client.zoneExists(dc.Name)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}

	if err := c.client.createZone(dc.Name); err != nil {
		return fmt.Errorf("TECHNITIUM: creating zone %s: %w", dc.Name, err)
	}

	printer.Warnf("TECHNITIUM: Added zone %s\n", dc.Name)
	return nil
}
