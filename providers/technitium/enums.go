package technitium

import "fmt"

// Technitium represents several DNSSEC-related numeric fields as their IANA
// registry names instead of the numbers themselves. DNSControl's RecordConfig
// stores the numbers, so the two are translated at the API boundary.

var dsAlgorithmNames = map[uint8]string{
	1:  "RSAMD5",
	3:  "DSA",
	5:  "RSASHA1",
	6:  "DSA-NSEC3-SHA1",
	7:  "RSASHA1-NSEC3-SHA1",
	8:  "RSASHA256",
	10: "RSASHA512",
	12: "ECC-GOST",
	13: "ECDSAP256SHA256",
	14: "ECDSAP384SHA384",
	15: "ED25519",
	16: "ED448",
}

var dsDigestTypeNames = map[uint8]string{
	1: "SHA1",
	2: "SHA256",
	3: "GOST-R-34-11-94",
	4: "SHA384",
}

var sshfpAlgorithmNames = map[uint8]string{
	1: "RSA",
	2: "DSA",
	3: "ECDSA",
	4: "Ed25519",
	6: "Ed448",
}

var sshfpFingerprintTypeNames = map[uint8]string{
	1: "SHA1",
	2: "SHA256",
}

var tlsaCertificateUsageNames = map[uint8]string{
	0: "PKIX-TA",
	1: "PKIX-EE",
	2: "DANE-TA",
	3: "DANE-EE",
}

var tlsaSelectorNames = map[uint8]string{
	0: "Cert",
	1: "SPKI",
}

var tlsaMatchingTypeNames = map[uint8]string{
	0: "Full",
	1: "SHA2-256",
	2: "SHA2-512",
}

// nameFor looks a numeric value up in one of the tables above.
func nameFor(table map[uint8]string, value uint8) (string, error) {
	name, ok := table[value]
	if !ok {
		return "", fmt.Errorf("value %d is not a recognized name in this table", value)
	}
	return name, nil
}

// valueFor is the reverse of nameFor, looking a Technitium enum name up to
// find the numeric value DNSControl stores.
func valueFor(table map[uint8]string, name string) (uint8, error) {
	for value, candidate := range table {
		if candidate == name {
			return value, nil
		}
	}
	return 0, fmt.Errorf("name %q is not recognized", name)
}
