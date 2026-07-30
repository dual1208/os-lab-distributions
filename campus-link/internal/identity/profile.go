package identity

import (
	"crypto/x509"
	"encoding/asn1"
	"net/url"
	"strings"
)

var subjectAltNameOID = asn1.ObjectIdentifier{2, 5, 29, 17}

// expectedIdentityDNS validates the canonical campus-link SPIFFE shape and
// returns the sole DNS SAN permitted for that identity. An empty result means
// that the profile permits no DNS SAN.
func expectedIdentityDNS(uriText string) (string, error) {
	parsed, err := url.Parse(uriText)
	if err != nil || parsed.Scheme != "spiffe" || parsed.Host != "campus-link" ||
		parsed.User != nil || parsed.Opaque != "" || parsed.RawPath != "" ||
		parsed.ForceQuery || parsed.RawQuery != "" || parsed.Fragment != "" ||
		parsed.String() != uriText {
		return "", ErrPeerIdentity
	}
	parts := strings.Split(strings.TrimPrefix(parsed.Path, "/"), "/")
	if !strings.HasPrefix(parsed.Path, "/") || len(parts) != 3 ||
		!canonicalIdentitySegment(parts[0]) {
		return "", ErrPeerIdentity
	}
	switch parts[1] + "/" + parts[2] {
	case "relay/control":
		return "gz.campus-link", nil
	case "site-a/control", "site-b/control":
		return "", nil
	case "site-a/data":
		return "site-a.campus-link", nil
	case "site-b/data":
		return "site-b.campus-link", nil
	default:
		return "", ErrPeerIdentity
	}
}

func canonicalIdentitySegment(value string) bool {
	if value == "" || value == "." || value == ".." {
		return false
	}
	for _, c := range []byte(value) {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '-' || c == '.' ||
			c == '_' || c == '~' {
			continue
		}
		return false
	}
	return true
}

func hasExactSANProfile(leaf *x509.Certificate, uriText, dnsName string) bool {
	if leaf == nil || len(leaf.URIs) != 1 || leaf.URIs[0] == nil ||
		leaf.URIs[0].String() != uriText || len(leaf.IPAddresses) != 0 ||
		len(leaf.EmailAddresses) != 0 {
		return false
	}
	if dnsName == "" {
		if len(leaf.DNSNames) != 0 {
			return false
		}
	} else if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != dnsName {
		return false
	}

	// Parse the SAN extension as GeneralNames too. crypto/x509 intentionally
	// ignores several GeneralName choices; accepting those would violate the
	// exact-profile contract even though they cannot affect Go hostname checks.
	extensions := 0
	for _, extension := range leaf.Extensions {
		if !extension.Id.Equal(subjectAltNameOID) {
			continue
		}
		extensions++
		var sequence asn1.RawValue
		rest, err := asn1.Unmarshal(extension.Value, &sequence)
		if err != nil || len(rest) != 0 || sequence.Class != asn1.ClassUniversal ||
			sequence.Tag != asn1.TagSequence || !sequence.IsCompound {
			return false
		}
		uriCount, dnsCount := 0, 0
		for names := sequence.Bytes; len(names) != 0; {
			var name asn1.RawValue
			remaining, err := asn1.Unmarshal(names, &name)
			if err != nil || len(remaining) >= len(names) ||
				name.Class != asn1.ClassContextSpecific || name.IsCompound {
				return false
			}
			switch name.Tag {
			case 2: // dNSName
				dnsCount++
				if dnsName == "" || string(name.Bytes) != dnsName {
					return false
				}
			case 6: // uniformResourceIdentifier
				uriCount++
				if string(name.Bytes) != uriText {
					return false
				}
			default:
				return false
			}
			names = remaining
		}
		wantDNS := 0
		if dnsName != "" {
			wantDNS = 1
		}
		if uriCount != 1 || dnsCount != wantDNS {
			return false
		}
	}
	return extensions == 1
}
