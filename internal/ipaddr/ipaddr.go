package ipaddr

import (
	"fmt"
	"net/netip"
	"strings"
)

// Normalize returns one canonical textual form for an IPv4 or IPv6 address.
// IPv4-mapped IPv6 addresses are normalized to plain IPv4.
func Normalize(value string) (string, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(value))
	if err != nil {
		return "", fmt.Errorf("invalid IP address %q", strings.TrimSpace(value))
	}

	return addr.Unmap().String(), nil
}

// Equal reports whether two textual IP addresses identify the same address
// after canonicalization.
func Equal(left string, right string) bool {
	leftNormalized, err := Normalize(left)
	if err != nil {
		return false
	}
	rightNormalized, err := Normalize(right)
	if err != nil {
		return false
	}

	return leftNormalized == rightNormalized
}
