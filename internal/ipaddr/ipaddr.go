package ipaddr

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// ErrInvalidIP is the sentinel cause returned (wrapped) by Normalize when a
// value is not a valid IP address. Callers that wrap Normalize's error with %w
// allow operators and tests to match the root cause via errors.Is.
var ErrInvalidIP = errors.New("invalid IP address")

// Normalize returns one canonical textual form for an IPv4 or IPv6 address.
// IPv4-mapped IPv6 addresses are normalized to plain IPv4.
func Normalize(value string) (string, error) {
	trimmed := strings.TrimSpace(value)
	addr, err := netip.ParseAddr(trimmed)
	if err != nil {
		return "", fmt.Errorf("%w %q: %v", ErrInvalidIP, trimmed, err)
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
