package discovery

import "testing"

func TestNormalizeWildcardListenHost(t *testing.T) {
	cases := map[string]string{
		"":            "127.0.0.1",
		"0.0.0.0":     "127.0.0.1",
		"::":          "127.0.0.1",
		"[::]":        "127.0.0.1",
		"  ::  ":      "127.0.0.1",
		"127.0.0.1":   "127.0.0.1",
		"10.0.0.5":    "10.0.0.5",
		"::1":         "::1",
		"example.lan": "example.lan",
	}

	for input, want := range cases {
		if got := normalizeWildcardListenHost(input); got != want {
			t.Fatalf("normalizeWildcardListenHost(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestXrayAPIServerAddressFormatsIPv6WithBrackets(t *testing.T) {
	server, err := xrayAPIServerAddress(APIEndpoint{
		Network: EndpointNetworkTCP,
		Address: "::1",
		Port:    10085,
	})
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if server != "[::1]:10085" {
		t.Fatalf("expected bracketed IPv6 server address, got %q", server)
	}
}

func TestXrayAPIServerAddressCollapsesBracketedWildcard(t *testing.T) {
	server, err := xrayAPIServerAddress(APIEndpoint{
		Network: EndpointNetworkTCP,
		Address: "[::]",
		Port:    10085,
	})
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if server != "127.0.0.1:10085" {
		t.Fatalf("expected wildcard to collapse to loopback, got %q", server)
	}
}

func TestXrayAPIServerAddressCollapsesIPv4Wildcards(t *testing.T) {
	for _, address := range []string{"", "0.0.0.0", "::"} {
		server, err := xrayAPIServerAddress(APIEndpoint{
			Network: EndpointNetworkTCP,
			Address: address,
			Port:    10085,
		})
		if err != nil {
			t.Fatalf("address %q: expected success, got %v", address, err)
		}
		if server != "127.0.0.1:10085" {
			t.Fatalf("address %q: expected loopback server address, got %q", address, server)
		}
	}
}

func TestNormalizeXrayClientIPStripsHostPort(t *testing.T) {
	cases := map[string]string{
		"1.2.3.4:443":         "1.2.3.4",
		"[2001:db8::1]:443":   "2001:db8::1",
		"1.2.3.4":             "1.2.3.4",
		"2001:db8::1":         "2001:db8::1",
		"::ffff:1.2.3.4":      "1.2.3.4",
		"  203.0.113.7:9000 ": "203.0.113.7",
	}

	for input, want := range cases {
		if got := normalizeXrayClientIP(input); got != want {
			t.Fatalf("normalizeXrayClientIP(%q) = %q, want %q", input, got, want)
		}
	}
}
