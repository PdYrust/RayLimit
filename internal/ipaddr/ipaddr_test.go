package ipaddr

import "testing"

func TestNormalizeCanonicalizesIPv4IPv6AndMappedIPv4(t *testing.T) {
	tests := []struct {
		raw  string
		want string
	}{
		{raw: "203.0.113.10", want: "203.0.113.10"},
		{raw: "2001:0db8::0010", want: "2001:db8::10"},
		{raw: "::ffff:203.0.113.10", want: "203.0.113.10"},
	}

	for _, test := range tests {
		got, err := Normalize(test.raw)
		if err != nil {
			t.Fatalf("expected %q to normalize, got %v", test.raw, err)
		}
		if got != test.want {
			t.Fatalf("expected %q to normalize to %q, got %q", test.raw, test.want, got)
		}
	}
}

func TestEqualUsesCanonicalIPIdentity(t *testing.T) {
	if !Equal("2001:0db8::0010", "2001:db8::10") {
		t.Fatal("expected equivalent ipv6 forms to compare equal")
	}
	if !Equal("::ffff:203.0.113.10", "203.0.113.10") {
		t.Fatal("expected mapped ipv4 form to compare equal to ipv4")
	}
	if Equal("203.0.113.10", "203.0.113.11") {
		t.Fatal("expected different addresses to compare unequal")
	}
}
