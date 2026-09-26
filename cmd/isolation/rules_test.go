package main

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseResolvConf(t *testing.T) {
	plain := `
# generated
nameserver 1.1.1.1
nameserver 8.8.8.8
nameserver 1.1.1.1
search example.com
`
	got := parseResolvConf(plain)
	want := []string{"1.1.1.1", "8.8.8.8"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("plain got %v", got)
	}

	resolved := `
# This is /run/systemd/resolve/resolv.conf
nameserver 172.31.48.1
nameserver 2001:db8::53
options edns0 trust-ad
`
	got = parseResolvConf(resolved)
	want = []string{"172.31.48.1", "2001:db8::53"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("systemd got %v", got)
	}
	if parseResolvConf("nameserver not-an-ip\n") != nil {
		t.Fatal("rejected non-ip")
	}
}

func TestParseScutilDNS(t *testing.T) {
	text := `
resolver #1
  nameserver[0] : 192.168.1.1
  nameserver[1] : 8.8.8.8
  nameserver[2] : 192.168.1.1
resolver #2
  nameserver[0] : 2001:db8::1
`
	got := parseScutilDNS(text)
	want := []string{"192.168.1.1", "8.8.8.8", "2001:db8::1"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v", got)
	}
}

func TestPfRules(t *testing.T) {
	got := pfRules([]string{"10.0.0.5"}, []string{"1.2.3.4"}, []string{"192.168.1.1"})
	if strings.Contains(got, "from any port 53") {
		t.Fatalf("wide inbound dns:\n%s", got)
	}
	if strings.Contains(got, "to any port 53") {
		t.Fatalf("wide outbound dns:\n%s", got)
	}
	for _, part := range []string{
		"set skip on lo0",
		"<clr_fqdn>",
		"pass out proto { udp tcp } to 192.168.1.1 port 53",
		"pass in from 10.0.0.5",
		"pass out to <clr_fqdn>",
		"table <clr_fqdn> persist { 1.2.3.4 }",
	} {
		if !strings.Contains(got, part) {
			t.Fatalf("missing %q in\n%s", part, got)
		}
	}
}
