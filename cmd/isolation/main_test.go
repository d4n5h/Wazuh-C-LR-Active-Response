package main

import (
	"errors"
	"net"
	"reflect"
	"strings"
	"testing"
)

func TestIsValidIP(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"10.0.0.5", true},
		{"10.0.0.0/24", true},
		{"2001:db8::1", true},
		{"manager.example.com", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := isValidIP(tc.in); got != tc.want {
			t.Errorf("isValidIP(%q)=%v want %v", tc.in, got, tc.want)
		}
	}
}

func TestIsFQDN(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"manager.example.com", true},
		{"a.b", true},
		{"localhost", false},
		{"-bad.example.com", false},
		{"bad_name.example.com", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := isFQDN(tc.in); got != tc.want {
			t.Errorf("isFQDN(%q)=%v want %v", tc.in, got, tc.want)
		}
	}
}

func TestSameSet(t *testing.T) {
	if !sameSet([]string{"b", "a"}, []string{"a", "b"}) {
		t.Fatal("order should not matter")
	}
	if sameSet([]string{"a"}, []string{"a", "b"}) {
		t.Fatal("different lengths")
	}
	if sameSet([]string{"a", "a"}, []string{"a", "b"}) {
		t.Fatal("different members")
	}
}

func TestDiff(t *testing.T) {
	add, remove := diff([]string{"1.1.1.1", "2.2.2.2"}, []string{"2.2.2.2", "3.3.3.3"})
	if !reflect.DeepEqual(add, []string{"3.3.3.3"}) || !reflect.DeepEqual(remove, []string{"1.1.1.1"}) {
		t.Fatalf("add=%v remove=%v", add, remove)
	}
	add, remove = diff(nil, []string{"1.1.1.1"})
	if !reflect.DeepEqual(add, []string{"1.1.1.1"}) || remove != nil {
		t.Fatalf("add=%v remove=%v", add, remove)
	}
}

func TestResolveEach(t *testing.T) {
	ok := func(name string) ([]net.IP, error) {
		switch name {
		case "good.example":
			return []net.IP{net.ParseIP("1.2.3.4"), net.ParseIP("2001:db8::5")}, nil
		case "also.example":
			return []net.IP{net.ParseIP("5.5.5.5")}, nil
		default:
			return nil, errors.New("no such host")
		}
	}
	got, complete := resolveEach([]string{"good.example", "also.example"}, []string{"9.9.9.9"}, ok)
	if !complete {
		t.Fatal("expected complete")
	}
	want := []string{"1.2.3.4", "2001:db8::5", "5.5.5.5"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v", got)
	}

	got, complete = resolveEach([]string{"good.example", "missing.example"}, []string{"9.9.9.9", "1.2.3.4"}, ok)
	if complete {
		t.Fatal("expected incomplete")
	}
	want = []string{"1.2.3.4", "2001:db8::5", "9.9.9.9"}
	if !sameSet(got, want) {
		t.Fatalf("merge got %v want %v", got, want)
	}

	got, complete = resolveEach([]string{"empty.example"}, []string{"9.9.9.9"}, func(string) ([]net.IP, error) {
		return nil, nil
	})
	if complete || !sameSet(got, []string{"9.9.9.9"}) {
		t.Fatalf("empty lookup complete=%v got=%v", complete, got)
	}
}

func TestSummaryOmitsNoise(t *testing.T) {
	line := summaryLine([]string{"10.0.0.5"}, nil, []string{"172.31.48.1"}, "C-LR-FQDN", nil)
	if strings.Contains(line, "Ok.") {
		t.Fatalf("summary has command noise: %s", line)
	}
	if len(line) > 300 {
		t.Fatalf("summary too long: %d", len(line))
	}
}

func TestImportOKKeepsBackup(t *testing.T) {
	if !importOK("Ok.\r\n", "") {
		t.Fatal("successful import")
	}
	if importOK("", "Access is denied.") || importOK("The requested operation requires elevation.", "") {
		t.Fatal("failed import must keep the backup")
	}
}
