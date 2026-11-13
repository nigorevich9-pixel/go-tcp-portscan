package portscan

import (
	"context"
	"net"
	"reflect"
	"strings"
	"testing"
)

func TestPortExpand(t *testing.T) {
	ok := []struct {
		spec PortSpec
		want []uint16
	}{
		{List(443, 80, 443, 1), []uint16{1, 80, 443}},
		{Range(2, 4), []uint16{2, 3, 4}},
		{Union(Range(1, 3), List(2, 80), Range(79, 81)), []uint16{1, 2, 3, 79, 80, 81}},
		{List(1), []uint16{1}},
		{List(65535), []uint16{65535}},
	}
	for _, c := range ok {
		got, err := c.spec.expand()
		if err != nil || !reflect.DeepEqual(got, c.want) {
			t.Fatalf("expand() = %v, %v; want %v", got, err, c.want)
		}
	}

	bad := []struct {
		spec PortSpec
		msg  string
	}{
		{List(0), "1..65535"},
		{List(65536), "1..65535"},
		{List(-3), "1..65535"},
		{Range(1000, 1), "задом"},
		{List(), "пустой"},
		{Union(), "пустой"},
		{PortSpec{}, "пустой"},
		{Union(Range(1, 3), List(0)), "1..65535"},
	}
	for _, c := range bad {
		_, err := c.spec.expand()
		if err == nil || !strings.Contains(err.Error(), c.msg) {
			t.Fatalf("spec=%v err=%v, ждали %q", c.spec, err, c.msg)
		}
	}
}

func TestHostnameCheck(t *testing.T) {
	good := []string{"localhost", "example.org", "EXAMPLE.ORG.", "xn--bcher-kva.example", "a-b.example"}
	for _, h := range good {
		if err := checkHostname(h); err != nil {
			t.Errorf("%q: %v", h, err)
		}
	}
	bad := []string{"", ".", "a..b", "-a.example", "a-.example", "example.org:443", "https://example.org", "[::1]", "256.255.255.255", "name_with_underscore"}
	for _, h := range bad {
		if err := checkHostname(h); err == nil {
			t.Errorf("%q прошёл, а не должен", h)
		}
	}
}

func TestResolveDedup(t *testing.T) {
	s, _ := New()
	lookups := 0
	s.lookup = func(_ context.Context, host string) ([]net.IPAddr, error) {
		lookups++
		if host != "Example.TEST" {
			t.Errorf("lookup %q", host)
		}
		return []net.IPAddr{
			{IP: net.ParseIP("192.0.2.10")},
			{IP: net.ParseIP("2001:db8::1")},
			{IP: net.ParseIP("192.0.2.10")},
		}, nil
	}

	got, err := s.resolve(context.Background(), []string{"Example.TEST", "example.test.", " 192.0.2.10 ", "192.0.2.10"})
	if err != nil {
		t.Fatal(err)
	}
	if lookups != 1 {
		t.Fatalf("dns вызывали %d раз", lookups)
	}
	if len(got) != 3 {
		t.Fatalf("targets=%v", got)
	}
}
