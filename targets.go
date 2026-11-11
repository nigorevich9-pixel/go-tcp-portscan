package portscan

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"unicode"
)

type target struct {
	host string
	ip   netip.Addr
}

func (s *Scanner) resolve(ctx context.Context, hosts []string) ([]target, error) {
	if len(hosts) == 0 {
		return nil, fmt.Errorf("portscan: не заданы хосты")
	}

	seenHost := make(map[string]struct{}, len(hosts))
	var out []target

	for i, raw := range hosts {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		host := strings.TrimSpace(raw)
		if host == "" {
			return nil, fmt.Errorf("portscan: пустой хост (индекс %d)", i)
		}

		if addr, err := netip.ParseAddr(host); err == nil {
			key := "ip:" + addr.String()
			if _, ok := seenHost[key]; ok {
				continue
			}
			seenHost[key] = struct{}{}
			out = append(out, target{host: host, ip: addr})
			continue
		}

		if err := checkHostname(host); err != nil {
			return nil, fmt.Errorf("portscan: плохой хост %q: %w", host, err)
		}
		key := "dns:" + strings.ToLower(strings.TrimSuffix(host, "."))
		if _, ok := seenHost[key]; ok {
			continue
		}
		seenHost[key] = struct{}{}

		addrs, err := s.lookup(ctx, host)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, fmt.Errorf("portscan: dns %q: %w", host, err)
		}

		seenIP := make(map[netip.Addr]struct{})
		ok := false
		for _, a := range addrs {
			ip, valid := netip.AddrFromSlice(a.IP)
			if !valid || !ip.IsValid() {
				continue
			}
			ip = ip.Unmap()
			if a.Zone != "" && ip.Is6() {
				ip = ip.WithZone(a.Zone)
			}
			if _, dup := seenIP[ip]; dup {
				continue
			}
			seenIP[ip] = struct{}{}
			out = append(out, target{host: host, ip: ip})
			ok = true
		}
		if !ok {
			return nil, fmt.Errorf("portscan: dns %q: нет A/AAAA", host)
		}
	}
	return out, nil
}

func checkHostname(host string) error {
	name := strings.TrimSuffix(host, ".")
	if name == "" || len(name) > 253 {
		return fmt.Errorf("странная длина имени")
	}
	if strings.Contains(host, ":") || strings.Contains(host, "/") {
		return fmt.Errorf("ожидался hostname, не url/host:port")
	}

	onlyDigitsAndDots := true
	for _, r := range name {
		if r != '.' && !unicode.IsDigit(r) {
			onlyDigitsAndDots = false
			break
		}
	}
	if onlyDigitsAndDots && strings.Contains(name, ".") {
		return fmt.Errorf("это не похоже на ip")
	}

	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 {
			return fmt.Errorf("битая dns-метка")
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("метка не может начинаться/заканчиваться на '-'")
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-'
			if !ok {
				return fmt.Errorf("недопустимый символ в имени")
			}
		}
	}
	return nil
}

func defaultLookup(ctx context.Context, host string) ([]net.IPAddr, error) {
	return net.DefaultResolver.LookupIPAddr(ctx, host)
}
