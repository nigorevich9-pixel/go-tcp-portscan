package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/nigorevich9-pixel/go-tcp-portscan"
)

func main() {
	timeout := flag.Duration("timeout", time.Second, "таймаут одного коннекта")
	n := flag.Int("n", 64, "сколько коннектов одновременно")
	portsFlag := flag.String("p", "22,80,443", "порты: 80,443 или 1-1024, можно смешанно")
	flag.Parse()

	if flag.NArg() == 0 {
		fmt.Fprintf(os.Stderr, "usage: scan [-p 22,80,8000-8010] [-n 64] host [host...]\n")
		os.Exit(2)
	}

	spec, err := parsePorts(*portsFlag)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	s, err := portscan.New(portscan.WithWorkers(*n), portscan.WithTimeout(*timeout))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	out, err := s.Scan(ctx, flag.Args(), spec)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	for r := range out {
		fmt.Printf("%s %s:%d %s %s\n", r.Host, r.IP, r.Port, r.State, r.Duration)
	}
}

func parsePorts(s string) (portscan.PortSpec, error) {
	var parts []portscan.PortSpec
	for _, chunk := range strings.Split(s, ",") {
		chunk = strings.TrimSpace(chunk)
		if chunk == "" {
			continue
		}
		if a, b, ok := strings.Cut(chunk, "-"); ok {
			from, err1 := strconv.Atoi(strings.TrimSpace(a))
			to, err2 := strconv.Atoi(strings.TrimSpace(b))
			if err1 != nil || err2 != nil {
				return portscan.PortSpec{}, fmt.Errorf("не понял диапазон %q", chunk)
			}
			parts = append(parts, portscan.Range(from, to))
			continue
		}
		p, err := strconv.Atoi(chunk)
		if err != nil {
			return portscan.PortSpec{}, fmt.Errorf("не понял порт %q", chunk)
		}
		parts = append(parts, portscan.List(p))
	}
	if len(parts) == 0 {
		return portscan.PortSpec{}, fmt.Errorf("порты не заданы")
	}
	return portscan.Union(parts...), nil
}
