package portscan

import "fmt"

// PortSpec — набор портов. Собирается через List / Range / Union.
type PortSpec struct {
	parts []portRange
}

type portRange struct {
	from int
	to   int
}

func List(ports ...int) PortSpec {
	s := PortSpec{parts: make([]portRange, 0, len(ports))}
	for _, p := range ports {
		s.parts = append(s.parts, portRange{p, p})
	}
	return s
}

func Range(from, to int) PortSpec {
	return PortSpec{parts: []portRange{{from, to}}}
}

func Union(specs ...PortSpec) PortSpec {
	var out PortSpec
	for _, s := range specs {
		out.parts = append(out.parts, s.parts...)
	}
	return out
}

func (s PortSpec) expand() ([]uint16, error) {
	if len(s.parts) == 0 {
		return nil, fmt.Errorf("portscan: пустой список портов")
	}

	var seen [65536]bool
	for _, r := range s.parts {
		if r.from < 1 || r.from > 65535 || r.to < 1 || r.to > 65535 {
			return nil, fmt.Errorf("portscan: порт должен быть 1..65535, пришло %d-%d", r.from, r.to)
		}
		if r.from > r.to {
			return nil, fmt.Errorf("portscan: диапазон задом наперёд: %d-%d", r.from, r.to)
		}
		for p := r.from; p <= r.to; p++ {
			seen[p] = true
		}
	}

	out := make([]uint16, 0)
	for p := 1; p <= 65535; p++ {
		if seen[p] {
			out = append(out, uint16(p))
		}
	}
	return out, nil
}
