package portscan

import (
	"net"
	"time"
)

type State string

const (
	StateOpen        State = "open"
	StateClosed      State = "closed"
	StateTimeout     State = "timeout"
	StateUnreachable State = "unreachable"
	StateCanceled    State = "canceled"
	StateError       State = "error"
)

// Result — одна попытка коннекта.
// Host — то, что передали в Scan (без пробелов по краям).
// IP — конкретный адрес после резолва; для DNS с несколькими A/AAAA будет несколько результатов.
type Result struct {
	Host     string
	IP       net.IP
	Port     uint16
	State    State
	Duration time.Duration
	Err      error
}
