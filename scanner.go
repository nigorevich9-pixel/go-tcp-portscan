package portscan

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"sync"
	"syscall"
	"time"
)

const (
	defaultWorkers = 64
	maxWorkers     = 4096
	defaultTimeout = time.Second
)

type Option func(*Scanner) error

type Scanner struct {
	workers int
	timeout time.Duration
	slots   chan struct{}
	dial    func(context.Context, string, string) (net.Conn, error)
	lookup  func(context.Context, string) ([]net.IPAddr, error)
}

func New(opts ...Option) (*Scanner, error) {
	s := &Scanner{
		workers: defaultWorkers,
		timeout: defaultTimeout,
		lookup:  defaultLookup,
	}
	for _, opt := range opts {
		if err := opt(s); err != nil {
			return nil, err
		}
	}
	s.slots = make(chan struct{}, s.workers)
	if s.dial == nil {
		s.dial = (&net.Dialer{Timeout: s.timeout}).DialContext
	}
	return s, nil
}

func WithWorkers(n int) Option {
	return func(s *Scanner) error {
		if n < 1 || n > maxWorkers {
			return fmt.Errorf("portscan: workers 1..%d, пришло %d", maxWorkers, n)
		}
		s.workers = n
		return nil
	}
}

func WithTimeout(d time.Duration) Option {
	return func(s *Scanner) error {
		if d <= 0 {
			return fmt.Errorf("portscan: таймаут должен быть > 0")
		}
		s.timeout = d
		return nil
	}
}

// Scan резолвит хосты и запускает TCP connect по каждому (host, ip, port).
// Канал закрывается, когда всё закончилось или отменили ctx.
// Если перестать читать канал — надо отменить контекст, иначе воркеры зависнут.
func (s *Scanner) Scan(ctx context.Context, hosts []string, ports PortSpec) (<-chan Result, error) {
	if s == nil {
		return nil, fmt.Errorf("portscan: Scanner == nil")
	}
	if ctx == nil {
		return nil, fmt.Errorf("portscan: контекст не задан")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	list, err := ports.expand()
	if err != nil {
		return nil, err
	}
	targets, err := s.resolve(ctx, hosts)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	jobs := make(chan job)
	out := make(chan Result)

	n := s.workers
	if total := len(list) * len(targets); total < n {
		n = total
	}

	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case j, ok := <-jobs:
					if !ok {
						return
					}
					res, ok := s.probe(ctx, j)
					if !ok {
						return
					}
					select {
					case out <- res:
					case <-ctx.Done():
						return
					}
				}
			}
		}()
	}

	go func() {
		defer close(jobs)
		for _, t := range targets {
			for _, p := range list {
				select {
				case jobs <- job{t, p}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	go func() {
		wg.Wait()
		close(out)
	}()
	return out, nil
}

type job struct {
	t    target
	port uint16
}

func (s *Scanner) probe(ctx context.Context, j job) (Result, bool) {
	select {
	case s.slots <- struct{}{}:
	case <-ctx.Done():
		return Result{}, false
	}
	defer func() { <-s.slots }()

	if ctx.Err() != nil {
		return Result{}, false
	}

	start := time.Now()
	addr := net.JoinHostPort(j.t.ip.String(), strconv.Itoa(int(j.port)))
	conn, err := s.dial(ctx, "tcp", addr)
	if conn != nil {
		_ = conn.Close()
	}
	if conn == nil && err == nil {
		err = fmt.Errorf("portscan: dial вернул nil, nil")
	}
	return Result{
		Host:     j.t.host,
		IP:       net.IP(j.t.ip.AsSlice()),
		Port:     j.port,
		State:    classify(err, ctx),
		Duration: time.Since(start),
		Err:      err,
	}, true
}

func classify(err error, ctx context.Context) State {
	if err == nil {
		return StateOpen
	}
	if ctx.Err() != nil || errors.Is(err, context.Canceled) {
		return StateCanceled
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return StateClosed
	}
	if errors.Is(err, syscall.EHOSTUNREACH) ||
		errors.Is(err, syscall.ENETUNREACH) ||
		errors.Is(err, syscall.EHOSTDOWN) ||
		errors.Is(err, syscall.ENETDOWN) {
		return StateUnreachable
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return StateTimeout
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return StateTimeout
	}
	return StateError
}
