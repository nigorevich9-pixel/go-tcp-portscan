package portscan

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

func TestNewOptions(t *testing.T) {
	s, err := New()
	if err != nil || s.workers != defaultWorkers || s.timeout != defaultTimeout {
		t.Fatalf("defaults: %+v err=%v", s, err)
	}

	s, err = New(WithWorkers(8), WithTimeout(50*time.Millisecond))
	if err != nil || s.workers != 8 || s.timeout != 50*time.Millisecond {
		t.Fatalf("custom: %+v err=%v", s, err)
	}

	if _, err := New(WithWorkers(0)); err == nil {
		t.Fatal("WithWorkers(0) должен падать")
	}
	if _, err := New(WithTimeout(0)); err == nil {
		t.Fatal("WithTimeout(0) должен падать")
	}
}

func TestLocalOpenClosed(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	defer ln.Close()
	open := ln.Addr().(*net.TCPAddr).Port

	tmp, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	closed := tmp.Addr().(*net.TCPAddr).Port
	tmp.Close()

	s, _ := New(WithWorkers(2), WithTimeout(time.Second))
	ch, err := s.Scan(context.Background(), []string{"127.0.0.1"}, List(open, closed))
	if err != nil {
		t.Fatal(err)
	}

	got := map[int]Result{}
	for r := range ch {
		got[int(r.Port)] = r
	}
	if got[open].State != StateOpen {
		t.Fatalf("открытый порт: %+v", got[open])
	}
	if got[closed].State != StateClosed {
		t.Fatalf("закрытый порт: %+v", got[closed])
	}
}

func TestIPv6Loopback(t *testing.T) {
	ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skip("нет ipv6 loopback:", err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	s, _ := New()
	ch, err := s.Scan(context.Background(), []string{"::1"}, List(port))
	if err != nil {
		t.Fatal(err)
	}
	r := <-ch
	if r.State != StateOpen || r.IP.To4() != nil {
		t.Fatalf("%+v", r)
	}
}

func TestClassifyViaStubDial(t *testing.T) {
	s, _ := New(WithWorkers(7))
	s.dial = func(_ context.Context, _, address string) (net.Conn, error) {
		_, p, _ := net.SplitHostPort(address)
		port, _ := strconv.Atoi(p)
		switch port {
		case 1:
			a, b := net.Pipe()
			b.Close()
			return a, nil
		case 2:
			return nil, fmt.Errorf("wrap: %w", syscall.ECONNREFUSED)
		case 3:
			return nil, timeoutError{}
		case 4:
			return nil, syscall.ENETUNREACH
		case 5:
			return nil, context.Canceled
		default:
			return nil, errors.New("что-то ещё")
		}
	}

	ch, err := s.Scan(context.Background(), []string{"192.0.2.1"}, Range(1, 6))
	if err != nil {
		t.Fatal(err)
	}
	want := map[uint16]State{
		1: StateOpen, 2: StateClosed, 3: StateTimeout,
		4: StateUnreachable, 5: StateCanceled, 6: StateError,
	}
	for r := range ch {
		if r.State != want[r.Port] {
			t.Errorf("порт %d: %s, ждали %s", r.Port, r.State, want[r.Port])
		}
		delete(want, r.Port)
	}
	if len(want) != 0 {
		t.Fatalf("не дошли результаты: %v", want)
	}
}

func TestDNSSeveralIPs(t *testing.T) {
	s, _ := New()
	s.lookup = func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{
			{IP: net.ParseIP("192.0.2.1")},
			{IP: net.ParseIP("2001:db8::1")},
		}, nil
	}
	s.dial = func(context.Context, string, string) (net.Conn, error) {
		return nil, syscall.ECONNREFUSED
	}

	ch, err := s.Scan(context.Background(), []string{"host.example", "HOST.EXAMPLE"}, Union(List(80), Range(80, 81)))
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for range ch {
		n++
	}
	if n != 4 {
		t.Fatalf("ожидали 2 ip * 2 порта = 4, получили %d", n)
	}
}

func TestBadInput(t *testing.T) {
	s, _ := New()
	var dials atomic.Int32
	s.dial = func(context.Context, string, string) (net.Conn, error) {
		dials.Add(1)
		return nil, syscall.ECONNREFUSED
	}

	cases := []struct {
		ctx   context.Context
		hosts []string
		ports PortSpec
	}{
		{nil, []string{"127.0.0.1"}, List(80)},
		{context.Background(), nil, List(80)},
		{context.Background(), []string{""}, List(80)},
		{context.Background(), []string{"127.0.0.1:80"}, List(80)},
		{context.Background(), []string{"127.0.0.1"}, List()},
		{context.Background(), []string{"127.0.0.1"}, List(70000)},
	}
	for _, c := range cases {
		ch, err := s.Scan(c.ctx, c.hosts, c.ports)
		if err == nil || ch != nil {
			t.Errorf("ждали ошибку, hosts=%v ports=%v err=%v", c.hosts, c.ports, err)
		}
	}
	if dials.Load() != 0 {
		t.Fatalf("dial не должен был вызываться: %d", dials.Load())
	}

	var nilS *Scanner
	if _, err := nilS.Scan(context.Background(), []string{"127.0.0.1"}, List(80)); err == nil {
		t.Fatal("nil scanner прошёл")
	}
}

func TestDNSErrorWrapped(t *testing.T) {
	s, _ := New()
	orig := &net.DNSError{Err: "no such host", Name: "nope.invalid", IsNotFound: true}
	s.lookup = func(context.Context, string) ([]net.IPAddr, error) { return nil, orig }

	ch, err := s.Scan(context.Background(), []string{"nope.invalid"}, List(80))
	if ch != nil || !errors.Is(err, orig) || !strings.Contains(err.Error(), "nope.invalid") {
		t.Fatalf("err=%v ch=%v", err, ch)
	}
}

func TestCancelUnblocksSlowReader(t *testing.T) {
	s, _ := New(WithWorkers(4))
	var n atomic.Int32
	s.dial = func(ctx context.Context, _, _ string) (net.Conn, error) {
		n.Add(1)
		select {
		case <-time.After(5 * time.Millisecond):
			return nil, syscall.ECONNREFUSED
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	ch, err := s.Scan(ctx, []string{"127.0.0.1"}, Range(1, 8000))
	if err != nil {
		t.Fatal(err)
	}

	time.Sleep(40 * time.Millisecond)
	if n.Load() > 4 {
		t.Fatalf("слишком много dial без чтения канала: %d", n.Load())
	}
	cancel()

	deadline := time.After(2 * time.Second)
	for {
		select {
		case _, ok := <-ch:
			if !ok {
				return
			}
		case <-deadline:
			t.Fatal("канал не закрылся после cancel")
		}
	}
}

func TestSharedWorkerLimit(t *testing.T) {
	const limit = 3
	s, _ := New(WithWorkers(limit))
	var live, peak atomic.Int32
	s.dial = func(ctx context.Context, _, _ string) (net.Conn, error) {
		cur := live.Add(1)
		for {
			old := peak.Load()
			if cur <= old || peak.CompareAndSwap(old, cur) {
				break
			}
		}
		defer live.Add(-1)
		select {
		case <-time.After(8 * time.Millisecond):
			return nil, syscall.ECONNREFUSED
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ch, err := s.Scan(context.Background(), []string{"192.0.2.10"}, Range(1, 10))
			if err != nil {
				t.Error(err)
				return
			}
			for range ch {
			}
		}()
	}
	wg.Wait()
	if peak.Load() > limit {
		t.Fatalf("пик %d > лимита %d", peak.Load(), limit)
	}
}

func TestCanceledContext(t *testing.T) {
	s, _ := New()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.Scan(ctx, []string{"127.0.0.1"}, List(80)); !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v", err)
	}

	ctx, stop := context.WithCancel(context.Background())
	entered := make(chan struct{})
	s.lookup = func(ctx context.Context, _ string) ([]net.IPAddr, error) {
		close(entered)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	go func() {
		<-entered
		stop()
	}()
	if _, err := s.Scan(ctx, []string{"wait.test"}, List(80)); !errors.Is(err, context.Canceled) {
		t.Fatalf("dns cancel: %v", err)
	}
}
