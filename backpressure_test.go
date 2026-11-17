package main

import (
	"context"
	"net"
	"os"
	"testing"
	"time"
)

func testReceiver(queue int) (*Receiver, chan Envelope) {
	ch := make(chan Envelope, queue)
	return NewReceiver(Config{}, ch, &Metrics{}), ch
}

func TestUDPDropsWhenQueueFull(t *testing.T) {
	r, _ := testReceiver(1)
	a := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 1}
	r.accept(nil, []byte("a=1"), a)
	r.accept(nil, []byte("a=2"), a)
	if r.metrics.UDPDropped.Load() != 1 || r.metrics.Received.Load() != 1 {
		t.Fatalf("dropped=%d received=%d", r.metrics.UDPDropped.Load(), r.metrics.Received.Load())
	}
}

func TestTCPWaitsInsteadOfDropping(t *testing.T) {
	r, ch := testReceiver(1)
	a := &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 1}
	ctx := context.Background()
	r.accept(ctx, []byte("a=1"), a)
	done := make(chan struct{})
	go func() { r.accept(ctx, []byte("a=2"), a); close(done) }()
	select {
	case <-done:
		t.Fatal("accept returned while the queue was full")
	case <-time.After(100 * time.Millisecond):
	}
	<-ch // make room
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("accept did not resume")
	}
	if r.metrics.UDPDropped.Load() != 0 || r.metrics.Received.Load() != 2 || r.metrics.TCPWaits.Load() != 1 {
		t.Fatalf("dropped=%d received=%d waits=%d", r.metrics.UDPDropped.Load(), r.metrics.Received.Load(), r.metrics.TCPWaits.Load())
	}
}

func TestTCPWaitStopsOnShutdown(t *testing.T) {
	r, _ := testReceiver(1)
	a := &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 1}
	ctx, cancel := context.WithCancel(context.Background())
	r.accept(ctx, []byte("a=1"), a)
	done := make(chan struct{})
	go func() { r.accept(ctx, []byte("a=2"), a); close(done) }()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("accept blocked after shutdown")
	}
}

func TestSpoolLimit(t *testing.T) {
	dir := t.TempDir()
	s := Spool{dir: dir, maxBytes: 1 << 10}
	rec := []LogRecord{{Raw: string(make([]byte, 2000)), Fields: map[string]string{}}}
	if err := s.Write(rec); err != nil {
		t.Fatalf("first write should succeed: %v", err)
	}
	spoolSizeCache.Lock()
	spoolSizeCache.dir = "" // force a re-scan
	spoolSizeCache.Unlock()
	if err := s.Write(rec); err == nil {
		t.Fatal("second write should be refused: spool over its limit")
	}
	if err := (Spool{dir: dir}).Write(rec); err != nil {
		t.Fatalf("maxBytes 0 means unlimited: %v", err)
	}
}

func TestHoldForConnect(t *testing.T) {
	cases := []struct {
		missing, connecting bool
		n                   int
		want                bool
	}{
		{true, true, 10, true},
		{true, true, holdMax, false}, // memory cap reached: spool
		{true, false, 10, false},     // database failed: spool
		{false, true, 10, false},     // connected: write
	}
	for _, c := range cases {
		if got := holdForConnect(c.missing, c.connecting, c.n); got != c.want {
			t.Errorf("%+v: got %v", c, got)
		}
	}
}

func TestSpoolFailedCounts(t *testing.T) {
	a := &App{}
	for i := 0; i < 3; i++ {
		a.spoolFailed(os.ErrPermission, 1000)
	}
	if a.metrics.SpoolLost.Load() != 3000 {
		t.Fatalf("lost=%d", a.metrics.SpoolLost.Load())
	}
}

func TestDoubledKeyIPIsRecovered(t *testing.T) {
	line := `date=2026-10-19 time=22:00:01 devname="FW1" type="traffic" subtype="forward" srcip=10.1.1.5 dstip=dstip=192.168.2.1 dstport=443`
	r := ParseLog([]byte(line), "10.0.0.1")
	if r.DstIP != "192.168.2.1" {
		t.Fatalf("dst ip %q, want 192.168.2.1 (fields: %q)", r.DstIP, r.Fields["dstip"])
	}
	// a record parsed by an older version and kept in the spool
	old := LogRecord{SrcIP: "10.1.1.5", DstIP: "dstip=192.168.2.1"}
	cleanRecord(&old)
	if old.DstIP != "192.168.2.1" {
		t.Fatalf("spooled record not repaired: %q", old.DstIP)
	}
	// anything that is still not an address is emptied, never sent to the inet column
	junk := LogRecord{DstIP: "dstip=not-an-ip"}
	cleanRecord(&junk)
	if junk.DstIP != "" {
		t.Fatalf("junk kept: %q", junk.DstIP)
	}
}
