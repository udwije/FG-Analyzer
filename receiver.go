package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Metrics struct {
	Received          atomic.Int64
	Written           atomic.Int64
	Skipped           atomic.Int64
	UDPDropped        atomic.Int64
	SpoolLost         atomic.Int64 // records that could not be saved (database down and spool full or unwritable)
	TCPWaits          atomic.Int64 // TCP messages that had to wait because the queue was full (back-pressure)
	DBErrors          atomic.Int64
	Quarantined       atomic.Int64
	ParsePartial      atomic.Int64
	ActiveConnections atomic.Int64
	LastReceived      atomic.Int64
	LastWritten       atomic.Int64
}

type Envelope struct {
	Data   []byte
	Source string
	Fields map[string]string // populated when receiver already parsed the message for filtering
}

// ---------------------------------------------------------------- per-firewall bookkeeping

type srcStat struct {
	received atomic.Int64
	last     atomic.Int64
}

var (
	srcMu    sync.RWMutex
	srcStats = map[string]*srcStat{}
	fwMu     sync.RWMutex
	fwByIP   = map[string]string{}
)

func setFirewalls(l []Firewall) {
	m := map[string]string{}
	for _, f := range l {
		m[f.IP] = f.Name
	}
	fwMu.Lock()
	fwByIP = m
	fwMu.Unlock()
}

// firewallName: configured name for the sending IP, else the FortiGate's own devname, else the IP.
func firewallName(sourceIP, devname string) string {
	fwMu.RLock()
	n := fwByIP[sourceIP]
	fwMu.RUnlock()
	if n != "" {
		return n
	}
	if devname != "" {
		return devname
	}
	return sourceIP
}

func noteSource(ip string) {
	srcMu.RLock()
	s := srcStats[ip]
	srcMu.RUnlock()
	if s == nil {
		srcMu.Lock()
		if s = srcStats[ip]; s == nil {
			s = &srcStat{}
			srcStats[ip] = s
		}
		srcMu.Unlock()
	}
	s.received.Add(1)
	s.last.Store(time.Now().Unix())
}

// sourceStatus lists every configured firewall plus any other sender seen since the service started.
func sourceStatus(cfg Config) []map[string]any {
	out := []map[string]any{}
	seen := map[string]bool{}
	srcMu.RLock()
	defer srcMu.RUnlock()
	row := func(ip, name string, configured bool) {
		m := map[string]any{"ip": ip, "name": name, "configured": configured, "received": int64(0), "last": int64(0)}
		if s := srcStats[ip]; s != nil {
			m["received"], m["last"] = s.received.Load(), s.last.Load()
		}
		out = append(out, m)
	}
	for _, f := range cfg.Firewalls {
		row(f.IP, f.Name, true)
		seen[f.IP] = true
	}
	extra := []string{}
	for ip := range srcStats {
		if !seen[ip] {
			extra = append(extra, ip)
		}
	}
	sort.Strings(extra)
	for _, ip := range extra {
		row(ip, firewallName(ip, ""), false)
	}
	return out
}

// ---------------------------------------------------------------- receiver

type Receiver struct {
	cfg     Config
	out     chan<- Envelope
	metrics *Metrics
	allowed map[string]bool
	allowedNets []netip.Prefix
	keep    map[string]bool
	wg      sync.WaitGroup
}

func NewReceiver(c Config, out chan<- Envelope, m *Metrics) *Receiver {
	r := &Receiver{cfg: c, out: out, metrics: m, allowed: map[string]bool{}, keep: map[string]bool{}}
	for _, v := range c.AllowedSources {
		v = strings.TrimSpace(v)
		if v == "" { continue }
		if p, err := netip.ParsePrefix(v); err == nil { r.allowedNets = append(r.allowedNets, p.Masked()); continue }
		if a, err := netip.ParseAddr(v); err == nil { r.allowed[a.String()] = true }
	}
	// A configured firewall list is an allow-list by default. Extra sources may be IPs or CIDRs.
	for _, f := range c.Firewalls {
		if a, err := netip.ParseAddr(strings.TrimSpace(f.IP)); err == nil { r.allowed[a.String()] = true }
	}
	for _, v := range c.KeepSubtypes {
		if v = strings.TrimSpace(v); v != "" {
			r.keep[v] = true
		}
	}
	return r
}

func (r *Receiver) allowedSource(addr net.Addr) bool {
	if len(r.allowed) == 0 && len(r.allowedNets) == 0 { return true }
	host, _, e := net.SplitHostPort(addr.String())
	if e == nil {
		if r.allowed[host] { return true }
		if a, err := netip.ParseAddr(host); err == nil { for _, p := range r.allowedNets { if p.Contains(a) { return true } } }
	}
	noteRefused(host)
	return false
}

var (
	refusedMu sync.Mutex
	refused   = map[string]int64{}
)

func noteRefused(ip string) {
	refusedMu.Lock()
	if len(refused) < 100 {
		refused[ip]++
	} else if _, ok := refused[ip]; ok {
		refused[ip]++
	}
	refusedMu.Unlock()
}

func refusedSenders() map[string]int64 {
	refusedMu.Lock()
	defer refusedMu.Unlock()
	out := make(map[string]int64, len(refused))
	for k, v := range refused {
		out[k] = v
	}
	return out
}

// accept queues one message. UDP (ctx == nil) drops when the queue is full; TCP waits for room, so the firewall's
// reliable-mode session slows down (and buffers on the FortiGate) instead of silently losing logs.
func (r *Receiver) accept(ctx context.Context, data []byte, addr net.Addr) {
	if !r.allowedSource(addr) {
		r.metrics.Skipped.Add(1)
		return
	}
	host, _, _ := net.SplitHostPort(addr.String())
	var fields map[string]string
	if len(r.keep) > 0 {
		fields = parseKV(string(data))
		if !r.keep[fields["subtype"]] && !r.keep[fields["type"]] {
			r.metrics.Skipped.Add(1)
			return
		}
	}
	cp := append([]byte(nil), data...)
	env := Envelope{Data: cp, Source: host, Fields: fields}
	queued := func() {
		r.metrics.Received.Add(1)
		r.metrics.LastReceived.Store(time.Now().Unix())
		noteSource(host)
	}
	select {
	case r.out <- env:
		queued()
		return
	default:
	}
	if ctx == nil { // UDP: nobody to slow down
		r.metrics.UDPDropped.Add(1)
		return
	}
	r.metrics.TCPWaits.Add(1)
	select {
	case r.out <- env:
		queued()
	case <-ctx.Done():
	}
}

func (r *Receiver) Start(ctx context.Context) error {
	errc := make(chan error, 2)
	if r.cfg.UDPEnabled {
		r.wg.Add(1)
		go func() { defer r.wg.Done(); errc <- r.serveUDP(ctx) }()
	}
	if r.cfg.TCPEnabled {
		r.wg.Add(1)
		go func() { defer r.wg.Done(); errc <- r.serveTCP(ctx) }()
	}
	if !r.cfg.UDPEnabled && !r.cfg.TCPEnabled {
		return fmt.Errorf("both TCP and UDP disabled")
	}
	go func() { r.wg.Wait(); close(errc) }()
	for {
		select {
		case err, ok := <-errc:
			if !ok {
				return nil
			}
			if err != nil && ctx.Err() == nil {
				return err
			}
		case <-ctx.Done():
			r.wg.Wait()
			return nil
		}
	}
}

func (r *Receiver) serveUDP(ctx context.Context) error {
	pc, e := net.ListenPacket("udp", r.cfg.ListenAddress)
	if e != nil {
		return e
	}
	defer pc.Close()
	if u, ok := pc.(*net.UDPConn); ok {
		_ = u.SetReadBuffer(8 << 20)
	}
	go func() { <-ctx.Done(); pc.Close() }()
	buf := make([]byte, 65535)
	for {
		n, a, e := pc.ReadFrom(buf)
		if e != nil {
			if ctx.Err() != nil {
				return nil
			}
			continue
		}
		for _, ln := range bytes.Split(buf[:n], []byte("\n")) {
			if len(bytes.TrimSpace(ln)) > 0 {
				r.accept(nil, ln, a)
			}
		}
	}
}

func (r *Receiver) serveTCP(ctx context.Context) error {
	ln, e := net.Listen("tcp", r.cfg.ListenAddress)
	if e != nil {
		return e
	}
	defer ln.Close()
	go func() { <-ctx.Done(); ln.Close() }()
	for {
		c, e := ln.Accept()
		if e != nil {
			if ctx.Err() != nil {
				return nil
			}
			return e
		}
		if !r.allowedSource(c.RemoteAddr()) {
			r.metrics.Skipped.Add(1)
			c.Close()
			continue
		}
		r.wg.Add(1)
		go func() { defer r.wg.Done(); r.handleTCP(ctx, c) }()
	}
}

func (r *Receiver) handleTCP(ctx context.Context, c net.Conn) {
	defer c.Close()
	r.metrics.ActiveConnections.Add(1)
	defer r.metrics.ActiveConnections.Add(-1)
	go func() { <-ctx.Done(); c.Close() }()
	br := bufio.NewReaderSize(c, 64*1024)
	for {
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Minute))
		msg, e := readSyslogFrame(br, r.cfg.MaxMessageBytes)
		if e != nil {
			if e != io.EOF && ctx.Err() == nil {
				log.Printf("tcp %s: %v", c.RemoteAddr(), e)
			}
			return
		}
		r.accept(ctx, msg, c.RemoteAddr())
	}
}

func readSyslogFrame(br *bufio.Reader, max int) ([]byte, error) {
	first, e := br.Peek(1)
	if e != nil {
		return nil, e
	}
	if first[0] >= '0' && first[0] <= '9' {
		prefix, e := br.ReadString(' ')
		if e != nil {
			return nil, e
		}
		n, e := strconv.Atoi(strings.TrimSpace(prefix))
		if e != nil || n < 1 || n > max {
			return nil, fmt.Errorf("invalid octet count")
		}
		b := make([]byte, n)
		_, e = io.ReadFull(br, b)
		return b, e
	}
	var b []byte
	for {
		frag, err := br.ReadSlice('\n')
		if len(b)+len(frag) > max { return nil, fmt.Errorf("message too large") }
		b = append(b, frag...)
		if err == nil { return bytes.TrimRight(b, "\r\n"), nil }
		if err != bufio.ErrBufferFull { return bytes.TrimRight(b, "\r\n"), err }
	}
}
