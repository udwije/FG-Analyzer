package main

import (
	"bufio"
	"context"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// v6.0: server health. Every minute LogSikka samples the host (CPU, I/O wait, load, memory, swap), its own pipeline
// (logs received and written per second, queue, spool, write latency, newest log age) and the database (connections,
// cache hit ratio). The last 24 hours are kept in memory for the System health page (a restart starts them again).
// Host figures come from /proc and are only filled on Linux.

type healthPoint struct {
	T        int64   `json:"t"`
	CPU      float64 `json:"cpu"`      // % busy, all cores
	IOWait   float64 `json:"iowait"`   // % of CPU time waiting for disk
	Load1    float64 `json:"load1"`    // 1-minute load average
	Cores    int     `json:"cores"`    //
	MemPct   float64 `json:"mem_pct"`  // used (total - available)
	SwapPct  float64 `json:"swap_pct"` //
	InRate   float64 `json:"in_rate"`  // logs received per second
	OutRate  float64 `json:"out_rate"` // logs written per second
	Queue    int     `json:"queue"`
	Spool    int     `json:"spool"`
	WriteMS  float64 `json:"write_ms"` // average time to write one batch
	LagSec   float64 `json:"lag_s"`    // age of the newest stored log (-1 unknown)
	DBConns  int     `json:"db_conns"`
	CacheHit float64 `json:"cache_hit"` // PostgreSQL buffer cache hit ratio, % (-1 unknown)
	GoMemMB  float64 `json:"go_mem_mb"`
	Routines int     `json:"goroutines"`
}

const healthKeep = 24 * 60

var hm = struct {
	sync.Mutex
	pts        []healthPoint
	cpuIdle    uint64
	cpuTotal   uint64
	cpuIOWait  uint64
	recv, wrtn int64
	at         time.Time
}{}

// batch write timing (exponential moving average, microseconds)
var writeEWMA atomic.Int64

func noteWrite(d time.Duration) {
	us := d.Microseconds()
	old := writeEWMA.Load()
	if old == 0 {
		writeEWMA.Store(us)
		return
	}
	writeEWMA.Store((old*7 + us) / 8)
}

// readCPU: aggregate jiffies from /proc/stat (total, idle+iowait, iowait).
func readCPU() (total, idle, iowait uint64, ok bool) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	if !sc.Scan() {
		return
	}
	fs := strings.Fields(sc.Text())
	if len(fs) < 6 || fs[0] != "cpu" {
		return
	}
	for i, x := range fs[1:] {
		n, _ := strconv.ParseUint(x, 10, 64)
		if i < 8 { // user nice system idle iowait irq softirq steal (guest is already in user)
			total += n
		}
		if i == 3 || i == 4 {
			idle += n
		}
		if i == 4 {
			iowait = n
		}
	}
	return total, idle, iowait, true
}

func readMem() (memPct, swapPct float64, ok bool) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return
	}
	defer f.Close()
	v := map[string]float64{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fs := strings.Fields(sc.Text())
		if len(fs) >= 2 {
			n, _ := strconv.ParseFloat(fs[1], 64)
			v[strings.TrimSuffix(fs[0], ":")] = n
		}
	}
	if v["MemTotal"] > 0 {
		memPct = 100 * (v["MemTotal"] - v["MemAvailable"]) / v["MemTotal"]
		ok = true
	}
	if v["SwapTotal"] > 0 {
		swapPct = 100 * (v["SwapTotal"] - v["SwapFree"]) / v["SwapTotal"]
	}
	return
}

func readLoad() float64 {
	b, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return -1
	}
	fs := strings.Fields(string(b))
	if len(fs) == 0 {
		return -1
	}
	f, _ := strconv.ParseFloat(fs[0], 64)
	return f
}

func round2(f float64) float64 { return float64(int64(f*100+0.5)) / 100 }

// sampleHealth takes one point. The first call only sets the counters.
func (a *App) sampleHealth(ctx context.Context) {
	now := time.Now()
	p := healthPoint{T: now.Unix(), Cores: runtime.NumCPU(), Load1: readLoad(), LagSec: -1, CacheHit: -1, Queue: len(a.queue), Routines: runtime.NumGoroutine()}
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	p.GoMemMB = round2(float64(ms.Sys) / (1 << 20))
	if files, err := a.spool.Files(); err == nil {
		p.Spool = len(files)
	}
	p.WriteMS = round2(float64(writeEWMA.Load()) / 1000)
	if m, s, ok := readMem(); ok {
		p.MemPct, p.SwapPct = round2(m), round2(s)
	}
	total, idle, iow, ok := readCPU()
	recv, wrtn := a.metrics.Received.Load(), a.metrics.Written.Load()
	hm.Lock()
	first := hm.at.IsZero()
	if ok && !first && total > hm.cpuTotal {
		dt := float64(total - hm.cpuTotal)
		p.CPU = round2(100 * (1 - float64(idle-hm.cpuIdle)/dt))
		p.IOWait = round2(100 * float64(iow-hm.cpuIOWait) / dt)
	}
	if !first {
		if secs := now.Sub(hm.at).Seconds(); secs > 0 {
			p.InRate = round2(float64(recv-hm.recv) / secs)
			p.OutRate = round2(float64(wrtn-hm.wrtn) / secs)
		}
	}
	hm.cpuTotal, hm.cpuIdle, hm.cpuIOWait, hm.recv, hm.wrtn, hm.at = total, idle, iow, recv, wrtn, now
	hm.Unlock()
	if d := a.getDB(); d != nil {
		c, cancel := context.WithTimeout(ctx, 10*time.Second)
		var conns int
		var hit *float64
		var newest *time.Time
		if d.pool.QueryRow(c, `SELECT (SELECT count(*) FROM pg_stat_activity WHERE datname = current_database()),
			(SELECT CASE WHEN blks_hit + blks_read = 0 THEN NULL ELSE 100.0 * blks_hit / (blks_hit + blks_read) END FROM pg_stat_database WHERE datname = current_database()),
			(SELECT max(event_time) FROM fortigate_logs WHERE event_time > now() - interval '1 day')`).Scan(&conns, &hit, &newest) == nil {
			p.DBConns = conns
			if hit != nil {
				p.CacheHit = round2(*hit)
			}
			if newest != nil {
				p.LagSec = round2(now.Sub(*newest).Seconds())
			}
		}
		cancel()
	}
	if first {
		return
	}
	hm.Lock()
	hm.pts = append(hm.pts, p)
	if len(hm.pts) > healthKeep {
		hm.pts = append([]healthPoint(nil), hm.pts[len(hm.pts)-healthKeep:]...)
	}
	hm.Unlock()
}

func (a *App) healthLoop(ctx context.Context) error {
	a.sampleHealth(ctx)
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			a.sampleHealth(ctx)
		}
	}
}

func healthSeries() []healthPoint {
	hm.Lock()
	defer hm.Unlock()
	return append([]healthPoint(nil), hm.pts...)
}

// /api/health/series (admin): the last 24 hours, one point per minute, plus the host basics.
func (a *App) handleHealthSeries(w http.ResponseWriter, r *http.Request) {
	host, _ := os.Hostname()
	jsonOut(w, map[string]any{"points": healthSeries(), "host": host, "os": runtime.GOOS, "cores": runtime.NumCPU(),
		"version": version, "started": a.started, "go": runtime.Version(), "bg_paused": bgPaused.Load(), "exclusions": exclInfo()})
}
