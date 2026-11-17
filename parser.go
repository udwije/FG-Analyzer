package main

import (
	"bytes"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

type LogRecord struct {
	EventTime       time.Time         `json:"event_time"`
	ReceivedAt      time.Time         `json:"received_at"`
	SourceIP        string            `json:"source_ip"`
	DeviceID        string            `json:"device_id"`
	VDOM            string            `json:"vdom"`
	LogID           string            `json:"log_id"`
	Type            string            `json:"type"`
	Subtype         string            `json:"subtype"`
	Level           string            `json:"level"`
	SrcIP           string            `json:"src_ip"`
	SrcPort         int               `json:"src_port"`
	DstIP           string            `json:"dst_ip"`
	DstPort         int               `json:"dst_port"`
	Protocol        string            `json:"protocol"`
	Action          string            `json:"action"`
	PolicyID        int               `json:"policy_id"`
	PolicyName      string            `json:"policy_name"`
	User            string            `json:"user"`
	Application     string            `json:"application"`
	Category        string            `json:"category"`
	AppRisk         string            `json:"app_risk"`
	Hostname        string            `json:"hostname"`
	URL             string            `json:"url"`
	SentBytes       int64             `json:"sent_bytes"`
	ReceivedBytes   int64             `json:"received_bytes"`
	DurationSeconds int64             `json:"duration_seconds"`
	ParseStatus     string            `json:"parse_status"`
	ParseError      string            `json:"parse_error,omitempty"`
	DeviceName      string            `json:"device_name"`
	SrcMAC          string            `json:"src_mac"`
	AITool          string            `json:"ai_tool"`
	Fields          map[string]string `json:"fields"`
	Raw             string            `json:"raw_message"`
}

func parseKV(s string) map[string]string {
	out := map[string]string{}
	for i := 0; i < len(s); {
		for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
			i++
		}
		start := i
		for i < len(s) && s[i] != '=' && s[i] != ' ' {
			i++
		}
		if i >= len(s) || s[i] != '=' {
			for i < len(s) && s[i] != ' ' {
				i++
			}
			continue
		}
		key := s[start:i]
		i++
		var value string
		if i < len(s) && s[i] == '"' {
			i++
			var b strings.Builder
			for i < len(s) {
				// v5.13: only \" and \\ are escapes; any other backslash is kept (CORP\nimal was stored as "CORPnimal")
				if s[i] == '\\' && i+1 < len(s) && (s[i+1] == '"' || s[i+1] == '\\') {
					b.WriteByte(s[i+1])
					i += 2
					continue
				}
				if s[i] == '"' {
					i++
					break
				}
				b.WriteByte(s[i])
				i++
			}
			value = b.String()
		} else {
			start = i
			for i < len(s) && s[i] != ' ' && s[i] != '\t' {
				i++
			}
			value = s[start:i]
		}
		if key != "" {
			out[key] = value
		}
	}
	return out
}

func epochToTime(n int64) (time.Time, bool) {
	switch {
	case n >= 1e17:
		return time.Unix(0, n).UTC(), true
	case n >= 1e14:
		return time.UnixMicro(n).UTC(), true
	case n >= 1e11:
		return time.UnixMilli(n).UTC(), true
	case n > 0:
		return time.Unix(n, 0).UTC(), true
	}
	return time.Time{}, false
}

func atoi(s string) int     { v, _ := strconv.Atoi(s); return v }
func atoi64(s string) int64 { v, _ := strconv.ParseInt(s, 10, 64); return v }
func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

// sanitizeLog makes a message safe for PostgreSQL text columns: NUL bytes and invalid UTF-8 would otherwise make the
// whole COPY batch fail (and, before this fix, block the spool forever).
func sanitizeLog(b []byte) []byte {
	if utf8.Valid(b) && bytes.IndexByte(b, 0) < 0 {
		return b
	}
	return bytes.ToValidUTF8(bytes.ReplaceAll(b, []byte{0}, nil), []byte("\uFFFD"))
}

func ParseLog(raw []byte, source string) LogRecord {
	raw = sanitizeLog(raw)
	now := time.Now().UTC()
	text := strings.TrimSpace(strings.Trim(string(raw), "\x00"))
	fields := parseKV(text)
	record := LogRecord{ReceivedAt: now, EventTime: now, SourceIP: source, Fields: fields, Raw: text, ParseStatus: "parsed"}

	if eventTime := fields["eventtime"]; eventTime != "" {
		// FortiOS 7.x writes eventtime in nanoseconds; older builds used seconds.
		if n, err := strconv.ParseInt(eventTime, 10, 64); err == nil {
			if t, ok := epochToTime(n); ok {
				record.EventTime = t
			} else {
				record.ParseStatus = "partial"
				record.ParseError = "invalid eventtime"
			}
		} else {
			record.ParseStatus = "partial"
			record.ParseError = "invalid eventtime"
		}
	} else if fields["date"] != "" && fields["time"] != "" {
		if parsed, err := time.ParseInLocation("2006-01-02 15:04:05", fields["date"]+" "+fields["time"], time.Local); err == nil {
			record.EventTime = parsed.UTC()
		} else {
			record.ParseStatus = "partial"
			record.ParseError = err.Error()
		}
	} else {
		record.ParseStatus = "partial"
		record.ParseError = "missing date/time"
	}

	record.DeviceID = fields["devid"]
	record.VDOM = fields["vd"]
	record.LogID = fields["logid"]
	record.Type = fields["type"]
	record.Subtype = fields["subtype"]
	record.Level = fields["level"]
	var okS, okD bool
	record.SrcIP, okS = cleanIP(fields["srcip"])
	record.SrcPort = atoi(fields["srcport"])
	record.DstIP, okD = cleanIP(fields["dstip"])
	if !okS || !okD {
		// keep the log (raw text unchanged) but never hand a non-address to an inet column
		record.ParseStatus = "partial"
		record.ParseError = fmt.Sprintf("invalid IP: srcip=%q dstip=%q", fields["srcip"], fields["dstip"])
	}
	record.DstPort = atoi(fields["dstport"])
	record.Protocol = firstNonEmpty(fields["proto"], fields["protocol"])
	record.Action = fields["action"]
	record.PolicyID = atoi(fields["policyid"])
	record.PolicyName = fields["policyname"]
	record.User = firstNonEmpty(fields["user"], fields["srcuser"], fields["unauthuser"])
	record.Application = firstNonEmpty(fields["app"], fields["application"])
	if record.Application == "" && record.Type == "traffic" {
		record.Application = fields["service"]
	} // "service" on UTM logs is just HTTP/HTTPS
	record.Category = firstNonEmpty(fields["catdesc"], fields["appcat"], fields["cat"])
	record.Hostname = firstNonEmpty(fields["hostname"], fields["dstname"], fields["srcname"])
	record.URL = fields["url"]
	record.AppRisk = fields["apprisk"]
	record.SentBytes = atoi64(firstNonEmpty(fields["sentbyte"], fields["sentbytes"]))
	record.ReceivedBytes = atoi64(firstNonEmpty(fields["rcvdbyte"], fields["receivedbyte"], fields["rcvdbytes"]))
	record.DurationSeconds = atoi64(fields["duration"])
	record.DeviceName = firewallName(source, fields["devname"])
	record.SrcMAC = normMAC(firstNonEmpty(fields["srcmac"], fields["mastersrcmac"]))
	record.AITool = classifyAI(record.Application, record.Hostname, record.Category, fields["cat"])
	return record
}

// cleanIP returns a valid address (IPv4-mapped IPv6 unmapped), or "" and false when the value is not an IP.
// An empty value is valid (not every log has both addresses).
func cleanIP(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", true
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return a.Unmap().String(), true
	}
	// FortiOS sometimes writes a doubled key (dstip=dstip=192.168.2.1), which parses as the value "dstip=192.168.2.1".
	// The address is still there: keep it instead of throwing the whole value away.
	if i := strings.LastIndexByte(s, '='); i >= 0 {
		if a, err := netip.ParseAddr(strings.TrimSpace(s[i+1:])); err == nil {
			return a.Unmap().String(), true
		}
	}
	return "", false
}

// cleanRecord applies the same checks to a record that was parsed earlier (for example by an older version and kept
// in the spool), so nothing invalid reaches an inet column. It returns true when something was corrected.
func cleanRecord(r *LogRecord) bool {
	changed := false
	fix := func(v *string, name string) {
		c, ok := cleanIP(*v)
		if !ok {
			if r.ParseError == "" {
				r.ParseError = fmt.Sprintf("invalid IP: %s=%q", name, *v)
			}
			r.ParseStatus = "partial"
			changed = true
		}
		*v = c
	}
	fix(&r.SrcIP, "srcip")
	fix(&r.DstIP, "dstip")
	if c, ok := cleanIP(r.SourceIP); ok && c != "" {
		r.SourceIP = c
	}
	return changed
}

// normMAC returns aa:bb:cc:dd:ee:ff, or "" when s is not a MAC address.
func normMAC(s string) string {
	h := make([]byte, 0, 12)
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f':
			h = append(h, c)
		case c >= 'A' && c <= 'F':
			h = append(h, c+32)
		case c == ':' || c == '-' || c == '.':
		default:
			return ""
		}
	}
	if len(h) != 12 {
		return ""
	}
	var b strings.Builder
	for i := 0; i < 12; i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.Write(h[i : i+2])
	}
	return b.String()
}
