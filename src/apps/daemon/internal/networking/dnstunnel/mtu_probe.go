package dnstunnel

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// MTUProbeResult reports the discovered query-size budget for one resolver.
type MTUProbeResult struct {
	Resolver       string        `json:"resolver"`
	UploadBudget   int           `json:"upload_budget"`   // largest outbound DNS query that survived
	DownloadBudget int           `json:"download_budget"` // replies echo the question plus records
	RoundTrips     int           `json:"round_trips"`
	Duration       time.Duration `json:"duration"`
	Err            string        `json:"error,omitempty"`
}

// MTUProber actively discovers the largest UDP DNS payload a resolver path
// accepts, replacing the static DefaultUDPBudget with measured reality.
//
// Method: binary-search an
// EDNS(0) padding label — send a well-formed query padded to `size` bytes; any
// answer (even SERVFAIL/REFUSED) proves the path carried it, while silence
// after retransmits marks the ceiling.
type MTUProber struct {
	ResolverIP string        // "1.2.3.4" or "1.2.3.4:53"
	QueryZone  string        // zone that will answer (authoritative side)
	Timeout    time.Duration // per-datagram wait, default 1200ms
	Retries    int           // retransmissions per probe size, default 2
	FloorSize  int           // never propose below this, default 512
	CeilSize   int           // never probe above this, default 4096

	// Dial replaces net.DialTimeout in tests (fake packet conn).
	Dial func(ctx context.Context, network, address string) (net.Conn, error)
}

// NewMTUProber builds a prober with library defaults.
func NewMTUProber(resolverIP, queryZone string) *MTUProber {
	return &MTUProber{
		ResolverIP: resolverIP,
		QueryZone:  queryZone,
		Timeout:    1200 * time.Millisecond,
		Retries:    2,
		FloorSize:  512,
		CeilSize:   4096,
	}
}

const (
	mtuProbeMinFloor = 128
	mtuPaddingFiller = byte('l')
)

// Probe runs the size search and returns the discovered budgets.
func (p *MTUProber) Probe(ctx context.Context) (MTUProbeResult, error) {
	result := MTUProbeResult{Resolver: p.ResolverIP}
	if p.QueryZone == "" {
		return result, fmt.Errorf("mtu probe requires a query zone")
	}
	host := p.ResolverIP
	if _, _, err := net.SplitHostPort(host); err != nil {
		host = net.JoinHostPort(host, "53")
	}
	dial := p.Dial
	if dial == nil {
		dial = (&net.Dialer{Timeout: 5 * time.Second}).DialContext
	}
	conn, err := dial(ctx, "udp", host)
	if err != nil {
		result.Err = fmt.Sprintf("dial: %v", err)
		return result, fmt.Errorf("mtu probe dial: %w", err)
	}
	defer conn.Close()

	started := time.Now()
	floor := p.FloorSize
	if floor < mtuProbeMinFloor {
		floor = mtuProbeMinFloor
	}
	ceil := p.CeilSize
	if ceil < floor {
		ceil = floor + 512
	}

	best := 0
	for ceil-floor > 16 {
		candidate := (floor + ceil) / 2
		ok, trips := p.probeSize(ctx, conn, candidate)
		result.RoundTrips += trips
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		if ok {
			best = candidate
			floor = candidate + 1
		} else {
			ceil = candidate - 1
		}
	}
	result.UploadBudget = best
	result.DownloadBudget = best + 16
	result.Duration = time.Since(started)
	if best == 0 {
		result.Err = "no size survived probing"
	}
	return result, nil
}

func (p *MTUProber) waitPerAttempt() time.Duration {
	if p.Timeout <= 0 {
		return 1200 * time.Millisecond
	}
	return p.Timeout
}

func (p *MTUProber) probeSize(ctx context.Context, conn net.Conn, size int) (bool, int) {
	query := buildPaddedQuery(p.QueryZone, size)
	attempts := p.Retries + 1
	baseDeadline := time.Now().Add(p.waitPerAttempt())
	for attempt := 0; attempt < attempts; attempt++ {
		select {
		case <-ctx.Done():
			return false, attempt + 1
		default:
		}
		_ = conn.SetReadDeadline(baseDeadline.Add(time.Duration(attempt+1) * p.waitPerAttempt()))
		if _, err := conn.Write(query); err != nil {
			continue
		}
		buf := make([]byte, size+512)
		n, err := conn.Read(buf)
		if err == nil && n >= 12 {
			return true, attempt + 1
		}
	}
	return false, attempts
}


// buildPaddedQuery crafts a DNS query for zone whose total wire length lands as
// close to target as possible, filling the difference with legal EDNS padding.
//
// Wire layout: header(12) + QNAME(labels incl. padding + root) + QTYPE/QCLASS(4)
// + OPT root(1)+type(2)+class(2)+ttl(4)+rdlen(2)+rdata(padding-11).
func buildPaddedQuery(zone string, target int) []byte {
	const (
		headerLen     = 12
		questionTail  = 4 // QTYPE + QCLASS
		optFixed      = 10
		optRoot       = 1
		optRDataFloor = 8
	)

	labels := splitLabels(zone)
	qnameLen := len(zone) - len(labels) + 1 // dots become length bytes; add root byte
	for _, l := range labels {
		qnameLen += len(l)
	}
	_ = qnameLen

	padTotal := target - headerLen - questionTail - optFixed - optRoot - qnameWireLen(zone)
	if padTotal < optRDataFloor {
		padTotal = optRDataFloor
	}

	buf := make([]byte, 0, target+64)
	var id uint16 = 0x4D54 // "MT" marker aids pcap triage
	buf = append(buf, byte(id>>8), byte(id))
	buf = append(buf, 0x00, 0x00) // flags: standard query
	buf = append(buf, 0x00, 0x01) // QDCOUNT = 1
	buf = append(buf, 0x00, 0x00) // ANCOUNT
	buf = append(buf, 0x00, 0x00) // NSCOUNT
	buf = append(buf, 0x00, 0x01) // ARCOUNT = 1 (EDNS OPT)

	for _, label := range splitLabels(zone) {
		buf = append(buf, byte(len(label)))
		buf = append(buf, strings.ToLower(label)...)
	}
	buf = append(buf, 0x00)                                 // root terminator
	buf = append(buf, 0x00, byte(qtypeA>>8), byte(qtypeA))  // QTYPE=A
	buf = append(buf, 0x00, 0x01)                           // QCLASS=IN

	// OPT RR: root(0), TYPE=41(0x0029), CLASS=payload size 4096, TTL=0,
	// RDLENGTH=padTotal, RDATA="padding..." option (code 12? we use raw filler
	// accepted as unknown option data by relays).
	buf = append(buf, 0x00)
	buf = append(buf, 0x00, 0x29)
	buf = append(buf, 0x10, 0x00)
	buf = append(buf, 0x00, 0x00, 0x00, 0x00)
	rdlen := padTotal
	if rdlen > 0xFFFF {
		rdlen = 0xFFFF
	}
	buf = append(buf, byte(rdlen>>8), byte(rdlen))
	fillers := chunkFiller(rdlen)
	for _, f := range fillers {
		buf = append(buf, f...)
	}
	return buf
}

// chunkFiller splits n filler bytes into DNS-legal ≤63B chunks.
func chunkFiller(n int) [][]byte {
	out := [][]byte{}
	for n > 0 {
		chunk := 63
		if chunk > n {
			chunk = n
		}
		piece := make([]byte, chunk)
		for i := range piece {
			piece[i] = mtuPaddingFiller
		}
		out = append(out, piece)
		n -= chunk
	}
	return out
}

func qnameWireLen(zone string) int {
	total := 1 // root
	for _, label := range splitLabels(zone) {
		total += 1 + len(label)
	}
	return total
}

// splitLabels splits a dotted name into labels.
func splitLabels(name string) []string {
	out := []string{}
	current := strings.Builder{}
	for _, c := range name {
		if c == '.' {
			if current.Len() > 0 {
				out = append(out, current.String())
				current.Reset()
			}
			continue
		}
		current.WriteRune(c)
	}
	if current.Len() > 0 {
		out = append(out, current.String())
	}
	return out
}

const qtypeA = 1
