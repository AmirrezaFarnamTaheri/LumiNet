package diagnostics

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/maybeknott/luminet/internal/protocols/tlsfragment"
	utls "github.com/refraction-networking/utls"
)

// MatrixResult represents one run output of the SNI spoofing matrix.
type MatrixResult struct {
	UTLS              string  `json:"utls"`
	FakeRepeat        int     `json:"fake_repeat"`
	FakeRepeatApplied bool    `json:"fake_repeat_applied"`
	EnableFragment    bool    `json:"enable_fragment"`
	Pass              bool    `json:"pass"`
	LatencyMs         float64 `json:"latency_ms"`
	Error             string  `json:"error,omitempty"`
}

// runSniMatrix exercises only behavior the target actually implements:
// UTLS {none, firefox, chrome, edge, safari} × Fragment {off, on}.
// FakeRepeat is retained as a compatibility field fixed at 1; raw fake-packet
// repetition is not implemented and must not manufacture duplicate evidence.
func (p *Pipeline) runSniMatrix(ctx context.Context, job *DiagnosticJob, result *DiagnosticResult) (*DiagnosticResult, error) {
	connectIP := job.Target
	if connectIP == "" {
		// Default to Cloudflare target if none specified
		connectIP = "104.16.124.96"
	}
	fakeSNI := job.Options["fake_sni"]
	if fakeSNI == "" {
		fakeSNI = "challenges.cloudflare.com"
	}

	utlsList := []string{"none", "firefox", "chrome", "edge", "safari"}
	repeats := []int{1}
	fragments := []bool{false, true}

	var matrixResults []MatrixResult
	successCount := 0

	for _, utlsName := range utlsList {
		for _, repeat := range repeats {
			for _, enableFrag := range fragments {
				if ctx.Err() != nil {
					break
				}

				start := time.Now()
				err := runSingleMatrixProbe(ctx, connectIP, fakeSNI, utlsName, repeat, enableFrag)
				latency := time.Since(start).Seconds() * 1000.0

				row := MatrixResult{
					UTLS:              utlsName,
					FakeRepeat:        repeat,
					FakeRepeatApplied: false,
					EnableFragment:    enableFrag,
					Pass:              err == nil,
					LatencyMs:         latency,
				}
				if err != nil {
					row.Error = err.Error()
				} else {
					successCount++
				}

				matrixResults = append(matrixResults, row)
				// Small delay to prevent rate-limiting or firewall flags
				time.Sleep(200 * time.Millisecond)
			}
		}
	}

	result.Success = successCount > 0
	result.Metrics["results"] = matrixResults
	result.Metrics["total_cases"] = len(matrixResults)
	result.Metrics["passed_cases"] = successCount

	return result, nil
}

func runSingleMatrixProbe(ctx context.Context, connectIP, fakeSNI, utlsName string, repeat int, enableFrag bool) error {
	dialer := &net.Dialer{Timeout: 4 * time.Second}
	rawConn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(connectIP, "443"))
	if err != nil {
		return fmt.Errorf("tcp dial failed: %w", err)
	}
	defer rawConn.Close()

	var conn net.Conn = rawConn
	if enableFrag {
		fragCfg := tlsfragment.UTLSFragmentConfig{
			Strategy:     tlsfragment.StrategySniSplit,
			SleepBetween: 10 * time.Millisecond,
		}
		conn = tlsfragment.WrapUTLSFragmentConn(rawConn, fragCfg)
	}

	var tlsConn net.Conn
	if utlsName == "none" {
		tlsConn = tls.Client(conn, &tls.Config{
			ServerName: fakeSNI,
		})
	} else {
		var clientHelloID utls.ClientHelloID
		switch utlsName {
		case "firefox":
			clientHelloID = utls.HelloFirefox_Auto
		case "chrome":
			clientHelloID = utls.HelloChrome_Auto
		case "edge":
			clientHelloID = utls.HelloEdge_Auto
		case "safari":
			clientHelloID = utls.HelloSafari_Auto
		default:
			clientHelloID = utls.HelloRandomized
		}

		uconn := utls.UClient(conn, &utls.Config{
			ServerName: fakeSNI,
		}, clientHelloID)
		tlsConn = uconn
	}

	// Set deadline for handshake
	_ = tlsConn.SetDeadline(time.Now().Add(5 * time.Second))
	if tc, ok := tlsConn.(*utls.UConn); ok {
		err = tc.Handshake()
	} else if tc, ok := tlsConn.(*tls.Conn); ok {
		err = tc.Handshake()
	}
	if err != nil {
		return fmt.Errorf("tls handshake: %w", err)
	}

	// Send basic probe request
	req := fmt.Sprintf("GET /cdn-cgi/trace HTTP/1.1\r\nHost: %s\r\nUser-Agent: Go-http-client/1.1\r\nConnection: close\r\n\r\n", fakeSNI)
	if _, err := tlsConn.Write([]byte(req)); err != nil {
		return fmt.Errorf("write HTTP probe: %w", err)
	}

	buf := make([]byte, 1024)
	n, err := io.ReadAtLeast(tlsConn, buf, 10)
	if err != nil && err != io.EOF {
		return fmt.Errorf("read HTTP response: %w", err)
	}

	resp := string(buf[:n])
	if !strings.Contains(resp, "HTTP/1.1 200") && !strings.Contains(resp, "HTTP/1.0 200") && !strings.Contains(resp, "h=challenges.cloudflare.com") {
		return fmt.Errorf("unexpected HTTP response status: %s", strings.Split(resp, "\r\n")[0])
	}

	return nil
}
