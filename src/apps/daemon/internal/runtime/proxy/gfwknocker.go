package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

type GFWKnockerFragmentor struct {
	ListenIP      string
	ListenPort    int
	TargetIP      string
	TargetPort    int
	IsFragment    bool
	NumFragment   int
	FragmentSleep time.Duration
	IsRawForward  bool
	listener      net.Listener
	wg            sync.WaitGroup
	ctx           context.Context
	cancel        context.CancelFunc
}

func NewGFWKnockerFragmentor(listenIP string, listenPort int, targetIP string, targetPort int, isFragment bool, numFragment int, fragmentSleep time.Duration) *GFWKnockerFragmentor {
	ctx, cancel := context.WithCancel(context.Background())
	return &GFWKnockerFragmentor{
		ListenIP:      listenIP,
		ListenPort:    listenPort,
		TargetIP:      targetIP,
		TargetPort:    targetPort,
		IsFragment:    isFragment,
		NumFragment:   numFragment,
		FragmentSleep: fragmentSleep,
		IsRawForward:  false,
		ctx:           ctx,
		cancel:        cancel,
	}
}

func (f *GFWKnockerFragmentor) Start() error {
	addr := fmt.Sprintf("%s:%d", f.ListenIP, f.ListenPort)
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	f.listener = l
	f.ListenPort = l.Addr().(*net.TCPAddr).Port

	f.wg.Add(1)
	go func() {
		defer f.wg.Done()
		for {
			conn, err := f.listener.Accept()
			if err != nil {
				if !waitAfterAcceptError(f.ctx.Done(), err) {
					return
				}
				continue
			}
			f.wg.Add(1)
			go func(c net.Conn) {
				defer f.wg.Done()
				f.handleConnection(c)
			}(conn)
		}
	}()
	return nil
}

func (f *GFWKnockerFragmentor) Stop() {
	f.cancel()
	if f.listener != nil {
		f.listener.Close()
	}
	f.wg.Wait()
}

func (f *GFWKnockerFragmentor) GetListenPort() int {
	return f.ListenPort
}

func (f *GFWKnockerFragmentor) handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	if f.IsRawForward {
		f.handleRawForward(clientConn)
		return
	}

	// Read CONNECT request or initial payload
	buff := make([]byte, 8192)
	n, err := clientConn.Read(buff)
	if err != nil || n == 0 {
		return
	}

	payload := buff[:n]
	payloadStr := string(payload)
	lines := strings.Split(payloadStr, "\r\n")
	if len(lines) == 0 {
		return
	}

	parts := strings.Split(lines[0], " ")
	if len(parts) < 2 {
		return
	}

	method := parts[0]
	rawHost := parts[1]

	var remoteHost string
	var remotePort string

	if method == "CONNECT" {
		if f.TargetIP != "" && f.TargetPort > 0 {
			remoteHost = f.TargetIP
			remotePort = fmt.Sprintf("%d", f.TargetPort)
		} else {
			h, p, err := net.SplitHostPort(rawHost)
			if err != nil {
				return
			}
			remoteHost = h
			remotePort = p
		}
	} else {
		// HTTP redirect or bad request
		clientConn.Write([]byte("HTTP/1.1 400 Bad Request\r\nProxy-agent: LumiNet/1.0\r\n\r\n"))
		return
	}

	backendAddr := net.JoinHostPort(remoteHost, remotePort)
	backendConn, err := net.DialTimeout("tcp", backendAddr, 8*time.Second)
	if err != nil {
		clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\nProxy-agent: LumiNet/1.0\r\n\r\n"))
		return
	}
	defer backendConn.Close()

	// Connection established response
	clientConn.Write([]byte("HTTP/1.1 200 Connection established\r\nProxy-agent: LumiNet/1.0\r\n\r\n"))

	// Pipe upstream and downstream
	var wg sync.WaitGroup
	wg.Add(2)

	// Upstream with fragmentation
	go func() {
		defer wg.Done()
		defer backendConn.Close()
		upBuff := make([]byte, 8192)
		first := f.IsFragment

		for {
			rn, err := clientConn.Read(upBuff)
			if err != nil {
				return
			}
			if rn == 0 {
				continue
			}
			if first {
				first = false
				f.sendFragmented(backendConn, upBuff[:rn])
			} else {
				if _, err := backendConn.Write(upBuff[:rn]); err != nil {
					return
				}
			}
		}
	}()

	// Downstream
	go func() {
		defer wg.Done()
		defer clientConn.Close()
		downBuff := make([]byte, 8192)
		for {
			rn, err := backendConn.Read(downBuff)
			if err != nil {
				return
			}
			if _, err := clientConn.Write(downBuff[:rn]); err != nil {
				return
			}
		}
	}()

	wg.Wait()
}

func (f *GFWKnockerFragmentor) sendFragmented(conn net.Conn, data []byte) {
	if len(data) <= 1 || f.NumFragment <= 1 {
		conn.Write(data)
		return
	}
	indices := PickKRandomInts(f.NumFragment-1, len(data))
	pre := 0
	for _, next := range indices {
		conn.Write(data[pre:next])
		time.Sleep(f.FragmentSleep)
		pre = next
	}
	conn.Write(data[pre:])
}

func (f *GFWKnockerFragmentor) handleRawForward(clientConn net.Conn) {
	if f.TargetIP == "" || f.TargetPort <= 0 {
		return
	}
	backendAddr := net.JoinHostPort(f.TargetIP, strconv.Itoa(f.TargetPort))
	backendConn, err := net.DialTimeout("tcp", backendAddr, 8*time.Second)
	if err != nil {
		return
	}
	defer backendConn.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	// Upstream with fragmentation
	go func() {
		defer wg.Done()
		defer backendConn.Close()
		upBuff := make([]byte, 8192)
		first := f.IsFragment
		for {
			rn, err := clientConn.Read(upBuff)
			if err != nil {
				return
			}
			if rn == 0 {
				continue
			}
			if first {
				first = false
				f.sendFragmented(backendConn, upBuff[:rn])
			} else {
				if _, err := backendConn.Write(upBuff[:rn]); err != nil {
					return
				}
			}
		}
	}()

	// Downstream
	go func() {
		defer wg.Done()
		defer clientConn.Close()
		downBuff := make([]byte, 8192)
		for {
			rn, err := backendConn.Read(downBuff)
			if err != nil {
				return
			}
			if _, err := clientConn.Write(downBuff[:rn]); err != nil {
				return
			}
		}
	}()

	wg.Wait()
}

type GFWKnockerDoH struct {
	DohURL     string
	dnsCache   map[string]string
	mu         sync.RWMutex
	fragmentor *GFWKnockerFragmentor
	httpClient *http.Client
}

func NewGFWKnockerDoH(dohURL string, targetIP string, targetPort int, isFragment bool, numFragment int, fragmentSleep time.Duration, offlineDNS map[string]string) *GFWKnockerDoH {
	actualDoh := dohURL
	if dohURL == "google" {
		actualDoh = "https://dns.google/resolve?name="
	} else if dohURL == "cloudflare" {
		actualDoh = "https://cloudflare-dns.com/dns-query?name="
	}
	cache := make(map[string]string)
	if offlineDNS != nil {
		for k, v := range offlineDNS {
			cache[k] = v
		}
	}
	frag := NewGFWKnockerFragmentor("127.0.0.1", 0, targetIP, targetPort, isFragment, numFragment, fragmentSleep)
	frag.Start()
	proxyURL, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", frag.GetListenPort()))
	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}
	return &GFWKnockerDoH{
		DohURL:     actualDoh,
		dnsCache:   cache,
		fragmentor: frag,
		httpClient: client,
	}
}

func (d *GFWKnockerDoH) Query(domain string) (string, error) {
	d.mu.RLock()
	val, ok := d.dnsCache[domain]
	d.mu.RUnlock()
	if ok {
		return val, nil
	}
	queryURL := fmt.Sprintf("%s%s&type=A&ct=%s", d.DohURL, domain, url.QueryEscape("application/dns-json"))
	req, err := http.NewRequest("GET", queryURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/dns-json")
	resp, err := d.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("bad status code: %d", resp.StatusCode)
	}
	body, err := readBoundedProxyHTTPBody(resp.Body, maxProxyControlHTTPBodyBytes, "DoH JSON response")
	if err != nil {
		return "", err
	}
	var parsed struct {
		Answer []struct {
			Type int    `json:"type"`
			Data string `json:"data"`
		} `json:"Answer"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", err
	}
	for _, ans := range parsed.Answer {
		if ans.Type == 1 { // A Record
			d.mu.Lock()
			d.dnsCache[domain] = ans.Data
			d.mu.Unlock()
			return ans.Data, nil
		}
	}
	return "", fmt.Errorf("no A record found")
}

func (d *GFWKnockerDoH) Stop() {
	if d.fragmentor != nil {
		d.fragmentor.Stop()
	}
}
