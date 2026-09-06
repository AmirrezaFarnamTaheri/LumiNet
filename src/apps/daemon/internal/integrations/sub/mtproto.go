package sub

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type MTProtoProxy struct {
	Host   string `json:"host"`
	Port   int    `json:"port"`
	Secret string `json:"secret"`
	PingMs int    `json:"ping_ms"`
}

var mtprotoMirrors = []string{
	"https://fastly.jsdelivr.net/gh/hookzof/socks5_list@master/tg/mtproto.json",
	"https://raw.gitmirror.com/hookzof/socks5_list/master/tg/mtproto.json",
	"https://ghproxy.net/https://raw.githubusercontent.com/hookzof/socks5_list/master/tg/mtproto.json",
}

func FetchAndTestMTProto(ctx context.Context) ([]MTProtoProxy, error) {
	var rawProxies []MTProtoProxy
	client := &http.Client{Timeout: 10 * time.Second}
	var fetchErr error

	for _, url := range mtprotoMirrors {
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			fetchErr = err
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			body, readErr := readBoundedSubscriptionBody(resp.Body)
			if readErr == nil {
				err = json.Unmarshal(body, &rawProxies)
			} else {
				err = readErr
			}
			if err == nil && len(rawProxies) > 0 {
				fetchErr = nil
				break
			}
		}
	}

	if fetchErr != nil {
		return nil, fmt.Errorf("failed to fetch from mirrors: %w", fetchErr)
	}

	if len(rawProxies) == 0 {
		return nil, fmt.Errorf("no proxies found")
	}

	return testAndFilterProxies(ctx, rawProxies), nil
}

func FetchAndTestMTProtoFromChannel(ctx context.Context, channel string) ([]MTProtoProxy, error) {
	links, err := FetchLinksFromTelegramChannel(ctx, channel)
	if err != nil {
		return nil, err
	}

	var rawProxies []MTProtoProxy
	seenProxy := make(map[string]bool)
	for _, match := range links {
		if !strings.HasPrefix(match, "tg://") && !strings.HasPrefix(match, "t.me/proxy") && !strings.HasPrefix(match, "https://t.me/proxy") {
			continue // skip non-MTProto
		}
		var u *url.URL
		if strings.HasPrefix(match, "tg://") {
			match = "https://t.me/" + strings.TrimPrefix(match, "tg://")
		} else if !strings.HasPrefix(match, "http") {
			match = "https://" + match
		}

		var parseErr error
		u, parseErr = url.Parse(match)
		if parseErr != nil {
			continue
		}

		q := u.Query()
		server := q.Get("server")
		portStr := q.Get("port")
		secret := q.Get("secret")

		if server == "" || portStr == "" || secret == "" {
			continue
		}

		port, parseErr := strconv.Atoi(portStr)
		if parseErr != nil {
			continue
		}

		key := fmt.Sprintf("%s:%d", server, port)
		if seenProxy[key] {
			continue
		}
		seenProxy[key] = true

		rawProxies = append(rawProxies, MTProtoProxy{
			Host:   server,
			Port:   port,
			Secret: secret,
		})
	}

	if len(rawProxies) == 0 {
		return nil, fmt.Errorf("no MTProto proxy links found in channel")
	}

	return testAndFilterProxies(ctx, rawProxies), nil
}

func testAndFilterProxies(ctx context.Context, rawProxies []MTProtoProxy) []MTProtoProxy {
	// Shuffle and limit to 40 proxies to test quickly
	rand.Seed(time.Now().UnixNano())
	rand.Shuffle(len(rawProxies), func(i, j int) {
		rawProxies[i], rawProxies[j] = rawProxies[j], rawProxies[i]
	})

	testLimit := 40
	if len(rawProxies) < testLimit {
		testLimit = len(rawProxies)
	}
	proxiesToTest := rawProxies[:testLimit]

	var wg sync.WaitGroup
	var mu sync.Mutex
	tested := make([]MTProtoProxy, 0, len(proxiesToTest))

	sem := make(chan struct{}, 15) // limit concurrency to 15 workers

	for _, p := range proxiesToTest {
		wg.Add(1)
		go func(proxy MTProtoProxy) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}

			addr := net.JoinHostPort(proxy.Host, fmt.Sprintf("%d", proxy.Port))
			start := time.Now()
			d := net.Dialer{Timeout: 2 * time.Second}
			conn, err := d.DialContext(ctx, "tcp", addr)
			if err == nil {
				conn.Close()
				proxy.PingMs = int(time.Since(start).Milliseconds())
				mu.Lock()
				tested = append(tested, proxy)
				mu.Unlock()
			}
		}(p)
	}

	wg.Wait()

	sort.Slice(tested, func(i, j int) bool {
		return tested[i].PingMs < tested[j].PingMs
	})

	return tested
}
