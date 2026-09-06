package sub

import (
	"context"
	"strings"
	"sync"

	"github.com/maybeknott/luminet/internal/foundation/resourcebudget"
	"github.com/maybeknott/luminet/internal/networking/proxyconfig"
)

type SubscriptionFilters struct {
	AllowProtocols   []string `json:"allow_protocols"`
	SearchQuery      string   `json:"search_query"`
	MinPort          int      `json:"min_port"`
	MaxPort          int      `json:"max_port"`
	AllowInsecureTLS bool     `json:"allow_insecure_tls"`
}

var DefaultSubscriptionLinks = []string{
	"https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
	"https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile-2.txt",
	"https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_VLESS_RUS_mobile.txt",
	"https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-checked.txt",
	"https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_VLESS_RUS.txt",
	"https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_SS+All_RUS.txt",
	"https://raw.githubusercontent.com/Mosifree/-FREE2CONFIG/refs/heads/main/FRAGMENT",
	"https://raw.githubusercontent.com/ThomasJasperthecat/sub/main/sublist1.txt",
	"https://raw.githubusercontent.com/masir-sefid/Sub/main/@Masir_Sefid.txt",
	"https://sub.iampedi5.live/sub/base64.txt",
	"https://sub.whitedns.one/sub/mihomo.yaml",
}

var DefaultTelegramChannels = []string{
	"@ProxyFree_Ru",
	"@TProxyRU",
	"@iRoProxy",
	"@proxyy",
	"@ProxyMTProto",
	"@Masir_Sefid",
	"@v2ray_outlinefree",
	"@ProxyDaemi",
}

const maxConcurrentSubscriptionInputs = 4

type subscriptionInputResolver func(context.Context, string, bool) []*proxyconfig.ProxyConfig

func AggregateSubscriptions(ctx context.Context, inputs []string, filters SubscriptionFilters) ([]*proxyconfig.ProxyConfig, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	resolvedInputs := resolveSubscriptionInputs(inputs)
	batches := resolveInputsBounded(ctx, resolvedInputs, filters.AllowInsecureTLS, resolveSubscriptionInput)

	aggregated := make([]*proxyconfig.ProxyConfig, 0)
	for _, batch := range batches {
		aggregated = append(aggregated, batch...)
	}

	filtered := make([]*proxyconfig.ProxyConfig, 0, len(aggregated))
	for _, c := range aggregated {
		if matchFilters(c, filters) {
			filtered = append(filtered, c)
		}
	}
	return dedupeProxyConfigs(filtered), nil
}

func resolveSubscriptionInputs(inputs []string) []string {
	if len(inputs) == 0 {
		out := make([]string, 0, len(DefaultSubscriptionLinks)+len(DefaultTelegramChannels))
		out = append(out, DefaultSubscriptionLinks...)
		out = append(out, DefaultTelegramChannels...)
		return out
	}
	var out []string
	for _, input := range inputs {
		if strings.EqualFold(strings.TrimSpace(input), "default") {
			out = append(out, DefaultSubscriptionLinks...)
			out = append(out, DefaultTelegramChannels...)
		} else {
			out = append(out, input)
		}
	}
	return out
}

func resolveInputsBounded(ctx context.Context, inputs []string, allowInsecureTLS bool, resolver subscriptionInputResolver) [][]*proxyconfig.ProxyConfig {
	results := make([][]*proxyconfig.ProxyConfig, len(inputs))
	if len(inputs) == 0 || resolver == nil {
		return results
	}
	workers := resourcebudget.Detect().CapWorkers(maxConcurrentSubscriptionInputs, maxConcurrentSubscriptionInputs)
	if len(inputs) < workers {
		workers = len(inputs)
	}
	type job struct {
		index int
		input string
	}
	jobs := make(chan job)
	var wg sync.WaitGroup
	wg.Add(workers)
	for range workers {
		go func() {
			defer wg.Done()
			for item := range jobs {
				if ctx != nil && ctx.Err() != nil {
					continue
				}
				results[item.index] = resolver(ctx, item.input, allowInsecureTLS)
			}
		}()
	}
	for index, input := range inputs {
		if ctx != nil {
			select {
			case <-ctx.Done():
				close(jobs)
				wg.Wait()
				return results
			case jobs <- job{index: index, input: input}:
			}
		} else {
			jobs <- job{index: index, input: input}
		}
	}
	close(jobs)
	wg.Wait()
	return results
}

func resolveSubscriptionInput(ctx context.Context, rawInput string, allowInsecureTLS bool) []*proxyconfig.ProxyConfig {
	input := strings.TrimSpace(rawInput)
	if input == "" {
		return nil
	}
	appendSafe := func(configs []*proxyconfig.ProxyConfig) []*proxyconfig.ProxyConfig {
		out := make([]*proxyconfig.ProxyConfig, 0, len(configs))
		for _, cfg := range configs {
			if filterSafeProxyConfig(cfg, allowInsecureTLS) {
				out = append(out, cfg)
			}
		}
		return out
	}

	if strings.HasPrefix(input, "http://") || strings.HasPrefix(input, "https://") {
		configs, err := Fetch(ctx, input)
		if err != nil {
			return nil
		}
		return appendSafe(configs)
	}
	if strings.Contains(input, "t.me/") || (!strings.Contains(input, "\n") && strings.HasPrefix(input, "@")) {
		links, err := FetchLinksFromTelegramChannel(ctx, input)
		if err != nil {
			return nil
		}
		configs := make([]*proxyconfig.ProxyConfig, 0, len(links))
		for _, link := range links {
			cfg, err := proxyconfig.ParseProxyURI(link)
			if err == nil {
				configs = append(configs, cfg)
			}
		}
		return appendSafe(configs)
	}
	configs, err := ParseContent(input)
	if err != nil {
		configs, err = proxyconfig.ParseProxyList(input)
	}
	if err != nil {
		return nil
	}
	return appendSafe(configs)
}

func matchFilters(c *proxyconfig.ProxyConfig, f SubscriptionFilters) bool {
	// Protocol check
	if len(f.AllowProtocols) > 0 {
		proto := strings.ToLower(string(c.Protocol))
		matched := false
		for _, allowed := range f.AllowProtocols {
			if strings.EqualFold(proto, strings.TrimSpace(allowed)) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Search query check
	if f.SearchQuery != "" {
		q := strings.ToLower(f.SearchQuery)
		host := strings.ToLower(c.Address)
		name := strings.ToLower(c.Name)
		if !strings.Contains(host, q) && !strings.Contains(name, q) {
			return false
		}
	}

	// Port check
	if f.MinPort > 0 && c.Port < f.MinPort {
		return false
	}
	if f.MaxPort > 0 && c.Port > f.MaxPort {
		return false
	}

	return true
}
