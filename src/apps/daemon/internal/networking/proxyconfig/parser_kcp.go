package proxyconfig

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

func queryKCPInt(q url.Values, key string, dst *int, set *bool) error {
	raw, ok := q[key]
	if !ok || len(raw) == 0 {
		return nil
	}
	value, err := strconv.Atoi(strings.TrimSpace(raw[len(raw)-1]))
	if err != nil {
		return fmt.Errorf("invalid KCP %s value: %w", key, err)
	}
	*dst, *set = value, true
	return nil
}

func queryKCPInt64(q url.Values, key string, dst *int64, set *bool) error {
	raw, ok := q[key]
	if !ok || len(raw) == 0 {
		return nil
	}
	value, err := strconv.ParseInt(strings.TrimSpace(raw[len(raw)-1]), 10, 64)
	if err != nil {
		return fmt.Errorf("invalid KCP %s value: %w", key, err)
	}
	*dst, *set = value, true
	return nil
}

func queryKCPFloat(q url.Values, key string, dst *float64, set *bool) error {
	raw, ok := q[key]
	if !ok || len(raw) == 0 {
		return nil
	}
	value, err := strconv.ParseFloat(strings.TrimSpace(raw[len(raw)-1]), 64)
	if err != nil {
		return fmt.Errorf("invalid KCP %s value: %w", key, err)
	}
	*dst, *set = value, true
	return nil
}

func queryKCPBool(q url.Values, key string, dst *bool, set *bool) error {
	raw, ok := q[key]
	if !ok || len(raw) == 0 {
		return nil
	}
	switch strings.ToLower(strings.TrimSpace(raw[len(raw)-1])) {
	case "1", "true", "yes", "on":
		*dst, *set = true, true
	case "0", "false", "no", "off":
		*dst, *set = false, true
	default:
		return fmt.Errorf("invalid KCP %s boolean %q", key, raw[len(raw)-1])
	}
	return nil
}

// parseKCP parses a kcp:// URI into a ProxyConfig.
func parseKCP(uri string) (*ProxyConfig, error) {
	parsed, err := url.Parse(uri)
	if err != nil {
		return nil, err
	}

	password := parsed.User.Username()
	if password == "" && parsed.User != nil {
		password = parsed.User.String()
	}

	port := 443
	if parsed.Port() != "" {
		value, err := strconv.Atoi(parsed.Port())
		if err != nil || value < 1 || value > 65535 {
			return nil, fmt.Errorf("invalid KCP port %q", parsed.Port())
		}
		port = value
	}

	q := parsed.Query()
	remark, _ := url.PathUnescape(parsed.Fragment)
	host := parsed.Hostname()
	if host == "" {
		return nil, fmt.Errorf("missing server address")
	}
	if password == "" {
		return nil, fmt.Errorf("missing password")
	}

	config := &ProxyConfig{
		Protocol:       ProtocolKCP,
		Name:           remark,
		Address:        host,
		Port:           port,
		Password:       password,
		Method:         q.Get("crypt"),
		KCPProfile:     q.Get("profile"),
		KCPCompression: q.Get("compression"),
	}

	for _, parse := range []func() error{
		func() error {
			return queryKCPFloat(q, "loss", &config.KCPObservedLossPercent, &config.KCPObservedLossSet)
		},
		func() error { return queryKCPInt(q, "data_shards", &config.KCPDataShards, &config.KCPDataShardsSet) },
		func() error {
			return queryKCPInt(q, "parity_shards", &config.KCPParityShards, &config.KCPParityShardsSet)
		},
		func() error { return queryKCPInt(q, "nodelay", &config.KCPNoDelay, &config.KCPNoDelaySet) },
		func() error { return queryKCPInt(q, "interval", &config.KCPInterval, &config.KCPIntervalSet) },
		func() error { return queryKCPInt(q, "resend", &config.KCPResend, &config.KCPResendSet) },
		func() error { return queryKCPInt(q, "nc", &config.KCPNoCongestion, &config.KCPNoCongestionSet) },
		func() error { return queryKCPInt(q, "sndwnd", &config.KCPSendWindow, &config.KCPSendWindowSet) },
		func() error { return queryKCPInt(q, "rcvwnd", &config.KCPReceiveWindow, &config.KCPReceiveWindowSet) },
		func() error { return queryKCPInt(q, "mtu", &config.KCPMTU, &config.KCPMTUSet) },
		func() error { return queryKCPBool(q, "acknodelay", &config.KCPACKNoDelay, &config.KCPACKNoDelaySet) },
		func() error { return queryKCPBool(q, "writedelay", &config.KCPWriteDelay, &config.KCPWriteDelaySet) },
		func() error { return queryKCPInt(q, "dscp", &config.KCPDSCP, &config.KCPDSCPSet) },
		func() error { return queryKCPInt(q, "readbuf", &config.KCPReadBufferBytes, &config.KCPReadBufferSet) },
		func() error {
			return queryKCPInt(q, "writebuf", &config.KCPWriteBufferBytes, &config.KCPWriteBufferSet)
		},
		func() error {
			return queryKCPInt(q, "dup", &config.KCPPacketDuplication, &config.KCPPacketDuplicationSet)
		},
		func() error { return queryKCPInt64(q, "rate", &config.KCPRateLimitBPS, &config.KCPRateLimitSet) },
		func() error { return queryKCPBool(q, "jitter", &config.KCPJitter, &config.KCPJitterSet) },
	} {
		if err := parse(); err != nil {
			return nil, err
		}
	}
	if q.Get("jitter_min") != "" {
		config.KCPJitterMin, err = strconv.Atoi(q.Get("jitter_min"))
		if err != nil {
			return nil, fmt.Errorf("invalid KCP jitter_min: %w", err)
		}
	}
	if q.Get("jitter_max") != "" {
		config.KCPJitterMax, err = strconv.Atoi(q.Get("jitter_max"))
		if err != nil {
			return nil, fmt.Errorf("invalid KCP jitter_max: %w", err)
		}
	}
	return config, nil
}
