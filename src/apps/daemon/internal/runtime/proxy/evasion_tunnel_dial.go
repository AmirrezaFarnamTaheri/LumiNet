package proxy

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/maybeknott/luminet/internal/platform/mobilehost"
	"net"
	"strings"
	"time"

	"github.com/maybeknott/luminet/internal/foundation/crypto"
	"github.com/maybeknott/luminet/internal/integrations/relayclient"
	"github.com/maybeknott/luminet/internal/runtime/trust"
)

// dialWithEvasion establishes an outbound connection using configured covert tunnels or evasion strategies.
func (m *EvasionTunnelManager) dialWithEvasion(ctx context.Context, host string, port uint16, cfg EvasionConfig) (net.Conn, error) {
	t0 := time.Now()

	covertMode := cfg.CovertMode
	covertServerlessUrl := cfg.CovertServerlessUrl
	covertGsaUrl := cfg.CovertGsaUrl
	covertGsaKey := cfg.CovertGsaKey
	covertGdocsFolderId := cfg.CovertGdocsFolderId
	covertGdocsAccessToken := cfg.CovertGdocsAccessToken
	fakePacketInject := cfg.FakePacketInject
	fakePacketTtl := cfg.FakePacketTtl
	mutateSniCase := cfg.MutateSniCase
	mutateMethod := cfg.MutateMethod
	mutateAbsoluteUri := cfg.MutateAbsoluteUri
	httpPadding := cfg.HttpPadding
	preflightSignature := cfg.PreflightSignature
	preflightDelayMs := cfg.PreflightDelayMs
	sessionFrag := cfg.SessionFrag
	sessionFragProb := cfg.SessionFragProb
	sessionFragMinTotal := cfg.SessionFragMinTotal
	sessionFragMaxTotal := cfg.SessionFragMaxTotal
	sessionFragMinChunk := cfg.SessionFragMinChunk
	sessionFragMaxChunk := cfg.SessionFragMaxChunk
	sessionFragMinDelayMs := cfg.SessionFragMinDelayMs
	sessionFragMaxDelayMs := cfg.SessionFragMaxDelayMs
	ipSpoofingEnabled := cfg.IpSpoofingEnabled
	ipSpoofingDecoyIP := cfg.IpSpoofingDecoyIP
	ipSpoofingDstReal := cfg.IpSpoofingDstReal
	outOfWindowEnabled := cfg.OutOfWindowEnabled
	outOfWindowSeqOffset := cfg.OutOfWindowSeqOffset
	decoySniPool := cfg.DecoySniPool
	oobEnabled := cfg.OobEnabled
	oobexEnabled := cfg.OobexEnabled
	lossRate := cfg.LossRate
	emulatedLatency := cfg.EmulatedLatency
	emulatedJitter := cfg.EmulatedJitter
	shaperReadRate := cfg.ShaperReadRate
	shaperWriteRate := cfg.ShaperWriteRate
	precisionSniSplits := cfg.PrecisionSniSplits
	randomMultiSplit := cfg.RandomMultiSplit
	numFragments := cfg.NumFragments
	splitBytes := cfg.SplitBytes
	delayMs := cfg.DelayMs
	mutateHost := cfg.MutateHost
	mutateHeaderSpace := cfg.MutateHeaderSpace
	autoSni := cfg.AutoSni
	sniSplitOffset := cfg.SniSplitOffset
	packets := cfg.Packets
	minLen := cfg.MinLength
	maxLen := cfg.MaxLength
	tlsRecordSplit := cfg.TlsRecordSplit
	dnsResolver := cfg.DnsResolver
	sniSpoof := cfg.SniSpoof
	clientHelloPadding := cfg.ClientHelloPadding
	delayJitter := cfg.DelayJitter
	tcpWindowClamp := cfg.TcpWindowClamp
	customUserAgent := cfg.CustomUserAgent

	var conn net.Conn
	var dialErr error

	switch covertMode {
	case "paqet":
		m.log("Routing connection to %s:%d over GFW Raw Handshake Bypass (paqet)", host, port)
		conn, dialErr = DialRawBypass(ctx, host, port)
	case "serverless":
		if covertServerlessUrl != "" {
			m.log("Routing connection to %s:%d over Serverless WebSocket Relay: %s", host, port, covertServerlessUrl)
			dialer := relayclient.NewServerlessDialer(covertServerlessUrl)
			conn, dialErr = dialer.DialTarget(ctx, host, int(port))
		} else {
			dialErr = fmt.Errorf("covert serverless relay URL is empty")
		}
	case "edge":
		if covertServerlessUrl != "" {
			m.log("Routing connection to %s:%d over Edge Worker Relay: %s", host, port, covertServerlessUrl)
			edgeCfg, err := parseProxyURI(covertServerlessUrl)
			if err != nil {
				dialErr = fmt.Errorf("failed to parse edge proxy URI: %w", err)
			} else {
				dialer := NewEdgeDialer(edgeCfg)
				conn, dialErr = dialer.DialTarget(ctx, host, int(port))
			}
		} else {
			dialErr = fmt.Errorf("covert serverless relay URL (used for edge proxy) is empty")
		}
	case "dnstunnel":
		dialErr = fmt.Errorf("covert DNS tunnel mode is unavailable: no production DNS tunnel transport is implemented")
	case "gsa":
		if covertGsaUrl != "" {
			m.log("Routing connection to %s:%d over GSA Web App Relay: %s", host, port, covertGsaUrl)
			addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
			conn = relayclient.NewGsaTunnelConn(covertGsaUrl, covertGsaKey, addr)
		} else {
			dialErr = fmt.Errorf("covert GSA relay URL is empty")
		}
	case "gdocs":
		if covertGdocsFolderId != "" {
			m.log("Routing connection to %s:%d over Google Docs Covert Channel: %s", host, port, covertGdocsFolderId)
			sessID := fmt.Sprintf("sess-%d", time.Now().UnixNano())
			transport, err := NewGDocsTransport(covertGdocsFolderId, covertGdocsAccessToken)
			if err != nil {
				dialErr = err
			} else {
				conn = transport.VirtualConnection(ctx, sessID)
			}
		} else {
			dialErr = fmt.Errorf("covert GDocs folder ID is empty")
		}
	case "gdrive":
		if covertGdocsFolderId != "" {
			m.log("Routing connection to %s:%d over Google Drive Covert Channel (Zephyr Mode): %s", host, port, covertGdocsFolderId)
			sessID := fmt.Sprintf("sess-%d", time.Now().UnixNano())
			transport, err := NewGDriveMailbox(covertGdocsFolderId, sessID, covertGdocsAccessToken)
			if err != nil {
				dialErr = err
			} else {
				conn = transport.VirtualConnection(ctx)
			}
		} else {
			dialErr = fmt.Errorf("covert GDrive folder ID is empty")
		}
	case "wstunnel":
		wsEnd := cfg.CovertCfg.WsEndpoint
		wsHeadersStr := cfg.CovertCfg.WsHeaders
		useUtls := cfg.CovertCfg.WsUseUtls
		fingerprint := cfg.CovertCfg.WsFingerprint
		extraPad := cfg.CovertCfg.WsPadding
		tunnelType := cfg.CovertCfg.WsTunnelType
		protectPath := cfg.CovertSocketProtectPath

		if wsEnd != "" {
			m.log("Routing connection to %s:%d over WebTunnel: %s (Type: %d)", host, port, wsEnd, tunnelType)
			client := NewWsTunnelClient(wsEnd)
			client.UseUTLS = useUtls
			client.Fingerprint = fingerprint
			client.ExtraPadding = extraPad
			client.TunnelType = tunnelType
			if protectPath != "" {
				client.SocketProtect = func(fd int) {
					_ = protectViaUnixSocket(protectPath, fd)
				}
			}
			if wsHeadersStr != "" {
				for _, line := range strings.Split(wsHeadersStr, ",") {
					parts := strings.SplitN(line, ":", 2)
					if len(parts) == 2 {
						client.Headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
					}
				}
			}
			dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			conn, dialErr = client.EstablishTunnel(dialCtx)
		} else {
			dialErr = fmt.Errorf("wstunnel endpoint URL is empty")
		}
	case "ssh":
		sshH := cfg.CovertCfg.SshHost
		sshU := cfg.CovertCfg.SshUser
		sshP := cfg.CovertCfg.SshPass
		sshK := cfg.CovertCfg.SshKey
		sshKP := cfg.CovertCfg.SshKeyPassphrase
		sshHostKey := cfg.CovertCfg.SshHostKeySHA256

		if sshH != "" {
			m.log("Routing connection to %s:%d over SSH Tunnel: %s", host, port, sshH)
			client := NewSshTunnelClient(sshH, sshU, sshP, sshK, sshHostKey).SetPrivateKeyPassphrase(sshKP)
			dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			targetAddr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
			conn, dialErr = client.DialTarget(dialCtx, targetAddr)
		} else {
			dialErr = fmt.Errorf("SSH tunnel host is empty")
		}
	case "kcp":
		kcpH := cfg.CovertCfg.SshHost
		pass := cfg.CovertCfg.SshPass
		noDelay := cfg.CovertCfg.KcpNoDelay
		interval := cfg.CovertCfg.KcpInterval
		resend := cfg.CovertCfg.KcpResend
		noCongest := cfg.CovertCfg.KcpNoCongestion
		sndWnd := cfg.CovertCfg.KcpSendWnd
		rcvWnd := cfg.CovertCfg.KcpRecvWnd
		mtu := cfg.CovertCfg.KcpMtu

		if kcpH != "" {
			m.log("Routing connection to %s:%d over KCP Transport to: %s", host, port, kcpH)
			kcpAddr, kcpPortStr, err := net.SplitHostPort(kcpH)
			var kcpPort int
			if err == nil {
				fmt.Sscanf(kcpPortStr, "%d", &kcpPort)
			} else {
				kcpAddr = kcpH
				kcpPort = 29900
			}
			kcfg := &proxyConfig{
				Protocol:         protocolKCP,
				Address:          kcpAddr,
				Port:             kcpPort,
				Password:         pass,
				Method:           "aes-128",
				KCPNoDelay:       noDelay,
				KCPInterval:      interval,
				KCPResend:        resend,
				KCPNoCongestion:  noCongest,
				KCPSendWindow:    sndWnd,
				KCPReceiveWindow: rcvWnd,
				KCPMTU:           mtu,
			}
			mgr := NewKcpTransportManager()
			conn, dialErr = mgr.Dial(kcfg)
		} else {
			dialErr = fmt.Errorf("KCP server host is empty")
		}
	case "tuic":
		dialErr = errors.New("covert TUIC mode is disabled: TUIC v5 requires QUIC; use the normal TUIC proxy outbound")
	default:
		if cfg.ResidentialCloaking {
			m.log("[Residential Cloaking] Egress mode active. Intercepting dial to %s:%d", host, port)
			targetHost := host
			if cfg.DnsLeaksShield {
				m.log("[Residential Cloaking] Shielding DNS leaks. Routing name resolution securely through egress resolver.")
				// DNS Leak Shield acts to prevent local server leaking
			}
			conn, dialErr = m.dialResidentialEgress(ctx, targetHost, port, cfg.ResidentialEgressNode)
		} else {
			resolvedIPs, err := resolveHostsSecurely(host, dnsResolver)
			if err != nil {
				m.log("DNS resolve failed for %s: %v. Falling back to direct dial.", host, err)
				resolvedIPs = []string{host}
			} else {
				m.log("Resolved %s -> %v securely via custom DNS", host, resolvedIPs)
			}

			// Auto Cloudflare ECH Detection & Upgrade
			isCloudflare := false
			if port == 443 && autoSni {
				for _, ipStr := range resolvedIPs {
					parsedIP := net.ParseIP(ipStr)
					if parsedIP != nil && IsCloudflareIP(parsedIP) {
						isCloudflare = true
						break
					}
				}
			}

			if isCloudflare {
				m.log("[Auto-ECH] Target %s resolved to Cloudflare. Resolving ECH config dynamically...", host)
				dohURL := GetSecureResolverURL(dnsResolver)
				echBytes, echErr := ResolveECHViaDoH(ctx, host, dohURL)
				if echErr == nil && len(echBytes) > 0 {
					m.log("[Auto-ECH] Successfully resolved ECH for %s (%d bytes). Establishing TLS-ECH connection...", host, len(echBytes))
					echConfigB64 := base64.StdEncoding.EncodeToString(echBytes)
					for _, ip := range resolvedIPs {
						addr := net.JoinHostPort(ip, "443")
						conn, dialErr = DialECH(ctx, "tcp", addr, host, echConfigB64, "")
						if dialErr == nil {
							m.log("[Auto-ECH] Connection to %s via ECH succeeded!", host)
							break
						}
						m.log("[Auto-ECH] ECH connection to %s failed: %v", addr, dialErr)
					}
				} else {
					m.log("[Auto-ECH] Dynamic ECH resolution failed for %s: %v. Falling back to plain TCP dial.", host, echErr)
				}
			}

			// Fallback to standard TCP dial if ECH failed or was not applicable
			if conn == nil {
				for _, ip := range resolvedIPs {
					addr := net.JoinHostPort(ip, fmt.Sprintf("%d", port))
					conn, dialErr = mobilehost.DialContext(ctx, "tcp", addr, 3*time.Second)
					if dialErr == nil {
						break
					}
					m.log("Failed to connect to %s: %v. Trying next IP...", addr, dialErr)
				}
			}
		}
	}

	if dialErr != nil && conn == nil {
		return nil, dialErr
	}

	if tcpConn, ok := conn.(*net.TCPConn); ok {
		if tcpWindowClamp > 0 {
			_ = tcpConn.SetReadBuffer(tcpWindowClamp)
			_ = tcpConn.SetWriteBuffer(tcpWindowClamp)
			m.log("Clamped TCP read/write buffer sizes to %d bytes", tcpWindowClamp)
		}
		if cfg.ResidentialCloaking {
			mssVal := cfg.MssClampingValue
			if cfg.MssPreset != "" {
				switch strings.ToLower(cfg.MssPreset) {
				case "lte":
					mssVal = 1380 // LTE MTU ~1420 -> MSS 1380
				case "3g":
					mssVal = 1220 // 3G/Mobile MTU ~1260 -> MSS 1220
				case "ethernet", "wifi":
					mssVal = 1460 // Standard Home ethernet MTU 1500 -> MSS 1460
				}
			}
			if mssVal > 0 {
				_ = tcpConn.SetReadBuffer(mssVal)
				_ = tcpConn.SetWriteBuffer(mssVal)
				m.log("[Residential Cloaking] Normalized TCP MTU (preset: %s): Clamped MSS to %d bytes", cfg.MssPreset, mssVal)
			}
		}
	}

	// Apply dynamic steganography or CFG obfuscation wrap if enabled
	upgenEn := cfg.UpgenEnabled
	upgenSeed := cfg.UpgenSeedHex
	upgenEntropy := cfg.UpgenEntropyMatch
	stegoEn := cfg.StegoEnabled
	stegoM := cfg.StegoMode
	stegoDecoy := cfg.StegoDecoyImagePath

	if upgenEn {
		mimic := "default"
		if upgenEntropy {
			if port == 443 {
				mimic = "https"
			} else if port == 53 {
				mimic = "dns"
			} else if port == 3478 {
				mimic = "stun"
			}
		}
		m.log("Wrapping connection in CFG Compiler dynamic layout obfuscation (mimic: %s)", mimic)
		conn = crypto.NewCFGConn(conn, []byte(upgenSeed), mimic)
	}

	if stegoEn {
		if stegoM == "webrtc_voip" {
			m.log("Wrapping connection in WebRTC steganographic VP8 camouflage")
			var secretToken []byte
			if stegoDecoy != "" {
				secretToken = DeriveSecretFromJoinLink(stegoDecoy)
			}
			if len(secretToken) == 0 {
				secretToken = []byte("default_webrtc_stego_secret")
			}
			stegoConn, err := NewWebRTCStegoConn(conn, secretToken)
			if err != nil {
				m.log("Failed to wrap connection in WebRTC Stego: %v", err)
			} else {
				conn = stegoConn
			}
		} else if stegoM == "pixel" {
			m.log("Wrapping connection in LSB pixel steganographic image camouflage (decoy: %s)", stegoDecoy)
			conn = NewPixelStegoConn(conn, stegoDecoy)
		}
	}

	if lossRate > 0 || emulatedLatency > 0 || emulatedJitter > 0 {
		m.log("Wrapping connection to %s:%d with LossyConn (loss: %.2f%%, latency: %dms, jitter: %dms)", host, port, lossRate*100.0, emulatedLatency, emulatedJitter)
		ratio := lossRate
		if ratio > 1.0 {
			ratio = ratio / 100.0
		}
		conn = NewLossyConn(conn, ratio, time.Duration(emulatedLatency)*time.Millisecond, time.Duration(emulatedJitter)*time.Millisecond)
	}

	if shaperReadRate > 0 || shaperWriteRate > 0 {
		m.log("Wrapping connection to %s:%d with ShapedConn (read: %d B/s, write: %d B/s)", host, port, shaperReadRate, shaperWriteRate)
		conn = NewShapedConn(conn, shaperReadRate, shaperWriteRate)
	}

	dialDuration := time.Since(t0)
	m.log("Established connection to %s:%d (RTT: %dms)", host, port, dialDuration.Milliseconds())

	return &evasionTunnelConn{
		Conn:                  conn,
		splitBytes:            splitBytes,
		delayMs:               delayMs,
		mutateHost:            mutateHost,
		mutateHeaderSpace:     mutateHeaderSpace,
		autoSni:               autoSni,
		precisionSniSplits:    precisionSniSplits,
		randomMultiSplit:      randomMultiSplit,
		numFragments:          numFragments,
		sniSplitOffset:        sniSplitOffset,
		packets:               packets,
		minLength:             minLen,
		maxLength:             maxLen,
		tlsRecordSplit:        tlsRecordSplit,
		sniSpoof:              sniSpoof,
		clientHelloPadding:    clientHelloPadding,
		delayJitter:           delayJitter,
		tcpWindowClamp:        tcpWindowClamp,
		customUserAgent:       customUserAgent,
		fakePacketInject:      fakePacketInject,
		fakePacketTtl:         fakePacketTtl,
		firstWrite:            true,
		mutateSniCase:         mutateSniCase,
		mutateMethod:          mutateMethod,
		mutateAbsoluteUri:     mutateAbsoluteUri,
		httpPadding:           httpPadding,
		preflightSignature:    preflightSignature,
		preflightDelayMs:      preflightDelayMs,
		sessionFrag:           sessionFrag,
		sessionFragProb:       sessionFragProb,
		sessionFragMinTotal:   sessionFragMinTotal,
		sessionFragMaxTotal:   sessionFragMaxTotal,
		sessionFragMinChunk:   sessionFragMinChunk,
		sessionFragMaxChunk:   sessionFragMaxChunk,
		sessionFragMinDelayMs: sessionFragMinDelayMs,
		sessionFragMaxDelayMs: sessionFragMaxDelayMs,
		ipSpoofingEnabled:     ipSpoofingEnabled,
		ipSpoofingDecoyIP:     ipSpoofingDecoyIP,
		ipSpoofingDstReal:     ipSpoofingDstReal,
		outOfWindowEnabled:    outOfWindowEnabled,
		outOfWindowSeqOffset:  outOfWindowSeqOffset,
		decoySniPool:          decoySniPool,
		oobEnabled:            oobEnabled,
		oobexEnabled:          oobexEnabled,
		residentialCloaking:   cfg.ResidentialCloaking,
	}, nil
}

// dialResidentialEgress establishes an outbound connection via a residential proxy egress node or Reticulum Mesh peer.
func (m *EvasionTunnelManager) dialResidentialEgress(ctx context.Context, host string, port uint16, egressAddr string) (net.Conn, error) {
	if strings.TrimSpace(egressAddr) == "" {
		return nil, fmt.Errorf("residential cloaking requires an explicit SOCKS5 egress address; mesh auto-discovery is unavailable")
	}

	selectedNodeName := egressAddr
	m.log("[Residential Cloaking] Routing connection via configured residential egress node: %s", egressAddr)

	t0 := time.Now()
	conn, err := mobilehost.DialContext(ctx, "tcp", egressAddr, 5*time.Second)
	if err != nil {
		trust.GetStore().RecordMetric(selectedNodeName, time.Since(t0), false, 1.0)
		return nil, fmt.Errorf("failed to connect to residential egress node: %w", err)
	}

	dialer := &EdgeDialer{}
	if err := dialer.handshakeSOCKS5(conn, host, int(port)); err != nil {
		_ = conn.Close()
		trust.GetStore().RecordMetric(selectedNodeName, time.Since(t0), false, 0.5)
		return nil, fmt.Errorf("socks5 handshake to %s:%d via residential egress failed: %w", host, port, err)
	}

	trust.GetStore().RecordMetric(selectedNodeName, time.Since(t0), true, 0.0)
	m.log("[Residential Cloaking] Successfully established residential proxy tunnel to target %s:%d (RTT: %dms)", host, port, time.Since(t0).Milliseconds())
	return conn, nil
}
