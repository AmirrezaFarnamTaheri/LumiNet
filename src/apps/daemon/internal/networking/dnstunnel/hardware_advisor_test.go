package dnstunnel

import (
	"math"
	"testing"
)

func TestAdviseClientMobilePoorLossy(t *testing.T) {
	p := ClientHardwareProfile{
		Connection:           ConnMobile4g5g,
		Quality:              QualityPoor,
		CPUCores:             2,
		RAMMB:                2048,
		ResolverCensus:       CensusFew,
		MtuPreference:        MtuPrefStable,
		UseCase:              UseCaseChat,
		EncryptionPreference: EncLight,
	}

	rec := AdviseClient(p)

	if rec.DataEncryptionMethod != 1 {
		t.Errorf("expected XOR (1), got %d", rec.DataEncryptionMethod)
	}
	if rec.PacketDuplicationCount != 4 {
		t.Errorf("expected dup 4 for poor lossy, got %d", rec.PacketDuplicationCount)
	}
	if rec.SetupPacketDuplicationCount != 5 {
		t.Errorf("expected setup dup 5, got %d", rec.SetupPacketDuplicationCount)
	}
	if rec.ResolverBalancingStrategy != 3 {
		t.Errorf("expected strat 3 (lowest loss), got %d", rec.ResolverBalancingStrategy)
	}
	if rec.StreamResolverFailoverThreshold != 2 || rec.StreamResolverFailoverCooldownSec != 4 {
		t.Errorf("unexpected failover parameters: thresh %d, cool %d",
			rec.StreamResolverFailoverThreshold, rec.StreamResolverFailoverCooldownSec)
	}
	if rec.MinUploadMTU != 25 || rec.MaxUploadMTU != 60 {
		t.Errorf("unexpected stable MTU: min %d, max %d", rec.MinUploadMTU, rec.MaxUploadMTU)
	}
	if rec.UploadCompressionType != 1 {
		t.Errorf("expected ZSTD (1), got %d", rec.UploadCompressionType)
	}
	if rec.ArqWindowSize != 1000 || rec.ArqDataNackMaxGap != 64 || rec.ArqMaxDataRetries != 1500 {
		t.Errorf("unexpected lossy ARQ values")
	}
	if math.Abs(rec.DispatcherIdlePollIntervalSec-0.030) > 1e-6 {
		t.Errorf("expected 30ms poll for 2 cores, got %f", rec.DispatcherIdlePollIntervalSec)
	}
}

func TestAdviseClientFiberStreamStrong(t *testing.T) {
	p := ClientHardwareProfile{
		Connection:           ConnFiber,
		Quality:              QualityExcellent,
		CPUCores:             8,
		RAMMB:                8192,
		ResolverCensus:       CensusMany,
		MtuPreference:        MtuPrefSpeed,
		UseCase:              UseCaseStream,
		EncryptionPreference: EncStrong,
	}

	rec := AdviseClient(p)

	if rec.DataEncryptionMethod != 5 {
		t.Errorf("expected AES-256-GCM (5), got %d", rec.DataEncryptionMethod)
	}
	if rec.PacketDuplicationCount != 1 {
		t.Errorf("expected dup 1 for fiber excellent, got %d", rec.PacketDuplicationCount)
	}
	if rec.ResolverBalancingStrategy != 4 {
		t.Errorf("expected strat 4 (lowest latency), got %d", rec.ResolverBalancingStrategy)
	}
	if rec.MtuTestParallelism != 64 {
		t.Errorf("expected parallelism 64, got %d", rec.MtuTestParallelism)
	}
	if rec.UploadCompressionType != 2 {
		t.Errorf("expected LZ4 (2) for stream, got %d", rec.UploadCompressionType)
	}
	if rec.TxChannelSize != 16384 || rec.RxChannelSize != 16384 {
		t.Errorf("expected 16384 buffer sizes, got tx %d rx %d", rec.TxChannelSize, rec.RxChannelSize)
	}
	if math.Abs(rec.DispatcherIdlePollIntervalSec-0.010) > 1e-6 {
		t.Errorf("expected 10ms poll for stream, got %f", rec.DispatcherIdlePollIntervalSec)
	}
	if math.Abs(rec.PingAggressiveIntervalSec-0.15) > 1e-6 {
		t.Errorf("expected 0.15s aggressive ping, got %f", rec.PingAggressiveIntervalSec)
	}
}

func TestAdviseServerMinimalVsEnterprise(t *testing.T) {
	minP := ServerHardwareProfile{
		CPUCores:             1,
		RAMMB:                512,
		NetworkMbps:          100,
		ConcurrentUserCount:  1,
		Traffic:              TrafficLight,
		EncryptionPreference: EncLight,
		UpstreamDNS:          UpstreamCloudflare,
		LossyClients:         false,
	}
	minRec := AdviseServer(minP)
	if minRec.DataEncryptionMethod != 1 {
		t.Errorf("expected encryption 1, got %d", minRec.DataEncryptionMethod)
	}
	if minRec.UDPReaders != 2 || minRec.DNSRequestWorkers != 4 {
		t.Errorf("unexpected worker count for minimal server")
	}
	if minRec.MaxConcurrentRequests != 4096 {
		t.Errorf("expected 4096 max concurrent, got %d", minRec.MaxConcurrentRequests)
	}
	if minRec.SocketBufferSizeBytes != 4*1024*1024 {
		t.Errorf("expected 4MB socket buffer, got %d", minRec.SocketBufferSizeBytes)
	}
	if minRec.PacketBlockControlDuplication != 1 {
		t.Errorf("expected ctrl dup 1, got %d", minRec.PacketBlockControlDuplication)
	}

	entP := ServerHardwareProfile{
		CPUCores:             8,
		RAMMB:                4096,
		NetworkMbps:          1000,
		ConcurrentUserCount:  30,
		Traffic:              TrafficHeavy,
		EncryptionPreference: EncBalanced,
		UpstreamDNS:          UpstreamCombined,
		LossyClients:         true,
	}
	entRec := AdviseServer(entP)
	if entRec.DataEncryptionMethod != 2 {
		t.Errorf("expected encryption 2, got %d", entRec.DataEncryptionMethod)
	}
	if len(entRec.DNSUpstreamServers) != 4 {
		t.Errorf("expected 4 upstream servers, got %d", len(entRec.DNSUpstreamServers))
	}
	if entRec.UDPReaders != 4 || entRec.DNSRequestWorkers != 8 {
		t.Errorf("unexpected worker count for enterprise server")
	}
	if entRec.MaxConcurrentRequests != 32768 {
		t.Errorf("expected 32768 max concurrent, got %d", entRec.MaxConcurrentRequests)
	}
	if entRec.SocketBufferSizeBytes != 16*1024*1024 {
		t.Errorf("expected 16MB socket buffer, got %d", entRec.SocketBufferSizeBytes)
	}
	if entRec.DNSCacheMaxRecords != 100000 {
		t.Errorf("expected 100k cache records, got %d", entRec.DNSCacheMaxRecords)
	}
	if entRec.PacketBlockControlDuplication != 3 || entRec.MaxPacketsPerBatch != 12 {
		t.Errorf("expected ctrl dup 3, batch 12 for lossy clients")
	}
	if entRec.SessionTimeoutSeconds != 180 {
		t.Errorf("expected 180s timeout, got %d", entRec.SessionTimeoutSeconds)
	}
	if entRec.SocksConnectTimeoutSeconds != 60 {
		t.Errorf("expected 60s connect timeout, got %d", entRec.SocksConnectTimeoutSeconds)
	}
	if entRec.SessionCleanupIntervalSeconds != 15 {
		t.Errorf("expected 15s cleanup interval, got %d", entRec.SessionCleanupIntervalSeconds)
	}
	if entRec.Socks5FragmentStoreCapacity != 2048 {
		t.Errorf("expected 2048 fragment store capacity, got %d", entRec.Socks5FragmentStoreCapacity)
	}
}
