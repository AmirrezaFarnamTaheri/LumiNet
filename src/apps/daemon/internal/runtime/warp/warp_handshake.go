package warp

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"time"

	"github.com/flynn/noise"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/curve25519"
)

func pingWarpHandshake(ctx context.Context, addr netip.AddrPort, opts WarpScannerOptions) (time.Duration, error) {
	privKeyBase64 := opts.WarpPrivateKey
	pubKeyBase64 := opts.WarpPeerPublicKey
	pskBase64 := opts.WarpPresharedKey

	if privKeyBase64 == "" {
		var priv [32]byte
		if _, err := crand.Read(priv[:]); err != nil {
			return 0, err
		}
		priv[0] &= 248
		priv[31] &= 127
		priv[31] |= 64
		privKeyBase64 = base64.StdEncoding.EncodeToString(priv[:])
	}

	staticKeyPair, err := staticKeypair(privKeyBase64)
	if err != nil {
		return 0, err
	}
	peerPublicKey, err := base64.StdEncoding.DecodeString(pubKeyBase64)
	if err != nil {
		return 0, err
	}

	var psk []byte
	if pskBase64 != "" {
		psk, _ = base64.StdEncoding.DecodeString(pskBase64)
	}
	if len(psk) == 0 {
		psk = make([]byte, 32)
	}

	ephemeral, err := ephemeralKeypair()
	if err != nil {
		return 0, err
	}

	cs := noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2s)
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:           cs,
		Pattern:               noise.HandshakeIK,
		Initiator:             true,
		StaticKeypair:         staticKeyPair,
		PeerStatic:            peerPublicKey,
		Prologue:              []byte("WireGuard v1 zx2c4 Jason@zx2c4.com"),
		PresharedKey:          psk,
		PresharedKeyPlacement: 2,
		EphemeralKeypair:      ephemeral,
		Random:                crand.Reader,
	})
	if err != nil {
		return 0, err
	}

	now := time.Now().UTC()
	const epochOffset = int64(4611686018427387914)
	tai64nTimestampBuf := make([]byte, 0, 16)
	tai64nTimestampBuf = binary.BigEndian.AppendUint64(tai64nTimestampBuf, uint64(epochOffset+now.Unix()))
	tai64nTimestampBuf = binary.BigEndian.AppendUint32(tai64nTimestampBuf, uint32(now.Nanosecond()))
	msg, _, _, err := hs.WriteMessage(nil, tai64nTimestampBuf)
	if err != nil {
		return 0, err
	}

	initiationPacket := new(bytes.Buffer)
	_ = binary.Write(initiationPacket, binary.BigEndian, []byte{0x01, 0x00, 0x00, 0x00})
	_ = binary.Write(initiationPacket, binary.BigEndian, uint32ToBytes(28))
	_ = binary.Write(initiationPacket, binary.BigEndian, msg)

	macKey := blake2s.Sum256(append([]byte("mac1----"), peerPublicKey...))
	hasher, err := blake2s.New128(macKey[:])
	if err != nil {
		return 0, err
	}
	if _, err := hasher.Write(initiationPacket.Bytes()); err != nil {
		return 0, err
	}
	initiationPacketMAC := hasher.Sum(nil)

	_ = binary.Write(initiationPacket, binary.BigEndian, initiationPacketMAC[:16])
	_ = binary.Write(initiationPacket, binary.BigEndian, [16]byte{})

	dialer := net.Dialer{Timeout: opts.ConnectionTimeout}
	conn, err := dialer.DialContext(ctx, "udp", addr.String())
	if err != nil {
		return 0, err
	}
	defer conn.Close()

	if opts.UseNoise {
		noisePackets := opts.NoiseCount
		if noisePackets <= 0 {
			noisePackets = 5
		}
		randomPacket := make([]byte, 80)
		for i := 0; i < noisePackets; i++ {
			select {
			case <-ctx.Done():
				return 0, ctx.Err()
			default:
			}
			packetSize := 40 + rand.IntN(40)
			if _, err := crand.Read(randomPacket[:packetSize]); err != nil {
				return 0, err
			}
			if _, err := conn.Write(randomPacket[:packetSize]); err != nil {
				return 0, err
			}
			timer := time.NewTimer(10 * time.Millisecond)
			select {
			case <-ctx.Done():
				if !timer.Stop() {
					<-timer.C
				}
				return 0, ctx.Err()
			case <-timer.C:
			}
		}
	}

	if _, err := initiationPacket.WriteTo(conn); err != nil {
		return 0, err
	}
	t0 := time.Now()

	response := make([]byte, 92)
	deadline := time.Now().Add(opts.HandshakeTimeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	_ = conn.SetReadDeadline(deadline)
	i, err := conn.Read(response)
	if err != nil {
		if ctx.Err() != nil {
			return 0, ctx.Err()
		}
		return 0, err
	}
	rtt := time.Since(t0)

	if i < 60 {
		return 0, fmt.Errorf("invalid handshake response length %d bytes", i)
	}
	if response[0] != 2 {
		return 0, errors.New("invalid response type")
	}
	if ourIndex := binary.LittleEndian.Uint32(response[8:12]); ourIndex != 28 {
		return 0, errors.New("invalid sender index in response")
	}
	payload, _, _, err := hs.ReadMessage(nil, response[12:60])
	if err != nil {
		return 0, err
	}
	if len(payload) != 0 {
		return 0, errors.New("unexpected payload in response")
	}
	return rtt, nil
}

func staticKeypair(privateKeyBase64 string) (noise.DHKey, error) {
	privateKey, err := base64.StdEncoding.DecodeString(privateKeyBase64)
	if err != nil {
		return noise.DHKey{}, err
	}
	var pubkey, privkey [32]byte
	copy(privkey[:], privateKey)
	curve25519.ScalarBaseMult(&pubkey, &privkey)
	return noise.DHKey{Private: privateKey, Public: pubkey[:]}, nil
}

func ephemeralKeypair() (noise.DHKey, error) {
	ephemeralPrivateKey := make([]byte, 32)
	if _, err := crand.Read(ephemeralPrivateKey); err != nil {
		return noise.DHKey{}, err
	}
	ephemeralPublicKey, err := curve25519.X25519(ephemeralPrivateKey, curve25519.Basepoint)
	if err != nil {
		return noise.DHKey{}, err
	}
	return noise.DHKey{Private: ephemeralPrivateKey, Public: ephemeralPublicKey}, nil
}

func uint32ToBytes(n uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, n)
	return b
}
