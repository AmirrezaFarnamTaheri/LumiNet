// Package proxy implements proxy servers and traffic sniffer capabilities.
// Target path: server/internal/proxy/handshake_fingerprint.go

package proxy

import (
	"bytes"
	"crypto/sha1" // skipcq: GSC-G505
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	tls "github.com/refraction-networking/utls"
	"golang.org/x/crypto/cryptobyte"
)

// Constants for QUIC Transport Parameters (RFC 9000)
const (
	qtpMaxIdleTimeout                 = 0x01
	qtpMaxUDPPayloadSize              = 0x03
	qtpInitialMaxData                 = 0x04
	qtpInitialMaxStreamDataBidiLocal  = 0x05
	qtpInitialMaxStreamDataBidiRemote = 0x06
	qtpInitialMaxStreamDataUni        = 0x07
	qtpInitialMaxStreamsBidi          = 0x08
	qtpInitialMaxStreamsUni           = 0x09
	qtpAckDelayExponent               = 0x0a
	qtpMaxAckDelay                    = 0x0b
	qtpActiveConnectionIDLimit        = 0x0e
	qtpGrease                         = 27
)

// Uint8Arr redefines how []uint8 is marshalled to JSON to display it as a list of numbers instead of a string.
type Uint8Arr []uint8

// MarshalJSON marshals the uint8 array to a JSON array.
func (u Uint8Arr) MarshalJSON() ([]byte, error) {
	if u == nil {
		return []byte("[]"), nil
	}
	var sb strings.Builder
	sb.WriteByte('[')
	for i, b := range u {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteString(fmt.Sprintf("%d", b))
	}
	sb.WriteByte(']')
	return []byte(sb.String()), nil
}

// FingerprintID represents the numeric ID of a fingerprint.
type FingerprintID int64

// AsHex returns the big-endian hexadecimal string of the ID.
func (id FingerprintID) AsHex() string {
	hid := make([]byte, 8)
	binary.BigEndian.PutUint64(hid, uint64(id))
	return hex.EncodeToString(hid)
}

// QUICTransportParameters holds the parsed QUIC transport parameters.
type QUICTransportParameters struct {
	MaxIdleTimeout                 Uint8Arr `json:"max_idle_timeout,omitempty"`
	MaxUDPPayloadSize              Uint8Arr `json:"max_udp_payload_size,omitempty"`
	InitialMaxData                 Uint8Arr `json:"initial_max_data,omitempty"`
	InitialMaxStreamDataBidiLocal  Uint8Arr `json:"initial_max_stream_data_bidi_local,omitempty"`
	InitialMaxStreamDataBidiRemote Uint8Arr `json:"initial_max_stream_data_bidi_remote,omitempty"`
	InitialMaxStreamDataUni        Uint8Arr `json:"initial_max_stream_data_uni,omitempty"`
	InitialMaxStreamsBidi          Uint8Arr `json:"initial_max_streams_bidi,omitempty"`
	InitialMaxStreamsUni           Uint8Arr `json:"initial_max_streams_uni,omitempty"`
	AckDelayExponent               Uint8Arr `json:"ack_delay_exponent,omitempty"`
	MaxAckDelay                    Uint8Arr `json:"max_ack_delay,omitempty"`
	ActiveConnectionIDLimit        Uint8Arr `json:"active_connection_id_limit,omitempty"`
	QTPIDs                         []uint64 `json:"tpids,omitempty"` // sorted parameter IDs
	HexID                          string   `json:"hex_id,omitempty"`
	NumID                          uint64   `json:"num_id,omitempty"`
}

// ClientHello represents a captured ClientHello message with all fingerprintable fields.
type ClientHello struct {
	raw []byte

	TLSRecordVersion    uint16 `json:"tls_record_version"`
	TLSHandshakeVersion uint16 `json:"tls_handshake_version"`

	CipherSuites         []uint16 `json:"cipher_suites"`
	CompressionMethods   Uint8Arr `json:"compression_methods"`
	Extensions           []uint16 `json:"extensions"`            // extension IDs in original order
	ExtensionsNormalized []uint16 `json:"extensions_normalized"` // sorted extension IDs

	ServerName          string   `json:"server_name"`
	NamedGroupList      []uint16 `json:"supported_groups"`
	ECPointFormatList   Uint8Arr `json:"ec_point_formats"`
	SignatureSchemeList []uint16 `json:"signature_algorithms"`
	ALPN                []string `json:"alpn"`
	CertCompressAlgo    []uint16 `json:"compress_certificate"`
	RecordSizeLimit     Uint8Arr `json:"record_size_limit"`
	SupportedVersions   []uint16 `json:"supported_versions"`
	PSKKeyExchangeModes Uint8Arr `json:"psk_key_exchange_modes"`
	KeyShare            []uint16 `json:"key_share"`
	ApplicationSettings []string `json:"application_settings"`

	NumID     int64  `json:"num_id,omitempty"`
	NormNumID int64  `json:"norm_num_id,omitempty"`
	HexID     string `json:"hex_id,omitempty"`
	NormHexID string `json:"norm_hex_id,omitempty"`

	qtp *QUICTransportParameters
}

// ReadClientHello reads a ClientHello record from a connection reader.
func ReadClientHello(r io.Reader) (*ClientHello, error) {
	ch := &ClientHello{}
	ch.raw = make([]byte, 5)
	if _, err := io.ReadFull(r, ch.raw); err != nil {
		return nil, err
	}

	if ch.raw[0] != 0x16 {
		return nil, errors.New("not a TLS handshake record")
	}

	length := binary.BigEndian.Uint16(ch.raw[3:5])
	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	ch.raw = append(ch.raw, payload...)
	return ch, nil
}

// UnmarshalClientHello parses a ClientHello from a byte slice.
func UnmarshalClientHello(p []byte) (*ClientHello, error) {
	ch, err := ReadClientHello(bytes.NewReader(p))
	if err != nil {
		return nil, err
	}
	if err := ch.ParseClientHello(); err != nil {
		return nil, err
	}
	return ch, nil
}

// Raw returns the raw captured handshake record bytes.
func (ch *ClientHello) Raw() []byte {
	return ch.raw
}

// ParseClientHello parses the captured ClientHello bytes.
func (ch *ClientHello) ParseClientHello() error {
	fingerprinter := tls.Fingerprinter{
		AllowBluntMimicry: true,
	}
	chs, err := fingerprinter.RawClientHello(ch.raw)
	if err != nil {
		return fmt.Errorf("failed to parse raw ClientHello: %w", err)
	}

	ch.CipherSuites = chs.CipherSuites
	ch.CompressionMethods = chs.CompressionMethods
	ch.parseExtensions(chs)

	chm := tls.UnmarshalClientHello(ch.raw[5:])
	if chm != nil {
		ch.ServerName = chm.ServerName
	}

	return ch.parseExtra()
}

func (ch *ClientHello) parseExtensions(chs *tls.ClientHelloSpec) {
	for _, ext := range chs.Extensions {
		switch ext := ext.(type) {
		case *tls.SupportedCurvesExtension:
			for _, curve := range ext.Curves {
				ch.NamedGroupList = append(ch.NamedGroupList, uint16(curve))
			}
		case *tls.SupportedPointsExtension:
			ch.ECPointFormatList = ext.SupportedPoints
		case *tls.SignatureAlgorithmsExtension:
			for _, sig := range ext.SupportedSignatureAlgorithms {
				ch.SignatureSchemeList = append(ch.SignatureSchemeList, uint16(sig))
			}
		case *tls.ALPNExtension:
			ch.ALPN = ext.AlpnProtocols
		case *tls.UtlsCompressCertExtension:
			for _, algo := range ext.Algorithms {
				ch.CertCompressAlgo = append(ch.CertCompressAlgo, uint16(algo))
			}
		case *tls.FakeRecordSizeLimitExtension:
			ch.RecordSizeLimit = append(ch.RecordSizeLimit, uint8(ext.Limit>>8), uint8(ext.Limit))
		case *tls.SupportedVersionsExtension:
			for _, ver := range ext.Versions {
				ch.SupportedVersions = append(ch.SupportedVersions, uint16(ver))
			}
		case *tls.PSKKeyExchangeModesExtension:
			ch.PSKKeyExchangeModes = ext.Modes
		case *tls.KeyShareExtension:
			for _, ks := range ext.KeyShares {
				ch.KeyShare = append(ch.KeyShare, uint16(ks.Group))
			}
		case *tls.ApplicationSettingsExtension:
			ch.ApplicationSettings = ext.SupportedProtocols
		case *tls.GenericExtension:
			if ext.Id == 57 { // QUIC Transport Parameters
				ch.qtp = ParseQUICTransportParameters(ext.Data)
			}
		}
	}
}

func (ch *ClientHello) parseExtra() error {
	s := cryptobyte.String(ch.raw)
	var recordVersion uint16
	if !s.Skip(1) || !s.ReadUint16(&recordVersion) || !s.Skip(2) {
		return errors.New("failed to parse TLS header")
	}
	ch.TLSRecordVersion = recordVersion

	var handshakeVersion uint16
	if !s.Skip(1) || !s.Skip(3) || !s.ReadUint16(&handshakeVersion) || !s.Skip(32) {
		return errors.New("failed to parse ClientHello body")
	}
	ch.TLSHandshakeVersion = handshakeVersion

	var sessionID cryptobyte.String
	if !s.ReadUint8LengthPrefixed(&sessionID) {
		return errors.New("unable to read session id")
	}

	var cipherSuites cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&cipherSuites) {
		return errors.New("unable to read ciphersuites")
	}

	var compressionMethods cryptobyte.String
	if !s.ReadUint8LengthPrefixed(&compressionMethods) {
		return errors.New("unable to read compression methods")
	}

	if s.Empty() {
		return nil
	}

	var extensions cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&extensions) {
		return errors.New("unable to read extensions data")
	}

	if err := ch.parseExtensionsExtra(extensions); err != nil {
		return err
	}

	ch.ExtensionsNormalized = make([]uint16, len(ch.Extensions))
	copy(ch.ExtensionsNormalized, ch.Extensions)
	sort.Slice(ch.ExtensionsNormalized, func(i, j int) bool {
		return ch.ExtensionsNormalized[i] < ch.ExtensionsNormalized[j]
	})

	ch.NumID, ch.NormNumID = ch.calcNumericID()
	ch.HexID = FingerprintID(ch.NumID).AsHex()
	ch.NormHexID = FingerprintID(ch.NormNumID).AsHex()
	return nil
}

func (ch *ClientHello) parseExtensionsExtra(extensions cryptobyte.String) error {
	var ids []uint16
	for !extensions.Empty() {
		var id uint16
		var data cryptobyte.String
		if !extensions.ReadUint16(&id) || !extensions.ReadUint16LengthPrefixed(&data) {
			return errors.New("unable to read extension details")
		}

		if id == 16 { // ALPN
			// Do nothing special
		} else if id == 51 { // KeyShare
			if data.Skip(2) {
				for !data.Empty() {
					var group, length uint16
					if data.ReadUint16(&group) && data.ReadUint16(&length) {
						if isGREASEU16(group) {
							group = 0x0A0A
						}
						data.Skip(int(length))
					} else {
						break
					}
				}
			}
		} else if isGREASEU16(id) {
			id = 0x0A0A
		}
		ids = append(ids, id)
	}
	ch.Extensions = ids
	return nil
}

func isGREASEU16(v uint16) bool {
	high := (v >> 8) & 0xFF
	low := v & 0xFF
	return high == low && (low&0x0F) == 0x0A
}

func ungreaseU16(v uint16) uint16 {
	if isGREASEU16(v) {
		return 0x0A0A
	}
	return v
}

func ungreasePSK(v byte) byte {
	greases := []byte{0x0B, 0x2A, 0x49, 0x68, 0x87, 0xA6, 0xC5, 0xE4}
	for _, g := range greases {
		if v == g {
			return 0x0B
		}
	}
	return v
}

func isGREASEALPN(s string) bool {
	if len(s) != 2 {
		return false
	}
	return s[0] == s[1] && (s[0]&0x0F) == 0x0A
}

func (ch *ClientHello) calcNumericID() (orig, norm int64) {
	for _, normalized := range []bool{false, true} {
		h := sha1.New() // skipcq: GSC-G401

		binary.Write(h, binary.BigEndian, uint32(ch.TLSHandshakeVersion))

		for _, cs := range ch.CipherSuites {
			binary.Write(h, binary.BigEndian, ungreaseU16(cs))
		}

		h.Write(ch.CompressionMethods)

		exts := ch.Extensions
		if normalized {
			exts = ch.ExtensionsNormalized
		}
		for _, ext := range exts {
			binary.Write(h, binary.BigEndian, ungreaseU16(ext))
		}

		for _, ng := range ch.NamedGroupList {
			binary.Write(h, binary.BigEndian, ungreaseU16(ng))
		}

		h.Write(ch.ECPointFormatList)

		for _, sa := range ch.SignatureSchemeList {
			binary.Write(h, binary.BigEndian, ungreaseU16(sa))
		}

		for _, proto := range ch.ALPN {
			if isGREASEALPN(proto) {
				proto = "\x0a\x0a"
			}
			h.Write([]byte{uint8(len(proto))})
			h.Write([]byte(proto))
		}

		for _, ks := range ch.KeyShare {
			binary.Write(h, binary.BigEndian, ungreaseU16(ks))
		}

		for _, mode := range ch.PSKKeyExchangeModes {
			h.Write([]byte{ungreasePSK(mode)})
		}

		for _, sv := range ch.SupportedVersions {
			binary.Write(h, binary.BigEndian, ungreaseU16(sv))
		}

		if len(ch.CertCompressAlgo) > 0 {
			h.Write([]byte{uint8(2 * len(ch.CertCompressAlgo))})
			for _, algo := range ch.CertCompressAlgo {
				binary.Write(h, binary.BigEndian, algo)
			}
		}

		if len(ch.RecordSizeLimit) >= 2 {
			h.Write(ch.RecordSizeLimit[:2])
		} else {
			h.Write([]byte{0, 0})
		}

		res := binary.BigEndian.Uint64(h.Sum(nil)[:8])
		if normalized {
			norm = int64(res)
		} else {
			orig = int64(res)
		}
	}
	return
}

// ParseQUICTransportParameters parses the transport parameters from extension bytes.
func ParseQUICTransportParameters(extData []byte) *QUICTransportParameters {
	qtp := &QUICTransportParameters{}
	r := bytes.NewReader(extData)
	for r.Len() > 0 {
		paramType, _, err := readVLI(r)
		if err != nil {
			break
		}
		paramValLen, _, err := readVLI(r)
		if err != nil {
			break
		}

		if paramType >= 27 && (paramType-27)%31 == 0 {
			qtp.QTPIDs = append(qtp.QTPIDs, qtpGrease)
		} else {
			qtp.QTPIDs = append(qtp.QTPIDs, paramType)
		}

		if paramValLen == 0 {
			continue
		}

		paramData := make([]byte, paramValLen)
		if n, _ := r.Read(paramData); uint64(n) != paramValLen {
			break
		}

		// Clean up VLI bits if necessary
		cleanedData := make([]byte, len(paramData))
		copy(cleanedData, paramData)
		cleanedData[0] &= 0x3f

		switch paramType {
		case qtpMaxIdleTimeout:
			qtp.MaxIdleTimeout = cleanedData
		case qtpMaxUDPPayloadSize:
			qtp.MaxUDPPayloadSize = cleanedData
		case qtpInitialMaxData:
			qtp.InitialMaxData = cleanedData
		case qtpInitialMaxStreamDataBidiLocal:
			qtp.InitialMaxStreamDataBidiLocal = cleanedData
		case qtpInitialMaxStreamDataBidiRemote:
			qtp.InitialMaxStreamDataBidiRemote = cleanedData
		case qtpInitialMaxStreamDataUni:
			qtp.InitialMaxStreamDataUni = cleanedData
		case qtpInitialMaxStreamsBidi:
			qtp.InitialMaxStreamsBidi = cleanedData
		case qtpInitialMaxStreamsUni:
			qtp.InitialMaxStreamsUni = cleanedData
		case qtpAckDelayExponent:
			qtp.AckDelayExponent = cleanedData
		case qtpMaxAckDelay:
			qtp.MaxAckDelay = cleanedData
		case qtpActiveConnectionIDLimit:
			qtp.ActiveConnectionIDLimit = cleanedData
		}
	}

	sort.Slice(qtp.QTPIDs, func(i, j int) bool {
		return qtp.QTPIDs[i] < qtp.QTPIDs[j]
	})

	h := sha1.New() // skipcq: GSC-G401
	for _, id := range qtp.QTPIDs {
		binary.Write(h, binary.BigEndian, id)
	}

	writeVLIBytes := func(arr Uint8Arr) {
		var val uint64
		for _, b := range arr {
			val = val<<8 | uint64(b)
		}
		binary.Write(h, binary.BigEndian, val)
	}

	writeVLIBytes(qtp.MaxIdleTimeout)
	writeVLIBytes(qtp.MaxUDPPayloadSize)
	writeVLIBytes(qtp.InitialMaxData)
	writeVLIBytes(qtp.InitialMaxStreamDataBidiLocal)
	writeVLIBytes(qtp.InitialMaxStreamDataBidiRemote)
	writeVLIBytes(qtp.InitialMaxStreamDataUni)
	writeVLIBytes(qtp.InitialMaxStreamsBidi)
	writeVLIBytes(qtp.InitialMaxStreamsUni)
	writeVLIBytes(qtp.AckDelayExponent)
	writeVLIBytes(qtp.MaxAckDelay)
	writeVLIBytes(qtp.ActiveConnectionIDLimit)

	qtp.NumID = binary.BigEndian.Uint64(h.Sum(nil)[:8])
	qtp.HexID = FingerprintID(qtp.NumID).AsHex()
	return qtp
}

func readVLI(r io.Reader) (uint64, int, error) {
	b := make([]byte, 1)
	if _, err := r.Read(b); err != nil {
		return 0, 0, err
	}

	var n int
	switch b[0] & 0xc0 {
	case 0x00:
		n = 1
	case 0x40:
		n = 2
	case 0x80:
		n = 4
	case 0xc0:
		n = 8
	}

	encoded := make([]byte, n)
	encoded[0] = b[0] & 0x3f
	if n > 1 {
		if _, err := io.ReadFull(r, encoded[1:]); err != nil {
			return 0, 0, err
		}
	}

	var val uint64
	for i := 0; i < n; i++ {
		val = (val << 8) | uint64(encoded[i])
	}
	return val, n, nil
}

// QUICClientHelloReconstructor reassembles split CRYPTO frames from QUIC Initial Packets.
type QUICClientHelloReconstructor struct {
	fullLen uint32
	buf     []byte
	frags   map[uint64][]byte
}

// NewQUICClientHelloReconstructor creates a new QUICClientHelloReconstructor.
func NewQUICClientHelloReconstructor() *QUICClientHelloReconstructor {
	return &QUICClientHelloReconstructor{
		frags: make(map[uint64][]byte),
	}
}

// AddFragment adds a CRYPTO frame fragment. Returns io.EOF when reassembly is complete.
func (q *QUICClientHelloReconstructor) AddFragment(offset uint64, frag []byte) error {
	if _, exists := q.frags[offset]; exists {
		return errors.New("duplicate fragment")
	}

	q.frags[offset] = frag

	for {
		if f, exists := q.frags[uint64(len(q.buf))]; exists {
			delete(q.frags, uint64(len(q.buf)))
			q.buf = append(q.buf, f...)
		} else {
			break
		}
	}

	if q.fullLen == 0 && len(q.buf) >= 4 {
		q.fullLen = binary.BigEndian.Uint32([]byte{0x00, q.buf[1], q.buf[2], q.buf[3]}) + 4
	}

	if q.fullLen > 0 && uint32(len(q.buf)) >= q.fullLen {
		return io.EOF
	}

	return nil
}

// Reconstruct returns the reassembled ClientHello.
func (q *QUICClientHelloReconstructor) Reconstruct() ([]byte, error) {
	if q.fullLen == 0 || uint32(len(q.buf)) < q.fullLen {
		return nil, errors.New("reassembly incomplete")
	}
	return q.buf[:q.fullLen], nil
}

type rewindConn struct {
	net.Conn
	reader bytes.Reader
}

// RewindConn wraps a connection and pushes the specified buffer back so next reads pull from it first.
func RewindConn(c net.Conn, buf []byte) (net.Conn, error) {
	if c == nil {
		return nil, errors.New("nil connection")
	}
	if len(buf) == 0 {
		return c, nil
	}
	return &rewindConn{
		Conn:   c,
		reader: *bytes.NewReader(buf),
	}, nil
}

func (c *rewindConn) Read(b []byte) (int, error) {
	if c.reader.Size() == 0 {
		return c.Conn.Read(b)
	}
	n, err := c.reader.Read(b)
	if errors.Is(err, io.EOF) {
		c.reader.Reset([]byte{})
		return n, nil
	}
	return n, err
}

func (c *rewindConn) CloseWrite() error {
	if cc, ok := c.Conn.(*net.TCPConn); ok {
		return cc.CloseWrite()
	}
	if cw, ok := c.Conn.(interface {
		CloseWrite() error
	}); ok {
		return cw.CloseWrite()
	}
	return errors.New("not supported")
}

// TLSFingerprinter manages passive TLS ClientHello fingerprinting.
type TLSFingerprinter struct {
	clientHellos sync.Map
	timeout      time.Duration
}

// NewTLSFingerprinter creates a new TLSFingerprinter.
func NewTLSFingerprinter(timeout time.Duration) *TLSFingerprinter {
	return &TLSFingerprinter{
		timeout: timeout,
	}
}

// HandleTCPConn captures, parses, fingerprints, and rewinds the TLS handshake.
func (tfp *TLSFingerprinter) HandleTCPConn(conn net.Conn) (net.Conn, error) {
	ch, err := ReadClientHello(conn)
	if err != nil {
		return nil, err
	}

	if err := ch.ParseClientHello(); err != nil {
		return nil, err
	}

	remoteAddr := conn.RemoteAddr().String()
	tfp.clientHellos.Store(remoteAddr, ch)

	go func(addr string, oldCh *ClientHello) {
		time.Sleep(tfp.timeout)
		tfp.clientHellos.CompareAndDelete(addr, oldCh)
	}(remoteAddr, ch)

	return RewindConn(conn, ch.Raw())
}

// GetClientHello retrieves the fingerprint parsed from a connection.
func (tfp *TLSFingerprinter) GetClientHello(remoteAddr string) *ClientHello {
	if val, ok := tfp.clientHellos.Load(remoteAddr); ok {
		return val.(*ClientHello)
	}
	return nil
}
