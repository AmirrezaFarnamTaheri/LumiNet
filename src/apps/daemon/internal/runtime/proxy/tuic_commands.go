package proxy

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
)

// TuicAddress defines the serializable network address format (Items 1-5)
type TuicAddress struct {
	AddrType byte
	Host     string
	Port     uint16
	IP       net.IP
}

// Write serializes the address to the writer (Items 6-8)
func (a *TuicAddress) Write(w io.Writer) error {
	if err := binary.Write(w, binary.BigEndian, a.AddrType); err != nil {
		return err
	}
	switch a.AddrType {
	case TuicAddrTypeDomain:
		hostBytes := []byte(a.Host)
		if err := binary.Write(w, binary.BigEndian, byte(len(hostBytes))); err != nil {
			return err
		}
		if _, err := w.Write(hostBytes); err != nil {
			return err
		}
		return binary.Write(w, binary.BigEndian, a.Port)
	case TuicAddrTypeIPv4:
		ip4 := a.IP.To4()
		if ip4 == nil {
			return errors.New("invalid IPv4 address")
		}
		if _, err := w.Write(ip4); err != nil {
			return err
		}
		return binary.Write(w, binary.BigEndian, a.Port)
	case TuicAddrTypeIPv6:
		ip6 := a.IP.To16()
		if ip6 == nil {
			return errors.New("invalid IPv6 address")
		}
		if _, err := w.Write(ip6); err != nil {
			return err
		}
		return binary.Write(w, binary.BigEndian, a.Port)
	case TuicAddrTypeNone:
		return nil
	default:
		return errors.New("unknown address type")
	}
}

// ReadAddress parses the address type from the reader (Items 9-11)
func ReadAddress(r io.Reader) (*TuicAddress, error) {
	var addrType byte
	if err := binary.Read(r, binary.BigEndian, &addrType); err != nil {
		return nil, err
	}

	addr := &TuicAddress{AddrType: addrType}
	switch addrType {
	case TuicAddrTypeDomain:
		var length byte
		if err := binary.Read(r, binary.BigEndian, &length); err != nil {
			return nil, err
		}
		buf := make([]byte, length)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err
		}
		addr.Host = string(buf)
		if err := binary.Read(r, binary.BigEndian, &addr.Port); err != nil {
			return nil, err
		}
	case TuicAddrTypeIPv4:
		buf := make([]byte, 4)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err
		}
		addr.IP = net.IP(buf)
		if err := binary.Read(r, binary.BigEndian, &addr.Port); err != nil {
			return nil, err
		}
	case TuicAddrTypeIPv6:
		buf := make([]byte, 16)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err
		}
		addr.IP = net.IP(buf)
		if err := binary.Read(r, binary.BigEndian, &addr.Port); err != nil {
			return nil, err
		}
	case TuicAddrTypeNone:
		// Do nothing
	default:
		return nil, errors.New("invalid TUIC address type")
	}
	return addr, nil
}

// TUIC Authenticate Frame structure (Items 12-13)
type TuicAuthenticateFrame struct {
	UUID  [16]byte
	Token [32]byte
}

// Write serializes the authenticate frame (Item 14)
func (f *TuicAuthenticateFrame) Write(w io.Writer) error {
	if _, err := w.Write([]byte{TuicVersion, TuicCmdAuthenticate}); err != nil {
		return err
	}
	if _, err := w.Write(f.UUID[:]); err != nil {
		return err
	}
	_, err := w.Write(f.Token[:])
	return err
}

// TUIC Connect Frame structure (Item 15)
type TuicConnectFrame struct {
	Addr TuicAddress
}

// Write serializes the connect frame (Item 16)
func (f *TuicConnectFrame) Write(w io.Writer) error {
	if _, err := w.Write([]byte{TuicVersion, TuicCmdConnect}); err != nil {
		return err
	}
	return f.Addr.Write(w)
}

// TUIC Packet Frame structure (Item 17)
type TuicPacketFrame struct {
	AssocID   uint16
	PacketID  uint16
	FragTotal byte
	FragID    byte
	Size      uint16
	Addr      TuicAddress
}

// Write serializes the packet frame (Item 18)
func (f *TuicPacketFrame) Write(w io.Writer) error {
	if _, err := w.Write([]byte{TuicVersion, TuicCmdPacket}); err != nil {
		return err
	}
	if err := binary.Write(w, binary.BigEndian, f.AssocID); err != nil {
		return err
	}
	if err := binary.Write(w, binary.BigEndian, f.PacketID); err != nil {
		return err
	}
	if _, err := w.Write([]byte{f.FragTotal, f.FragID}); err != nil {
		return err
	}
	if err := binary.Write(w, binary.BigEndian, f.Size); err != nil {
		return err
	}
	return f.Addr.Write(w)
}

// TUIC Dissociate Frame structure (Item 19)
type TuicDissociateFrame struct {
	AssocID uint16
}

// Write serializes the dissociate frame (Item 20)
func (f *TuicDissociateFrame) Write(w io.Writer) error {
	if _, err := w.Write([]byte{TuicVersion, TuicCmdDissociate}); err != nil {
		return err
	}
	return binary.Write(w, binary.BigEndian, f.AssocID)
}

// TUIC Heartbeat Frame structure (Item 21)
type TuicHeartbeatFrame struct{}

// Write serializes the heartbeat frame (Item 22)
func (f *TuicHeartbeatFrame) Write(w io.Writer) error {
	_, err := w.Write([]byte{TuicVersion, TuicCmdHeartbeat})
	return err
}
