package nat

import (
	"io"
	"net"
	"net/netip"
)

const (
	portBegin  = 30000
	portLength = 4096
)

func Start(
	device io.ReadWriter,
	network netip.Prefix,
	portal netip.Addr,
) (*TCP, *UDP, error) {
	if !portal.Is4() || !network.Addr().Is4() {
		return nil, nil, net.InvalidAddrError("only ipv4 supported")
	}

	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, nil, err
	}

	tab := newTable()
	udp := &UDP{
		device: device,
		buf:    [65535]byte{},
	}
	tcp := &TCP{
		listener: listener,
		portal:   portal,
		table:    tab,
	}

	broadcast := BroadcastAddr(network)
	gateway := network.Addr()
	gatewayPort := uint16(listener.Addr().(*net.TCPAddr).Port)

	defragger := NewIPv4Defragmenter()

	go func() {
		defer func() {
			_ = tcp.Close()
			_ = udp.Close()
		}()

		buf := make([]byte, 65535)

		for {
			n, err := device.Read(buf)
			if err != nil {
				return
			}

			raw := buf[:n]

			if !IsIPv4(raw) {
				continue
			}

			raw, err = defragger.DefragIPv4(raw)
			if err == ErrIncompleteFragment {
				continue
			}
			if err != nil || raw == nil {
				continue
			}

			ip := IPv4Packet(raw)
			if !ip.Valid() {
				continue
			}

			if !ip.DestinationIP().IsGlobalUnicast() || ip.DestinationIP() == broadcast {
				continue
			}

			switch ip.Protocol() {
			case ProtocolTCP:
				t := TCPPacket(ip.Payload())
				if !t.Valid() {
					continue
				}

				if ip.DestinationIP() == portal {
					if ip.SourceIP() == gateway && t.SourcePort() == gatewayPort {
						tup := tab.findTupleByPort(t.DestinationPort())
						if tup == zeroTuple {
							continue
						}

						ip.SetSourceIP(tup.to.Addr())
						t.SetSourcePort(tup.to.Port())
						ip.SetDestinationIP(tup.from.Addr())
						t.SetDestinationPort(tup.from.Port())

						ip.ResetChecksum()
						t.ResetChecksum(ip.PseudoSum())

						_, _ = device.Write(raw)
					}
				} else {
					tup := tuple{
						from: netip.AddrPortFrom(ip.SourceIP(), t.SourcePort()),
						to:   netip.AddrPortFrom(ip.DestinationIP(), t.DestinationPort()),
					}

					port := tab.findPortByTuple(tup)
					if port == 0 {
						if t.Flags() != TCPSyn {
							continue
						}

						port = tab.newConn(tup)
					}

					ip.SetSourceIP(portal)
					ip.SetDestinationIP(gateway)
					t.SetSourcePort(port)
					t.SetDestinationPort(gatewayPort)

					ip.ResetChecksum()
					t.ResetChecksum(ip.PseudoSum())

					_, _ = device.Write(raw)
				}
			case ProtocolUDP:
				u := UDPPacket(ip.Payload())
				if !u.Valid() {
					continue
				}

				udp.handleUDPPacket(ip, u)
			case ICMP:
				i := ICMPPacket(ip.Payload())

				if i.Type() != ICMPTypePingRequest || i.Code() != 0 {
					continue
				}

				i.SetType(ICMPTypePingResponse)

				source := ip.SourceIP()
				destination := ip.DestinationIP()
				ip.SetSourceIP(destination)
				ip.SetDestinationIP(source)

				ip.ResetChecksum()
				i.ResetChecksum()

				_, _ = device.Write(raw)
			}
		}
	}()

	return tcp, udp, nil
}
