package tlsfragment

// SNIHostRange parses a raw TLS ClientHello and returns the byte range [start, end)
// of the SNI hostname within data. It returns (0, 0) on any parse failure.
func SNIHostRange(data []byte) (int, int) {
	if len(data) < 5 || data[0] != 0x16 {
		return 0, 0
	}
	i := 5
	if len(data) < i+4 || data[i] != 0x01 {
		return 0, 0
	}
	i += 4
	if len(data) < i+2+32+1 {
		return 0, 0
	}
	i += 2 + 32
	sessionLen := int(data[i])
	i++
	if len(data) < i+sessionLen+2 {
		return 0, 0
	}
	i += sessionLen
	cipherLen := int(data[i])<<8 | int(data[i+1])
	i += 2
	if len(data) < i+cipherLen+1 {
		return 0, 0
	}
	i += cipherLen
	compressionLen := int(data[i])
	i++
	if len(data) < i+compressionLen+2 {
		return 0, 0
	}
	i += compressionLen
	extLen := int(data[i])<<8 | int(data[i+1])
	i += 2
	extEnd := i + extLen
	if len(data) < extEnd {
		return 0, 0
	}
	for i+4 <= extEnd {
		typ := int(data[i])<<8 | int(data[i+1])
		length := int(data[i+2])<<8 | int(data[i+3])
		i += 4
		if i+length > extEnd {
			return 0, 0
		}
		if typ == 0x0000 {
			return sniHostRangeInExtension(data, i, i+length)
		}
		i += length
	}
	return 0, 0
}

func sniHostRangeInExtension(data []byte, start, end int) (int, int) {
	i := start
	if i+2 > end {
		return 0, 0
	}
	listLen := int(data[i])<<8 | int(data[i+1])
	i += 2
	if i+listLen > end {
		return 0, 0
	}
	for i+3 <= end {
		nameType := data[i]
		nameLen := int(data[i+1])<<8 | int(data[i+2])
		i += 3
		if i+nameLen > end {
			return 0, 0
		}
		if nameType == 0 {
			return i, i + nameLen
		}
		i += nameLen
	}
	return 0, 0
}
