package proxy

import (
	"bytes"
	"fmt"
	"io"
	"regexp"
	"strings"
)

// V2RayDomainType matches the V2Ray Geosite Domain.Type enum.
type V2RayDomainType int

const (
	V2RayDomainPlain  V2RayDomainType = 0
	V2RayDomainRegex  V2RayDomainType = 1
	V2RayDomainDomain V2RayDomainType = 2
	V2RayDomainFull   V2RayDomainType = 3
)

// V2RayDomain represents a domain rule in V2Ray.
type V2RayDomain struct {
	Type  V2RayDomainType
	Value string
}

// V2RayGeoSite represents a set of domain rules for a country/category.
type V2RayGeoSite struct {
	CountryCode string
	Domains     []V2RayDomain
}

func (s *V2RayGeoSite) Validate() error {
	for _, domain := range s.Domains {
		if domain.Value == "" {
			return fmt.Errorf("empty domain value")
		}
		if domain.Type == V2RayDomainRegex {
			if _, err := regexp.Compile(domain.Value); err != nil {
				return fmt.Errorf("invalid regex '%s': %w", domain.Value, err)
			}
		} else {
			if strings.Contains(domain.Value, " ") {
				return fmt.Errorf("domain value '%s' contains spaces", domain.Value)
			}
		}
	}
	return nil
}

// CompileGeositeDat encodes a list of V2RayGeoSite rules into V2Ray/Xray compatible geosite.dat Protobuf format.
func CompileGeositeDat(sites []V2RayGeoSite, w io.Writer) error {
	var listBuf bytes.Buffer

	for _, site := range sites {
		if err := site.Validate(); err != nil {
			return fmt.Errorf("geosite validation failed: %w", err)
		}

		var siteBuf bytes.Buffer

		// Write country_code (Tag 1, Wire Type 2: string)
		writeStringTag(&siteBuf, 1, site.CountryCode)

		// Write domains (Tag 2, Wire Type 2: repeated message)
		for _, domain := range site.Domains {
			var domBuf bytes.Buffer
			// Write Type (Tag 1, Wire Type 0: varint)
			writeVarintTag(&domBuf, 1, uint64(domain.Type))
			// Write Value (Tag 2, Wire Type 2: string)
			writeStringTag(&domBuf, 2, domain.Value)

			writeBytesTag(&siteBuf, 2, domBuf.Bytes())
		}

		// Write GeoSite (Tag 1, Wire Type 2: repeated message in GeoSiteList)
		writeBytesTag(&listBuf, 1, siteBuf.Bytes())
	}

	_, err := w.Write(listBuf.Bytes())
	return err
}

func writeVarint(w io.Writer, x uint64) {
	var buf [10]byte
	i := 0
	for x >= 0x80 {
		buf[i] = byte(x | 0x80)
		x >>= 7
		i++
	}
	buf[i] = byte(x)
	i++
	_, _ = w.Write(buf[:i])
}

func writeVarintTag(w io.Writer, tag int, val uint64) {
	// wire type 0 for varint
	writeVarint(w, uint64((tag<<3)|0))
	writeVarint(w, val)
}

func writeBytesTag(w io.Writer, tag int, data []byte) {
	// wire type 2 for length-delimited
	writeVarint(w, uint64((tag<<3)|2))
	writeVarint(w, uint64(len(data)))
	_, _ = w.Write(data)
}

func writeStringTag(w io.Writer, tag int, s string) {
	writeBytesTag(w, tag, []byte(s))
}
