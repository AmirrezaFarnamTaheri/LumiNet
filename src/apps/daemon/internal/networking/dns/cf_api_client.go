// Package dns implements domain name resolution and custom wizards.

package dns

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"strings"

	cfapi "github.com/cloudflare/cloudflare-go/v7"
	"github.com/cloudflare/cloudflare-go/v7/accounts"
	"github.com/cloudflare/cloudflare-go/v7/dns"
	"github.com/cloudflare/cloudflare-go/v7/option"
	"github.com/cloudflare/cloudflare-go/v7/origin_ca_certificates"
	"github.com/cloudflare/cloudflare-go/v7/shared"
	"github.com/cloudflare/cloudflare-go/v7/ssl"
	"github.com/cloudflare/cloudflare-go/v7/user"
	"github.com/cloudflare/cloudflare-go/v7/zones"
)

// CloudflareClient defines operations supported by the Cloudflare wizard API.
type CloudflareClient interface {
	VerifyToken(ctx context.Context) error
	ListZones(ctx context.Context) ([]Zone, error)
	GetZoneByName(ctx context.Context, name string) (*Zone, error)
	EnsureDNSRecord(ctx context.Context, zoneID string, record DNSRecord) (*DNSRecordResult, error)
	SetSSLModeStrict(ctx context.Context, zoneID string) error
	CreateOriginCertificate(ctx context.Context, req OriginCertRequest) (*OriginCert, error)
}

// CloudflareSDKClient implements CloudflareClient using cloudflare-go SDK.
type CloudflareSDKClient struct {
	client    *cfapi.Client
	accountID string
}

// NewCloudflareSDKClient initializes a new Cloudflare SDK client wrapper.
func NewCloudflareSDKClient(token, accountID string) *CloudflareSDKClient {
	return &CloudflareSDKClient{
		client:    cfapi.NewClient(option.WithAPIToken(token)),
		accountID: strings.TrimSpace(accountID),
	}
}

// VerifyToken verifies the scopes and status of the current API token.
func (c *CloudflareSDKClient) VerifyToken(ctx context.Context) error {
	if c.accountID != "" {
		res, err := c.client.Accounts.Tokens.Verify(ctx, accounts.TokenVerifyParams{
			AccountID: cfapi.F(c.accountID),
		})
		if err != nil {
			return err
		}
		if res.Status != accounts.TokenVerifyResponseStatusActive {
			return fmt.Errorf("account token status is %s", res.Status)
		}
		return nil
	}

	res, err := c.client.User.Tokens.Verify(ctx)
	if err != nil {
		return err
	}
	if res.Status != user.TokenVerifyResponseStatusActive {
		return fmt.Errorf("token status is %s", res.Status)
	}
	return nil
}

// ListZones lists up to 50 zones accessible by the token.
func (c *CloudflareSDKClient) ListZones(ctx context.Context) ([]Zone, error) {
	page, err := c.client.Zones.List(ctx, zones.ZoneListParams{
		PerPage: cfapi.F(float64(50)),
	})
	if err != nil {
		return nil, err
	}
	out := make([]Zone, 0, len(page.Result))
	for _, zone := range page.Result {
		out = append(out, fromSDKZone(zone))
	}
	return out, nil
}

// GetZoneByName returns the zone matching the given domain name.
func (c *CloudflareSDKClient) GetZoneByName(ctx context.Context, name string) (*Zone, error) {
	page, err := c.client.Zones.List(ctx, zones.ZoneListParams{
		Name:    cfapi.F(name),
		PerPage: cfapi.F(float64(10)),
	})
	if err != nil {
		return nil, err
	}
	for _, zone := range page.Result {
		if strings.EqualFold(zone.Name, name) {
			mapped := fromSDKZone(zone)
			return &mapped, nil
		}
	}
	return nil, fmt.Errorf("zone %q not found", name)
}

// EnsureDNSRecord creates or updates a DNS record under the specified zone ID.
func (c *CloudflareSDKClient) EnsureDNSRecord(ctx context.Context, zoneID string, record DNSRecord) (*DNSRecordResult, error) {
	if strings.ToUpper(record.Type) != "A" {
		return nil, fmt.Errorf("unsupported DNS record type %q", record.Type)
	}
	if record.TTL == 0 {
		record.TTL = DefaultTTL
	}

	existing, err := c.findDNSRecord(ctx, zoneID, record)
	if err != nil {
		return nil, err
	}
	body := dns.ARecordParam{
		Name:    cfapi.F(record.Name),
		TTL:     cfapi.F(dns.TTL(record.TTL)),
		Type:    cfapi.F(dns.ARecordTypeA),
		Content: cfapi.F(record.Content),
		Proxied: cfapi.F(record.Proxied),
	}

	if existing == nil {
		created, err := c.client.DNS.Records.New(ctx, dns.RecordNewParams{
			ZoneID: cfapi.F(zoneID),
			Body:   body,
		})
		if err != nil {
			return &DNSRecordResult{Record: record, Status: DNSRecordFailed, Error: err.Error()}, err
		}
		return &DNSRecordResult{Record: record, Status: DNSRecordCreated, ID: created.ID}, nil
	}

	if existing.Content == record.Content && existing.Proxied == record.Proxied && int(existing.TTL) == record.TTL {
		return &DNSRecordResult{Record: record, Status: DNSRecordUnchanged, ID: existing.ID}, nil
	}

	updated, err := c.client.DNS.Records.Edit(ctx, existing.ID, dns.RecordEditParams{
		ZoneID: cfapi.F(zoneID),
		Body:   body,
	})
	if err != nil {
		return &DNSRecordResult{Record: record, Status: DNSRecordFailed, ID: existing.ID, Error: err.Error()}, err
	}
	return &DNSRecordResult{Record: record, Status: DNSRecordUpdated, ID: updated.ID}, nil
}

// SetSSLModeStrict sets the SSL mode of the zone to Strict.
func (c *CloudflareSDKClient) SetSSLModeStrict(ctx context.Context, zoneID string) error {
	_, err := c.client.Zones.Settings.Edit(ctx, "ssl", zones.SettingEditParams{
		ZoneID: cfapi.F(zoneID),
		Body: zones.SettingEditParamsBody{
			Value: cfapi.F[interface{}](zones.SSLValueStrict),
		},
	})
	return err
}

// CreateOriginCertificate generates and signs a new Origin CA certificate.
func (c *CloudflareSDKClient) CreateOriginCertificate(ctx context.Context, req OriginCertRequest) (*OriginCert, error) {
	validity := ssl.RequestValidity5475
	if req.RequestedValidity > 0 {
		validity = ssl.RequestValidity(req.RequestedValidity)
	}
	requestType := shared.CertificateRequestTypeOriginECC
	if req.RequestType != "" {
		requestType = shared.CertificateRequestType(req.RequestType)
	}
	cert, err := c.client.OriginCACertificates.New(ctx, origin_ca_certificates.OriginCACertificateNewParams{
		Csr:               cfapi.F(req.CSRPEM),
		Hostnames:         cfapi.F(req.Hostnames),
		RequestType:       cfapi.F(requestType),
		RequestedValidity: cfapi.F(validity),
	})
	if err != nil {
		return nil, err
	}
	return &OriginCert{
		ID:             cert.ID,
		CertificatePEM: cert.Certificate,
		ExpiresOn:      cert.ExpiresOn,
	}, nil
}

func (c *CloudflareSDKClient) findDNSRecord(ctx context.Context, zoneID string, record DNSRecord) (*dns.RecordResponse, error) {
	page, err := c.client.DNS.Records.List(ctx, dns.RecordListParams{
		ZoneID: cfapi.F(zoneID),
		Name: cfapi.F(dns.RecordListParamsName{
			Exact: cfapi.F(record.Name),
		}),
		Type:    cfapi.F(dns.RecordListParamsTypeA),
		PerPage: cfapi.F(float64(10)),
	})
	if err != nil {
		return nil, err
	}
	for _, existing := range page.Result {
		if strings.EqualFold(existing.Name, record.Name) && string(existing.Type) == strings.ToUpper(record.Type) {
			item := existing
			return &item, nil
		}
	}
	return nil, nil
}

func fromSDKZone(zone zones.Zone) Zone {
	return Zone{
		ID:          zone.ID,
		Name:        zone.Name,
		Status:      string(zone.Status),
		NameServers: zone.NameServers,
	}
}

// BuildOriginCertRequest creates a private key and CSR for origin certificate provisioning.
// Maps to upstream BuildOriginCertRequest().
func BuildOriginCertRequest(domain string) (OriginCertRequest, string, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return OriginCertRequest{}, "", fmt.Errorf("generate origin private key: %w", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: domain},
		DNSNames: []string{domain, "*." + domain},
	}, privateKey)
	if err != nil {
		return OriginCertRequest{}, "", fmt.Errorf("generate origin CSR: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return OriginCertRequest{}, "", fmt.Errorf("marshal origin private key: %w", err)
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if csrPEM == nil || keyPEM == nil {
		return OriginCertRequest{}, "", fmt.Errorf("encode origin certificate material")
	}

	return OriginCertRequest{
		Hostnames:         []string{domain, "*." + domain},
		RequestType:       "origin-ecc",
		RequestedValidity: 5475,
		CSRPEM:            string(csrPEM),
	}, string(keyPEM), nil
}
