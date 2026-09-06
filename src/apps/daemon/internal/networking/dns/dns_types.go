// Package dns implements domain name resolution and custom wizards.

package dns

import (
	"encoding/json"
	"fmt"
	"time"
)

const (
	SSLModeStrict = "strict"
	DefaultTTL    = 1
)

// DNSRecord represents a DNS record configuration.
type DNSRecord struct {
	Name    string `json:"name" yaml:"name"`
	Type    string `json:"type" yaml:"type"`
	Content string `json:"content" yaml:"content"`
	Proxied bool   `json:"proxied" yaml:"proxied"`
	TTL     int    `json:"ttl" yaml:"ttl"`
	Purpose string `json:"purpose" yaml:"purpose"`
}

// Getters & Setters for DNSRecord
func (r *DNSRecord) GetName() string     { return r.Name }
func (r *DNSRecord) SetName(v string)    { r.Name = v }
func (r *DNSRecord) GetType() string     { return r.Type }
func (r *DNSRecord) SetType(v string)    { r.Type = v }
func (r *DNSRecord) GetContent() string  { return r.Content }
func (r *DNSRecord) SetContent(v string) { r.Content = v }
func (r *DNSRecord) GetProxied() bool    { return r.Proxied }
func (r *DNSRecord) SetProxied(v bool)   { r.Proxied = v }
func (r *DNSRecord) GetTTL() int         { return r.TTL }
func (r *DNSRecord) SetTTL(v int)        { r.TTL = v }
func (r *DNSRecord) GetPurpose() string  { return r.Purpose }
func (r *DNSRecord) SetPurpose(v string) { r.Purpose = v }

// Builders for DNSRecord
func (r *DNSRecord) WithName(v string) *DNSRecord    { r.SetName(v); return r }
func (r *DNSRecord) WithType(v string) *DNSRecord    { r.SetType(v); return r }
func (r *DNSRecord) WithContent(v string) *DNSRecord { r.SetContent(v); return r }
func (r *DNSRecord) WithProxied(v bool) *DNSRecord   { r.SetProxied(v); return r }
func (r *DNSRecord) WithTTL(v int) *DNSRecord        { r.SetTTL(v); return r }
func (r *DNSRecord) WithPurpose(v string) *DNSRecord { r.SetPurpose(v); return r }

// String returns a string representation of the DNSRecord.
func (r *DNSRecord) String() string {
	return fmt.Sprintf("%s %s %s (TTL: %d, Proxied: %t)", r.Name, r.Type, r.Content, r.TTL, r.Proxied)
}

// DNSRecordStatus represents the outcome status of a record operation.
type DNSRecordStatus string

const (
	DNSRecordCreated   DNSRecordStatus = "CREATED"
	DNSRecordUpdated   DNSRecordStatus = "UPDATED"
	DNSRecordUnchanged DNSRecordStatus = "UNCHANGED"
	DNSRecordFailed    DNSRecordStatus = "FAILED"
)

// DNSRecordResult holds the outcome of a DNS record configuration.
type DNSRecordResult struct {
	Record DNSRecord       `json:"record" yaml:"record"`
	Status DNSRecordStatus `json:"status" yaml:"status"`
	ID     string          `json:"id,omitempty" yaml:"id,omitempty"`
	Error  string          `json:"error,omitempty" yaml:"error,omitempty"`
}

// Getters & Setters for DNSRecordResult
func (r *DNSRecordResult) GetRecord() DNSRecord        { return r.Record }
func (r *DNSRecordResult) SetRecord(v DNSRecord)       { r.Record = v }
func (r *DNSRecordResult) GetStatus() DNSRecordStatus  { return r.Status }
func (r *DNSRecordResult) SetStatus(v DNSRecordStatus) { r.Status = v }
func (r *DNSRecordResult) GetID() string               { return r.ID }
func (r *DNSRecordResult) SetID(v string)              { r.ID = v }
func (r *DNSRecordResult) GetError() string            { return r.Error }
func (r *DNSRecordResult) SetError(v string)           { r.Error = v }

// Builders for DNSRecordResult
func (r *DNSRecordResult) WithRecord(v DNSRecord) *DNSRecordResult       { r.SetRecord(v); return r }
func (r *DNSRecordResult) WithStatus(v DNSRecordStatus) *DNSRecordResult { r.SetStatus(v); return r }
func (r *DNSRecordResult) WithID(v string) *DNSRecordResult              { r.SetID(v); return r }
func (r *DNSRecordResult) WithError(v string) *DNSRecordResult           { r.SetError(v); return r }

// Zone represents a Cloudflare DNS zone.
type Zone struct {
	ID          string   `json:"id" yaml:"id"`
	Name        string   `json:"name" yaml:"name"`
	Status      string   `json:"status" yaml:"status"`
	NameServers []string `json:"name_servers" yaml:"name_servers"`
}

// Getters & Setters for Zone
func (z *Zone) GetID() string             { return z.ID }
func (z *Zone) SetID(v string)            { z.ID = v }
func (z *Zone) GetName() string           { return z.Name }
func (z *Zone) SetName(v string)          { z.Name = v }
func (z *Zone) GetStatus() string         { return z.Status }
func (z *Zone) SetStatus(v string)        { z.Status = v }
func (z *Zone) GetNameServers() []string  { return z.NameServers }
func (z *Zone) SetNameServers(v []string) { z.NameServers = v }

// Builders for Zone
func (z *Zone) WithID(v string) *Zone            { z.SetID(v); return z }
func (z *Zone) WithName(v string) *Zone          { z.SetName(v); return z }
func (z *Zone) WithStatus(v string) *Zone        { z.SetStatus(v); return z }
func (z *Zone) WithNameServers(v []string) *Zone { z.SetNameServers(v); return z }

// OriginCertRequest holds variables needed to request an origin certificate.
type OriginCertRequest struct {
	Hostnames         []string `json:"hostnames" yaml:"hostnames"`
	RequestType       string   `json:"request_type" yaml:"request_type"`
	RequestedValidity int      `json:"requested_validity" yaml:"requested_validity"`
	CSRPEM            string   `json:"-" yaml:"-"`
}

// Getters & Setters for OriginCertRequest
func (r *OriginCertRequest) GetHostnames() []string     { return r.Hostnames }
func (r *OriginCertRequest) SetHostnames(v []string)    { r.Hostnames = v }
func (r *OriginCertRequest) GetRequestType() string     { return r.RequestType }
func (r *OriginCertRequest) SetRequestType(v string)    { r.RequestType = v }
func (r *OriginCertRequest) GetRequestedValidity() int  { return r.RequestedValidity }
func (r *OriginCertRequest) SetRequestedValidity(v int) { r.RequestedValidity = v }
func (r *OriginCertRequest) GetCSRPEM() string          { return r.CSRPEM }
func (r *OriginCertRequest) SetCSRPEM(v string)         { r.CSRPEM = v }

// Builders for OriginCertRequest
func (r *OriginCertRequest) WithHostnames(v []string) *OriginCertRequest { r.SetHostnames(v); return r }
func (r *OriginCertRequest) WithRequestType(v string) *OriginCertRequest {
	r.SetRequestType(v)
	return r
}
func (r *OriginCertRequest) WithRequestedValidity(v int) *OriginCertRequest {
	r.SetRequestedValidity(v)
	return r
}
func (r *OriginCertRequest) WithCSRPEM(v string) *OriginCertRequest { r.SetCSRPEM(v); return r }

// OriginCert represents a Cloudflare-signed Origin CA certificate.
type OriginCert struct {
	ID             string `json:"id,omitempty" yaml:"id,omitempty"`
	CertificatePEM string `json:"certificate_pem" yaml:"certificate_pem"`
	PrivateKeyPEM  string `json:"-" yaml:"-"`
	ExpiresOn      string `json:"expires_on,omitempty" yaml:"expires_on,omitempty"`
}

// Getters & Setters for OriginCert
func (c *OriginCert) GetID() string              { return c.ID }
func (c *OriginCert) SetID(v string)             { c.ID = v }
func (c *OriginCert) GetCertificatePEM() string  { return c.CertificatePEM }
func (c *OriginCert) SetCertificatePEM(v string) { c.CertificatePEM = v }
func (c *OriginCert) GetPrivateKeyPEM() string   { return c.PrivateKeyPEM }
func (c *OriginCert) SetPrivateKeyPEM(v string)  { c.PrivateKeyPEM = v }
func (c *OriginCert) GetExpiresOn() string       { return c.ExpiresOn }
func (c *OriginCert) SetExpiresOn(v string)      { c.ExpiresOn = v }

// Builders for OriginCert
func (c *OriginCert) WithID(v string) *OriginCert             { c.SetID(v); return c }
func (c *OriginCert) WithCertificatePEM(v string) *OriginCert { c.SetCertificatePEM(v); return c }
func (c *OriginCert) WithPrivateKeyPEM(v string) *OriginCert  { c.SetPrivateKeyPEM(v); return c }
func (c *OriginCert) WithExpiresOn(v string) *OriginCert      { c.SetExpiresOn(v); return c }

// ProjectConfig holds standard config parameters.
type ProjectConfig struct {
	Project    string           `json:"project" yaml:"project"`
	ZoneID     string           `json:"zone_id" yaml:"zone_id"`
	VPSIP      string           `json:"vps_ip" yaml:"vps_ip"`
	Cloudflare CloudflareConfig `json:"cloudflare" yaml:"cloudflare"`
}

// Getters & Setters for ProjectConfig
func (c *ProjectConfig) GetProject() string               { return c.Project }
func (c *ProjectConfig) SetProject(v string)              { c.Project = v }
func (c *ProjectConfig) GetZoneID() string                { return c.ZoneID }
func (c *ProjectConfig) SetZoneID(v string)               { c.ZoneID = v }
func (c *ProjectConfig) GetVPSIP() string                 { return c.VPSIP }
func (c *ProjectConfig) SetVPSIP(v string)                { c.VPSIP = v }
func (c *ProjectConfig) GetCloudflare() CloudflareConfig  { return c.Cloudflare }
func (c *ProjectConfig) SetCloudflare(v CloudflareConfig) { c.Cloudflare = v }

// CloudflareConfig wraps zone details and DNS record templates.
type CloudflareConfig struct {
	AccountID string      `json:"account_id,omitempty" yaml:"account_id,omitempty"`
	SSLMode   string      `json:"ssl_mode" yaml:"ssl_mode"`
	Records   []DNSRecord `json:"records" yaml:"records"`
}

// Getters & Setters for CloudflareConfig
func (c *CloudflareConfig) GetAccountID() string     { return c.AccountID }
func (c *CloudflareConfig) SetAccountID(v string)    { c.AccountID = v }
func (c *CloudflareConfig) GetSSLMode() string       { return c.SSLMode }
func (c *CloudflareConfig) SetSSLMode(v string)      { c.SSLMode = v }
func (c *CloudflareConfig) GetRecords() []DNSRecord  { return c.Records }
func (c *CloudflareConfig) SetRecords(v []DNSRecord) { c.Records = v }

// DNSPlan holds a plan containing record overrides.
type DNSPlan struct {
	Records []DNSRecord `json:"records" yaml:"records"`
}

// ProtocolPlan holds protocol configurations.
type ProtocolPlan struct {
	Protocols []Protocol `json:"protocols" yaml:"protocols"`
}

// Protocol configuration structure.
type Protocol struct {
	Name              string `json:"name" yaml:"name"`
	Enabled           bool   `json:"enabled" yaml:"enabled"`
	Hostname          string `json:"hostname" yaml:"hostname"`
	Port              int    `json:"port" yaml:"port"`
	Network           string `json:"network,omitempty" yaml:"network,omitempty"`
	Transport         string `json:"transport,omitempty" yaml:"transport,omitempty"`
	Tag               string `json:"tag,omitempty" yaml:"tag,omitempty"`
	ClientEmail       string `json:"client_email,omitempty" yaml:"client_email,omitempty"`
	Path              string `json:"path,omitempty" yaml:"path,omitempty"`
	TLS               bool   `json:"tls,omitempty" yaml:"tls,omitempty"`
	UDP               bool   `json:"udp,omitempty" yaml:"udp,omitempty"`
	CloudflareProxied bool   `json:"cloudflare_proxied" yaml:"cloudflare_proxied"`
	Certificate       string `json:"certificate,omitempty" yaml:"certificate,omitempty"`
}

// Getters & Setters for Protocol
func (p *Protocol) GetName() string             { return p.Name }
func (p *Protocol) SetName(v string)            { p.Name = v }
func (p *Protocol) GetEnabled() bool            { return p.Enabled }
func (p *Protocol) SetEnabled(v bool)           { p.Enabled = v }
func (p *Protocol) GetHostname() string         { return p.Hostname }
func (p *Protocol) SetHostname(v string)        { p.Hostname = v }
func (p *Protocol) GetPort() int                { return p.Port }
func (p *Protocol) SetPort(v int)               { p.Port = v }
func (p *Protocol) GetNetwork() string          { return p.Network }
func (p *Protocol) SetNetwork(v string)         { p.Network = v }
func (p *Protocol) GetTransport() string        { return p.Transport }
func (p *Protocol) SetTransport(v string)       { p.Transport = v }
func (p *Protocol) GetTag() string              { return p.Tag }
func (p *Protocol) SetTag(v string)             { p.Tag = v }
func (p *Protocol) GetClientEmail() string      { return p.ClientEmail }
func (p *Protocol) SetClientEmail(v string)     { p.ClientEmail = v }
func (p *Protocol) GetPath() string             { return p.Path }
func (p *Protocol) SetPath(v string)            { p.Path = v }
func (p *Protocol) GetTLS() bool                { return p.TLS }
func (p *Protocol) SetTLS(v bool)               { p.TLS = v }
func (p *Protocol) GetUDP() bool                { return p.UDP }
func (p *Protocol) SetUDP(v bool)               { p.UDP = v }
func (p *Protocol) GetCloudflareProxied() bool  { return p.CloudflareProxied }
func (p *Protocol) SetCloudflareProxied(v bool) { p.CloudflareProxied = v }
func (p *Protocol) GetCertificate() string      { return p.Certificate }
func (p *Protocol) SetCertificate(v string)     { p.Certificate = v }

// Builders for Protocol
func (p *Protocol) WithName(v string) *Protocol     { p.SetName(v); return p }
func (p *Protocol) WithEnabled(v bool) *Protocol    { p.SetEnabled(v); return p }
func (p *Protocol) WithHostname(v string) *Protocol { p.SetHostname(v); return p }
func (p *Protocol) WithPort(v int) *Protocol        { p.SetPort(v); return p }

// ProvisionInput holds required variables to run zone provisions.
type ProvisionInput struct {
	Token     string
	AccountID string
	Domain    string
	VPSIP     string
	Root      string
}

// ProvisionResult holds provisioning outputs.
type ProvisionResult struct {
	ProjectDir   string
	Zone         Zone
	DNSResults   []DNSRecordResult
	OriginCert   OriginCert
	Config       ProjectConfig
	DNSPlan      DNSPlan
	ProtocolPlan ProtocolPlan
}

// CloudflareState represents the current state of Cloudflare DNS zone setups.
type CloudflareState struct {
	Zone         Zone              `json:"zone"`
	DNSResults   []DNSRecordResult `json:"dns_results"`
	OriginCertID string            `json:"origin_cert_id,omitempty"`
	AppliedAt    time.Time         `json:"applied_at"`
}

// XUIPlan represents remote Xray X-UI deployment parameters.
type XUIPlan struct {
	Domain          string        `json:"domain" yaml:"domain"`
	Remote          XUIRemotePlan `json:"remote" yaml:"remote"`
	InstallRequired bool          `json:"install_required" yaml:"install_required"`
	Protocols       []Protocol    `json:"protocols" yaml:"protocols"`
	Conflicts       []XUIConflict `json:"conflicts,omitempty" yaml:"conflicts,omitempty"`
	Warnings        []string      `json:"warnings,omitempty" yaml:"warnings,omitempty"`
	ComposePath     string        `json:"compose_path,omitempty" yaml:"compose_path,omitempty"`
	PlannedAt       time.Time     `json:"planned_at" yaml:"planned_at"`
}

// XUIRemotePlan represents SSH remote hosts configuration.
type XUIRemotePlan struct {
	SSHHost       string `json:"ssh_host" yaml:"ssh_host"`
	SSHUser       string `json:"ssh_user" yaml:"ssh_user"`
	SSHPort       int    `json:"ssh_port" yaml:"ssh_port"`
	ContainerName string `json:"container_name,omitempty" yaml:"container_name,omitempty"`
	PanelPort     int    `json:"panel_port" yaml:"panel_port"`
	WebBasePath   string `json:"web_base_path,omitempty" yaml:"web_base_path,omitempty"`
}

// XUIState represents actual running deployment state.
type XUIState struct {
	Domain        string            `json:"domain"`
	RemoteHost    string            `json:"remote_host"`
	ContainerName string            `json:"container_name,omitempty"`
	Installed     bool              `json:"installed"`
	AppliedAt     time.Time         `json:"applied_at"`
	Inbounds      []XUIInboundState `json:"inbounds"`
	Outbounds     []string          `json:"outbounds"`
	Warnings      []string          `json:"warnings,omitempty"`
}

// XUIInboundState lists configured inbound properties.
type XUIInboundState struct {
	Tag      string `json:"tag"`
	Protocol string `json:"protocol"`
	Hostname string `json:"hostname"`
	Port     int    `json:"port"`
	Network  string `json:"network"`
}

// ClientLinks holds subscription sharing link maps.
type ClientLinks struct {
	Clients []ClientLink `json:"clients" yaml:"clients"`
}

// ClientLink maps client applications configuration URLs.
type ClientLink struct {
	Name     string `json:"name" yaml:"name"`
	Protocol string `json:"protocol" yaml:"protocol"`
	Hostname string `json:"hostname" yaml:"hostname"`
	Link     string `json:"link" yaml:"link"`
}

// InactiveZoneError signals zone configuration status is not active.
type InactiveZoneError struct {
	Zone Zone
}

func (e InactiveZoneError) Error() string {
	return "cloudflare zone is not active"
}

// SerializeJSON converts any object to its JSON string representation.
func SerializeJSON(v interface{}) (string, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(data), nil
}
