// Package provision manages infrastructure provisioning.

package provision

import "time"

// BillingZone represents mod_whitednszone_zones DB schema.
type BillingZone struct {
	ID          int       `json:"id" db:"id"`
	UserID      int       `json:"userid" db:"userid"`
	Domain      string    `json:"domain" db:"domain"`
	ZoneID      string    `json:"zone_id" db:"zone_id"`
	Status      string    `json:"status" db:"status"`
	Nameservers string    `json:"nameservers,omitempty" db:"nameservers"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`
}

// Getters & Setters for BillingZone
func (z *BillingZone) GetID() int { return z.ID }
func (z *BillingZone) SetID(v int) { z.ID = v }
func (z *BillingZone) GetUserID() int { return z.UserID }
func (z *BillingZone) SetUserID(v int) { z.UserID = v }
func (z *BillingZone) GetDomain() string { return z.Domain }
func (z *BillingZone) SetDomain(v string) { z.Domain = v }
func (z *BillingZone) GetZoneID() string { return z.ZoneID }
func (z *BillingZone) SetZoneID(v string) { z.ZoneID = v }
func (z *BillingZone) GetStatus() string { return z.Status }
func (z *BillingZone) SetStatus(v string) { z.Status = v }

// BillingRecord represents mod_whitednszone_records DB schema.
type BillingRecord struct {
	ID        int       `json:"id" db:"id"`
	ZoneID    int       `json:"zone_id" db:"zone_id"`
	RecordID  string    `json:"record_id" db:"record_id"`
	Name      string    `json:"name" db:"name"`
	Type      string    `json:"type" db:"type"`
	Content   string    `json:"content" db:"content"`
	TTL       int       `json:"ttl" db:"ttl"`
	Priority  *int      `json:"priority,omitempty" db:"priority"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

// Getters & Setters for BillingRecord
func (r *BillingRecord) GetID() int { return r.ID }
func (r *BillingRecord) SetID(v int) { r.ID = v }
func (r *BillingRecord) GetZoneID() int { return r.ZoneID }
func (r *BillingRecord) SetZoneID(v int) { r.ZoneID = v }
func (r *BillingRecord) GetRecordID() string { return r.RecordID }
func (r *BillingRecord) SetRecordID(v string) { r.RecordID = v }
func (r *BillingRecord) GetName() string { return r.Name }
func (r *BillingRecord) SetName(v string) { r.Name = v }

// BillingAuditLog represents mod_whitednszone_audit DB schema.
type BillingAuditLog struct {
	ID        int       `json:"id" db:"id"`
	UserID    int       `json:"userid" db:"userid"`
	ZoneID    *int      `json:"zone_id,omitempty" db:"zone_id"`
	Action    string    `json:"action" db:"action"`
	Details   string    `json:"details,omitempty" db:"details"`
	IPAddress string    `json:"ip_address,omitempty" db:"ip_address"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

// BillingTemplate represents mod_whitednszone_templates DB schema.
type BillingTemplate struct {
	ID          int       `json:"id" db:"id"`
	Name        string    `json:"name" db:"name"`
	Category    string    `json:"category" db:"category"`
	Description string    `json:"description,omitempty" db:"description"`
	Records     string    `json:"records" db:"records"` // JSON string representation of template records
	IsPreset    bool      `json:"is_preset" db:"is_preset"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`
}
