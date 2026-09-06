// Package ui implements admin panel models, wireguard obfuscation, and subscription services.
// Ported from: ui-templates-prx11-main
// Target path: server/internal/ui/uitemplates_configs.go

package ui

import "time"

// UITemplateTheme represents admin panel custom colors.
type UITemplateTheme struct {
	ThemeID      string
	ThemeName    string
	DarkStyle    bool
	PrimaryColor string
}

// Getters & Setters for UITemplateTheme
func (t *UITemplateTheme) GetThemeID() string { return t.ThemeID }
func (t *UITemplateTheme) SetThemeID(v string) { t.ThemeID = v }
func (t *UITemplateTheme) GetThemeName() string { return t.ThemeName }
func (t *UITemplateTheme) SetThemeName(v string) { t.ThemeName = v }
func (t *UITemplateTheme) GetDarkStyle() bool { return t.DarkStyle }
func (t *UITemplateTheme) SetDarkStyle(v bool) { t.DarkStyle = v }
func (t *UITemplateTheme) GetPrimaryColor() string { return t.PrimaryColor }
func (t *UITemplateTheme) SetPrimaryColor(v string) { t.PrimaryColor = v }

// UITemplateLayout holds visual dashboard parameters.
type UITemplateLayout struct {
	LayoutID       int
	ColumnsCount   int
	SidebarVisible bool
}

// Getters & Setters for UITemplateLayout
func (l *UITemplateLayout) GetLayoutID() int { return l.LayoutID }
func (l *UITemplateLayout) SetLayoutID(v int) { l.LayoutID = v }
func (l *UITemplateLayout) GetColumnsCount() int { return l.ColumnsCount }
func (l *UITemplateLayout) SetColumnsCount(v int) { l.ColumnsCount = v }
func (l *UITemplateLayout) GetSidebarVisible() bool { return l.SidebarVisible }
func (l *UITemplateLayout) SetSidebarVisible(v bool) { l.SidebarVisible = v }

// UITemplateSubscription mirrors sub.ejs EJS data object fields.
type UITemplateSubscription struct {
	SubID          string
	Email          string
	SubURLContent  string
	Enable         bool
	UploadBytes    int64
	DownloadBytes  int64
	TotalBytes     int64
	ExpiryTime     int64
	TelegramURL    string
	WhatsAppURL    string
	CreatedAt      time.Time
	LastAccessedAt time.Time
}

// Getters & Setters for UITemplateSubscription
func (s *UITemplateSubscription) GetSubID() string { return s.SubID }
func (s *UITemplateSubscription) SetSubID(v string) { s.SubID = v }
func (s *UITemplateSubscription) GetEmail() string { return s.Email }
func (s *UITemplateSubscription) SetEmail(v string) { s.Email = v }
func (s *UITemplateSubscription) GetSubURLContent() string { return s.SubURLContent }
func (s *UITemplateSubscription) SetSubURLContent(v string) { s.SubURLContent = v }
func (s *UITemplateSubscription) GetEnable() bool { return s.Enable }
func (s *UITemplateSubscription) SetEnable(v bool) { s.Enable = v }
func (s *UITemplateSubscription) GetUploadBytes() int64 { return s.UploadBytes }
func (s *UITemplateSubscription) SetUploadBytes(v int64) { s.UploadBytes = v }
func (s *UITemplateSubscription) GetDownloadBytes() int64 { return s.DownloadBytes }
func (s *UITemplateSubscription) SetDownloadBytes(v int64) { s.DownloadBytes = v }
func (s *UITemplateSubscription) GetTotalBytes() int64 { return s.TotalBytes }
func (s *UITemplateSubscription) SetTotalBytes(v int64) { s.TotalBytes = v }
func (s *UITemplateSubscription) GetExpiryTime() int64 { return s.ExpiryTime }
func (s *UITemplateSubscription) SetExpiryTime(v int64) { s.ExpiryTime = v }
func (s *UITemplateSubscription) GetTelegramURL() string { return s.TelegramURL }
func (s *UITemplateSubscription) SetTelegramURL(v string) { s.TelegramURL = v }
func (s *UITemplateSubscription) GetWhatsAppURL() string { return s.WhatsAppURL }
func (s *UITemplateSubscription) SetWhatsAppURL(v string) { s.WhatsAppURL = v }
func (s *UITemplateSubscription) GetCreatedAt() time.Time { return s.CreatedAt }
func (s *UITemplateSubscription) SetCreatedAt(v time.Time) { s.CreatedAt = v }
func (s *UITemplateSubscription) GetLastAccessedAt() time.Time { return s.LastAccessedAt }
func (s *UITemplateSubscription) SetLastAccessedAt(v time.Time) { s.LastAccessedAt = v }

// UITemplateI18nSet holds localization key-value pairs for one language.
type UITemplateI18nSet struct {
	Locale          string
	PageTitle       string
	ActiveLabel     string
	InactiveLabel   string
	UploadLabel     string
	DownloadLabel   string
	UsedVolumeLabel string
	RemainingLabel  string
	TotalLabel      string
	ExpiryLabel     string
	CopySuccessMsg  string
	CopyErrorMsg    string
	UnlimitedLabel  string
	NotUsedLabel    string
}

// Getters & Setters for UITemplateI18nSet
func (i *UITemplateI18nSet) GetLocale() string { return i.Locale }
func (i *UITemplateI18nSet) SetLocale(v string) { i.Locale = v }
func (i *UITemplateI18nSet) GetPageTitle() string { return i.PageTitle }
func (i *UITemplateI18nSet) SetPageTitle(v string) { i.PageTitle = v }
func (i *UITemplateI18nSet) GetActiveLabel() string { return i.ActiveLabel }
func (i *UITemplateI18nSet) SetActiveLabel(v string) { i.ActiveLabel = v }
func (i *UITemplateI18nSet) GetInactiveLabel() string { return i.InactiveLabel }
func (i *UITemplateI18nSet) SetInactiveLabel(v string) { i.InactiveLabel = v }
func (i *UITemplateI18nSet) GetUploadLabel() string { return i.UploadLabel }
func (i *UITemplateI18nSet) SetUploadLabel(v string) { i.UploadLabel = v }
func (i *UITemplateI18nSet) GetDownloadLabel() string { return i.DownloadLabel }
func (i *UITemplateI18nSet) SetDownloadLabel(v string) { i.DownloadLabel = v }
func (i *UITemplateI18nSet) GetUsedVolumeLabel() string { return i.UsedVolumeLabel }
func (i *UITemplateI18nSet) SetUsedVolumeLabel(v string) { i.UsedVolumeLabel = v }
func (i *UITemplateI18nSet) GetRemainingLabel() string { return i.RemainingLabel }
func (i *UITemplateI18nSet) SetRemainingLabel(v string) { i.RemainingLabel = v }
func (i *UITemplateI18nSet) GetTotalLabel() string { return i.TotalLabel }
func (i *UITemplateI18nSet) SetTotalLabel(v string) { i.TotalLabel = v }
func (i *UITemplateI18nSet) GetExpiryLabel() string { return i.ExpiryLabel }
func (i *UITemplateI18nSet) SetExpiryLabel(v string) { i.ExpiryLabel = v }
func (i *UITemplateI18nSet) GetCopySuccessMsg() string { return i.CopySuccessMsg }
func (i *UITemplateI18nSet) SetCopySuccessMsg(v string) { i.CopySuccessMsg = v }
func (i *UITemplateI18nSet) GetCopyErrorMsg() string { return i.CopyErrorMsg }
func (i *UITemplateI18nSet) SetCopyErrorMsg(v string) { i.CopyErrorMsg = v }
func (i *UITemplateI18nSet) GetUnlimitedLabel() string { return i.UnlimitedLabel }
func (i *UITemplateI18nSet) SetUnlimitedLabel(v string) { i.UnlimitedLabel = v }
func (i *UITemplateI18nSet) GetNotUsedLabel() string { return i.NotUsedLabel }
func (i *UITemplateI18nSet) SetNotUsedLabel(v string) { i.NotUsedLabel = v }

// UITemplateQRConfig holds QR code generation parameters.
type UITemplateQRConfig struct {
	LinkURL      string
	Width        int
	Height       int
	ErrorLevel   string
	GeneratedAt  time.Time
}

// Getters & Setters for UITemplateQRConfig
func (q *UITemplateQRConfig) GetLinkURL() string { return q.LinkURL }
func (q *UITemplateQRConfig) SetLinkURL(v string) { q.LinkURL = v }
func (q *UITemplateQRConfig) GetWidth() int { return q.Width }
func (q *UITemplateQRConfig) SetWidth(v int) { q.Width = v }
func (q *UITemplateQRConfig) GetHeight() int { return q.Height }
func (q *UITemplateQRConfig) SetHeight(v int) { q.Height = v }
func (q *UITemplateQRConfig) GetErrorLevel() string { return q.ErrorLevel }
func (q *UITemplateQRConfig) SetErrorLevel(v string) { q.ErrorLevel = v }
func (q *UITemplateQRConfig) GetGeneratedAt() time.Time { return q.GeneratedAt }
func (q *UITemplateQRConfig) SetGeneratedAt(v time.Time) { q.GeneratedAt = v }
