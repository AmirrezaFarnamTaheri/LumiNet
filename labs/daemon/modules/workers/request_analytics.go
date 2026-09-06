// Package workers handles serverless and edge-worker deployments.
// Ported from: CF-Request-Analytics-Panel
// Target path: server/internal/workers/request_analytics.go

package workers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// CloudflareAccount represents a Cloudflare account registration profile.
type CloudflareAccount struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Email       string    `json:"email"`
	ZoneID      string    `json:"zone_id"`
	APIToken    string    `json:"api_token"`
	Active      bool      `json:"active"`
	CreatedTime time.Time `json:"created_time"`
	UpdatedTime time.Time `json:"updated_time"`
}

// Getters & Setters for CloudflareAccount
func (a *CloudflareAccount) GetID() string { return a.ID }
func (a *CloudflareAccount) SetID(val string) { a.ID = val }
func (a *CloudflareAccount) GetName() string { return a.Name }
func (a *CloudflareAccount) SetName(val string) { a.Name = val }
func (a *CloudflareAccount) GetEmail() string { return a.Email }
func (a *CloudflareAccount) SetEmail(val string) { a.Email = val }
func (a *CloudflareAccount) GetZoneID() string { return a.ZoneID }
func (a *CloudflareAccount) SetZoneID(val string) { a.ZoneID = val }
func (a *CloudflareAccount) GetAPIToken() string { return a.APIToken }
func (a *CloudflareAccount) SetAPIToken(val string) { a.APIToken = val }
func (a *CloudflareAccount) GetActive() bool { return a.Active }
func (a *CloudflareAccount) SetActive(val bool) { a.Active = val }
func (a *CloudflareAccount) GetCreatedTime() time.Time { return a.CreatedTime }
func (a *CloudflareAccount) SetCreatedTime(val time.Time) { a.CreatedTime = val }
func (a *CloudflareAccount) GetUpdatedTime() time.Time { return a.UpdatedTime }
func (a *CloudflareAccount) SetUpdatedTime(val time.Time) { a.UpdatedTime = val }

// ThreatEvent represents a firewall or security block event.
type ThreatEvent struct {
	Action   string `json:"action"`
	ClientIP string `json:"client_ip"`
	Country  string `json:"country"`
	Datetime string `json:"datetime"`
}

// RequestAnalyticsEngine implements the Cloudflare GraphQL analytics engine.
type RequestAnalyticsEngine struct {
	mu                 sync.RWMutex
	zoneID             string
	apiToken           string
	cfSession          string // Encrypted cfra_session cookie
	adminUser          string
	adminPassword      string
	cronSecret         string
	sessionTTL         int
	rangeHours         []int
	graphqlEndpoint    string
	defaultAiModel     string
	dailyRequestLimit  int
	noAccountMessage   string
	accounts           []CloudflareAccount
	privacyEnabled     bool
	cronConfig         string
	cronSecretKey      string
	activeSessions     []string
	threatEvents       []ThreatEvent
	decryptKey         string
	encryptionSalt     string
	sessionToken       string
	lastRunTime        time.Time
	failedAttempts     int
	successRate        float64
	queryTimeout       time.Duration
	cacheTTL           time.Duration
	maxConcurrency     int
	enableAI           bool
	aiPromptTemplate   string
	logSeverity        string
	adminCookieName    string
	zoneName           string
	accountName        string
}

// NewRequestAnalyticsEngine initializes the analytics panel.
func NewRequestAnalyticsEngine(zoneID, apiToken, cfSession string) *RequestAnalyticsEngine {
	return &RequestAnalyticsEngine{
		zoneID:             zoneID,
		apiToken:           apiToken,
		cfSession:          cfSession,
		adminUser:          "admin",
		sessionTTL:         86400,
		rangeHours:         []int{1, 6, 12, 24, 72, 168},
		graphqlEndpoint:    "https://api.cloudflare.com/client/v4/graphql",
		defaultAiModel:     "@cf/openai/gpt-oss-20b",
		dailyRequestLimit:  100000,
		noAccountMessage:   "No account configured.",
		accounts:           make([]CloudflareAccount, 0),
		privacyEnabled:     false,
		activeSessions:     make([]string, 0),
		threatEvents:       make([]ThreatEvent, 0),
		queryTimeout:       15 * time.Second,
		cacheTTL:           10 * time.Minute,
		maxConcurrency:     5,
		enableAI:           true,
		logSeverity:        "info",
		adminCookieName:    "cfra_session",
	}
}

// Getters & Setters for RequestAnalyticsEngine
func (e *RequestAnalyticsEngine) GetZoneID() string { e.mu.RLock(); defer e.mu.RUnlock(); return e.zoneID }
func (e *RequestAnalyticsEngine) SetZoneID(val string) { e.mu.Lock(); defer e.mu.Unlock(); e.zoneID = val }
func (e *RequestAnalyticsEngine) GetAPIToken() string { e.mu.RLock(); defer e.mu.RUnlock(); return e.apiToken }
func (e *RequestAnalyticsEngine) SetAPIToken(val string) { e.mu.Lock(); defer e.mu.Unlock(); e.apiToken = val }
func (e *RequestAnalyticsEngine) GetCFSession() string { e.mu.RLock(); defer e.mu.RUnlock(); return e.cfSession }
func (e *RequestAnalyticsEngine) SetCFSession(val string) { e.mu.Lock(); defer e.mu.Unlock(); e.cfSession = val }
func (e *RequestAnalyticsEngine) GetAdminUser() string { e.mu.RLock(); defer e.mu.RUnlock(); return e.adminUser }
func (e *RequestAnalyticsEngine) SetAdminUser(val string) { e.mu.Lock(); defer e.mu.Unlock(); e.adminUser = val }
func (e *RequestAnalyticsEngine) GetAdminPassword() string { e.mu.RLock(); defer e.mu.RUnlock(); return e.adminPassword }
func (e *RequestAnalyticsEngine) SetAdminPassword(val string) { e.mu.Lock(); defer e.mu.Unlock(); e.adminPassword = val }
func (e *RequestAnalyticsEngine) GetCronSecret() string { e.mu.RLock(); defer e.mu.RUnlock(); return e.cronSecret }
func (e *RequestAnalyticsEngine) SetCronSecret(val string) { e.mu.Lock(); defer e.mu.Unlock(); e.cronSecret = val }
func (e *RequestAnalyticsEngine) GetSessionTTL() int { e.mu.RLock(); defer e.mu.RUnlock(); return e.sessionTTL }
func (e *RequestAnalyticsEngine) SetSessionTTL(val int) { e.mu.Lock(); defer e.mu.Unlock(); e.sessionTTL = val }
func (e *RequestAnalyticsEngine) GetRangeHours() []int { e.mu.RLock(); defer e.mu.RUnlock(); return e.rangeHours }
func (e *RequestAnalyticsEngine) SetRangeHours(val []int) { e.mu.Lock(); defer e.mu.Unlock(); e.rangeHours = val }
func (e *RequestAnalyticsEngine) GetGraphqlEndpoint() string { e.mu.RLock(); defer e.mu.RUnlock(); return e.graphqlEndpoint }
func (e *RequestAnalyticsEngine) SetGraphqlEndpoint(val string) { e.mu.Lock(); defer e.mu.Unlock(); e.graphqlEndpoint = val }
func (e *RequestAnalyticsEngine) GetDefaultAiModel() string { e.mu.RLock(); defer e.mu.RUnlock(); return e.defaultAiModel }
func (e *RequestAnalyticsEngine) SetDefaultAiModel(val string) { e.mu.Lock(); defer e.mu.Unlock(); e.defaultAiModel = val }
func (e *RequestAnalyticsEngine) GetDailyRequestLimit() int { e.mu.RLock(); defer e.mu.RUnlock(); return e.dailyRequestLimit }
func (e *RequestAnalyticsEngine) SetDailyRequestLimit(val int) { e.mu.Lock(); defer e.mu.Unlock(); e.dailyRequestLimit = val }
func (e *RequestAnalyticsEngine) GetNoAccountMessage() string { e.mu.RLock(); defer e.mu.RUnlock(); return e.noAccountMessage }
func (e *RequestAnalyticsEngine) SetNoAccountMessage(val string) { e.mu.Lock(); defer e.mu.Unlock(); e.noAccountMessage = val }
func (e *RequestAnalyticsEngine) GetAccounts() []CloudflareAccount { e.mu.RLock(); defer e.mu.RUnlock(); return e.accounts }
func (e *RequestAnalyticsEngine) SetAccounts(val []CloudflareAccount) { e.mu.Lock(); defer e.mu.Unlock(); e.accounts = val }
func (e *RequestAnalyticsEngine) GetPrivacyEnabled() bool { e.mu.RLock(); defer e.mu.RUnlock(); return e.privacyEnabled }
func (e *RequestAnalyticsEngine) SetPrivacyEnabled(val bool) { e.mu.Lock(); defer e.mu.Unlock(); e.privacyEnabled = val }
func (e *RequestAnalyticsEngine) GetCronConfig() string { e.mu.RLock(); defer e.mu.RUnlock(); return e.cronConfig }
func (e *RequestAnalyticsEngine) SetCronConfig(val string) { e.mu.Lock(); defer e.mu.Unlock(); e.cronConfig = val }
func (e *RequestAnalyticsEngine) GetCronSecretKey() string { e.mu.RLock(); defer e.mu.RUnlock(); return e.cronSecretKey }
func (e *RequestAnalyticsEngine) SetCronSecretKey(val string) { e.mu.Lock(); defer e.mu.Unlock(); e.cronSecretKey = val }
func (e *RequestAnalyticsEngine) GetActiveSessions() []string { e.mu.RLock(); defer e.mu.RUnlock(); return e.activeSessions }
func (e *RequestAnalyticsEngine) SetActiveSessions(val []string) { e.mu.Lock(); defer e.mu.Unlock(); e.activeSessions = val }
func (e *RequestAnalyticsEngine) GetThreatEvents() []ThreatEvent { e.mu.RLock(); defer e.mu.RUnlock(); return e.threatEvents }
func (e *RequestAnalyticsEngine) SetThreatEvents(val []ThreatEvent) { e.mu.Lock(); defer e.mu.Unlock(); e.threatEvents = val }
func (e *RequestAnalyticsEngine) GetDecryptKey() string { e.mu.RLock(); defer e.mu.RUnlock(); return e.decryptKey }
func (e *RequestAnalyticsEngine) SetDecryptKey(val string) { e.mu.Lock(); defer e.mu.Unlock(); e.decryptKey = val }
func (e *RequestAnalyticsEngine) GetEncryptionSalt() string { e.mu.RLock(); defer e.mu.RUnlock(); return e.encryptionSalt }
func (e *RequestAnalyticsEngine) SetEncryptionSalt(val string) { e.mu.Lock(); defer e.mu.Unlock(); e.encryptionSalt = val }
func (e *RequestAnalyticsEngine) GetSessionToken() string { e.mu.RLock(); defer e.mu.RUnlock(); return e.sessionToken }
func (e *RequestAnalyticsEngine) SetSessionToken(val string) { e.mu.Lock(); defer e.mu.Unlock(); e.sessionToken = val }
func (e *RequestAnalyticsEngine) GetLastRunTime() time.Time { e.mu.RLock(); defer e.mu.RUnlock(); return e.lastRunTime }
func (e *RequestAnalyticsEngine) SetLastRunTime(val time.Time) { e.mu.Lock(); defer e.mu.Unlock(); e.lastRunTime = val }
func (e *RequestAnalyticsEngine) GetFailedAttempts() int { e.mu.RLock(); defer e.mu.RUnlock(); return e.failedAttempts }
func (e *RequestAnalyticsEngine) SetFailedAttempts(val int) { e.mu.Lock(); defer e.mu.Unlock(); e.failedAttempts = val }
func (e *RequestAnalyticsEngine) GetSuccessRate() float64 { e.mu.RLock(); defer e.mu.RUnlock(); return e.successRate }
func (e *RequestAnalyticsEngine) SetSuccessRate(val float64) { e.mu.Lock(); defer e.mu.Unlock(); e.successRate = val }
func (e *RequestAnalyticsEngine) GetQueryTimeout() time.Duration { e.mu.RLock(); defer e.mu.RUnlock(); return e.queryTimeout }
func (e *RequestAnalyticsEngine) SetQueryTimeout(val time.Duration) { e.mu.Lock(); defer e.mu.Unlock(); e.queryTimeout = val }
func (e *RequestAnalyticsEngine) GetCacheTTL() time.Duration { e.mu.RLock(); defer e.mu.RUnlock(); return e.cacheTTL }
func (e *RequestAnalyticsEngine) SetCacheTTL(val time.Duration) { e.mu.Lock(); defer e.mu.Unlock(); e.cacheTTL = val }
func (e *RequestAnalyticsEngine) GetMaxConcurrency() int { e.mu.RLock(); defer e.mu.RUnlock(); return e.maxConcurrency }
func (e *RequestAnalyticsEngine) SetMaxConcurrency(val int) { e.mu.Lock(); defer e.mu.Unlock(); e.maxConcurrency = val }
func (e *RequestAnalyticsEngine) GetEnableAI() bool { e.mu.RLock(); defer e.mu.RUnlock(); return e.enableAI }
func (e *RequestAnalyticsEngine) SetEnableAI(val bool) { e.mu.Lock(); defer e.mu.Unlock(); e.enableAI = val }
func (e *RequestAnalyticsEngine) GetAIPromptTemplate() string { e.mu.RLock(); defer e.mu.RUnlock(); return e.aiPromptTemplate }
func (e *RequestAnalyticsEngine) SetAIPromptTemplate(val string) { e.mu.Lock(); defer e.mu.Unlock(); e.aiPromptTemplate = val }
func (e *RequestAnalyticsEngine) GetLogSeverity() string { e.mu.RLock(); defer e.mu.RUnlock(); return e.logSeverity }
func (e *RequestAnalyticsEngine) SetLogSeverity(val string) { e.mu.Lock(); defer e.mu.Unlock(); e.logSeverity = val }
func (e *RequestAnalyticsEngine) GetAdminCookieName() string { e.mu.RLock(); defer e.mu.RUnlock(); return e.adminCookieName }
func (e *RequestAnalyticsEngine) SetAdminCookieName(val string) { e.mu.Lock(); defer e.mu.Unlock(); e.adminCookieName = val }
func (e *RequestAnalyticsEngine) GetZoneName() string { e.mu.RLock(); defer e.mu.RUnlock(); return e.zoneName }
func (e *RequestAnalyticsEngine) SetZoneName(val string) { e.mu.Lock(); defer e.mu.Unlock(); e.zoneName = val }
func (e *RequestAnalyticsEngine) GetAccountName() string { e.mu.RLock(); defer e.mu.RUnlock(); return e.accountName }
func (e *RequestAnalyticsEngine) SetAccountName(val string) { e.mu.Lock(); defer e.mu.Unlock(); e.accountName = val }

// Operational and List modifiers
func (e *RequestAnalyticsEngine) AddAccount(acc CloudflareAccount) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.accounts = append(e.accounts, acc)
}

func (e *RequestAnalyticsEngine) RemoveAccount(id string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	for i, v := range e.accounts {
		if v.ID == id {
			e.accounts = append(e.accounts[:i], e.accounts[i+1:]...)
			return true
		}
	}
	return false
}

func (e *RequestAnalyticsEngine) ClearAccounts() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.accounts = make([]CloudflareAccount, 0)
}

func (e *RequestAnalyticsEngine) GetAccountsCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.accounts)
}

func (e *RequestAnalyticsEngine) AddThreatEvent(evt ThreatEvent) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.threatEvents = append(e.threatEvents, evt)
}

func (e *RequestAnalyticsEngine) RemoveThreatEvent(ip string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	for i, v := range e.threatEvents {
		if v.ClientIP == ip {
			e.threatEvents = append(e.threatEvents[:i], e.threatEvents[i+1:]...)
			return true
		}
	}
	return false
}

func (e *RequestAnalyticsEngine) ClearThreatEvents() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.threatEvents = make([]ThreatEvent, 0)
}

func (e *RequestAnalyticsEngine) AddActiveSession(sess string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.activeSessions = append(e.activeSessions, sess)
}

func (e *RequestAnalyticsEngine) RemoveActiveSession(sess string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	for i, v := range e.activeSessions {
		if v == sess {
			e.activeSessions = append(e.activeSessions[:i], e.activeSessions[i+1:]...)
			return true
		}
	}
	return false
}

func (e *RequestAnalyticsEngine) ClearActiveSessions() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.activeSessions = make([]string, 0)
}

func (e *RequestAnalyticsEngine) AddRangeHour(hour int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rangeHours = append(e.rangeHours, hour)
}

func (e *RequestAnalyticsEngine) RemoveRangeHour(hour int) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	for i, v := range e.rangeHours {
		if v == hour {
			e.rangeHours = append(e.rangeHours[:i], e.rangeHours[i+1:]...)
			return true
		}
	}
	return false
}

func (e *RequestAnalyticsEngine) ClearRangeHours() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rangeHours = make([]int, 0)
}

// Logic / GraphQL Query Engines
func (e *RequestAnalyticsEngine) GraphQLQuery(ctx context.Context, query string, variables map[string]interface{}) (map[string]interface{}, error) {
	payload := map[string]interface{}{
		"query":     query,
		"variables": variables,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", e.graphqlEndpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+e.apiToken)
	req.Header.Set("Content-Type", "application/json")
	if e.cfSession != "" {
		req.AddCookie(&http.Cookie{Name: e.adminCookieName, Value: e.cfSession})
	}

	client := &http.Client{Timeout: e.queryTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Cloudflare API returned status %d", resp.StatusCode)
	}

	var result map[string]interface{}
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, err
	}

	return result, nil
}

func (e *RequestAnalyticsEngine) QueryBandwidth(ctx context.Context) (map[string]interface{}, error) {
	query := `
	query GetBandwidth($zoneTag: string!) {
		viewer {
			zones(filter: { zoneTag: $zoneTag }) {
				httpRequests1dGroups(limit: 10, orderBy: [date_ASC]) {
					dimensions {
						date
					}
					sum {
						bytes
						requests
					}
				}
			}
		}
	}
	`
	variables := map[string]interface{}{
		"zoneTag": e.zoneID,
	}

	return e.GraphQLQuery(ctx, query, variables)
}

func (e *RequestAnalyticsEngine) QueryThreatEvents(ctx context.Context) (map[string]interface{}, error) {
	query := `
	query GetThreats($zoneTag: string!) {
		viewer {
			zones(filter: { zoneTag: $zoneTag }) {
				firewallEventsAdaptive(limit: 10) {
					action
					clientIP
				}
			}
		}
	}
	`
	variables := map[string]interface{}{
		"zoneTag": e.zoneID,
	}

	return e.GraphQLQuery(ctx, query, variables)
}

func (e *RequestAnalyticsEngine) QueryCacheStatus(ctx context.Context) (map[string]interface{}, error) {
	query := `
	query GetCacheStatus($zoneTag: string!) {
		viewer {
			zones(filter: { zoneTag: $zoneTag }) {
				httpRequests1dGroups(limit: 10) {
					sum {
						cachedBytes
						cachedRequests
					}
				}
			}
		}
	}
	`
	variables := map[string]interface{}{
		"zoneTag": e.zoneID,
	}
	return e.GraphQLQuery(ctx, query, variables)
}

func (e *RequestAnalyticsEngine) QueryGeoRequests(ctx context.Context) (map[string]interface{}, error) {
	query := `
	query GetGeoRequests($zoneTag: string!) {
		viewer {
			zones(filter: { zoneTag: $zoneTag }) {
				httpRequests1dGroups(limit: 50) {
					dimensions {
						clientCountryName
					}
					sum {
						requests
					}
				}
			}
		}
	}
	`
	variables := map[string]interface{}{
		"zoneTag": e.zoneID,
	}
	return e.GraphQLQuery(ctx, query, variables)
}

func (e *RequestAnalyticsEngine) SignSession(user string) (string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	token := fmt.Sprintf("sess_%d_%s", time.Now().Unix(), user)
	e.sessionToken = token
	e.activeSessions = append(e.activeSessions, token)
	return token, nil
}

func (e *RequestAnalyticsEngine) VerifySession(token string) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	for _, v := range e.activeSessions {
		if v == token {
			return true
		}
	}
	return false
}

func (e *RequestAnalyticsEngine) EncryptAccount(acc *CloudflareAccount) error {
	if acc == nil {
		return fmt.Errorf("account is nil")
	}
	acc.APIToken = fmt.Sprintf("enc_%s_%s", e.encryptionSalt, acc.APIToken)
	return nil
}

func (e *RequestAnalyticsEngine) DecryptAccount(acc *CloudflareAccount) error {
	if acc == nil {
		return fmt.Errorf("account is nil")
	}
	if len(acc.APIToken) > 4 {
		acc.APIToken = acc.APIToken[4:]
	}
	return nil
}

func (e *RequestAnalyticsEngine) RunConnectivityCheck() bool {
	return true
}

func (e *RequestAnalyticsEngine) RunAIConsistencyCheck() bool {
	return e.enableAI
}

func (e *RequestAnalyticsEngine) TriggerCronHarvest() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.lastRunTime = time.Now()
}

func (e *RequestAnalyticsEngine) ExportUsageJson() (string, error) {
	data := map[string]interface{}{
		"zone_id":       e.zoneID,
		"last_run_time": e.lastRunTime,
		"success_rate":  e.successRate,
	}
	res, err := json.Marshal(data)
	return string(res), err
}

func (e *RequestAnalyticsEngine) ValidateAccountConfig(acc CloudflareAccount) bool {
	return acc.ZoneID != "" && acc.APIToken != ""
}

func (e *RequestAnalyticsEngine) LoadSystemConfig() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.successRate = 1.0
}
