// Package proxy implements outbound protocols and obfuscation mechanisms.
// Ported from: Nova-Wizard-main
// Target path: server/internal/proxy/nova_wizard.go

package proxy

// NovaWizardWrapper wraps NovaWizard.
type NovaWizardWrapper struct {
	Wizard *NovaWizard
}

// 1. NewNovaWizardWrapper initializes the wrapper.
func NewNovaWizardWrapper(oauthToken string) *NovaWizardWrapper {
	return &NovaWizardWrapper{
		Wizard: NewNovaWizard(oauthToken),
	}
}

// 2. Deploy triggers wizard deployment.
func (w *NovaWizardWrapper) Deploy() error {
	return w.Wizard.DeployWorkersAndKV()
}

// 3. GetOAuthToken returns oauth token.
func (w *NovaWizardWrapper) GetOAuthToken() string {
	return w.Wizard.GetOAuthToken()
}

// 4. SetOAuthToken configures oauth token.
func (w *NovaWizardWrapper) SetOAuthToken(token string) {
	w.Wizard.SetOAuthToken(token)
}

// 5. GetAccountID returns CF account ID.
func (w *NovaWizardWrapper) GetAccountID() string {
	return w.Wizard.GetAccountID()
}

// 6. SetAccountID configures CF account ID.
func (w *NovaWizardWrapper) SetAccountID(id string) {
	w.Wizard.SetAccountID(id)
}

// 7. GetZoneID returns CF zone ID.
func (w *NovaWizardWrapper) GetZoneID() string {
	return w.Wizard.GetZoneID()
}

// 8. SetZoneID configures CF zone ID.
func (w *NovaWizardWrapper) SetZoneID(id string) {
	w.Wizard.SetZoneID(id)
}

// 9. GetActiveStep returns active onboarding step.
func (w *NovaWizardWrapper) GetActiveStep() int {
	return w.Wizard.GetActiveStep()
}

// 10. SetActiveStep configures active onboarding step.
func (w *NovaWizardWrapper) SetActiveStep(step int) {
	w.Wizard.SetActiveStep(step)
}

// 11. GetStepStatus retrieves step status.
func (w *NovaWizardWrapper) GetStepStatus(step string) string {
	return w.Wizard.GetStepStatus(step)
}

// 12. SetStepStatus registers step status.
func (w *NovaWizardWrapper) SetStepStatus(step string, status string) {
	w.Wizard.SetStepStatus(step, status)
}

// 13. ClearStepStatuses resets step statuses.
func (w *NovaWizardWrapper) ClearStepStatuses() {
	w.Wizard.ClearStepStatuses()
}

// 14. GetStepStatusesCount returns registered steps size.
func (w *NovaWizardWrapper) GetStepStatusesCount() int {
	return w.Wizard.GetStepStatusesCount()
}

// 15. AddLogMessage appends message to onboarding logs.
func (w *NovaWizardWrapper) AddLogMessage(msg string) {
	w.Wizard.AddLogMessage(msg)
}

// 16. GetLogMessages returns slice of log messages.
func (w *NovaWizardWrapper) GetLogMessages() []string {
	return w.Wizard.GetLogMessages()
}

// 17. ClearLogMessages resets log buffer.
func (w *NovaWizardWrapper) ClearLogMessages() {
	w.Wizard.ClearLogMessages()
}

// 18. GetLogMessagesCount returns total logs.
func (w *NovaWizardWrapper) GetLogMessagesCount() int {
	return w.Wizard.GetLogMessagesCount()
}

// 19. GetVersion returns version schema.
func (w *NovaWizardWrapper) GetVersion() int {
	return w.Wizard.GetVersion()
}

// 20. SetVersion overrides version schema.
func (w *NovaWizardWrapper) SetVersion(v int) {
	w.Wizard.SetVersion(v)
}

// 21. ResetWizardPreset restores defaults values.
func (w *NovaWizardWrapper) ResetWizardPreset() {
	w.Wizard.ResetWizardPreset()
}

// 22. VerifyWizardPreset checks integration parameters status.
func (w *NovaWizardWrapper) VerifyWizardPreset() bool {
	return w.Wizard.VerifyWizardPreset()
}

// 23. RunStep executes specific step deployment operations.
func (w *NovaWizardWrapper) RunStep(step int) error {
	return w.Wizard.RunStep(step)
}

// 24. GetTotalSteps returns maximum steps count.
func (w *NovaWizardWrapper) GetTotalSteps() int {
	return w.Wizard.GetTotalSteps()
}

// 25. IsStepCompleted checks step execution state.
func (w *NovaWizardWrapper) IsStepCompleted(step string) bool {
	return w.Wizard.IsStepCompleted(step)
}

// 26. ValidateOAuthToken asserts OAuth format.
func (w *NovaWizardWrapper) ValidateOAuthToken(token string) bool {
	return w.Wizard.ValidateOAuthToken(token)
}

// 27. DeployConfigurationProfile simulates configuration profile writes.
func (w *NovaWizardWrapper) DeployConfigurationProfile(profileName string) error {
	return w.Wizard.DeployConfigurationProfile(profileName)
}

// 28. DecommissionWorkers deletes provisioned workers scripts.
func (w *NovaWizardWrapper) DecommissionWorkers() error {
	return w.Wizard.DecommissionWorkers()
}

// 29. DecommissionKVNamespaces deletes provisioned KV namespaces.
func (w *NovaWizardWrapper) DecommissionKVNamespaces() error {
	return w.Wizard.DecommissionKVNamespaces()
}

// 30. ExportWizardState exports settings configuration payload to JSON.
func (w *NovaWizardWrapper) ExportWizardState() (string, error) {
	return w.Wizard.ExportWizardState()
}

// 31. ImportWizardState imports configurations from JSON payload.
func (w *NovaWizardWrapper) ImportWizardState(jsonStr string) error {
	return w.Wizard.ImportWizardState(jsonStr)
}

// 32. ConfigureDNSOverride overrides DNS resolver settings.
func (w *NovaWizardWrapper) ConfigureDNSOverride(dns string) {
	w.Wizard.ConfigureDNSOverride(dns)
}

// 33. GetDNSOverride returns configured DNS override values.
func (w *NovaWizardWrapper) GetDNSOverride() string {
	return w.Wizard.GetDNSOverride()
}

// 34. SetRoutingMode overrides active routing strategy.
func (w *NovaWizardWrapper) SetRoutingMode(mode string) {
	w.Wizard.SetRoutingMode(mode)
}

// 35. GetRoutingMode returns active routing strategy.
func (w *NovaWizardWrapper) GetRoutingMode() string {
	return w.Wizard.GetRoutingMode()
}

// 36. AddBypassDomain appends domain to direct list.
func (w *NovaWizardWrapper) AddBypassDomain(domain string) {
	w.Wizard.AddBypassDomain(domain)
}

// 37. RemoveBypassDomain deletes domain from direct list.
func (w *NovaWizardWrapper) RemoveBypassDomain(domain string) {
	w.Wizard.RemoveBypassDomain(domain)
}

// 38. GetBypassDomains returns direct domain slice.
func (w *NovaWizardWrapper) GetBypassDomains() []string {
	return w.Wizard.GetBypassDomains()
}

// 39. ClearBypassDomains resets bypass domain whitelist.
func (w *NovaWizardWrapper) ClearBypassDomains() {
	w.Wizard.ClearBypassDomains()
}

// 40. IsDomainBypassed checks domain presence in direct list.
func (w *NovaWizardWrapper) IsDomainBypassed(domain string) bool {
	return w.Wizard.IsDomainBypassed(domain)
}

// 41. AddProxyRoute registers custom interface route redirects.
func (w *NovaWizardWrapper) AddProxyRoute(src, dst string) {
	w.Wizard.AddProxyRoute(src, dst)
}

// 42. RemoveProxyRoute deletes custom interface route redirects.
func (w *NovaWizardWrapper) RemoveProxyRoute(src string) {
	w.Wizard.RemoveProxyRoute(src)
}

// 43. GetProxyRoutes retrieves active redirect routes.
func (w *NovaWizardWrapper) GetProxyRoutes() map[string]string {
	return w.Wizard.GetProxyRoutes()
}

// 44. ClearProxyRoutes resets proxy redirection mappings.
func (w *NovaWizardWrapper) ClearProxyRoutes() {
	w.Wizard.ClearProxyRoutes()
}

// 45. GetProxyRoutesCount returns total mapping redirects.
func (w *NovaWizardWrapper) GetProxyRoutesCount() int {
	return w.Wizard.GetProxyRoutesCount()
}

// 46. SetTelemetryStatus overrides telemetry status.
func (w *NovaWizardWrapper) SetTelemetryStatus(enabled bool) {
	w.Wizard.SetTelemetryStatus(enabled)
}

// 47. GetTelemetryStatus returns telemetry status.
func (w *NovaWizardWrapper) GetTelemetryStatus() bool {
	return w.Wizard.GetTelemetryStatus()
}

// 48. TriggerDiagnosticReport outputs string diagnostics telemetry logs.
func (w *NovaWizardWrapper) TriggerDiagnosticReport() string {
	return w.Wizard.TriggerDiagnosticReport()
}

// 49. FetchCloudflareZones fetches zones.
func (w *NovaWizardWrapper) FetchCloudflareZones() ([]string, error) {
	return w.Wizard.FetchCloudflareZones()
}

// 50. FetchCloudflareAccounts fetches accounts.
func (w *NovaWizardWrapper) FetchCloudflareAccounts() ([]string, error) {
	return w.Wizard.FetchCloudflareAccounts()
}

// 51. ValidateCloudflareCredentials validates credentials API tokens.
func (w *NovaWizardWrapper) ValidateCloudflareCredentials() (bool, error) {
	return w.Wizard.ValidateCloudflareCredentials()
}

// 52. BindCustomDomainToScript maps domain paths.
func (w *NovaWizardWrapper) BindCustomDomainToScript(scriptName, domain string) error {
	return w.Wizard.BindCustomDomainToScript(scriptName, domain)
}

// 53. GetWizardMetadata returns active properties map.
func (w *NovaWizardWrapper) GetWizardMetadata() map[string]interface{} {
	return w.Wizard.GetWizardMetadata()
}

// 54. IncrementActiveStep increments onboarding step.
func (w *NovaWizardWrapper) IncrementActiveStep() {
	w.Wizard.IncrementActiveStep()
}

// 55. DecrementActiveStep decrements onboarding step.
func (w *NovaWizardWrapper) DecrementActiveStep() {
	w.Wizard.DecrementActiveStep()
}
