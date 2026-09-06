package diagnostics

import (
	"fmt"
	"strings"
	"time"
)

type ServiceIncidentPolicyRequest struct {
	PreviousStatus                    string    `json:"previous_status"`
	CurrentStatus                     string    `json:"current_status"`
	PreviousReason                    string    `json:"previous_reason,omitempty"`
	CurrentReason                     string    `json:"current_reason,omitempty"`
	IncidentOpen                      bool      `json:"incident_open,omitempty"`
	FailureStartedAt                  time.Time `json:"failure_started_at,omitempty"`
	AsOf                              time.Time `json:"as_of,omitempty"`
	Maintenance                       bool      `json:"maintenance,omitempty"`
	NotificationGraceSeconds          int       `json:"notification_grace_seconds,omitempty"`
	SuppressReasonChangeNotifications bool      `json:"suppress_reason_change_notifications,omitempty"`
	LastIncidentCallbackAt            time.Time `json:"last_incident_callback_at,omitempty"`
	IncidentCallbackEverySeconds      int       `json:"incident_callback_every_seconds,omitempty"`
	LastPersistedAt                   time.Time `json:"last_persisted_at,omitempty"`
	WriteCooldownSeconds              int       `json:"write_cooldown_seconds,omitempty"`
	IncidentRetentionDays             int       `json:"incident_retention_days,omitempty"`
	LatencyRetentionHours             int       `json:"latency_retention_hours,omitempty"`
}

type ServiceIncidentPolicyPlan struct {
	Transition            string   `json:"transition"`
	Notify                bool     `json:"notify"`
	IncidentCallbackDue   bool     `json:"incident_callback_due"`
	Persist               bool     `json:"persist"`
	FailureAgeSeconds     int64    `json:"failure_age_seconds,omitempty"`
	IncidentRetentionDays int      `json:"incident_retention_days"`
	LatencyRetentionHours int      `json:"latency_retention_hours"`
	SuppressionReasons    []string `json:"suppression_reasons"`
	Invariants            []string `json:"invariants"`
	ReadOnly              bool     `json:"read_only"`
}

func normalizeMonitorStatus(raw string) (string, error) {
	v := strings.ToLower(strings.TrimSpace(raw))
	if v == "" {
		v = "unknown"
	}
	if v != "unknown" && v != "up" && v != "down" {
		return "", fmt.Errorf("unsupported monitor status %q", raw)
	}
	return v, nil
}

func BuildServiceIncidentPolicyPlan(req ServiceIncidentPolicyRequest) (ServiceIncidentPolicyPlan, error) {
	previous, err := normalizeMonitorStatus(req.PreviousStatus)
	if err != nil {
		return ServiceIncidentPolicyPlan{}, err
	}
	current, err := normalizeMonitorStatus(req.CurrentStatus)
	if err != nil {
		return ServiceIncidentPolicyPlan{}, err
	}
	now := req.AsOf
	if now.IsZero() {
		now = time.Now()
	}
	grace := req.NotificationGraceSeconds
	if grace == 0 {
		grace = 60
	}
	callbackEvery := req.IncidentCallbackEverySeconds
	if callbackEvery == 0 {
		callbackEvery = 60
	}
	cooldown := req.WriteCooldownSeconds
	if cooldown == 0 {
		cooldown = 180
	}
	incidentRetention := req.IncidentRetentionDays
	if incidentRetention == 0 {
		incidentRetention = 90
	}
	latencyRetention := req.LatencyRetentionHours
	if latencyRetention == 0 {
		latencyRetention = 12
	}
	if grace < 0 || grace > 86400 || callbackEvery < 15 || callbackEvery > 86400 || cooldown < 0 || cooldown > 86400 {
		return ServiceIncidentPolicyPlan{}, fmt.Errorf("incident timing policy is outside supported bounds")
	}
	if incidentRetention < 1 || incidentRetention > 3650 || latencyRetention < 1 || latencyRetention > 24*365 {
		return ServiceIncidentPolicyPlan{}, fmt.Errorf("incident retention policy is outside supported bounds")
	}
	failureAge := int64(0)
	if !req.FailureStartedAt.IsZero() && current == "down" {
		if req.FailureStartedAt.After(now) {
			return ServiceIncidentPolicyPlan{}, fmt.Errorf("failure_started_at cannot be in the future")
		}
		failureAge = int64(now.Sub(req.FailureStartedAt).Seconds())
	}
	graceCrossed := current == "down" && failureAge >= int64(grace)

	transition := "none"
	switch {
	case current == "down" && previous != "down":
		transition = "open"
	case current == "up" && previous == "down":
		transition = "recover"
	case current == "down" && previous == "down" && strings.TrimSpace(req.CurrentReason) != strings.TrimSpace(req.PreviousReason):
		transition = "reason-change"
	case current == "down":
		transition = "sustain"
	}

	notify := false
	suppression := []string{}
	switch transition {
	case "open", "sustain":
		notify = graceCrossed
	case "reason-change":
		notify = graceCrossed && !req.SuppressReasonChangeNotifications
		if req.SuppressReasonChangeNotifications {
			suppression = append(suppression, "reason-change notifications suppressed by policy")
		}
	case "recover":
		// Recovery is notification-worthy only for an incident that crossed the
		// grace period; short flaps should not produce orphan recovery notices.
		if req.IncidentOpen && !req.FailureStartedAt.IsZero() && !req.FailureStartedAt.After(now) {
			notify = int64(now.Sub(req.FailureStartedAt).Seconds()) >= int64(grace)
		}
	}
	if current == "down" && !graceCrossed {
		suppression = append(suppression, "notification grace period not yet crossed")
	}
	if req.Maintenance && notify {
		notify = false
		suppression = append(suppression, "maintenance window suppresses notifications")
	}

	callbackDue := current == "down" && req.IncidentOpen && graceCrossed
	if callbackDue && !req.LastIncidentCallbackAt.IsZero() {
		callbackDue = now.Sub(req.LastIncidentCallbackAt) >= time.Duration(callbackEvery)*time.Second
	}
	if req.Maintenance {
		callbackDue = false
	}

	statusChanged := previous != current || (current == "down" && strings.TrimSpace(req.PreviousReason) != strings.TrimSpace(req.CurrentReason))
	persist := statusChanged || req.LastPersistedAt.IsZero() || now.Sub(req.LastPersistedAt) >= time.Duration(cooldown)*time.Second

	return ServiceIncidentPolicyPlan{
		Transition:            transition,
		Notify:                notify,
		IncidentCallbackDue:   callbackDue,
		Persist:               persist,
		FailureAgeSeconds:     failureAge,
		IncidentRetentionDays: incidentRetention,
		LatencyRetentionHours: latencyRetention,
		SuppressionReasons:    suppression,
		Invariants: []string{
			"endpoint health and incident lifecycle are separate state machines",
			"short failures below the grace period do not produce orphan recovery notifications",
			"maintenance suppresses notification side effects but does not erase health evidence",
			"templated notification URLs, headers, and bodies must be redacted before logging",
			"status changes bypass persistence cooldown while steady-state writes remain bounded",
		},
		ReadOnly: true,
	}, nil
}
