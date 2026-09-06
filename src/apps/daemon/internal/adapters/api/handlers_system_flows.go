package api

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	canonicalprovider "github.com/maybeknott/luminet/internal/analysis/provider"
	"github.com/maybeknott/luminet/internal/foundation/flowregistry"
	"github.com/maybeknott/luminet/internal/platform/system"
)

const (
	defaultFlowListLimit = 1000
	maxFlowQueryLen      = 256
	flowCloseTimeout     = 5 * time.Second
	bulkFlowCloseTimeout = 15 * time.Second
)

type flowListResponse struct {
	Flows            []flowView                   `json:"flows"`
	Coverage         []flowregistry.OwnerCoverage `json:"coverage"`
	Stats            flowregistry.Stats           `json:"stats"`
	Matched          int                          `json:"matched"`
	Returned         int                          `json:"returned"`
	NetworkRevision  uint64                       `json:"network_revision"`
	CoverageComplete bool                         `json:"coverage_complete"`
	CoverageModel    string                       `json:"coverage_model"`
}

type flowProviderAttribution struct {
	ProviderID  string `json:"provider_id"`
	DisplayName string `json:"display_name"`
	Prefix      string `json:"prefix"`
	Confidence  string `json:"confidence"`
	CorpusID    string `json:"corpus_id"`
	CorpusStale bool   `json:"corpus_stale"`
}

type flowView struct {
	flowregistry.Snapshot
	DestinationProvider *flowProviderAttribution `json:"destination_provider,omitempty"`
}

type bulkFlowCloseRequest struct {
	Confirm bool     `json:"confirm"`
	IDs     []string `json:"ids"`
}

type flowCloseResult struct {
	ID     string `json:"id"`
	Closed bool   `json:"closed"`
	Error  string `json:"error,omitempty"`
	Code   string `json:"code,omitempty"`
}

func parseBoundedPositiveInt(raw string, fallback, max int) (int, error) {
	if strings.TrimSpace(raw) == "" {
		return fallback, nil
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v < 1 || v > max {
		return 0, errors.New("invalid bounded integer")
	}
	return v, nil
}

func flowMatchesQuery(f flowregistry.Snapshot, q string) bool {
	if q == "" {
		return true
	}
	values := []string{
		f.ID, f.Owner, f.Network, f.Protocol, f.Source, f.Destination,
		f.Host, f.Process, f.ProcessPath, f.Rule, f.RulePayload,
		strings.Join(f.Chain, " "),
	}
	for k, v := range f.Labels {
		values = append(values, k, v)
	}
	for _, value := range values {
		if strings.Contains(strings.ToLower(value), q) {
			return true
		}
	}
	return false
}

func flowDestinationIP(destination string) (netip.Addr, bool) {
	destination = strings.TrimSpace(destination)
	if destination == "" {
		return netip.Addr{}, false
	}
	host := destination
	if splitHost, _, err := net.SplitHostPort(destination); err == nil {
		host = splitHost
	}
	host = strings.Trim(strings.TrimSpace(host), "[]")
	addr, err := netip.ParseAddr(host)
	return addr, err == nil
}

func viewFlow(flow flowregistry.Snapshot) flowView {
	view := flowView{Snapshot: flow}
	if addr, ok := flowDestinationIP(flow.Destination); ok {
		if match, found := canonicalprovider.DefaultService.Lookup(addr); found {
			status, _ := canonicalprovider.DefaultService.Status(time.Now())
			view.DestinationProvider = &flowProviderAttribution{
				ProviderID: match.ProviderID, DisplayName: match.DisplayName, Prefix: match.Prefix.String(),
				Confidence: match.Confidence, CorpusID: match.CorpusID, CorpusStale: status.Stale,
			}
		}
	}
	return view
}

// GetSystemFlows handles GET /api/system/flows. It reports only owner-declared
// registered flows; CoverageComplete=false is deliberate capability truth and
// prevents clients from treating absence from this registry as host-wide proof.
func (s *Server) GetSystemFlows(c *gin.Context) {
	limit, err := parseBoundedPositiveInt(c.Query("limit"), defaultFlowListLimit, flowregistry.DefaultMaxFlows)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "limit must be between 1 and 4096"})
		return
	}
	owner := strings.TrimSpace(c.Query("owner"))
	if len(owner) > flowregistry.MaxOwnerLen {
		c.JSON(http.StatusBadRequest, gin.H{"error": "owner filter is too long"})
		return
	}
	q := strings.ToLower(strings.TrimSpace(c.Query("q")))
	if len(q) > maxFlowQueryLen {
		c.JSON(http.StatusBadRequest, gin.H{"error": "query is too long"})
		return
	}

	reg := flowregistry.Default()
	all := reg.Snapshot()
	filtered := make([]flowregistry.Snapshot, 0, len(all))
	for _, flow := range all {
		if owner != "" && flow.Owner != owner {
			continue
		}
		if !flowMatchesQuery(flow, q) {
			continue
		}
		filtered = append(filtered, flow)
	}
	matched := len(filtered)
	// Newest first for operator inspection while retaining deterministic ID
	// ordering for flows with identical start times.
	sort.SliceStable(filtered, func(i, j int) bool {
		if filtered[i].StartedAt.Equal(filtered[j].StartedAt) {
			return filtered[i].ID > filtered[j].ID
		}
		return filtered[i].StartedAt.After(filtered[j].StartedAt)
	})
	if len(filtered) > limit {
		filtered = filtered[:limit]
	}

	views := make([]flowView, 0, len(filtered))
	for _, flow := range filtered {
		views = append(views, viewFlow(flow))
	}
	c.JSON(http.StatusOK, flowListResponse{
		Flows:            views,
		Coverage:         reg.Coverage(),
		Stats:            reg.Stats(),
		Matched:          matched,
		Returned:         len(filtered),
		NetworkRevision:  system.GetNetworkMonitor().Snapshot().Revision,
		CoverageComplete: false,
		CoverageModel:    "participating-runtime-owners-only",
	})
}

// GetSystemFlow handles GET /api/system/flows/:id.
func (s *Server) GetSystemFlow(c *gin.Context) {
	id := strings.TrimSpace(c.Param("id"))
	if id == "" || len(id) > 64 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid flow id"})
		return
	}
	flow, ok := flowregistry.Default().Get(id)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "flow not found"})
		return
	}
	c.JSON(http.StatusOK, viewFlow(flow))
}

func flowCloseError(err error) (status int, code string) {
	switch {
	case err == nil:
		return http.StatusOK, ""
	case errors.Is(err, flowregistry.ErrNotFound):
		return http.StatusNotFound, "not_found"
	case errors.Is(err, flowregistry.ErrNotCloseable):
		return http.StatusUnprocessableEntity, "not_closeable"
	case errors.Is(err, flowregistry.ErrClosing):
		return http.StatusConflict, "already_closing"
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return http.StatusGatewayTimeout, "owner_close_timeout"
	default:
		return http.StatusBadGateway, "owner_close_failed"
	}
}

// CloseSystemFlow handles DELETE /api/system/flows/:id. The registry never
// tears down a flow itself; it asks the owning runtime to do so and only removes
// the record after the owner reports success or independently ends the flow.
func (s *Server) CloseSystemFlow(c *gin.Context) {
	id := strings.TrimSpace(c.Param("id"))
	if id == "" || len(id) > 64 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid flow id"})
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), flowCloseTimeout)
	defer cancel()
	err := flowregistry.Default().Close(ctx, id)
	status, code := flowCloseError(err)
	if err != nil {
		c.JSON(status, gin.H{"error": err.Error(), "code": code, "id": id})
		return
	}
	c.JSON(http.StatusOK, flowCloseResult{ID: id, Closed: true})
}

// CloseSystemFlows handles POST /api/system/flows/close. It intentionally
// accepts only an explicit bounded ID set and requires operation-specific
// confirmation; there is no implicit "close all" mode.
func (s *Server) CloseSystemFlows(c *gin.Context) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 32<<10)
	var req bulkFlowCloseRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if !req.Confirm {
		c.JSON(http.StatusPreconditionRequired, gin.H{"error": "explicit confirmation is required"})
		return
	}
	if len(req.IDs) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "at least one flow id is required"})
		return
	}
	if len(req.IDs) > flowregistry.MaxBulkCloseFlows {
		c.JSON(http.StatusBadRequest, gin.H{"error": "too many flow ids", "max": flowregistry.MaxBulkCloseFlows})
		return
	}
	ids := make([]string, 0, len(req.IDs))
	seen := make(map[string]struct{}, len(req.IDs))
	for _, raw := range req.IDs {
		id := strings.TrimSpace(raw)
		if id == "" || len(id) > 64 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid flow id in request"})
			return
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		ids = append(ids, id)
	}
	if len(ids) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "at least one unique flow id is required"})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), bulkFlowCloseTimeout)
	defer cancel()
	resultMap, err := flowregistry.Default().CloseIDs(ctx, ids)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	results := make([]flowCloseResult, 0, len(ids))
	closed := 0
	failed := 0
	for _, id := range ids {
		err := resultMap[id]
		_, code := flowCloseError(err)
		item := flowCloseResult{ID: id, Closed: err == nil, Code: code}
		if err != nil {
			item.Error = err.Error()
			failed++
		} else {
			closed++
		}
		results = append(results, item)
	}
	status := "closed"
	if failed > 0 && closed > 0 {
		status = "partial"
	} else if failed > 0 {
		status = "failed"
	}
	c.JSON(http.StatusOK, gin.H{"status": status, "closed": closed, "failed": failed, "results": results})
}
