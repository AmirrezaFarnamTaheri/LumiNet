package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/maybeknott/luminet/internal/integrations/captchaclient"
	"github.com/maybeknott/luminet/internal/integrations/sub"
	"github.com/maybeknott/luminet/internal/networking/proxyconfig"
)

type SubscriptionAggregateRequest struct {
	Inputs         []string `json:"inputs" binding:"required"`
	AllowProtocols []string `json:"allow_protocols"`
	SearchQuery    string   `json:"search_query"`
	MinPort        int      `json:"min_port"`
	MaxPort        int      `json:"max_port"`
}

type SubscriptionShapeRequest struct {
	TemplateURI  string   `json:"template_uri" binding:"required"`
	CleanIPs     []string `json:"clean_ips" binding:"required"`
	NameTemplate string   `json:"name_template"`
}

type SubscriptionActionResponse struct {
	Count   int                   `json:"count"`
	Results []ParsedProxyResponse `json:"results"`
	RawURIs []string              `json:"raw_uris"`
}

// AggregateSubscriptionsHandler handles POST /api/subscriptions/aggregate
func (s *Server) AggregateSubscriptionsHandler(c *gin.Context) {
	var req SubscriptionAggregateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	filters := sub.SubscriptionFilters{
		AllowProtocols: req.AllowProtocols,
		SearchQuery:    req.SearchQuery,
		MinPort:        req.MinPort,
		MaxPort:        req.MaxPort,
	}

	ctx := c.Request.Context()
	if s.configManager != nil {
		cfg := s.configManager.Get()
		if cfg != nil && cfg.CaptchaSolver.Enabled {
			solver := captchaclient.NewCaptchaSolver(cfg.CaptchaSolver.APIKey, cfg.CaptchaSolver.EndpointURL)
			ctx = sub.WithCaptchaSolver(ctx, solver)
		}
	}

	configs, err := sub.AggregateSubscriptions(ctx, req.Inputs, filters)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	results := make([]ParsedProxyResponse, 0, len(configs))
	rawURIs := make([]string, 0, len(configs))
	for i, cfg := range configs {
		uri := cfg.ToURI()
		rawURIs = append(rawURIs, uri)
		results = append(results, ParsedProxyResponse{
			Index:     i + 1,
			Protocol:  string(cfg.Protocol),
			Name:      cfg.Name,
			Address:   cfg.Address,
			Port:      cfg.Port,
			TLS:       cfg.TLS,
			SNI:       cfg.SNI,
			Transport: cfg.Transport,
			Preview:   proxyconfig.URITransportPreview(uri, 110),
		})
	}

	c.JSON(http.StatusOK, SubscriptionActionResponse{
		Count:   len(results),
		Results: results,
		RawURIs: rawURIs,
	})
}

// ShapeSubscriptionHandler handles POST /api/subscriptions/shape
func (s *Server) ShapeSubscriptionHandler(c *gin.Context) {
	var req SubscriptionShapeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	templateCfg, err := proxyconfig.ParseProxyURI(req.TemplateURI)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to parse template URI: " + err.Error()})
		return
	}

	configs, err := sub.ShapeProxyConfig(templateCfg, req.CleanIPs, req.NameTemplate)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	results := make([]ParsedProxyResponse, 0, len(configs))
	rawURIs := make([]string, 0, len(configs))
	for i, cfg := range configs {
		uri := cfg.ToURI()
		rawURIs = append(rawURIs, uri)
		results = append(results, ParsedProxyResponse{
			Index:     i + 1,
			Protocol:  string(cfg.Protocol),
			Name:      cfg.Name,
			Address:   cfg.Address,
			Port:      cfg.Port,
			TLS:       cfg.TLS,
			SNI:       cfg.SNI,
			Transport: cfg.Transport,
			Preview:   proxyconfig.URITransportPreview(uri, 110),
		})
	}

	c.JSON(http.StatusOK, SubscriptionActionResponse{
		Count:   len(results),
		Results: results,
		RawURIs: rawURIs,
	})
}

type SubscriptionDeepLinkInspectRequest struct {
	DeepLink string `json:"deep_link" binding:"required"`
}

// InspectSubscriptionDeepLink validates a luminet://import proposal without
// fetching, persisting, activating, or refreshing the referenced profile.
func (s *Server) InspectSubscriptionDeepLink(c *gin.Context) {
	var req SubscriptionDeepLinkInspectRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	proposal, err := sub.ParseDeepLinkImport(req.DeepLink)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"proposal":              proposal,
		"authoritative":         false,
		"requires_confirmation": true,
		"side_effects":          []string{},
	})
}
