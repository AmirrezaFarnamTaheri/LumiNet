package api

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/maybeknott/luminet/internal/foundation/capabilities"
	"github.com/maybeknott/luminet/internal/runtime/routingplugin"
)

// setupRoutingPluginRoutes registers routing plugin endpoints.
func (s *Server) setupRoutingPluginRoutes(rg *gin.RouterGroup) {
	plugins := rg.Group("/system/plugins")
	plugins.Use(capabilities.GuardRoute(s.capabilities, capabilities.CapRoutingPlugins))
	plugins.GET("", s.GetRoutingPlugins)
	plugins.POST("/validate", s.ValidateRoutingPlugin)
}

// GetRoutingPlugins returns all available routing plugins.
func (s *Server) GetRoutingPlugins(c *gin.Context) {
	registry, err := routingplugin.DefaultRoutingPluginRegistry()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"schema_version": 1,
			"valid":          false,
			"status":         "error",
			"phase":          "REGISTRY",
			"retryable":      false,
			"error_code":     "PLUGIN_REGISTRY_UNAVAILABLE",
			"field":          "registry",
			"message":        "routing plugin registry unavailable",
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"schema_version": 1,
		"plugins":        registry.List(),
	})
}

// ValidateRoutingPlugin validates a given routing plugin configuration.
func (s *Server) ValidateRoutingPlugin(c *gin.Context) {
	var cfg routingplugin.RoutingPluginConfig
	if err := c.ShouldBindJSON(&cfg); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"schema_version": 1,
			"valid":          false,
			"status":         "error",
			"phase":          "MALFORMED",
			"retryable":      false,
			"error_code":     "PLUGIN_CONFIG_MALFORMED",
			"field":          "request_body",
			"message":        "invalid plugin validation request body",
		})
		return
	}

	registry, err := routingplugin.DefaultRoutingPluginRegistry()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"schema_version": 1,
			"valid":          false,
			"status":         "error",
			"phase":          "REGISTRY",
			"retryable":      false,
			"error_code":     "PLUGIN_REGISTRY_UNAVAILABLE",
			"field":          "registry",
			"message":        "routing plugin registry unavailable",
		})
		return
	}

	result, err := routingplugin.ValidateRoutingPluginConfig(registry, cfg)
	if err != nil {
		msg := "routing plugin validation failed"
		field := "config"
		code := "PLUGIN_CONFIG_INVALID"

		switch {
		case errors.Is(err, routingplugin.ErrPluginConfig):
			msg = "routing plugin configuration is invalid; inspect error_code, field, and local diagnostics"
		case errors.Is(err, routingplugin.ErrPluginDescriptor):
			msg = "routing plugin registry is invalid"
		case errors.Is(err, routingplugin.ErrRouteValidation):
			msg = "route configuration is invalid"
		}

		c.JSON(http.StatusBadRequest, gin.H{
			"schema_version": 1,
			"valid":          false,
			"status":         "error",
			"phase":          "VALIDATION",
			"retryable":      false,
			"error_code":     code,
			"field":          field,
			"message":        msg,
		})
		return
	}

	c.JSON(http.StatusOK, result)
}
