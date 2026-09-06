package api

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/maybeknott/luminet/internal/integrations/sub"
)

const maxLocalConversionRequestBytes int64 = 8 << 20

type subscriptionConvertRequest struct {
	Content   string               `json:"content" binding:"required"`
	Target    sub.ConversionTarget `json:"target" binding:"required"`
	Strict    *bool                `json:"strict,omitempty"`
	Transform *sub.TransformSpec   `json:"transform,omitempty"`
}

// ConvertSubscriptionHandler handles POST /api/subscriptions/convert.
// It is deliberately local-input-only: conversion never interprets Content as
// a URL to fetch, and it never mutates managed subscription/profile state.
func (s *Server) ConvertSubscriptionHandler(c *gin.Context) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxLocalConversionRequestBytes)
	var req subscriptionConvertRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if strings.TrimSpace(req.Content) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "content is required"})
		return
	}
	if !sub.ValidConversionTarget(req.Target) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported conversion target", "supported_targets": sub.SupportedConversionTargets()})
		return
	}
	strict := true
	if req.Strict != nil {
		strict = *req.Strict
	}
	configs, err := sub.ParseContent(req.Content)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": "input could not be parsed as a supported subscription/profile: " + err.Error()})
		return
	}
	var transformReport *sub.TransformReport
	if req.Transform != nil {
		transformed, report, transformErr := sub.TransformConfigs(configs, *req.Transform)
		transformReport = &report
		if transformErr != nil {
			c.JSON(http.StatusUnprocessableEntity, gin.H{"error": "local node transformation rejected: " + transformErr.Error(), "transformation": report})
			return
		}
		configs = transformed
		if len(configs) == 0 {
			c.JSON(http.StatusUnprocessableEntity, gin.H{"error": "local node transformation removed every node", "transformation": report})
			return
		}
	}
	result, err := sub.ConvertConfigs(configs, req.Target, strict)
	result.Transformation = transformReport
	if err == nil {
		roundTrip := sub.ValidateRoundTrip(configs, result.Content, sub.ParseContent)
		result.RoundTrip = &roundTrip
		if strict && !roundTrip.Compatible {
			c.JSON(http.StatusUnprocessableEntity, gin.H{"error": "strict conversion failed local round-trip validation", "result": result})
			return
		}
	}
	if errors.Is(err, sub.ErrStrictConversion) {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": err.Error(), "result": result})
		return
	}
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error(), "result": result})
		return
	}
	c.JSON(http.StatusOK, result)
}
