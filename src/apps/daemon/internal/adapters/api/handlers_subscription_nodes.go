package api

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
)

type subscriptionNodeVisibilityRequest struct {
	NodeIDs []string `json:"node_ids" binding:"required"`
	Hidden  bool     `json:"hidden"`
}

type subscriptionNodeActivateRequest struct {
	SocksPort int `json:"socks_port,omitempty"`
}

type subscriptionRuntimeStopRequest struct {
	ProfileID string `json:"profile_id" binding:"required"`
	NodeID    string `json:"node_id" binding:"required"`
}

func (s *Server) ListSubscriptionNodes(c *gin.Context) {
	includeHidden, _ := strconv.ParseBool(c.Query("include_hidden"))
	nodes, ok := s.profileService.ListNodes(c.Param("id"), includeHidden)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "profile not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"nodes":               nodes,
		"total":               len(nodes),
		"credentials_exposed": false,
	})
}

func (s *Server) SetSubscriptionNodeVisibility(c *gin.Context) {
	profileID := c.Param("id")
	var request subscriptionNodeVisibilityRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if request.Hidden && s.subscriptionRuntime != nil {
		status := s.subscriptionRuntime.Status()
		if status.Active && status.ProfileID == profileID {
			for _, id := range request.NodeIDs {
				if id == status.NodeID {
					c.JSON(http.StatusConflict, gin.H{"error": "cannot hide the active subscription node; stop it first"})
					return
				}
			}
		}
	}
	if err := s.profileService.SetNodesHidden(profileID, request.NodeIDs, request.Hidden); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	nodes, _ := s.profileService.ListNodes(profileID, true)
	c.JSON(http.StatusOK, gin.H{"nodes": nodes, "credentials_exposed": false})
}

func (s *Server) ActivateSubscriptionNode(c *gin.Context) {
	profileID := c.Param("id")
	nodeID := c.Param("node_id")
	var request subscriptionNodeActivateRequest
	if c.Request.ContentLength != 0 {
		if err := c.ShouldBindJSON(&request); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
	}
	cfg, err := s.profileService.ResolveNode(profileID, nodeID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	status, err := s.subscriptionRuntime.Activate(profileID, nodeID, cfg, request.SocksPort)
	if err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": err.Error(), "runtime": s.subscriptionRuntime.Status()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"runtime":                      status,
		"does_not_modify_system_proxy": true,
		"credentials_exposed":          false,
	})
}

func (s *Server) GetSubscriptionRuntime(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"runtime":                      s.subscriptionRuntime.Status(),
		"does_not_modify_system_proxy": true,
	})
}

func (s *Server) StopSubscriptionRuntime(c *gin.Context) {
	var request subscriptionRuntimeStopRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := s.subscriptionRuntime.Stop(request.ProfileID, request.NodeID); err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": err.Error(), "runtime": s.subscriptionRuntime.Status()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"runtime": s.subscriptionRuntime.Status()})
}
