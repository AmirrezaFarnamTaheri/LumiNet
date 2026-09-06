package api

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/maybeknott/luminet/internal/foundation/config"
)

// proxyNodeResponse is the operator-facing representation of a stored proxy
// node. Credentials are intentionally never serialized back to the API client:
// callers can observe whether authentication is configured, but not recover a
// value that they did not just submit.
type proxyNodeResponse struct {
	ID          string `json:"id"`
	Host        string `json:"host"`
	Port        int    `json:"port"`
	Type        string `json:"type"`
	Auth        bool   `json:"auth"`
	HasPassword bool   `json:"has_password"`
	Username    string `json:"username,omitempty"`
	Notes       string `json:"notes"`
}

func publicProxyNode(node config.ProxyNodeConfig) proxyNodeResponse {
	return proxyNodeResponse{
		ID:          node.ID,
		Host:        node.Host,
		Port:        node.Port,
		Type:        node.Type,
		Auth:        node.Auth,
		HasPassword: node.Password != "",
		Username:    node.Username,
		Notes:       node.Notes,
	}
}

// ListProxyNodes handles GET /api/proxies — returns all registered proxy nodes.
func (s *Server) ListProxyNodes(c *gin.Context) {
	cfg, revision := s.configManager.GetWithRevision()
	exposeConfigRevision(c, revision)
	response := make([]proxyNodeResponse, 0, len(cfg.ProxyNodes))
	for _, node := range cfg.ProxyNodes {
		response = append(response, publicProxyNode(node))
	}
	c.JSON(http.StatusOK, response)
}

// AddProxyNode handles POST /api/proxies — registers a new proxy node.
func (s *Server) AddProxyNode(c *gin.Context) {
	var node config.ProxyNodeConfig
	if err := c.ShouldBindJSON(&node); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if node.ID == "" {
		node.ID = fmt.Sprintf("p%d", time.Now().Unix())
	}

	if _, committed := commitConfigMutation(c, s.configManager, 0, func(cfg *config.Config) error {
		cfg.ProxyNodes = append(cfg.ProxyNodes, node)
		return nil
	}); !committed {
		return
	}

	c.JSON(http.StatusCreated, publicProxyNode(node))
}

// DeleteProxyNode handles DELETE /api/proxies/:id — removes a registered proxy node.
func (s *Server) DeleteProxyNode(c *gin.Context) {
	id := c.Param("id")
	initial := s.configManager.Get()
	found := false
	for _, node := range initial.ProxyNodes {
		if node.ID == id {
			found = true
			break
		}
	}
	if !found {
		c.JSON(http.StatusNotFound, gin.H{"error": "proxy node not found"})
		return
	}

	if _, committed := commitConfigMutation(c, s.configManager, 0, func(cfg *config.Config) error {
		newNodes := make([]config.ProxyNodeConfig, 0, len(cfg.ProxyNodes))
		for _, node := range cfg.ProxyNodes {
			if node.ID != id {
				newNodes = append(newNodes, node)
			}
		}
		cfg.ProxyNodes = newNodes
		return nil
	}); !committed {
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "deleted"})
}
