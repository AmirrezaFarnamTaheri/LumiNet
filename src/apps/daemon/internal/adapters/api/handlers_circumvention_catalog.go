package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/maybeknott/luminet/internal/analysis/provider"
)

func (s *Server) setupCircumventionCatalogRoutes(rg *gin.RouterGroup) {
	rg.GET("/circumvention/catalog", s.GetCircumventionCatalog)
}

func (s *Server) GetCircumventionCatalog(c *gin.Context) {
	items := provider.CircumventionCatalog()
	c.JSON(http.StatusOK, gin.H{"items": items, "count": len(items)})
}
