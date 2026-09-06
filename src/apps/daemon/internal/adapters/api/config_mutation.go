package api

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/maybeknott/luminet/internal/foundation/config"
)

func configRevisionETag(revision uint64) string {
	return fmt.Sprintf(`"cfg-%d"`, revision)
}

func parseConfigRevisionETag(raw string) (uint64, error) {
	raw = strings.TrimSpace(raw)
	if len(raw) < len(`"cfg-0"`) || raw[0] != '"' || raw[len(raw)-1] != '"' {
		return 0, errors.New(`config revision ETag must be quoted as "cfg-<revision>"`)
	}
	if strings.Contains(raw, ",") || strings.HasPrefix(raw, `W/`) || raw == `*` {
		return 0, errors.New("config mutation requires one strong revision ETag")
	}
	inner := raw[1 : len(raw)-1]
	if !strings.HasPrefix(inner, "cfg-") {
		return 0, errors.New(`config revision ETag must use the form "cfg-<revision>"`)
	}
	digits := strings.TrimPrefix(inner, "cfg-")
	if digits == "" {
		return 0, errors.New("config revision ETag is missing a revision")
	}
	revision, err := strconv.ParseUint(digits, 10, 64)
	if err != nil {
		return 0, errors.New("config revision ETag contains an invalid revision")
	}
	return revision, nil
}

func configRevisionConflictStatus(ifMatch string) int {
	if strings.TrimSpace(ifMatch) != "" {
		return http.StatusPreconditionFailed
	}
	return http.StatusConflict
}

func exposeConfigRevision(c *gin.Context, revision uint64) {
	c.Header("ETag", configRevisionETag(revision))
}

// configMutationOptions resolves the optimistic-concurrency contract. A client-
// supplied If-Match or body revision is an explicit precondition and therefore
// gets exactly one CAS attempt. With no client precondition, the server may
// replay the side-effect-free intent against a fresh authoritative snapshot
// when a concurrent unrelated mutation wins the first race.
func configMutationOptions(c *gin.Context, bodyRevision uint64) (config.MutationOptions, bool) {
	if raw := strings.TrimSpace(c.GetHeader("If-Match")); raw != "" {
		revision, err := parseConfigRevisionETag(raw)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return config.MutationOptions{}, false
		}
		return config.MutationOptions{ExpectedRevision: &revision}, true
	}
	if bodyRevision != 0 {
		revision := bodyRevision
		return config.MutationOptions{ExpectedRevision: &revision}, true
	}
	return config.MutationOptions{MaxAttempts: config.DefaultMutationAttempts}, true
}

// commitConfigMutation is the single HTTP adapter for intent-based live
// configuration mutations. The callback may run more than once and therefore
// MUST only mutate the supplied Config; runtime/network side effects belong
// strictly after this function reports a durable commit.
func commitConfigMutation(c *gin.Context, manager *config.Manager, bodyRevision uint64, mutate func(*config.Config) error) (config.MutationResult, bool) {
	options, ok := configMutationOptions(c, bodyRevision)
	if !ok {
		return config.MutationResult{}, false
	}

	result, err := manager.Mutate(options, mutate)
	if result.Revision != 0 || manager.Revision() == 0 {
		exposeConfigRevision(c, result.Revision)
	}
	c.Header("X-LumiNet-Config-Mutation-Attempts", strconv.Itoa(result.Attempts))
	if err == nil {
		return result, true
	}
	if errors.Is(err, config.ErrRevisionConflict) {
		c.JSON(configRevisionConflictStatus(c.GetHeader("If-Match")), gin.H{
			"error":            "configuration changed since this mutation snapshot was read",
			"current_revision": result.Revision,
			"attempts":         result.Attempts,
		})
		return result, false
	}
	c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error(), "attempts": result.Attempts})
	return result, false
}
