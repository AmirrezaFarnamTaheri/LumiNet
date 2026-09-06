// Package v2rayconfig provides V2Ray/Xray configuration building with anti-censorship features.
// Ported from: v2ray_client-master
// Target path: server/internal/v2rayconfig/v2ray_client_wrapper.go

package v2rayconfig

import (
	"fmt"
	"time"
)

// V2rayConfigModel represents the database model for V2Ray client instances configurations persistence.
type V2rayConfigModel struct {
	ID        uint      `json:"id" gorm:"primaryKey"`
	Key       string    `json:"key" gorm:"uniqueIndex"`
	Value     string    `json:"value"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ErrorHandlerMock simulates HTTP web errors renders.
func ErrorHandlerMock(statusCode int) (string, int) {
	switch statusCode {
	case 404:
		return "404 Not Found Template Rendered", 404
	case 500:
		return "500 Internal Error Template Rendered", 500
	default:
		return "200 OK", 200
	}
}

// ShellContextMock returns SQLAlchemy context mappings.
func ShellContextMock(db interface{}, cfg *V2rayConfigModel) map[string]interface{} {
	return map[string]interface{}{
		"db":          db,
		"v2rayConfig": cfg,
	}
}

// Baseline VMess client JSON configuration schema template.
const VMessClientTemplate = `{
  "outbounds": [
    {
      "protocol": "vmess",
      "settings": {
        "vnext": [
          {
            "address": "%s",
            "port": %d,
            "users": [
              {
                "id": "%s",
                "alterId": 0,
                "security": "auto"
              }
            ]
          }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "%s"
        }
      }
    }
  ]
}`

// BuildVMessClientConfig creates JSON outbound configuration based on variables.
func BuildVMessClientConfig(address string, port int, uuid string, path string) string {
	return fmt.Sprintf(VMessClientTemplate, address, port, uuid, path)
}
