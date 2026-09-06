// Package proxy implements outbound protocols and obfuscation mechanisms.
// Ported from: XHTTPRelayAzure-main
// Target path: server/internal/proxy/xhttp_azure.go

package proxy

import (
	"fmt"
	"log"
	"net/http"
	"time"
)

// XHTTPAzure manages the Azure App Service Node.js XHTTP relay provisioning and timeout overrides.
type XHTTPAzure struct {
	Timeout time.Duration
}

// NewXHTTPAzure instantiates a new XHTTPAzure.
func NewXHTTPAzure() *XHTTPAzure {
	return &XHTTPAzure{
		Timeout: 0, // 0 means no timeout (removed hard timeouts for long streams)
	}
}

// GetClient returns an http.Client configured with the custom timeout overrides.
func (x *XHTTPAzure) GetClient() *http.Client {
	return &http.Client{
		Timeout: x.Timeout,
	}
}

// ProvisionAzureRelay returns a shell script containing the PowerShell CLI commands to deploy/provision the Azure App Service node relay.
func (x *XHTTPAzure) ProvisionAzureRelay(subscriptionID, resourceGroup, appName string) string {
	script := fmt.Sprintf(`
# Login to Azure
az login

# Set active subscription
az account set --subscription "%s"

# Create a resource group if it does not exist
az group create --name "%s" --location "eastus"

# Create an App Service plan
az appservice plan create --name "%s-plan" --resource-group "%s" --sku B1 --is-linux

# Create the Web App running Node.js
az webapp create --name "%s" --resource-group "%s" --plan "%s-plan" --runtime "NODE|18-lts"

# Configure continuous deployment or zip deployment
az webapp config appsettings set --name "%s" --resource-group "%s" --settings WEBSITE_RUN_FROM_PACKAGE="1"
`, subscriptionID, resourceGroup, appName, resourceGroup, appName, resourceGroup, appName, appName, resourceGroup)

	log.Printf("XHTTPAzure: Generated PowerShell provisioning script for app %s", appName)
	return script
}

// RunRelay is the legacy diagnostic entry trigger.
func (x *XHTTPAzure) RunRelay() {
	// Diagnostic stub
}
