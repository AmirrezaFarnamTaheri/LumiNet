package sub

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/maybeknott/luminet/internal/networking/proxyconfig"
)

const (
	maxMaterializedNodes = 4096
	maxNodeMutationIDs   = 256
)

// MaterializedNodeView is the credential-redacted operator view of a parsed
// subscription node. It is intentionally not a serializable ProxyConfig.
type MaterializedNodeView struct {
	ID                 string                    `json:"id"`
	Protocol           proxyconfig.ProxyProtocol `json:"protocol"`
	Name               string                    `json:"name,omitempty"`
	Address            string                    `json:"address"`
	Port               int                       `json:"port"`
	Transport          string                    `json:"transport,omitempty"`
	TLS                bool                      `json:"tls"`
	SNI                string                    `json:"sni,omitempty"`
	Hidden             bool                      `json:"hidden"`
	RuntimeActivatable bool                      `json:"runtime_activatable"`
	RuntimeCores       []string                  `json:"runtime_cores,omitempty"`
	RuntimeReason      string                    `json:"runtime_reason,omitempty"`
}

type materializedNode struct {
	id          string
	providerKey string
	fingerprint string
	hidden      bool
	config      *proxyconfig.ProxyConfig
}

type profileNodeCatalogue struct {
	nodes []*materializedNode
}

// NodeCatalogue owns parsed subscription-node materialization for the daemon
// lifetime. Credentials stay only in the private ProxyConfig copies.
type NodeCatalogue struct {
	mu       sync.RWMutex
	secret   [32]byte
	profiles map[string]*profileNodeCatalogue
}

func NewNodeCatalogue() (*NodeCatalogue, error) {
	c := &NodeCatalogue{profiles: make(map[string]*profileNodeCatalogue)}
	if _, err := rand.Read(c.secret[:]); err != nil {
		return nil, fmt.Errorf("initialize subscription node identity key: %w", err)
	}
	return c, nil
}

// Replace atomically replaces one profile's materialized nodes. Exact
// duplicates are collapsed. Existing IDs and hide state survive refresh only
// for exact matches or unambiguous one-to-one provider-visible matches.
func (c *NodeCatalogue) Replace(profileID string, configs []*proxyconfig.ProxyConfig) error {
	profileID = strings.TrimSpace(profileID)
	if profileID == "" {
		return fmt.Errorf("profile id is required")
	}
	if len(configs) == 0 {
		return fmt.Errorf("subscription profile %q has no materialized nodes", profileID)
	}
	if len(configs) > maxMaterializedNodes {
		return fmt.Errorf("subscription profile %q exceeds %d materialized nodes", profileID, maxMaterializedNodes)
	}

	type candidate struct {
		config      *proxyconfig.ProxyConfig
		providerKey string
		fingerprint string
	}
	candidates := make([]candidate, 0, len(configs))
	seenFingerprints := make(map[string]struct{}, len(configs))
	newProviderCounts := make(map[string]int)
	for i, cfg := range configs {
		if cfg == nil {
			return fmt.Errorf("subscription profile %q node %d is nil", profileID, i+1)
		}
		clone, err := cloneCatalogueConfig(cfg)
		if err != nil {
			return fmt.Errorf("clone subscription profile %q node %d: %w", profileID, i+1, err)
		}
		providerKey, err := catalogueProviderIdentity(clone)
		if err != nil {
			return fmt.Errorf("identify subscription profile %q node %d: %w", profileID, i+1, err)
		}
		fingerprint, err := c.catalogueFingerprint(clone)
		if err != nil {
			return fmt.Errorf("fingerprint subscription profile %q node %d: %w", profileID, i+1, err)
		}
		if _, duplicate := seenFingerprints[fingerprint]; duplicate {
			continue
		}
		seenFingerprints[fingerprint] = struct{}{}
		candidates = append(candidates, candidate{config: clone, providerKey: providerKey, fingerprint: fingerprint})
		newProviderCounts[providerKey]++
	}
	if len(candidates) == 0 {
		return fmt.Errorf("subscription profile %q has no unique materialized nodes", profileID)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	old := c.profiles[profileID]
	oldExact := make(map[string]*materializedNode)
	oldByProvider := make(map[string][]*materializedNode)
	if old != nil {
		for _, node := range old.nodes {
			oldExact[node.fingerprint] = node
			oldByProvider[node.providerKey] = append(oldByProvider[node.providerKey], node)
		}
	}

	next := &profileNodeCatalogue{nodes: make([]*materializedNode, 0, len(candidates))}
	usedOldIDs := make(map[string]struct{})
	for _, item := range candidates {
		node := &materializedNode{
			providerKey: item.providerKey,
			fingerprint: item.fingerprint,
			config:      item.config,
		}
		if existing := oldExact[item.fingerprint]; existing != nil {
			node.id = existing.id
			node.hidden = existing.hidden
			usedOldIDs[existing.id] = struct{}{}
		} else if matches := oldByProvider[item.providerKey]; newProviderCounts[item.providerKey] == 1 && len(matches) == 1 {
			if _, alreadyUsed := usedOldIDs[matches[0].id]; !alreadyUsed {
				node.id = matches[0].id
				node.hidden = matches[0].hidden
				usedOldIDs[matches[0].id] = struct{}{}
			}
		}
		if node.id == "" {
			node.id = c.newPublicNodeID(profileID, item.fingerprint)
		}
		next.nodes = append(next.nodes, node)
	}
	c.profiles[profileID] = next
	return nil
}

func (c *NodeCatalogue) List(profileID string, includeHidden bool) []MaterializedNodeView {
	c.mu.RLock()
	profile := c.profiles[profileID]
	if profile == nil {
		c.mu.RUnlock()
		return []MaterializedNodeView{}
	}
	views := make([]MaterializedNodeView, 0, len(profile.nodes))
	for _, node := range profile.nodes {
		if node.hidden && !includeHidden {
			continue
		}
		views = append(views, catalogueNodeView(node))
	}
	c.mu.RUnlock()
	sort.SliceStable(views, func(i, j int) bool {
		if views[i].Name != views[j].Name {
			return views[i].Name < views[j].Name
		}
		if views[i].Address != views[j].Address {
			return views[i].Address < views[j].Address
		}
		if views[i].Port != views[j].Port {
			return views[i].Port < views[j].Port
		}
		return views[i].ID < views[j].ID
	})
	return views
}

// SetHidden applies one bounded, atomic local overlay mutation. It refuses a
// result with zero visible nodes because such a profile cannot be activated.
func (c *NodeCatalogue) SetHidden(profileID string, ids []string, hidden bool) error {
	if len(ids) == 0 {
		return fmt.Errorf("at least one node id is required")
	}
	if len(ids) > maxNodeMutationIDs {
		return fmt.Errorf("node mutation exceeds %d ids", maxNodeMutationIDs)
	}
	wanted := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" {
			return fmt.Errorf("node id must not be empty")
		}
		wanted[id] = struct{}{}
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	profile := c.profiles[profileID]
	if profile == nil {
		return fmt.Errorf("subscription profile %q has no materialized nodes", profileID)
	}
	found := make(map[string]*materializedNode, len(wanted))
	for _, node := range profile.nodes {
		if _, ok := wanted[node.id]; ok {
			found[node.id] = node
		}
	}
	if len(found) != len(wanted) {
		return fmt.Errorf("one or more subscription node ids are unknown")
	}
	visible := 0
	for _, node := range profile.nodes {
		nextHidden := node.hidden
		if _, change := wanted[node.id]; change {
			nextHidden = hidden
		}
		if !nextHidden {
			visible++
		}
	}
	if visible == 0 {
		return fmt.Errorf("at least one subscription node must remain visible")
	}
	for _, node := range found {
		node.hidden = hidden
	}
	return nil
}

func (c *NodeCatalogue) Resolve(profileID, nodeID string) (*proxyconfig.ProxyConfig, error) {
	c.mu.RLock()
	profile := c.profiles[profileID]
	if profile == nil {
		c.mu.RUnlock()
		return nil, fmt.Errorf("subscription profile %q has no materialized nodes", profileID)
	}
	var selected *materializedNode
	for _, node := range profile.nodes {
		if node.id == nodeID {
			selected = node
			break
		}
	}
	if selected == nil {
		c.mu.RUnlock()
		return nil, fmt.Errorf("subscription node %q not found", nodeID)
	}
	if selected.hidden {
		c.mu.RUnlock()
		return nil, fmt.Errorf("subscription node %q is hidden", nodeID)
	}
	clone, err := cloneCatalogueConfig(selected.config)
	c.mu.RUnlock()
	if err != nil {
		return nil, fmt.Errorf("clone subscription node %q: %w", nodeID, err)
	}
	return clone, nil
}

func (c *NodeCatalogue) Clear(profileID string) {
	c.mu.Lock()
	delete(c.profiles, profileID)
	c.mu.Unlock()
}

func catalogueNodeView(node *materializedNode) MaterializedNodeView {
	cfg := node.config
	compatibility := proxyconfig.EvaluateExternalCoreCompatibility(cfg)
	return MaterializedNodeView{
		ID: node.id, Protocol: cfg.Protocol, Name: cfg.Name,
		Address: cfg.Address, Port: cfg.Port, Transport: cfg.Transport,
		TLS: cfg.TLS, SNI: cfg.SNI, Hidden: node.hidden,
		RuntimeActivatable: compatibility.Activatable,
		RuntimeCores:       append([]string(nil), compatibility.Cores...),
		RuntimeReason:      compatibility.Reason,
	}
}

func cloneCatalogueConfig(cfg *proxyconfig.ProxyConfig) (*proxyconfig.ProxyConfig, error) {
	data, err := json.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	var clone proxyconfig.ProxyConfig
	if err := json.Unmarshal(data, &clone); err != nil {
		return nil, err
	}
	return &clone, nil
}

func catalogueProviderIdentity(cfg *proxyconfig.ProxyConfig) (string, error) {
	// Include only provider-visible routing/transport identity. Authentication
	// credentials and RawURI are deliberately excluded so local ownership can
	// survive a provider credential rotation when the node is unambiguous.
	visible := struct {
		Protocol                                                   proxyconfig.ProxyProtocol `json:"protocol"`
		Name, Address                                              string
		Port                                                       int
		Method, Transport                                          string
		TLS                                                        bool
		SNI, Path, Host, ServiceName, Authority, Flow, Fingerprint string
		PublicKey, ShortID, SpiderX                                string
		MTU                                                        int
	}{
		Protocol: cfg.Protocol, Name: cfg.Name, Address: strings.ToLower(strings.TrimSpace(cfg.Address)), Port: cfg.Port,
		Method: cfg.Method, Transport: cfg.Transport, TLS: cfg.TLS, SNI: strings.ToLower(strings.TrimSpace(cfg.SNI)),
		Path: cfg.Path, Host: strings.ToLower(strings.TrimSpace(cfg.Host)), ServiceName: cfg.ServiceName, Authority: cfg.Authority,
		Flow: cfg.Flow, Fingerprint: cfg.Fingerprint, PublicKey: cfg.PublicKey, ShortID: cfg.ShortID, SpiderX: cfg.SpiderX, MTU: cfg.MTU,
	}
	data, err := json.Marshal(visible)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func (c *NodeCatalogue) catalogueFingerprint(cfg *proxyconfig.ProxyConfig) (string, error) {
	data, err := json.Marshal(cfg)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, c.secret[:])
	_, _ = mac.Write(data)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

func (c *NodeCatalogue) newPublicNodeID(profileID, fingerprint string) string {
	mac := hmac.New(sha256.New, c.secret[:])
	_, _ = mac.Write([]byte(profileID))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(fingerprint))
	digest := mac.Sum(nil)
	return "sn_" + base64.RawURLEncoding.EncodeToString(digest[:18])
}
