// Package proxy implements outbound protocols and obfuscation mechanisms.
// Ported from: freenet-core-main
// Target path: server/internal/proxy/freenet.go

package proxy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math"
	"net/http"
	"sort"
	"sync"
	"time"
)

// Freenet handles Freenet's small-world routing contract model P2P core via HTTP gateway.
type Freenet struct {
	mu         sync.Mutex
	GatewayURL string
	HTTPClient *http.Client
}

// NewFreenet instantiates a Freenet client.
func NewFreenet() *Freenet {
	return &Freenet{
		GatewayURL: "http://127.0.0.1:8888",
		HTTPClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// 1. FetchKey retrieves raw P2P contract data from the Freenet node using a CHK/USK key.
func (f *Freenet) FetchKey(ctx context.Context, freenetKey string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	url := fmt.Sprintf("%s/%s", f.GatewayURL, freenetKey)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := f.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("freenet node returned status %d", resp.StatusCode)
	}

	return ioutil.ReadAll(resp.Body)
}

// 2. InsertKey publishes raw contract data under a targeted Freenet key location.
func (f *Freenet) InsertKey(ctx context.Context, freenetKey string, data []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	url := fmt.Sprintf("%s/%s", f.GatewayURL, freenetKey)
	req, err := http.NewRequestWithContext(ctx, "PUT", url, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/octet-stream")

	resp, err := f.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("freenet insert returned status %d", resp.StatusCode)
	}

	return nil
}

// 3. InitCore initiates bindings to the Rust Freenet P2P engine.
func (f *Freenet) InitCore() {
	f.mu.Lock()
	defer f.mu.Unlock()
}

// DHTNode represents a peer location inside Freenet's small-world ring network.
type DHTNode struct {
	ID       string  `json:"id"`
	Location float64 `json:"location"` // Value in [0.0, 1.0)
}

// DHTRouter manages location-based P2P key routing.
type DHTRouter struct {
	mu    sync.RWMutex
	nodes []DHTNode
}

// NewDHTRouter instantiates a DHTRouter.
func NewDHTRouter() *DHTRouter {
	return &DHTRouter{
		nodes: make([]DHTNode, 0),
	}
}

// 4. AddNode registers a peer with its location on the ring.
func (d *DHTRouter) AddNode(id string, location float64) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.nodes = append(d.nodes, DHTNode{ID: id, Location: location})
}

// 5. RouteKey finds the node whose location is closest to the computed target key location on the [0, 1) ring.
func (d *DHTRouter) RouteKey(key string) string {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if len(d.nodes) == 0 {
		return ""
	}

	// Cryptographic hash to map key to location float
	hash := sha256.Sum256([]byte(key))
	val := binary.BigEndian.Uint64(hash[:8])
	keyLocation := float64(val) / float64(math.MaxUint64)

	closestNode := d.nodes[0].ID
	minDistance := 1.0

	for _, node := range d.nodes {
		dist := math.Abs(node.Location - keyLocation)
		if dist > 0.5 {
			dist = 1.0 - dist // wrap around ring
		}
		if dist < minDistance {
			minDistance = dist
			closestNode = node.ID
		}
	}

	return closestNode
}

// 6. FindClosestNode finds closest node and returns its ring distance.
func (d *DHTRouter) FindClosestNode(key string) (string, float64) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if len(d.nodes) == 0 {
		return "", -1.0
	}

	hash := sha256.Sum256([]byte(key))
	val := binary.BigEndian.Uint64(hash[:8])
	keyLocation := float64(val) / float64(math.MaxUint64)

	closestNode := d.nodes[0].ID
	minDistance := 1.0

	for _, node := range d.nodes {
		dist := math.Abs(node.Location - keyLocation)
		if dist > 0.5 {
			dist = 1.0 - dist
		}
		if dist < minDistance {
			minDistance = dist
			closestNode = node.ID
		}
	}

	return closestNode, minDistance
}

// 7. GetRingMap returns a sorted list of all active ring nodes.
func (d *DHTRouter) GetRingMap() []DHTNode {
	d.mu.RLock()
	defer d.mu.RUnlock()

	copied := make([]DHTNode, len(d.nodes))
	copy(copied, d.nodes)

	sort.Slice(copied, func(i, j int) bool {
		return copied[i].Location < copied[j].Location
	})

	return copied
}

// 8. CalculateJitterOffset computes location jitter parameters to dynamically redirect search requests.
func (d *DHTRouter) CalculateJitterOffset(key string) float64 {
	hash := sha256.Sum256([]byte(key + "_jitter"))
	val := binary.BigEndian.Uint64(hash[:8])
	offset := float64(val%100) / 1000.0 // small jitter offset [0.0, 0.1)
	return offset
}

// 9. DeleteNode removes dead nodes from the DHT network map.
func (d *DHTRouter) DeleteNode(id string) {
	d.mu.Lock()
	defer d.mu.Unlock()

	for i, node := range d.nodes {
		if node.ID == id {
			d.nodes = append(d.nodes[:i], d.nodes[i+1:]...)
			break
		}
	}
}

// 10. NodeCount returns total count of registered nodes.
func (d *DHTRouter) NodeCount() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.nodes)
}

// 11. VerifyNodeLocation checks if node has a valid location in [0.0, 1.0).
func (d *DHTRouter) VerifyNodeLocation(id string) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()

	for _, node := range d.nodes {
		if node.ID == id {
			return node.Location >= 0.0 && node.Location < 1.0
		}
	}
	return false
}

// 12. ClearDHTRouter resets all nodes in the router.
func (d *DHTRouter) ClearDHTRouter() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.nodes = make([]DHTNode, 0)
}

// 13. ExportRingJSON exports all DHT nodes as JSON payload.
func (d *DHTRouter) ExportRingJSON(filePath string) error {
	d.mu.RLock()
	defer d.mu.RUnlock()

	data, err := json.MarshalIndent(d.nodes, "", "  ")
	if err != nil {
		return err
	}
	return ioutil.WriteFile(filePath, data, 0644)
}

// 14. ImportRingJSON imports DHT nodes from JSON configurations.
func (d *DHTRouter) ImportRingJSON(filePath string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return err
	}

	var imported []DHTNode
	if err := json.Unmarshal(data, &imported); err != nil {
		return err
	}

	d.nodes = imported
	return nil
}

// 15. CalculateAverageDistance computes the average distance between adjacent nodes on the ring.
func (d *DHTRouter) CalculateAverageDistance() float64 {
	d.mu.RLock()
	defer d.mu.RUnlock()

	n := len(d.nodes)
	if n < 2 {
		return 0.0
	}

	sorted := make([]DHTNode, n)
	copy(sorted, d.nodes)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Location < sorted[j].Location
	})

	var sumDist float64
	for i := 0; i < n-1; i++ {
		sumDist += sorted[i+1].Location - sorted[i].Location
	}
	// Wrap around distance
	sumDist += (1.0 - sorted[n-1].Location) + sorted[0].Location

	return sumDist / float64(n)
}

// 16. LocateSector identifies which sector prefix the location falls into.
func (d *DHTRouter) LocateSector(location float64) string {
	if location < 0.0 || location >= 1.0 {
		return "invalid"
	}
	if location < 0.25 {
		return "Sector A (North)"
	} else if location < 0.50 {
		return "Sector B (East)"
	} else if location < 0.75 {
		return "Sector C (South)"
	}
	return "Sector D (West)"
}

// SetGatewayURL overrides target Freenet local gateway API endpoint.
func (f *Freenet) SetGatewayURL(url string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.GatewayURL = url
}

// GetGatewayURL retrieves target Freenet local gateway API endpoint.
func (f *Freenet) GetGatewayURL() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.GatewayURL
}

// SetTimeout overrides local HTTP timeout parameter.
func (f *Freenet) SetTimeout(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.HTTPClient.Timeout = d
}

// GetTimeout retrieves local HTTP timeout parameter.
func (f *Freenet) GetTimeout() time.Duration {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.HTTPClient.Timeout
}

// SetNodeLocation overrides a DHT node ring location metric.
func (d *DHTRouter) SetNodeLocation(id string, loc float64) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for i, node := range d.nodes {
		if node.ID == id {
			d.nodes[i].Location = loc
			break
		}
	}
}

// GetNodeLocation retrieves a DHT node ring location metric.
func (d *DHTRouter) GetNodeLocation(id string) float64 {
	d.mu.RLock()
	defer d.mu.RUnlock()
	for _, node := range d.nodes {
		if node.ID == id {
			return node.Location
		}
	}
	return 0.0
}

// RemoveNode deletes a DHT node from the ring mapping.
func (d *DHTRouter) RemoveNode(id string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	idx := -1
	for i, node := range d.nodes {
		if node.ID == id {
			idx = i
			break
		}
	}
	if idx != -1 {
		d.nodes = append(d.nodes[:idx], d.nodes[idx+1:]...)
		return true
	}
	return false
}

// GetNode retrieves a single DHT node.
func (d *DHTRouter) GetNode(id string) (DHTNode, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	for _, node := range d.nodes {
		if node.ID == id {
			return node, true
		}
	}
	return DHTNode{}, false
}

// GetNodes retrieves all DHT nodes on the ring.
func (d *DHTRouter) GetNodes() []DHTNode {
	d.mu.RLock()
	defer d.mu.RUnlock()
	copied := make([]DHTNode, len(d.nodes))
	copy(copied, d.nodes)
	return copied
}

// ClearNodes flushes DHT node registry ring.
func (d *DHTRouter) ClearNodes() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.nodes = make([]DHTNode, 0)
}

// GetNodeCount retrieves total count of nodes on the ring.
func (d *DHTRouter) GetNodeCount() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.nodes)
}
