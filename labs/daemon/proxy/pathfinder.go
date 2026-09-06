package proxy

import (
	"container/heap"
	"errors"
	"math"
	"time"
)

// PathNode represents a node in the Dijkstra solver priority queue
type PathNode struct {
	ID       string
	Priority time.Duration
	index    int
}

// PriorityQueue implements heap.Interface to select the lowest-latency node path
type PriorityQueue []*PathNode

func (pq PriorityQueue) Len() int           { return len(pq) }
func (pq PriorityQueue) Less(i, j int) bool { return pq[i].Priority < pq[j].Priority }
func (pq PriorityQueue) Swap(i, j int) {
	pq[i], pq[j] = pq[j], pq[i]
	pq[i].index = i
	pq[j].index = j
}

// Push adds an item to the priority queue
func (pq *PriorityQueue) Push(x interface{}) {
	n := len(*pq)
	item := x.(*PathNode)
	item.index = n
	*pq = append(*pq, item)
}

// Pop extracts the lowest-priority item from the queue
func (pq *PriorityQueue) Pop() interface{} {
	old := *pq
	n := len(old)
	item := old[n-1]
	old[n-1] = nil
	item.index = -1
	*pq = old[0 : n-1]
	return item
}

// DijkstraPathfinder computes the lowest-latency multi-hop path across proxy nodes
type DijkstraPathfinder struct{}

// FindBestHopChain calculates the shortest (lowest total latency) path from source to destination
func (dp *DijkstraPathfinder) FindBestHopChain(
	startNode string,
	endNode string,
	nodes []string,
	latencyMatrix map[string]map[string]time.Duration,
) ([]string, error) {
	if startNode == endNode {
		return []string{startNode}, nil
	}

	dist := make(map[string]time.Duration)
	prev := make(map[string]string)
	pq := make(PriorityQueue, 0)
	nodeMap := make(map[string]*PathNode)

	// Initialize distances
	for _, node := range nodes {
		if node == startNode {
			dist[node] = 0
		} else {
			dist[node] = time.Duration(math.MaxInt64)
		}
		item := &PathNode{
			ID:       node,
			Priority: dist[node],
		}
		nodeMap[node] = item
		heap.Push(&pq, item)
	}

	// Ensure start and end nodes are tracked if not in the main node list
	if _, ok := nodeMap[startNode]; !ok {
		dist[startNode] = 0
		item := &PathNode{ID: startNode, Priority: 0}
		nodeMap[startNode] = item
		heap.Push(&pq, item)
	}
	if _, ok := nodeMap[endNode]; !ok {
		dist[endNode] = time.Duration(math.MaxInt64)
		item := &PathNode{ID: endNode, Priority: time.Duration(math.MaxInt64)}
		nodeMap[endNode] = item
		heap.Push(&pq, item)
	}

	for pq.Len() > 0 {
		curr := heap.Pop(&pq).(*PathNode)
		u := curr.ID

		if u == endNode {
			break
		}

		if dist[u] == time.Duration(math.MaxInt64) {
			break
		}

		// Traverse edges from u to neighbors
		neighbors, exists := latencyMatrix[u]
		if !exists {
			continue
		}

		for v, latency := range neighbors {
			alt := dist[u] + latency
			targetDist, exists := dist[v]
			if !exists {
				targetDist = time.Duration(math.MaxInt64)
			}
			if alt < targetDist {
				dist[v] = alt
				prev[v] = u

				// Update priority in heap
				if item, exists := nodeMap[v]; exists {
					item.Priority = alt
					heap.Fix(&pq, item.index)
				}
			}
		}
	}

	// Reconstruct path
	path := make([]string, 0)
	curr := endNode
	for curr != "" {
		path = append([]string{curr}, path...)
		curr = prev[curr]
	}

	if len(path) == 0 || path[0] != startNode {
		return nil, errors.New("no valid path found across the proxy node mesh")
	}

	return path, nil
}
