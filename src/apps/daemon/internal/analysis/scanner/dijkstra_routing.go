
package scanner

import (
	"container/heap"
	"math"
)

// PathEdge represents a hop link in the proxy network.
type PathEdge struct {
	To     string
	Weight float64 // Latency or loss rate weight
}

// Graph represents a directed network map of nodes and connections.
type Graph struct {
	adjacencyList map[string][]PathEdge
}

// NewGraph creates a new network graph map.
func NewGraph() *Graph {
	return &Graph{
		adjacencyList: make(map[string][]PathEdge),
	}
}

// AddEdge inserts a directed weighted link between two proxy nodes.
func (g *Graph) AddEdge(from, to string, weight float64) {
	g.adjacencyList[from] = append(g.adjacencyList[from], PathEdge{To: to, Weight: weight})
}

// DijkstraResult holds path solver outputs.
type DijkstraResult struct {
	Path     []string
	Distance float64
}

type item struct {
	value    string
	priority float64
	index    int
}

type priorityQueue []*item

func (pq priorityQueue) Len() int           { return len(pq) }
func (pq priorityQueue) Less(i, j int) bool { return pq[i].priority < pq[j].priority }
func (pq priorityQueue) Swap(i, j int) {
	pq[i], pq[j] = pq[j], pq[i]
	pq[i].index = i
	pq[j].index = j
}
func (pq *priorityQueue) Push(x interface{}) {
	n := len(*pq)
	it := x.(*item)
	it.index = n
	*pq = append(*pq, it)
}
func (pq *priorityQueue) Pop() interface{} {
	old := *pq
	n := len(old)
	it := old[n-1]
	old[n-1] = nil
	it.index = -1
	*pq = old[0 : n-1]
	return it
}

// FindShortestPath solves Dijkstra's algorithm for shortest path between start and end.
func (g *Graph) FindShortestPath(start, end string) *DijkstraResult {
	distances := make(map[string]float64)
	previous := make(map[string]string)
	pq := make(priorityQueue, 0)
	heap.Init(&pq)

	for node := range g.adjacencyList {
		distances[node] = math.MaxFloat64
	}
	distances[start] = 0.0

	heap.Push(&pq, &item{value: start, priority: 0.0})

	for pq.Len() > 0 {
		curr := heap.Pop(&pq).(*item)
		currNode := curr.value

		if currNode == end {
			break
		}

		if curr.priority > distances[currNode] {
			continue
		}

		for _, edge := range g.adjacencyList[currNode] {
			newDist := distances[currNode] + edge.Weight
			if oldDist, ok := distances[edge.To]; !ok || newDist < oldDist {
				distances[edge.To] = newDist
				previous[edge.To] = currNode
				heap.Push(&pq, &item{value: edge.To, priority: newDist})
			}
		}
	}

	if distances[end] == math.MaxFloat64 {
		return nil // unreachable
	}

	// Reconstruct path
	path := make([]string, 0)
	curr := end
	for curr != "" {
		path = append([]string{curr}, path...)
		curr = previous[curr]
	}

	return &DijkstraResult{
		Path:     path,
		Distance: distances[end],
	}
}
