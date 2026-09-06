package proxy

import (
	"crypto/rand"
	"io"
	"math/big"
	"sort"
)

// PickKRandomInts chooses k unique random integers from 1 to N, sorted in ascending order.
// This is used to partition the first outbound packet buffer into fragmented chunks.
func PickKRandomInts(k int, N int) []int {
	return pickKRandomIntsWithReader(rand.Reader, k, N)
}

func pickKRandomIntsWithReader(entropy io.Reader, k int, N int) []int {
	if k <= 0 || N <= 1 {
		return nil
	}
	if k >= N {
		k = N - 1
	}

	// Generate pool of numbers from 1 to N
	pool := make([]int, N)
	for i := 0; i < N; i++ {
		pool[i] = i + 1
	}

	// Fisher-Yates shuffle using cryptographically secure random integers
	for i := N - 1; i > 0; i-- {
		nBig, err := rand.Int(entropy, big.NewInt(int64(i+1)))
		if err != nil {
			// Entropy failure must not panic or silently downgrade to predictable randomness.
			return nil
		}
		j := int(nBig.Int64())
		pool[i], pool[j] = pool[j], pool[i]
	}

	// Select first k elements and sort them
	result := make([]int, k)
	copy(result, pool[:k])
	sort.Ints(result)
	return result
}
