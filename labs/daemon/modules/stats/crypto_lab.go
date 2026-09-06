// Package stats provides analytics, machine learning, and uptime telemetry logic.
// Ported from: My-CryptoLab-Project
// Target path: server/internal/stats/crypto_lab.go

package stats

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"log/slog"
	"math"
	"sync"
)

// CryptoLabEngine handles feature extraction and walk-forward prediction.
type CryptoLabEngine struct {
	mu         sync.RWMutex
	windowSize int
}

// NewCryptoLabEngine creates a new CryptoLab instance.
func NewCryptoLabEngine() *CryptoLabEngine {
	return &CryptoLabEngine{
		windowSize: 10,
	}
}

// 1. pearsonCorrelation computes the Pearson correlation coefficient between two slices.
func (c *CryptoLabEngine) pearsonCorrelation(x, y []float64) float64 {
	n := len(x)
	if n == 0 || n != len(y) {
		return 0.0
	}

	var sumX, sumY, sumXY, sumX2, sumY2 float64
	for i := 0; i < n; i++ {
		sumX += x[i]
		sumY += y[i]
		sumXY += x[i] * y[i]
		sumX2 += x[i] * x[i]
		sumY2 += y[i] * y[i]
	}

	num := float64(n)*sumXY - sumX*sumY
	den := math.Sqrt((float64(n)*sumX2 - sumX*sumX) * (float64(n)*sumY2 - sumY*sumY))
	if den == 0 {
		return 0.0
	}

	return num / den
}

// 2. ThreeBranchFeatureExtractor processes asset, context, and graph neighbor rolling correlations.
func (c *CryptoLabEngine) ThreeBranchFeatureExtractor(assetData, contextData, graphData []float64) []float64 {
	slog.Info("CryptoLab: extracting 3-branch features via rolling Pearson correlation")

	c.mu.RLock()
	window := c.windowSize
	c.mu.RUnlock()

	if len(assetData) < window || len(contextData) < window || len(graphData) < window {
		return nil
	}

	length := len(assetData)
	features := make([]float64, 0, length-window+1)

	for i := 0; i <= length-window; i++ {
		end := i + window
		assetSub := assetData[i:end]
		contextSub := contextData[i:end]
		graphSub := graphData[i:end]

		r1 := c.pearsonCorrelation(assetSub, contextSub)
		r2 := c.pearsonCorrelation(assetSub, graphSub)

		score := 0.6*r1 + 0.4*r2
		features = append(features, score)
	}

	return features
}

// 3. WalkForwardValidation implements walk-forward prediction validation logic.
func (c *CryptoLabEngine) WalkForwardValidation(features []float64, target []float64, windowSize int) float64 {
	log.Printf("CryptoLab: Running Walk-Forward Validation with window %d", windowSize)

	if len(features) < windowSize || len(target) < windowSize {
		return 0.0
	}

	var errorSum float64
	steps := len(features) - windowSize

	for i := 0; i < steps; i++ {
		pred := features[i+windowSize-1]
		actual := target[i+windowSize]

		diff := pred - actual
		errorSum += diff * diff
	}

	mse := errorSum / float64(steps)
	log.Printf("CryptoLab: Walk-Forward Validation completed. MSE: %.4f", mse)
	return mse
}

// 4. SetWindowSize configures rolling window limits.
func (c *CryptoLabEngine) SetWindowSize(w int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.windowSize = w
}

// 5. GetWindowSize returns active rolling window limits.
func (c *CryptoLabEngine) GetWindowSize() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.windowSize
}

// 6. CalculateMean computes standard average indicators.
func (c *CryptoLabEngine) CalculateMean(data []float64) float64 {
	n := len(data)
	if n == 0 {
		return 0.0
	}
	var sum float64
	for _, val := range data {
		sum += val
	}
	return sum / float64(n)
}

// 7. CalculateVariance computes statistical variance limits.
func (c *CryptoLabEngine) CalculateVariance(data []float64) float64 {
	n := len(data)
	if n < 2 {
		return 0.0
	}
	mean := c.CalculateMean(data)
	var sum float64
	for _, val := range data {
		diff := val - mean
		sum += diff * diff
	}
	return sum / float64(n-1)
}

// 8. CalculateStandardDeviation returns square root of variance.
func (c *CryptoLabEngine) CalculateStandardDeviation(data []float64) float64 {
	return math.Sqrt(c.CalculateVariance(data))
}

// 9. CalculateCovariance calculates covariance.
func (c *CryptoLabEngine) CalculateCovariance(x, y []float64) float64 {
	n := len(x)
	if n == 0 || n != len(y) {
		return 0.0
	}
	meanX := c.CalculateMean(x)
	meanY := c.CalculateMean(y)

	var sum float64
	for i := 0; i < n; i++ {
		sum += (x[i] - meanX) * (y[i] - meanY)
	}
	return sum / float64(n)
}

// 10. CalculateMSE returns mean squared errors.
func (c *CryptoLabEngine) CalculateMSE(actual, predicted []float64) (float64, error) {
	n := len(actual)
	if n == 0 || n != len(predicted) {
		return 0.0, fmt.Errorf("slice length mismatch")
	}

	var sum float64
	for i := 0; i < n; i++ {
		diff := actual[i] - predicted[i]
		sum += diff * diff
	}
	return sum / float64(n), nil
}

// 11. CalculateMAE returns mean absolute errors.
func (c *CryptoLabEngine) CalculateMAE(actual, predicted []float64) (float64, error) {
	n := len(actual)
	if n == 0 || n != len(predicted) {
		return 0.0, fmt.Errorf("slice length mismatch")
	}

	var sum float64
	for i := 0; i < n; i++ {
		sum += math.Abs(actual[i] - predicted[i])
	}
	return sum / float64(n), nil
}

// 12. ExportFeaturesJSON saves features matrix to JSON.
func (c *CryptoLabEngine) ExportFeaturesJSON(features []float64, filePath string) error {
	data, err := json.MarshalIndent(features, "", "  ")
	if err != nil {
		return err
	}
	return ioutil.WriteFile(filePath, data, 0644)
}

// 13. NormalizeData maps data to [0.0, 1.0].
func (c *CryptoLabEngine) NormalizeData(data []float64) []float64 {
	if len(data) == 0 {
		return nil
	}
	min := data[0]
	max := data[0]
	for _, val := range data {
		if val < min {
			min = val
		}
		if val > max {
			max = val
		}
	}
	if max == min {
		return make([]float64, len(data))
	}

	norm := make([]float64, len(data))
	for idx, val := range data {
		norm[idx] = (val - min) / (max - min)
	}
	return norm
}

// 14. RollingMean calculates moving averages.
func (c *CryptoLabEngine) RollingMean(data []float64, window int) []float64 {
	if len(data) < window || window <= 0 {
		return nil
	}
	var res []float64
	for i := 0; i <= len(data)-window; i++ {
		sub := data[i : i+window]
		res = append(res, c.CalculateMean(sub))
	}
	return res
}

// 15. RunAnalytics is the diagnostic entry trigger.
func (c *CryptoLabEngine) RunAnalytics() {
	// Diagnostic stub
}
