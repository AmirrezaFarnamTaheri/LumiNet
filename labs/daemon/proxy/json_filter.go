package proxy

import (
	"encoding/json"
	"fmt"

	"github.com/itchyny/gojq"
)

// ExecuteJSONFilter parses the input JSON, compiles the JQ query string,
// and executes it, returning the transformed object.
func ExecuteJSONFilter(jsonData []byte, queryStr string) (interface{}, error) {
	var input interface{}
	if err := json.Unmarshal(jsonData, &input); err != nil {
		return nil, fmt.Errorf("invalid input JSON: %w", err)
	}

	query, err := gojq.Parse(queryStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JQ query: %w", err)
	}

	iter := query.Run(input)
	var results []interface{}
	for {
		v, ok := iter.Next()
		if !ok {
			break
		}
		if err, ok := v.(error); ok {
			return nil, fmt.Errorf("JQ execution error: %w", err)
		}
		results = append(results, v)
	}

	if len(results) == 0 {
		return nil, nil
	}
	if len(results) == 1 {
		return results[0], nil
	}
	return results, nil
}

// TransformSubscriptionJSON applies a JQ query to transform nested subscription JSON blocks.
func TransformSubscriptionJSON(jsonData []byte, queryStr string) ([]byte, error) {
	res, err := ExecuteJSONFilter(jsonData, queryStr)
	if err != nil {
		return nil, err
	}
	out, err := json.Marshal(res)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal JQ result: %w", err)
	}
	return out, nil
}
