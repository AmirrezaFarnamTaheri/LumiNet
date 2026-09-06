// Package diagnostics provides jq evaluation utilities.
// JQ evaluator wrapper
// for LumiNet's config/telemetry filtering needs.
package diagnostics

import (
	"context"
	"fmt"
	"io"

	"github.com/itchyny/gojq"
)

const maxJQResults = 4096

// EvalQuery evaluates a jq query against one caller-supplied value. It does not
// install module or environment loaders and bounds materialized output so a
// valid but expanding jq expression cannot grow memory without limit.
func EvalQuery(ctx context.Context, query string, input any) ([]any, error) {
	if ctx == nil {
		return nil, fmt.Errorf("nil jq context")
	}
	q, err := gojq.Parse(query)
	if err != nil {
		return nil, err
	}
	iter := q.RunWithContext(ctx, input)
	out := make([]any, 0, 16)
	for {
		v, ok := iter.Next()
		if !ok {
			break
		}
		if err, ok := v.(error); ok {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		if len(out) >= maxJQResults {
			return nil, fmt.Errorf("jq result limit exceeded (%d)", maxJQResults)
		}
		out = append(out, v)
	}
	return out, nil
}
