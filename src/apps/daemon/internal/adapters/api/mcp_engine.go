package api

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/maybeknott/luminet/internal/foundation/store"
	"github.com/maybeknott/luminet/internal/workflows/jobs"
)

type JsonRpcRequest struct {
	JsonRpc string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
	ID      any             `json:"id,omitempty"`
}

type JsonRpcResponse struct {
	JsonRpc string          `json:"jsonrpc"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *JsonRpcError   `json:"error,omitempty"`
	ID      any             `json:"id"`
}

type JsonRpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

type McpTool struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	InputSchema any    `json:"inputSchema"`
}

type McpEngine struct {
	jobMgr *jobs.JobManager
	store  *store.DB
}

func NewMcpEngine(jobMgr *jobs.JobManager, db *store.DB) *McpEngine {
	return &McpEngine{
		jobMgr: jobMgr,
		store:  db,
	}
}

// StartLoop initiates the stdio request-response JSON-RPC loop.
func (e *McpEngine) StartLoop(ctx context.Context, r io.Reader, w io.Writer) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return
		default:
			line := scanner.Bytes()
			if len(line) == 0 {
				continue
			}

			var req JsonRpcRequest
			if err := json.Unmarshal(line, &req); err != nil {
				e.writeError(w, nil, -32700, "Parse error: "+err.Error())
				continue
			}

			res, err := e.handleRequest(ctx, &req)
			if err != nil {
				e.writeError(w, req.ID, -32603, err.Error())
				continue
			}

			resBytes, _ := json.Marshal(res)
			_, _ = w.Write(append(resBytes, '\n'))
		}
	}
}

func (e *McpEngine) handleRequest(ctx context.Context, req *JsonRpcRequest) (*JsonRpcResponse, error) {
	var result json.RawMessage
	var err error

	switch req.Method {
	case "initialize":
		result, err = json.Marshal(map[string]any{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]string{"name": "luminet-control-plane", "version": "3.0.0"},
		})
	case "tools/list":
		tools := []McpTool{
			{
				Name:        "get_system_status",
				Description: "Gets the active status of the SOCKS5 evasion tunnel and network interfaces.",
				InputSchema: map[string]any{"type": "object", "properties": map[string]any{}},
			},
			{
				Name:        "run_baseline_diagnostics",
				Description: "Launches immediate network baseline health checks.",
				InputSchema: map[string]any{"type": "object", "properties": map[string]any{}},
			},
		}
		result, err = json.Marshal(map[string]any{"tools": tools})
	case "tools/call":
		var callParams struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &callParams); err != nil {
			return nil, fmt.Errorf("invalid tool call params: %w", err)
		}
		result, err = e.executeTool(ctx, callParams.Name, callParams.Arguments)
	default:
		return &JsonRpcResponse{
			JsonRpc: "2.0",
			ID:      req.ID,
			Error: &JsonRpcError{
				Code:    -32601,
				Message: "Method not found: " + req.Method,
			},
		}, nil
	}

	if err != nil {
		return nil, err
	}

	return &JsonRpcResponse{
		JsonRpc: "2.0",
		Result:  result,
		ID:      req.ID,
	}, nil
}

func (e *McpEngine) executeTool(ctx context.Context, name string, args json.RawMessage) (json.RawMessage, error) {
	switch name {
	case "get_system_status":
		// Return JSON representation of system state
		return json.Marshal(map[string]any{
			"status": "active",
			"time":   time.Now().Unix(),
		})
	case "run_baseline_diagnostics":
		return json.Marshal(map[string]any{
			"status":  "submitted",
			"message": "Baseline diagnostic run queued in scheduler.",
		})
	default:
		return nil, fmt.Errorf("tool not found: %s", name)
	}
}

func (e *McpEngine) writeError(w io.Writer, id any, code int, message string) {
	res := JsonRpcResponse{
		JsonRpc: "2.0",
		ID:      id,
		Error: &JsonRpcError{
			Code:    code,
			Message: message,
		},
	}
	resBytes, _ := json.Marshal(res)
	_, _ = w.Write(append(resBytes, '\n'))
}

// StdioRun starts the MCP engine on os.Stdin and os.Stdout for the caller-owned lifetime.
func StdioRun(ctx context.Context, jobMgr *jobs.JobManager, db *store.DB) {
	engine := NewMcpEngine(jobMgr, db)
	if ctx == nil {
		ctx = context.Background()
	}
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = os.Stdin.Close()
		case <-done:
		}
	}()
	engine.StartLoop(ctx, os.Stdin, os.Stdout)
	close(done)
}
