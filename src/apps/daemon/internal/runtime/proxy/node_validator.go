package proxy

import "fmt"

// NodeProfile describes a proxy node for validation.
type NodeProfile struct {
	Type     string
	Address  string
	Port     int
	Password string
}

// ValidationResult holds the outcome of a node profile validation.
type ValidationResult struct {
	success bool
	reason  string
}

// Success returns true if the node profile is valid.
func (r *ValidationResult) Success() bool {
	return r.success
}

// Reason returns the human-readable failure reason (empty on success).
func (r *ValidationResult) Reason() string {
	return r.reason
}

// NodeValidator validates proxy node profiles for structural correctness.
type NodeValidator struct{}

// NewNodeValidator returns a new NodeValidator.
func NewNodeValidator() *NodeValidator {
	return &NodeValidator{}
}

// Validate checks that the NodeProfile has all required fields populated.
func (v *NodeValidator) Validate(p *NodeProfile) *ValidationResult {
	if p == nil {
		return &ValidationResult{false, "nil profile"}
	}
	if p.Type == "" {
		return &ValidationResult{false, "type is required"}
	}
	if p.Address == "" {
		return &ValidationResult{false, "address is required"}
	}
	if p.Port <= 0 || p.Port > 65535 {
		return &ValidationResult{false, fmt.Sprintf("invalid port: %d", p.Port)}
	}
	if p.Password == "" {
		return &ValidationResult{false, "password is required"}
	}
	return &ValidationResult{true, ""}
}
