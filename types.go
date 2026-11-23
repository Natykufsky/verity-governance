package governance

import (
	"time"

	"github.com/google/uuid"
)

// State represents the explicit lifecycle state of a governance request.
type State string

const (
	StatePending   State = "pending"
	StateApproved  State = "approved"
	StateExecuting State = "executing"
	StateExecuted  State = "executed"
	StateFailed    State = "failed"
	StateRejected  State = "rejected"
	StateExpired   State = "expired"
	StateCancelled State = "cancelled"
)

// IsTerminal reports whether the state cannot transition further.
func (s State) IsTerminal() bool {
	switch s {
	case StateExecuted, StateFailed, StateRejected, StateExpired, StateCancelled:
		return true
	default:
		return false
	}
}

// IsLegalTransition validates state machine transitions per the v2 governance specification.
// Note: pending -> executed and approved -> executed are intentionally forbidden;
// every execution must pass through StateExecuting.
func IsLegalTransition(from, to State) bool {
	if from == to {
		return true
	}
	switch from {
	case StatePending:
		return to == StateApproved || to == StateRejected || to == StateExpired || to == StateCancelled
	case StateApproved:
		return to == StateExecuting || to == StateCancelled
	case StateExecuting:
		return to == StateExecuted || to == StateFailed
	default:
		return false
	}
}

// Principal represents the host-agnostic authenticated actor invoking governance operations.
type Principal struct {
	ActorID uuid.UUID         `json:"actor_id"`
	OrgID   uuid.UUID         `json:"org_id"`
	Roles   []string          `json:"roles,omitempty"`
	Meta    map[string]string `json:"meta,omitempty"`
}

// PolicyRule defines a versioned, tenant- and scope-bound maker-checker rule.
type PolicyRule struct {
	ID                   uuid.UUID  `json:"id"`
	Version              int        `json:"version"`
	RootID               uuid.UUID  `json:"root_id"`
	OrgID                uuid.UUID  `json:"org_id"`
	ScopeID              uuid.UUID  `json:"scope_id"`
	Permission           string     `json:"permission"`
	MinAmount            *float64   `json:"min_amount,omitempty"`
	MaxAmount            *float64   `json:"max_amount,omitempty"`
	MakerRoles           []string   `json:"maker_roles"`
	CheckerRoles         []string   `json:"checker_roles"`
	RequiredApprovals    int        `json:"required_approvals"`
	RequiredReason       bool       `json:"required_reason"`
	AllowSelfApproval    bool       `json:"allow_self_approval"`
	RequireStepUp        bool       `json:"require_step_up"`
	ExpiresInHours       int        `json:"expires_in_hours"`
	MaxPayloadBytes      int        `json:"max_payload_bytes"`
	PayloadSchemaVersion int        `json:"payload_schema_version"`
	IsActive             bool       `json:"is_active"`
	DeletedAt            *time.Time `json:"deleted_at,omitempty"`
	CreatedBy            uuid.UUID  `json:"created_by"`
	CreatedAt            time.Time  `json:"created_at"`
	UpdatedBy            *uuid.UUID `json:"updated_by,omitempty"`
	UpdatedAt            time.Time  `json:"updated_at"`
}

// Ticket represents an immutable-snapshot maker-checker request in the governance ledger.
type Ticket struct {
	ID                   uuid.UUID          `json:"id"`
	OrgID                uuid.UUID          `json:"org_id"`
	ScopeID              uuid.UUID          `json:"scope_id"`
	Permission           string             `json:"permission"`
	TargetResourceType   string             `json:"target_resource_type"`
	TargetResourceID     string             `json:"target_resource_id,omitempty"`
	Title                string             `json:"title"`
	Description          string             `json:"description,omitempty"`
	Payload              map[string]any     `json:"payload,omitempty"`
	PayloadEnc           []byte             `json:"-"`
	PayloadHash          []byte             `json:"-"`
	PayloadHashHex       string             `json:"payload_hash"`
	PayloadSig           []byte             `json:"-"`
	PayloadBytes         int                `json:"payload_bytes"`
	PayloadSchemaVersion int                `json:"payload_schema_version"`
	PolicyRuleID         uuid.UUID          `json:"policy_rule_id"`
	PolicySnapshot       PolicyRule         `json:"policy_snapshot"`
	RequiredApprovals    int                `json:"required_approvals"`
	ApprovalsCount       int                `json:"approvals_count"`
	State                State              `json:"state"`
	RequestedBy          uuid.UUID          `json:"requested_by"`
	RequestedFromIP      string             `json:"requested_from_ip,omitempty"`
	RequestedVia         string             `json:"requested_via"`
	IdempotencyKey       string             `json:"idempotency_key"`
	CancelReason         string             `json:"cancel_reason,omitempty"`
	CancelledBy          *uuid.UUID         `json:"cancelled_by,omitempty"`
	CancelledAt          *time.Time         `json:"cancelled_at,omitempty"`
	ExpiresAt            time.Time          `json:"expires_at"`
	ExpiredAt            *time.Time         `json:"expired_at,omitempty"`
	ExecutingAt          *time.Time         `json:"executing_at,omitempty"`
	ExecutedAt           *time.Time         `json:"executed_at,omitempty"`
	FailedAt             *time.Time         `json:"failed_at,omitempty"`
	ExecutionAttempts    int                `json:"execution_attempts"`
	ExecutionResult      *ExecutionResult   `json:"execution_result,omitempty"`
	Approvals            []ApprovalDecision `json:"approvals,omitempty"`
	CreatedAt            time.Time          `json:"created_at"`
	UpdatedAt            time.Time          `json:"updated_at"`
}

// ApprovalDecision records one checker's decision on a ticket (M-of-N audit trail).
type ApprovalDecision struct {
	ID            uuid.UUID `json:"id"`
	RequestID     uuid.UUID `json:"request_id"`
	ApproverID    uuid.UUID `json:"approver_id"`
	Decision      string    `json:"decision"` // "approved" | "rejected"
	Reason        string    `json:"reason,omitempty"`
	DecidedVia    string    `json:"decided_via"`
	DecidedFromIP string    `json:"decided_from_ip,omitempty"`
	StepUpUsed    bool      `json:"step_up_used"`
	DecidedAt     time.Time `json:"decided_at"`
}

// OutboxItem represents a queued crash-safe execution job in governance_outbox.
type OutboxItem struct {
	ID            uuid.UUID  `json:"id"`
	RequestID     uuid.UUID  `json:"request_id"`
	OrgID         uuid.UUID  `json:"org_id"`
	PayloadEnc    []byte     `json:"-"`
	ActionKey     string     `json:"action_key"`
	Attempts      int        `json:"attempts"`
	LastError     string     `json:"last_error,omitempty"`
	NextAttemptAt time.Time  `json:"next_attempt_at"`
	CompletedAt   *time.Time `json:"completed_at,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
}

// ExecutionResult is the typed outcome persisted in governance_request.execution_result.
type ExecutionResult struct {
	Status    string         `json:"status"` // "ok" | "noop" | "rejected" | "failed"
	ErrorCode string         `json:"error_code,omitempty"`
	Detail    string         `json:"detail,omitempty"`
	Output    map[string]any `json:"output,omitempty"`
}

// Decision is returned by Preview (dry-run evaluation).
type Decision struct {
	RequiresApproval bool        `json:"requires_approval"`
	ShadowMode       bool        `json:"shadow_mode,omitempty"`
	Rule             *PolicyRule `json:"rule,omitempty"`
	Reason           string      `json:"reason"`
}

// SubmitInput carries parameters to create a new governance ticket.
type SubmitInput struct {
	Principal      Principal
	Permission     string
	ScopeID        uuid.UUID
	Amount         *float64
	TargetType     string
	TargetID       string
	Title          string
	Description    string
	Payload        map[string]any
	RequestedVia   string // "web", "mobile", "api", "cli"
	RequestedFromIP string
	IdempotencyKey string // required; retries return the same ticket
}

// DecisionInput carries parameters for Approve or Reject.
type DecisionInput struct {
	Principal     Principal
	RequestID     uuid.UUID
	StepUpToken   string
	Reason        string
	PayloadHash   []byte // raw bytes; if empty, PayloadHashHex is decoded
	PayloadHashHex string
	DecidedVia    string
	DecidedFromIP string
}

// RuleInput carries parameters for creating or updating (versioning) a PolicyRule.
type RuleInput struct {
	ScopeID              uuid.UUID `json:"scope_id"`
	Permission           string    `json:"permission"`
	MinAmount            *float64  `json:"min_amount,omitempty"`
	MaxAmount            *float64  `json:"max_amount,omitempty"`
	MakerRoles           []string  `json:"maker_roles,omitempty"`
	CheckerRoles         []string  `json:"checker_roles"`
	RequiredApprovals    int       `json:"required_approvals,omitempty"`
	RequiredReason       bool      `json:"required_reason,omitempty"`
	AllowSelfApproval    bool      `json:"allow_self_approval,omitempty"`
	RequireStepUp        *bool     `json:"require_step_up,omitempty"` // defaults to true if nil
	ExpiresInHours       int       `json:"expires_in_hours,omitempty"`
	MaxPayloadBytes      int       `json:"max_payload_bytes,omitempty"`
	PayloadSchemaVersion int       `json:"payload_schema_version,omitempty"`
}

// ListFilter filters tickets returned by Engine.List.
type ListFilter struct {
	States      []State
	Permission  string
	ScopeID     *uuid.UUID
	RequestedBy *uuid.UUID
	CreatedFrom *time.Time
	CreatedTo   *time.Time
	Page        int // 1-based; default 1
	PageSize    int // default 50, max 200
}

// RuleFilter filters active rules returned by Engine.ListRules.
type RuleFilter struct {
	Permission string
	ScopeID    *uuid.UUID
}

// Page wraps paginated query results.
type Page[T any] struct {
	Items      []T `json:"items"`
	Total      int `json:"total"`
	Page       int `json:"page"`
	PageSize   int `json:"page_size"`
	TotalPages int `json:"total_pages"`
}

// EventType identifies the 12 canonical governance lifecycle events.
type EventType string

const (
	EventRequestCreated      EventType = "governance.request.created"
	EventRequestApproved     EventType = "governance.request.approved"
	EventRequestRejected     EventType = "governance.request.rejected"
	EventRequestExpired      EventType = "governance.request.expired"
	EventRequestCancelled    EventType = "governance.request.cancelled"
	EventRequestExecuting    EventType = "governance.request.executing"
	EventRequestExecuted     EventType = "governance.request.executed"
	EventRequestFailed       EventType = "governance.request.failed"
	EventRequestSelfApproved EventType = "governance.request.self_approved"
	EventRuleCreated         EventType = "governance.rule.created"
	EventRuleUpdated         EventType = "governance.rule.updated"
	EventRuleDeleted         EventType = "governance.rule.deleted"
)

// Event is emitted on every governance state or rule transition.
type Event struct {
	Type        EventType      `json:"type"`
	OrgID       uuid.UUID      `json:"org_id"`
	ScopeID     uuid.UUID      `json:"scope_id,omitempty"`
	RequestID   uuid.UUID      `json:"request_id,omitempty"`
	RuleID      uuid.UUID      `json:"rule_id,omitempty"`
	ActorID     uuid.UUID      `json:"actor_id,omitempty"`
	Permission  string         `json:"permission,omitempty"`
	PayloadHash string         `json:"payload_hash,omitempty"`
	OccurredAt  time.Time      `json:"occurred_at"`
	Metadata    map[string]any `json:"metadata,omitempty"`
}

// Notification describes an out-of-band notification dispatched by the Engine.
type Notification struct {
	EventType      EventType  `json:"event_type"`
	OrgID          uuid.UUID  `json:"org_id"`
	ScopeID        uuid.UUID  `json:"scope_id"`
	RequestID      uuid.UUID  `json:"request_id"`
	Permission     string     `json:"permission"`
	Title          string     `json:"title"`
	RecipientRoles []string   `json:"recipient_roles,omitempty"`
	RecipientIDs   []uuid.UUID `json:"recipient_ids,omitempty"`
	Message        string     `json:"message"`
	OccurredAt     time.Time  `json:"occurred_at"`
}

