package governance

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"
)

// ActionExecutor executes an approved governance ticket payload.
// Execute MUST be idempotent on reqID: calling twice with the same reqID must
// produce the same external effect as calling once.
type ActionExecutor interface {
	Execute(ctx context.Context, reqID uuid.UUID, payload map[string]any) (ExecutionResult, error)
}

// ActionExecutorFunc adapts an ordinary function to ActionExecutor.
type ActionExecutorFunc func(ctx context.Context, reqID uuid.UUID, payload map[string]any) (ExecutionResult, error)

func (f ActionExecutorFunc) Execute(ctx context.Context, reqID uuid.UUID, payload map[string]any) (ExecutionResult, error) {
	return f(ctx, reqID, payload)
}

// ScopeResolver resolves the ancestor hierarchy for a scope within a tenant org.
// Returned slice MUST be ordered from most-specific (scopeID at index 0) to root (last index).
type ScopeResolver interface {
	Ancestors(ctx context.Context, orgID, scopeID uuid.UUID) ([]uuid.UUID, error)
}

// RoleResolver answers role-membership and rule-creation validation queries against the host IAM.
type RoleResolver interface {
	// HoldsRole answers whether the principal holds `role` at `scopeID` (including inheritance).
	HoldsRole(ctx context.Context, p Principal, role string, scopeID uuid.UUID) (bool, error)
	// ValidateRolesForScope rejects roles that do not exist or cannot be held at `scopeID`.
	ValidateRolesForScope(ctx context.Context, orgID, scopeID uuid.UUID, roles []string) error
}

// IdentityGuard returns a canonical identity hash (e.g. SHA-256 of verified email/phone)
// to prevent the same human from self-approving using two distinct accounts.
type IdentityGuard interface {
	IdentityHash(ctx context.Context, actorID uuid.UUID) (string, error)
}

// StepUpVerifier validates a fresh step-up authentication token (e.g. TOTP / sudo password).
type StepUpVerifier interface {
	VerifyStepUp(ctx context.Context, p Principal, token string) error
}

// CryptoProvider performs RFC 8785-style canonicalization, SHA-256 hashing,
// Ed25519 signing/verification, and enc:v2 envelope encryption/decryption.
type CryptoProvider interface {
	Canonicalize(payload map[string]any) ([]byte, error)
	Hash(canonical []byte) []byte
	Sign(meta string, hash []byte) ([]byte, error)
	Verify(meta string, hash, sig []byte) bool
	Encrypt(workspace string, plaintext []byte) ([]byte, error)
	Decrypt(ciphertext []byte) ([]byte, error)
}

// EventPublisher publishes immutable governance lifecycle events (e.g. NATS JetStream, Kafka, webhooks).
type EventPublisher interface {
	Publish(ctx context.Context, event Event) error
}

// Notifier dispatches out-of-band notifications (email, push, in-app).
// Failures are logged and never roll back governance state transitions.
type Notifier interface {
	Notify(ctx context.Context, n Notification) error
}

// Clock provides current time for deterministic expiry and SLA testing.
type Clock interface {
	Now() time.Time
}

// RealClock returns time.Now().UTC().
type RealClock struct{}

func (RealClock) Now() time.Time { return time.Now().UTC() }

// RecordApprovalResult summarizes the atomic approval transaction outcome.
type RecordApprovalResult struct {
	Ticket             *Ticket
	ThresholdReached   bool
	IdempotentReplay   bool
	EnqueuedForExecute bool
}

// Store is the persistence boundary implemented by memstore (tests) and pgstore (PostgreSQL).
// All tenant-scoped methods MUST enforce strict orgID isolation (returning ErrNotFound on mismatch).
type Store interface {
	// Rules (append-only versioned)
	CreateRule(ctx context.Context, rule *PolicyRule) (*PolicyRule, error)
	UpdateRuleVersion(ctx context.Context, orgID, rootID uuid.UUID, next *PolicyRule) (*PolicyRule, error)
	SoftDeleteRule(ctx context.Context, orgID, rootID, deletedBy uuid.UUID, now time.Time) (*PolicyRule, error)
	ListActiveRules(ctx context.Context, orgID uuid.UUID, filter RuleFilter) ([]PolicyRule, error)
	ListRuleVersions(ctx context.Context, orgID, rootID uuid.UUID) ([]PolicyRule, error)
	ResolveMatchingRule(ctx context.Context, orgID uuid.UUID, ancestors []uuid.UUID, permission string, amount *float64) (*PolicyRule, error)

	// Requests / Tickets
	CreateTicketIdempotent(ctx context.Context, ticket *Ticket) (stored *Ticket, created bool, err error)
	GetTicket(ctx context.Context, orgID, requestID uuid.UUID) (*Ticket, error)
	ListTickets(ctx context.Context, orgID uuid.UUID, filter ListFilter) (Page[Ticket], error)

	// Atomic state transitions
	RecordApprovalAndMaybeEnqueue(
		ctx context.Context,
		orgID, requestID uuid.UUID,
		decision ApprovalDecision,
		actionKey string,
		now time.Time,
	) (RecordApprovalResult, error)

	RecordRejection(
		ctx context.Context,
		orgID, requestID uuid.UUID,
		decision ApprovalDecision,
		now time.Time,
	) (*Ticket, error)

	CancelTicket(
		ctx context.Context,
		orgID, requestID, actorID uuid.UUID,
		reason string,
		now time.Time,
	) (*Ticket, error)

	// Outbox worker operations
	ClaimOutboxBatch(ctx context.Context, now time.Time, limit int) ([]OutboxItem, error)
	GetTicketByIDForWorker(ctx context.Context, orgID, requestID uuid.UUID) (*Ticket, error)
	MarkOutboxExecuted(ctx context.Context, orgID, requestID uuid.UUID, result ExecutionResult, now time.Time) error
	MarkOutboxRetry(ctx context.Context, outboxID uuid.UUID, errMsg string, nextAttempt time.Time) error
	MarkOutboxFailed(ctx context.Context, orgID, requestID, outboxID uuid.UUID, result ExecutionResult, errMsg string, now time.Time) error

	// Expiry worker operations
	ExpirePendingTickets(ctx context.Context, now time.Time, limit int) ([]Ticket, error)
}

// -----------------------------------------------------------------------------
// Built-in Noop & Static Helper Implementations
// -----------------------------------------------------------------------------

type NoopEventPublisher struct{}

func (NoopEventPublisher) Publish(context.Context, Event) error { return nil }

type NoopNotifier struct{}

func (NoopNotifier) Notify(context.Context, Notification) error { return nil }

// StaticScopeResolver is a lightweight in-memory ScopeResolver for tests and flat hierarchies.
type StaticScopeResolver struct {
	mu      sync.RWMutex
	parents map[uuid.UUID]uuid.UUID
}

func NewStaticScopeResolver() *StaticScopeResolver {
	return &StaticScopeResolver{parents: make(map[uuid.UUID]uuid.UUID)}
}

func (r *StaticScopeResolver) SetParent(child, parent uuid.UUID) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.parents[child] = parent
}

func (r *StaticScopeResolver) Ancestors(_ context.Context, _ uuid.UUID, scopeID uuid.UUID) ([]uuid.UUID, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	chain := []uuid.UUID{scopeID}
	seen := map[uuid.UUID]bool{scopeID: true}
	cur := scopeID
	for {
		p, ok := r.parents[cur]
		if !ok || p == uuid.Nil || seen[p] {
			break
		}
		seen[p] = true
		chain = append(chain, p)
		cur = p
	}
	return chain, nil
}

// StaticRoleResolver is an in-memory RoleResolver useful for unit tests and prototypes.
type StaticRoleResolver struct {
	mu          sync.RWMutex
	allowed     map[string]bool                         // global catalog of valid roles
	scopeRoles  map[uuid.UUID]map[string]bool           // optional per-scope allowed roles
	assignments map[uuid.UUID]map[uuid.UUID]map[string]bool // actor -> scope -> role
	scopes      ScopeResolver
}

func NewStaticRoleResolver(scopes ScopeResolver, validRoles ...string) *StaticRoleResolver {
	allowed := make(map[string]bool, len(validRoles))
	for _, r := range validRoles {
		allowed[r] = true
	}
	return &StaticRoleResolver{
		allowed:     allowed,
		scopeRoles:  make(map[uuid.UUID]map[string]bool),
		assignments: make(map[uuid.UUID]map[uuid.UUID]map[string]bool),
		scopes:      scopes,
	}
}

func (r *StaticRoleResolver) RestrictScopeRoles(scopeID uuid.UUID, roles ...string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	m := make(map[string]bool, len(roles))
	for _, role := range roles {
		m[role] = true
	}
	r.scopeRoles[scopeID] = m
}

func (r *StaticRoleResolver) Grant(actorID, scopeID uuid.UUID, role string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.assignments[actorID] == nil {
		r.assignments[actorID] = make(map[uuid.UUID]map[string]bool)
	}
	if r.assignments[actorID][scopeID] == nil {
		r.assignments[actorID][scopeID] = make(map[string]bool)
	}
	r.assignments[actorID][scopeID][role] = true
}

func (r *StaticRoleResolver) HoldsRole(ctx context.Context, p Principal, role string, scopeID uuid.UUID) (bool, error) {
	// Check explicit principal roles if no scope assignments configured
	r.mu.RLock()
	actorScopes := r.assignments[p.ActorID]
	r.mu.RUnlock()

	if actorScopes != nil {
		ancestors := []uuid.UUID{scopeID}
		if r.scopes != nil {
			if chain, err := r.scopes.Ancestors(ctx, p.OrgID, scopeID); err == nil && len(chain) > 0 {
				ancestors = chain
			}
		}
		r.mu.RLock()
		defer r.mu.RUnlock()
		// Also allow uuid.Nil as global grant
		for _, sc := range append(ancestors, uuid.Nil) {
			if actorScopes[sc][role] {
				return true, nil
			}
		}
		return false, nil
	}

	for _, held := range p.Roles {
		if held == role {
			return true, nil
		}
	}
	return false, nil
}

func (r *StaticRoleResolver) ValidateRolesForScope(_ context.Context, _, scopeID uuid.UUID, roles []string) error {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if restricted, ok := r.scopeRoles[scopeID]; ok {
		for _, role := range roles {
			if !restricted[role] {
				return NewError(CodeInvalidRule, "role '"+role+"' cannot be held in target scope")
			}
		}
		return nil
	}
	if len(r.allowed) == 0 {
		return nil
	}
	for _, role := range roles {
		if !r.allowed[role] {
			return NewError(CodeInvalidRule, "unknown role '"+role+"'")
		}
	}
	return nil
}

