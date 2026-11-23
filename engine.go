package governance

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

const (
	DefaultExpiresInHours       = 72
	MinExpiresInHours           = 1
	MaxExpiresInHours           = 720
	DefaultMaxPayloadBytes      = 65536
	MinMaxPayloadBytes          = 1024
	MaxMaxPayloadBytes          = 1048576
	DefaultRuleCacheTTL         = 60 * time.Second
	DefaultOutboxMaxAttempts    = 5
	DefaultOutboxBaseBackoff    = 5 * time.Second
)

// Config configures a Governance Engine instance.
type Config struct {
	Store          Store
	Scopes         ScopeResolver
	Roles          RoleResolver
	Crypto         CryptoProvider
	IdentityGuard  IdentityGuard   // optional: blocks dual-account self-approval by email/phone hash
	StepUpVerifier StepUpVerifier  // optional: required when a matched rule sets RequireStepUp=true
	Events         EventPublisher  // optional: defaults to NoopEventPublisher
	Notifier       Notifier        // optional: defaults to NoopNotifier
	Metrics        MetricsRecorder // optional: defaults to NoopMetrics
	Clock          Clock           // optional: defaults to RealClock
	Logger         *slog.Logger    // optional: defaults to slog.Default()
	RuleCacheTTL   time.Duration   // optional: defaults to 60s; negative disables caching

	// Rollout controls (§14):
	// ShadowMode logs governance_shadow_hold_total without blocking callers unless
	// the permission is explicitly listed in EnforcedPermissions.
	ShadowMode          bool
	EnforcedPermissions map[string]bool
}

type ruleCacheEntry struct {
	rule      *PolicyRule
	expiresAt time.Time
}

// Engine orchestrates dynamic Maker-Checker policy evaluation, cryptographic binding,
// dual-custody M-of-N approvals, rule versioning, and crash-safe execution dispatch.
type Engine struct {
	store          Store
	scopes         ScopeResolver
	roles          RoleResolver
	crypto         CryptoProvider
	identityGuard  IdentityGuard
	stepUpVerifier StepUpVerifier
	events         EventPublisher
	notifier       Notifier
	metrics        MetricsRecorder
	clock          Clock
	logger         *slog.Logger

	shadowMode   bool
	enforcedPerm map[string]bool

	ruleCacheTTL time.Duration
	cacheMu      sync.RWMutex
	ruleCache    map[string]ruleCacheEntry

	registryMu sync.RWMutex
	registry   map[string]ActionExecutor
}

// NewEngine validates Config and constructs an initialized Engine.
func NewEngine(cfg Config) (*Engine, error) {
	if cfg.Store == nil {
		return nil, errors.New("governance: Store is required")
	}
	if cfg.Scopes == nil {
		return nil, errors.New("governance: ScopeResolver is required")
	}
	if cfg.Roles == nil {
		return nil, errors.New("governance: RoleResolver is required")
	}
	if cfg.Crypto == nil {
		return nil, errors.New("governance: CryptoProvider is required")
	}
	if cfg.Events == nil {
		cfg.Events = NoopEventPublisher{}
	}
	if cfg.Notifier == nil {
		cfg.Notifier = NoopNotifier{}
	}
	if cfg.Metrics == nil {
		cfg.Metrics = NoopMetrics{}
	}
	if cfg.Clock == nil {
		cfg.Clock = RealClock{}
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	ttl := cfg.RuleCacheTTL
	if ttl == 0 {
		ttl = DefaultRuleCacheTTL
	}

	enforced := make(map[string]bool, len(cfg.EnforcedPermissions))
	for k, v := range cfg.EnforcedPermissions {
		enforced[k] = v
	}

	return &Engine{
		store:          cfg.Store,
		scopes:         cfg.Scopes,
		roles:          cfg.Roles,
		crypto:         cfg.Crypto,
		identityGuard:  cfg.IdentityGuard,
		stepUpVerifier: cfg.StepUpVerifier,
		events:         cfg.Events,
		notifier:       cfg.Notifier,
		metrics:        cfg.Metrics,
		clock:          cfg.Clock,
		logger:         cfg.Logger,
		shadowMode:     cfg.ShadowMode,
		enforcedPerm:   enforced,
		ruleCacheTTL:   ttl,
		ruleCache:      make(map[string]ruleCacheEntry),
		registry:       make(map[string]ActionExecutor),
	}, nil
}

// RegisterExecutor binds an idempotent ActionExecutor to an action key (typically a permission string).
func (e *Engine) RegisterExecutor(actionKey string, exec ActionExecutor) {
	e.registryMu.Lock()
	defer e.registryMu.Unlock()
	e.registry[actionKey] = exec
}

func (e *Engine) getExecutor(actionKey string) (ActionExecutor, bool) {
	e.registryMu.RLock()
	defer e.registryMu.RUnlock()
	exec, ok := e.registry[actionKey]
	return exec, ok
}

func (e *Engine) isShadowForPermission(perm string) bool {
	if !e.shadowMode {
		return false
	}
	return !e.enforcedPerm[perm]
}

// -----------------------------------------------------------------------------
// 1. Preview / Dry-Run & Scope Resolution (§4, §7)
// -----------------------------------------------------------------------------

// Preview evaluates whether an action would require approval without causing side effects.
func (e *Engine) Preview(ctx context.Context, p Principal, permission string, scopeID uuid.UUID, amount *float64) (Decision, error) {
	rule, err := e.resolveRule(ctx, p.OrgID, scopeID, permission, amount)
	if err != nil {
		return Decision{}, err
	}
	if rule == nil {
		return Decision{
			RequiresApproval: false,
			Reason:           "no matching active governance policy rule",
		}, nil
	}

	// If maker_roles is non-empty, verify whether caller is covered by maker_roles.
	// If caller holds none of maker_roles (e.g. a non-maker role), the rule still applies
	// unless caller already holds a checker role and AllowSelfApproval is true (direct path check is up to host).
	shadow := e.isShadowForPermission(permission)
	if shadow {
		e.metrics.IncShadowHold(permission)
		return Decision{
			RequiresApproval: false,
			ShadowMode:       true,
			Rule:             rule,
			Reason:           fmt.Sprintf("shadow mode: would have matched rule %s (v%d) at scope %s", rule.RootID, rule.Version, rule.ScopeID),
		}, nil
	}

	return Decision{
		RequiresApproval: true,
		Rule:             rule,
		Reason:           fmt.Sprintf("matched rule %s (v%d) at scope %s", rule.RootID, rule.Version, rule.ScopeID),
	}, nil
}

func (e *Engine) resolveRule(ctx context.Context, orgID, scopeID uuid.UUID, permission string, amount *float64) (*PolicyRule, error) {
	// Cache key only when amount is nil (or includes exact amount)
	amtKey := "nil"
	if amount != nil {
		amtKey = fmt.Sprintf("%.4f", *amount)
	}
	cacheKey := fmt.Sprintf("%s|%s|%s|%s", orgID, permission, scopeID, amtKey)

	if e.ruleCacheTTL > 0 {
		e.cacheMu.RLock()
		entry, ok := e.ruleCache[cacheKey]
		e.cacheMu.RUnlock()
		if ok && e.clock.Now().Before(entry.expiresAt) {
			if entry.rule == nil {
				return nil, nil
			}
			cp := *entry.rule
			return &cp, nil
		}
	}

	ancestors, err := e.scopes.Ancestors(ctx, orgID, scopeID)
	if err != nil {
		return nil, fmt.Errorf("governance: resolve scope ancestors: %w", err)
	}
	if len(ancestors) == 0 {
		ancestors = []uuid.UUID{scopeID}
	}

	rule, err := e.store.ResolveMatchingRule(ctx, orgID, ancestors, permission, amount)
	if err != nil {
		return nil, err
	}

	if e.ruleCacheTTL > 0 {
		var cached *PolicyRule
		if rule != nil {
			cp := *rule
			cached = &cp
		}
		e.cacheMu.Lock()
		e.ruleCache[cacheKey] = ruleCacheEntry{
			rule:      cached,
			expiresAt: e.clock.Now().Add(e.ruleCacheTTL),
		}
		e.cacheMu.Unlock()
	}

	return rule, nil
}

func (e *Engine) invalidateRuleCache(orgID uuid.UUID, permission string) {
	prefix := fmt.Sprintf("%s|%s|", orgID, permission)
	e.cacheMu.Lock()
	defer e.cacheMu.Unlock()
	for k := range e.ruleCache {
		if strings.HasPrefix(k, prefix) {
			delete(e.ruleCache, k)
		}
	}
}

// -----------------------------------------------------------------------------
// 2. Submit (Idempotent, Cryptographically Bound, Snapshot-Frozen)
// -----------------------------------------------------------------------------

// Submit creates a pending governance ticket bound to the canonical payload hash,
// Ed25519 signature, enc:v2 envelope encryption, and immutable policy snapshot.
// Submitting twice with the same (OrgID, IdempotencyKey) returns the existing ticket.
func (e *Engine) Submit(ctx context.Context, in SubmitInput) (*Ticket, error) {
	if strings.TrimSpace(in.IdempotencyKey) == "" {
		return nil, ErrIdempotencyRequired
	}
	if strings.TrimSpace(in.Permission) == "" {
		return nil, NewError(CodeInvalidRule, "permission is required")
	}
	if strings.TrimSpace(in.Title) == "" {
		return nil, NewError(CodeInvalidRule, "title is required")
	}
	if strings.TrimSpace(in.TargetType) == "" {
		return nil, NewError(CodeInvalidRule, "target_resource_type is required")
	}
	if in.RequestedVia == "" {
		in.RequestedVia = "api"
	}

	rule, err := e.resolveRule(ctx, in.Principal.OrgID, in.ScopeID, in.Permission, in.Amount)
	if err != nil {
		return nil, err
	}
	if rule == nil {
		return nil, ErrRuleNotFound
	}

	// If rule restricts maker_roles, verify caller holds at least one maker role
	if len(rule.MakerRoles) > 0 {
		allowedMaker, err := e.holdsAnyRole(ctx, in.Principal, rule.MakerRoles, in.ScopeID)
		if err != nil {
			return nil, err
		}
		if !allowedMaker {
			return nil, NewError(CodeRoleRequired, "caller does not hold an authorized maker role for this policy")
		}
	}

	// Canonicalize and enforce payload size limit
	canonicalBytes, err := e.crypto.Canonicalize(in.Payload)
	if err != nil {
		return nil, fmt.Errorf("governance: canonicalize payload: %w", err)
	}
	if len(canonicalBytes) > rule.MaxPayloadBytes {
		return nil, NewError(CodePayloadTooLarge, fmt.Sprintf("payload size %d exceeds limit %d bytes", len(canonicalBytes), rule.MaxPayloadBytes))
	}

	// Hash, Sign, Encrypt (enc:v2)
	payloadHash := e.crypto.Hash(canonicalBytes)
	meta := buildRequestMeta(in.Principal.OrgID, in.Permission, in.ScopeID, in.TargetType, in.TargetID)
	payloadSig, err := e.crypto.Sign(meta, payloadHash)
	if err != nil {
		return nil, fmt.Errorf("governance: sign payload: %w", err)
	}
	payloadEnc, err := e.crypto.Encrypt(in.Principal.OrgID.String(), canonicalBytes)
	if err != nil {
		return nil, fmt.Errorf("governance: encrypt payload: %w", err)
	}

	now := e.clock.Now().UTC()
	snapshot := *rule
	ticket := &Ticket{
		ID:                   uuid.New(),
		OrgID:                in.Principal.OrgID,
		ScopeID:              in.ScopeID,
		Permission:           in.Permission,
		TargetResourceType:   in.TargetType,
		TargetResourceID:     in.TargetID,
		Title:                in.Title,
		Description:          in.Description,
		Payload:              in.Payload,
		PayloadEnc:           payloadEnc,
		PayloadHash:          payloadHash,
		PayloadHashHex:       hex.EncodeToString(payloadHash),
		PayloadSig:           payloadSig,
		PayloadBytes:         len(canonicalBytes),
		PayloadSchemaVersion: rule.PayloadSchemaVersion,
		PolicyRuleID:         rule.ID,
		PolicySnapshot:       snapshot,
		RequiredApprovals:    rule.RequiredApprovals,
		ApprovalsCount:       0,
		State:                StatePending,
		RequestedBy:          in.Principal.ActorID,
		RequestedFromIP:      in.RequestedFromIP,
		RequestedVia:         in.RequestedVia,
		IdempotencyKey:       in.IdempotencyKey,
		ExpiresAt:            now.Add(time.Duration(rule.ExpiresInHours) * time.Hour),
		CreatedAt:            now,
		UpdatedAt:            now,
	}

	stored, created, err := e.store.CreateTicketIdempotent(ctx, ticket)
	if err != nil {
		return nil, err
	}
	if err := e.hydratePayload(stored); err != nil {
		return nil, err
	}

	if created {
		e.metrics.IncRequestsCreated(stored.Permission, stored.State)
		e.publishEvent(ctx, Event{
			Type:        EventRequestCreated,
			OrgID:       stored.OrgID,
			ScopeID:     stored.ScopeID,
			RequestID:   stored.ID,
			RuleID:      stored.PolicyRuleID,
			ActorID:     stored.RequestedBy,
			Permission:  stored.Permission,
			PayloadHash: stored.PayloadHashHex,
			OccurredAt:  now,
		})
		e.dispatchNotification(ctx, Notification{
			EventType:      EventRequestCreated,
			OrgID:          stored.OrgID,
			ScopeID:        stored.ScopeID,
			RequestID:      stored.ID,
			Permission:     stored.Permission,
			Title:          stored.Title,
			RecipientRoles: stored.PolicySnapshot.CheckerRoles,
			Message:        fmt.Sprintf("New approval request '%s' awaits %d checker sign-off(s).", stored.Title, stored.RequiredApprovals),
			OccurredAt:     now,
		})
	}

	return stored, nil
}

// -----------------------------------------------------------------------------
// 3. Approve / Reject / Cancel (§3, §5, §6, §9)
// -----------------------------------------------------------------------------

// Approve records a checker's approval atomically. If the M-of-N threshold is reached,
// the ticket transitions to executing and is enqueued to governance_outbox in the same transaction.
// Approve NEVER calls ActionExecutor inline.
func (e *Engine) Approve(ctx context.Context, in DecisionInput) (*Ticket, error) {
	if in.DecidedVia == "" {
		in.DecidedVia = "api"
	}

	ticket, err := e.store.GetTicket(ctx, in.Principal.OrgID, in.RequestID)
	if err != nil {
		return nil, err
	}

	// Idempotent replay: if this approver already approved this ticket, return it cleanly
	for _, dec := range ticket.Approvals {
		if dec.ApproverID == in.Principal.ActorID && dec.Decision == "approved" {
			if err := e.hydratePayload(ticket); err != nil {
				return nil, err
			}
			return ticket, nil
		}
	}

	now := e.clock.Now().UTC()
	if ticket.State == StateExpired || (ticket.State == StatePending && !ticket.ExpiresAt.After(now)) {
		return nil, ErrExpired
	}
	if ticket.State != StatePending {
		return nil, NewError(CodeStateConflict, fmt.Sprintf("ticket is in state '%s', expected 'pending'", ticket.State))
	}

	rule := ticket.PolicySnapshot

	// 1. Verify checker holds at least one required checker role in scope
	isChecker, err := e.holdsAnyRole(ctx, in.Principal, rule.CheckerRoles, ticket.ScopeID)
	if err != nil {
		return nil, err
	}
	if !isChecker {
		return nil, ErrRoleRequired
	}

	// 2. Dual-custody self-approval guard (account ID + multi-account identity hash guard)
	isSelfApproval := ticket.RequestedBy == in.Principal.ActorID
	if !isSelfApproval && e.identityGuard != nil {
		makerHash, err1 := e.identityGuard.IdentityHash(ctx, ticket.RequestedBy)
		checkerHash, err2 := e.identityGuard.IdentityHash(ctx, in.Principal.ActorID)
		if err1 != nil || err2 != nil {
			// Fail closed on identity guard error
			return nil, NewError(CodeSelfApprovalForbidden, "unable to verify distinct approver identity")
		}
		if makerHash != "" && checkerHash != "" && makerHash == checkerHash {
			isSelfApproval = true
		}
	}
	if isSelfApproval && !rule.AllowSelfApproval {
		return nil, ErrSelfApprovalForbidden
	}

	// 3. Reason enforcement (mandatory if rule requires it OR when self-approval is used per §5.4)
	if (rule.RequiredReason || isSelfApproval) && strings.TrimSpace(in.Reason) == "" {
		return nil, ErrReasonRequired
	}

	// 4. Step-up authentication enforcement (mandatory if rule.RequireStepUp OR self-approval per §5.4)
	stepUpUsed := false
	if rule.RequireStepUp || isSelfApproval {
		if strings.TrimSpace(in.StepUpToken) == "" || e.stepUpVerifier == nil {
			return nil, ErrStepUpRequired
		}
		if err := e.stepUpVerifier.VerifyStepUp(ctx, in.Principal, in.StepUpToken); err != nil {
			return nil, NewError(CodeStepUpRequired, "step-up verification failed", err)
		}
		stepUpUsed = true
	}

	// 5. Payload hash & signature binding verification (§5.2)
	expectedHash, err := resolveProvidedHash(in.PayloadHash, in.PayloadHashHex)
	if err != nil || len(expectedHash) == 0 {
		return nil, NewError(CodeHashMismatch, "payload_hash is required to bind approval to exact content")
	}
	if !bytes.Equal(expectedHash, ticket.PayloadHash) {
		return nil, ErrHashMismatch
	}
	meta := buildRequestMeta(ticket.OrgID, ticket.Permission, ticket.ScopeID, ticket.TargetResourceType, ticket.TargetResourceID)
	if !e.crypto.Verify(meta, ticket.PayloadHash, ticket.PayloadSig) {
		e.metrics.IncExecutionError(ticket.Permission, CodePayloadIntegrityFailure)
		return nil, ErrPayloadIntegrityFailure
	}

	// 6. Atomic DB transition (+ outbox enqueue if M-of-N threshold reached)
	decision := ApprovalDecision{
		ID:            uuid.New(),
		RequestID:     ticket.ID,
		ApproverID:    in.Principal.ActorID,
		Decision:      "approved",
		Reason:        strings.TrimSpace(in.Reason),
		DecidedVia:    in.DecidedVia,
		DecidedFromIP: in.DecidedFromIP,
		StepUpUsed:    stepUpUsed,
		DecidedAt:     now,
	}

	res, err := e.store.RecordApprovalAndMaybeEnqueue(ctx, in.Principal.OrgID, ticket.ID, decision, ticket.Permission, now)
	if err != nil {
		return nil, err
	}
	if err := e.hydratePayload(res.Ticket); err != nil {
		return nil, err
	}

	if !res.IdempotentReplay {
		e.metrics.IncRequestsDecided(ticket.Permission, "approved")
		if isSelfApproval {
			e.publishEvent(ctx, Event{
				Type:        EventRequestSelfApproved,
				OrgID:       ticket.OrgID,
				ScopeID:     ticket.ScopeID,
				RequestID:   ticket.ID,
				ActorID:     in.Principal.ActorID,
				Permission:  ticket.Permission,
				PayloadHash: ticket.PayloadHashHex,
				OccurredAt:  now,
				Metadata:    map[string]any{"reason": decision.Reason, "step_up_used": stepUpUsed},
			})
		}
		e.publishEvent(ctx, Event{
			Type:        EventRequestApproved,
			OrgID:       ticket.OrgID,
			ScopeID:     ticket.ScopeID,
			RequestID:   ticket.ID,
			ActorID:     in.Principal.ActorID,
			Permission:  ticket.Permission,
			PayloadHash: ticket.PayloadHashHex,
			OccurredAt:  now,
			Metadata: map[string]any{
				"approvals_count":    res.Ticket.ApprovalsCount,
				"required_approvals": res.Ticket.RequiredApprovals,
				"threshold_reached":  res.ThresholdReached,
			},
		})
		if res.ThresholdReached {
			e.metrics.ObserveApprovalDuration(ticket.Permission, now.Sub(ticket.CreatedAt))
			e.publishEvent(ctx, Event{
				Type:        EventRequestExecuting,
				OrgID:       ticket.OrgID,
				ScopeID:     ticket.ScopeID,
				RequestID:   ticket.ID,
				ActorID:     in.Principal.ActorID,
				Permission:  ticket.Permission,
				PayloadHash: ticket.PayloadHashHex,
				OccurredAt:  now,
			})
			e.dispatchNotification(ctx, Notification{
				EventType:    EventRequestApproved,
				OrgID:        ticket.OrgID,
				ScopeID:      ticket.ScopeID,
				RequestID:    ticket.ID,
				Permission:   ticket.Permission,
				Title:        ticket.Title,
				RecipientIDs: []uuid.UUID{ticket.RequestedBy},
				Message:      fmt.Sprintf("Approval threshold met for '%s'; queued for execution.", ticket.Title),
				OccurredAt:   now,
			})
		} else {
			e.dispatchNotification(ctx, Notification{
				EventType:      EventRequestApproved,
				OrgID:          ticket.OrgID,
				ScopeID:        ticket.ScopeID,
				RequestID:      ticket.ID,
				Permission:     ticket.Permission,
				Title:          ticket.Title,
				RecipientRoles: rule.CheckerRoles,
				Message:        fmt.Sprintf("Partial approval (%d/%d) recorded for '%s'.", res.Ticket.ApprovalsCount, res.Ticket.RequiredApprovals, ticket.Title),
				OccurredAt:     now,
			})
		}
	}

	return res.Ticket, nil
}

// Reject transitions a pending ticket to terminal rejected state.
func (e *Engine) Reject(ctx context.Context, in DecisionInput) (*Ticket, error) {
	if strings.TrimSpace(in.Reason) == "" {
		return nil, ErrReasonRequired
	}
	if in.DecidedVia == "" {
		in.DecidedVia = "api"
	}

	ticket, err := e.store.GetTicket(ctx, in.Principal.OrgID, in.RequestID)
	if err != nil {
		return nil, err
	}

	now := e.clock.Now().UTC()
	if ticket.State == StateExpired || (ticket.State == StatePending && !ticket.ExpiresAt.After(now)) {
		return nil, ErrExpired
	}
	if ticket.State != StatePending {
		return nil, NewError(CodeStateConflict, fmt.Sprintf("ticket is in state '%s', expected 'pending'", ticket.State))
	}

	isChecker, err := e.holdsAnyRole(ctx, in.Principal, ticket.PolicySnapshot.CheckerRoles, ticket.ScopeID)
	if err != nil {
		return nil, err
	}
	if !isChecker {
		return nil, ErrRoleRequired
	}

	decision := ApprovalDecision{
		ID:            uuid.New(),
		RequestID:     ticket.ID,
		ApproverID:    in.Principal.ActorID,
		Decision:      "rejected",
		Reason:        strings.TrimSpace(in.Reason),
		DecidedVia:    in.DecidedVia,
		DecidedFromIP: in.DecidedFromIP,
		DecidedAt:     now,
	}

	updated, err := e.store.RecordRejection(ctx, in.Principal.OrgID, ticket.ID, decision, now)
	if err != nil {
		return nil, err
	}
	if err := e.hydratePayload(updated); err != nil {
		return nil, err
	}

	e.metrics.IncRequestsDecided(ticket.Permission, "rejected")
	e.publishEvent(ctx, Event{
		Type:        EventRequestRejected,
		OrgID:       ticket.OrgID,
		ScopeID:     ticket.ScopeID,
		RequestID:   ticket.ID,
		ActorID:     in.Principal.ActorID,
		Permission:  ticket.Permission,
		PayloadHash: ticket.PayloadHashHex,
		OccurredAt:  now,
		Metadata:    map[string]any{"reason": decision.Reason},
	})
	e.dispatchNotification(ctx, Notification{
		EventType:    EventRequestRejected,
		OrgID:        ticket.OrgID,
		ScopeID:      ticket.ScopeID,
		RequestID:    ticket.ID,
		Permission:   ticket.Permission,
		Title:        ticket.Title,
		RecipientIDs: []uuid.UUID{ticket.RequestedBy},
		Message:      fmt.Sprintf("Request '%s' was rejected: %s", ticket.Title, decision.Reason),
		OccurredAt:   now,
	})

	return updated, nil
}

// Cancel allows the maker to withdraw a pending request before any approval decision is recorded.
func (e *Engine) Cancel(ctx context.Context, p Principal, requestID uuid.UUID, reason string) error {
	ticket, err := e.store.GetTicket(ctx, p.OrgID, requestID)
	if err != nil {
		return err
	}
	if ticket.RequestedBy != p.ActorID {
		return NewError(CodeForbidden, "only the original maker may cancel a request")
	}
	if ticket.State != StatePending {
		return NewError(CodeStateConflict, fmt.Sprintf("cannot cancel ticket in state '%s'", ticket.State))
	}
	if ticket.ApprovalsCount > 0 || len(ticket.Approvals) > 0 {
		return ErrAlreadyInReview
	}

	now := e.clock.Now().UTC()
	updated, err := e.store.CancelTicket(ctx, p.OrgID, requestID, p.ActorID, strings.TrimSpace(reason), now)
	if err != nil {
		return err
	}

	e.publishEvent(ctx, Event{
		Type:        EventRequestCancelled,
		OrgID:       updated.OrgID,
		ScopeID:     updated.ScopeID,
		RequestID:   updated.ID,
		ActorID:     p.ActorID,
		Permission:  updated.Permission,
		PayloadHash: updated.PayloadHashHex,
		OccurredAt:  now,
		Metadata:    map[string]any{"reason": reason},
	})
	e.dispatchNotification(ctx, Notification{
		EventType:      EventRequestCancelled,
		OrgID:          updated.OrgID,
		ScopeID:        updated.ScopeID,
		RequestID:      updated.ID,
		Permission:     updated.Permission,
		Title:          updated.Title,
		RecipientRoles: updated.PolicySnapshot.CheckerRoles,
		Message:        fmt.Sprintf("Maker cancelled request '%s'.", updated.Title),
		OccurredAt:     now,
	})
	return nil
}

// -----------------------------------------------------------------------------
// 4. Read Operations (Tenant-Scoped)
// -----------------------------------------------------------------------------

func (e *Engine) Get(ctx context.Context, p Principal, requestID uuid.UUID) (*Ticket, error) {
	t, err := e.store.GetTicket(ctx, p.OrgID, requestID)
	if err != nil {
		return nil, err
	}
	if err := e.hydratePayload(t); err != nil {
		return nil, err
	}
	return t, nil
}

func (e *Engine) List(ctx context.Context, p Principal, filter ListFilter) (Page[Ticket], error) {
	if filter.Page <= 0 {
		filter.Page = 1
	}
	if filter.PageSize <= 0 {
		filter.PageSize = 50
	}
	if filter.PageSize > 200 {
		filter.PageSize = 200
	}
	if len(filter.States) == 0 {
		filter.States = []State{StatePending}
	}

	page, err := e.store.ListTickets(ctx, p.OrgID, filter)
	if err != nil {
		return Page[Ticket]{}, err
	}
	for i := range page.Items {
		_ = e.hydratePayload(&page.Items[i])
	}
	return page, nil
}

// -----------------------------------------------------------------------------
// 5. Rule Administration (Append-Only Versioned + Validated)
// -----------------------------------------------------------------------------

func (e *Engine) CreateRule(ctx context.Context, p Principal, in RuleInput) (*PolicyRule, error) {
	rule, err := e.validateAndNormalizeRule(ctx, p, in)
	if err != nil {
		return nil, err
	}
	now := e.clock.Now().UTC()
	rule.ID = uuid.New()
	rule.RootID = rule.ID
	rule.Version = 1
	rule.IsActive = true
	rule.CreatedBy = p.ActorID
	rule.CreatedAt = now
	rule.UpdatedAt = now

	created, err := e.store.CreateRule(ctx, rule)
	if err != nil {
		return nil, err
	}
	e.invalidateRuleCache(p.OrgID, created.Permission)
	e.publishEvent(ctx, Event{
		Type:       EventRuleCreated,
		OrgID:      created.OrgID,
		ScopeID:    created.ScopeID,
		RuleID:     created.ID,
		ActorID:    p.ActorID,
		Permission: created.Permission,
		OccurredAt: now,
		Metadata:   map[string]any{"root_id": created.RootID.String(), "version": created.Version},
	})
	return created, nil
}

// UpdateRule appends a new version for rootID and soft-deactivates the previous active version.
func (e *Engine) UpdateRule(ctx context.Context, p Principal, rootID uuid.UUID, in RuleInput) (*PolicyRule, error) {
	rule, err := e.validateAndNormalizeRule(ctx, p, in)
	if err != nil {
		return nil, err
	}
	now := e.clock.Now().UTC()
	rule.ID = uuid.New()
	rule.RootID = rootID
	rule.IsActive = true
	rule.CreatedBy = p.ActorID
	rule.CreatedAt = now
	updatedBy := p.ActorID
	rule.UpdatedBy = &updatedBy
	rule.UpdatedAt = now

	updated, err := e.store.UpdateRuleVersion(ctx, p.OrgID, rootID, rule)
	if err != nil {
		return nil, err
	}
	e.invalidateRuleCache(p.OrgID, updated.Permission)
	e.publishEvent(ctx, Event{
		Type:       EventRuleUpdated,
		OrgID:      updated.OrgID,
		ScopeID:    updated.ScopeID,
		RuleID:     updated.ID,
		ActorID:    p.ActorID,
		Permission: updated.Permission,
		OccurredAt: now,
		Metadata:   map[string]any{"root_id": updated.RootID.String(), "version": updated.Version},
	})
	return updated, nil
}

func (e *Engine) DeleteRule(ctx context.Context, p Principal, rootID uuid.UUID) error {
	now := e.clock.Now().UTC()
	deleted, err := e.store.SoftDeleteRule(ctx, p.OrgID, rootID, p.ActorID, now)
	if err != nil {
		return err
	}
	e.invalidateRuleCache(p.OrgID, deleted.Permission)
	e.publishEvent(ctx, Event{
		Type:       EventRuleDeleted,
		OrgID:      deleted.OrgID,
		ScopeID:    deleted.ScopeID,
		RuleID:     deleted.ID,
		ActorID:    p.ActorID,
		Permission: deleted.Permission,
		OccurredAt: now,
		Metadata:   map[string]any{"root_id": deleted.RootID.String(), "version": deleted.Version},
	})
	return nil
}

func (e *Engine) ListRules(ctx context.Context, p Principal, filter RuleFilter) ([]PolicyRule, error) {
	return e.store.ListActiveRules(ctx, p.OrgID, filter)
}

func (e *Engine) ListRuleVersions(ctx context.Context, p Principal, rootID uuid.UUID) ([]PolicyRule, error) {
	return e.store.ListRuleVersions(ctx, p.OrgID, rootID)
}

// -----------------------------------------------------------------------------
// Internal Helpers
// -----------------------------------------------------------------------------

func (e *Engine) validateAndNormalizeRule(ctx context.Context, p Principal, in RuleInput) (*PolicyRule, error) {
	if strings.TrimSpace(in.Permission) == "" {
		return nil, NewError(CodeInvalidRule, "permission is required")
	}
	if in.ScopeID == uuid.Nil {
		return nil, NewError(CodeInvalidRule, "scope_id is required")
	}
	if len(in.CheckerRoles) == 0 {
		return nil, NewError(CodeInvalidRule, "checker_roles must be non-empty")
	}
	if in.MinAmount != nil && in.MaxAmount != nil && *in.MinAmount > *in.MaxAmount {
		return nil, NewError(CodeInvalidRule, "min_amount cannot exceed max_amount")
	}

	reqApprovals := in.RequiredApprovals
	if reqApprovals == 0 {
		reqApprovals = 1
	}
	if reqApprovals < 1 {
		return nil, NewError(CodeInvalidRule, "required_approvals must be >= 1")
	}

	expiresHrs := in.ExpiresInHours
	if expiresHrs == 0 {
		expiresHrs = DefaultExpiresInHours
	}
	if expiresHrs < MinExpiresInHours || expiresHrs > MaxExpiresInHours {
		return nil, NewError(CodeInvalidRule, fmt.Sprintf("expires_in_hours must be between %d and %d", MinExpiresInHours, MaxExpiresInHours))
	}

	maxPayload := in.MaxPayloadBytes
	if maxPayload == 0 {
		maxPayload = DefaultMaxPayloadBytes
	}
	if maxPayload < MinMaxPayloadBytes || maxPayload > MaxMaxPayloadBytes {
		return nil, NewError(CodeInvalidRule, fmt.Sprintf("max_payload_bytes must be between %d and %d", MinMaxPayloadBytes, MaxMaxPayloadBytes))
	}

	schemaVer := in.PayloadSchemaVersion
	if schemaVer == 0 {
		schemaVer = 1
	}

	requireStepUp := true
	if in.RequireStepUp != nil {
		requireStepUp = *in.RequireStepUp
	}
	requiredReason := in.RequiredReason
	if in.AllowSelfApproval {
		// Per §5.4: self-approval always forces required_reason=true
		requiredReason = true
	}

	// Validate roles exist and can be held in target scope (§7.1)
	if len(in.MakerRoles) > 0 {
		if err := e.roles.ValidateRolesForScope(ctx, p.OrgID, in.ScopeID, in.MakerRoles); err != nil {
			return nil, NewError(CodeInvalidRule, "invalid maker_roles for scope", err)
		}
	}
	if err := e.roles.ValidateRolesForScope(ctx, p.OrgID, in.ScopeID, in.CheckerRoles); err != nil {
		return nil, NewError(CodeInvalidRule, "invalid checker_roles for scope", err)
	}

	makers := append([]string(nil), in.MakerRoles...)
	if makers == nil {
		makers = []string{}
	}
	checkers := append([]string(nil), in.CheckerRoles...)

	return &PolicyRule{
		OrgID:                p.OrgID,
		ScopeID:              in.ScopeID,
		Permission:           strings.TrimSpace(in.Permission),
		MinAmount:            in.MinAmount,
		MaxAmount:            in.MaxAmount,
		MakerRoles:           makers,
		CheckerRoles:         checkers,
		RequiredApprovals:    reqApprovals,
		RequiredReason:       requiredReason,
		AllowSelfApproval:    in.AllowSelfApproval,
		RequireStepUp:        requireStepUp,
		ExpiresInHours:       expiresHrs,
		MaxPayloadBytes:      maxPayload,
		PayloadSchemaVersion: schemaVer,
	}, nil
}

func (e *Engine) holdsAnyRole(ctx context.Context, p Principal, roles []string, scopeID uuid.UUID) (bool, error) {
	for _, r := range roles {
		ok, err := e.roles.HoldsRole(ctx, p, r, scopeID)
		if err != nil {
			return false, err
		}
		if ok {
			return true, nil
		}
	}
	return false, nil
}

func (e *Engine) hydratePayload(t *Ticket) error {
	if t == nil {
		return nil
	}
	if t.PayloadHashHex == "" && len(t.PayloadHash) > 0 {
		t.PayloadHashHex = hex.EncodeToString(t.PayloadHash)
	}
	if t.Payload != nil || len(t.PayloadEnc) == 0 {
		return nil
	}
	plain, err := e.crypto.Decrypt(t.PayloadEnc)
	if err != nil {
		return NewError(CodePayloadIntegrityFailure, "failed to decrypt ticket payload", err)
	}
	var m map[string]any
	if err := json.Unmarshal(plain, &m); err != nil {
		return NewError(CodePayloadIntegrityFailure, "failed to decode decrypted payload", err)
	}
	t.Payload = m
	return nil
}

func (e *Engine) publishEvent(ctx context.Context, ev Event) {
	if err := e.events.Publish(ctx, ev); err != nil {
		e.logger.ErrorContext(ctx, "governance event publish failed", "event", ev.Type, "error", err)
	}
}

func (e *Engine) dispatchNotification(ctx context.Context, n Notification) {
	if err := e.notifier.Notify(ctx, n); err != nil {
		e.logger.ErrorContext(ctx, "governance notification failed", "event", n.EventType, "request_id", n.RequestID, "error", err)
	}
}

func buildRequestMeta(orgID uuid.UUID, permission string, scopeID uuid.UUID, targetType, targetID string) string {
	return fmt.Sprintf("%s|%s|%s|%s|%s", orgID.String(), permission, scopeID.String(), targetType, targetID)
}

func resolveProvidedHash(raw []byte, hexStr string) ([]byte, error) {
	if len(raw) > 0 {
		return raw, nil
	}
	hexStr = strings.TrimSpace(hexStr)
	if hexStr == "" {
		return nil, nil
	}
	return hex.DecodeString(hexStr)
}

