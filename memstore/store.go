package memstore

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
	gov "github.com/Natykufsky/verity-governance"
)

// Store is a thread-safe in-memory implementation of governance.Store.
// It faithfully enforces tenant isolation, uniqueness constraints, state-machine
// guards, M-of-N atomic transitions, outbox leasing, and expiry sweeps.
type Store struct {
	mu      sync.Mutex
	rules   map[uuid.UUID]*gov.PolicyRule // rule.ID -> rule
	tickets map[uuid.UUID]*gov.Ticket     // ticket.ID -> ticket
	idemp   map[string]uuid.UUID          // "orgID|idempotencyKey" -> ticket.ID
	outbox  map[uuid.UUID]*gov.OutboxItem // outbox.ID -> item
}

func New() *Store {
	return &Store{
		rules:   make(map[uuid.UUID]*gov.PolicyRule),
		tickets: make(map[uuid.UUID]*gov.Ticket),
		idemp:   make(map[string]uuid.UUID),
		outbox:  make(map[uuid.UUID]*gov.OutboxItem),
	}
}

func cloneRule(r *gov.PolicyRule) *gov.PolicyRule {
	if r == nil {
		return nil
	}
	cp := *r
	cp.MakerRoles = append([]string(nil), r.MakerRoles...)
	cp.CheckerRoles = append([]string(nil), r.CheckerRoles...)
	if r.MinAmount != nil {
		v := *r.MinAmount
		cp.MinAmount = &v
	}
	if r.MaxAmount != nil {
		v := *r.MaxAmount
		cp.MaxAmount = &v
	}
	return &cp
}

func cloneTicket(t *gov.Ticket) *gov.Ticket {
	if t == nil {
		return nil
	}
	cp := *t
	cp.Payload = nil // Engine hydrates from PayloadEnc
	cp.PayloadEnc = append([]byte(nil), t.PayloadEnc...)
	cp.PayloadHash = append([]byte(nil), t.PayloadHash...)
	cp.PayloadSig = append([]byte(nil), t.PayloadSig...)
	cp.Approvals = append([]gov.ApprovalDecision(nil), t.Approvals...)
	if t.ExecutionResult != nil {
		er := *t.ExecutionResult
		cp.ExecutionResult = &er
	}
	return &cp
}

// -----------------------------------------------------------------------------
// Rules
// -----------------------------------------------------------------------------

func (s *Store) CreateRule(_ context.Context, rule *gov.PolicyRule) (*gov.PolicyRule, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := cloneRule(rule)
	s.rules[cp.ID] = cp
	return cloneRule(cp), nil
}

func (s *Store) UpdateRuleVersion(_ context.Context, orgID, rootID uuid.UUID, next *gov.PolicyRule) (*gov.PolicyRule, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	maxVersion := 0
	var active *gov.PolicyRule
	for _, r := range s.rules {
		if r.OrgID == orgID && r.RootID == rootID {
			if r.Version > maxVersion {
				maxVersion = r.Version
			}
			if r.IsActive && r.DeletedAt == nil {
				active = r
			}
		}
	}
	if maxVersion == 0 {
		return nil, gov.ErrRuleNotFound
	}
	if active != nil {
		now := next.UpdatedAt
		active.IsActive = false
		active.DeletedAt = &now
		active.UpdatedAt = now
		active.UpdatedBy = next.UpdatedBy
	}

	cp := cloneRule(next)
	cp.OrgID = orgID
	cp.RootID = rootID
	cp.Version = maxVersion + 1
	cp.IsActive = true
	cp.DeletedAt = nil
	s.rules[cp.ID] = cp
	return cloneRule(cp), nil
}

func (s *Store) SoftDeleteRule(_ context.Context, orgID, rootID, deletedBy uuid.UUID, now time.Time) (*gov.PolicyRule, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, r := range s.rules {
		if r.OrgID == orgID && r.RootID == rootID && r.IsActive && r.DeletedAt == nil {
			r.IsActive = false
			r.DeletedAt = &now
			r.UpdatedBy = &deletedBy
			r.UpdatedAt = now
			return cloneRule(r), nil
		}
	}
	return nil, gov.ErrRuleNotFound
}

func (s *Store) ListActiveRules(_ context.Context, orgID uuid.UUID, filter gov.RuleFilter) ([]gov.PolicyRule, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]gov.PolicyRule, 0)
	for _, r := range s.rules {
		if r.OrgID != orgID || !r.IsActive || r.DeletedAt != nil {
			continue
		}
		if filter.Permission != "" && r.Permission != filter.Permission {
			continue
		}
		if filter.ScopeID != nil && r.ScopeID != *filter.ScopeID {
			continue
		}
		out = append(out, *cloneRule(r))
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
	return out, nil
}

func (s *Store) ListRuleVersions(_ context.Context, orgID, rootID uuid.UUID) ([]gov.PolicyRule, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]gov.PolicyRule, 0)
	for _, r := range s.rules {
		if r.OrgID == orgID && r.RootID == rootID {
			out = append(out, *cloneRule(r))
		}
	}
	if len(out) == 0 {
		return nil, gov.ErrRuleNotFound
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Version > out[j].Version
	})
	return out, nil
}

func (s *Store) ResolveMatchingRule(_ context.Context, orgID uuid.UUID, ancestors []uuid.UUID, permission string, amount *float64) (*gov.PolicyRule, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// ancestors[0] is most specific (depth 0); lower depth wins, tie-broken by higher version.
	depthByScope := make(map[uuid.UUID]int, len(ancestors))
	for idx, sc := range ancestors {
		if _, exists := depthByScope[sc]; !exists {
			depthByScope[sc] = idx
		}
	}

	var best *gov.PolicyRule
	bestDepth := int(^uint(0) >> 1)

	for _, r := range s.rules {
		if r.OrgID != orgID || r.Permission != permission || !r.IsActive || r.DeletedAt != nil {
			continue
		}
		d, ok := depthByScope[r.ScopeID]
		if !ok {
			continue
		}
		if r.MinAmount != nil && (amount == nil || *amount < *r.MinAmount) {
			continue
		}
		if r.MaxAmount != nil && (amount == nil || *amount > *r.MaxAmount) {
			continue
		}
		if best == nil || d < bestDepth || (d == bestDepth && r.Version > best.Version) {
			best = r
			bestDepth = d
		}
	}
	return cloneRule(best), nil
}

// -----------------------------------------------------------------------------
// Requests / Tickets
// -----------------------------------------------------------------------------

func (s *Store) CreateTicketIdempotent(_ context.Context, ticket *gov.Ticket) (*gov.Ticket, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := ticket.OrgID.String() + "|" + ticket.IdempotencyKey
	if existingID, ok := s.idemp[key]; ok {
		return cloneTicket(s.tickets[existingID]), false, nil
	}

	cp := cloneTicket(ticket)
	s.tickets[cp.ID] = cp
	s.idemp[key] = cp.ID
	return cloneTicket(cp), true, nil
}

func (s *Store) GetTicket(_ context.Context, orgID, requestID uuid.UUID) (*gov.Ticket, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	t, ok := s.tickets[requestID]
	if !ok || t.OrgID != orgID {
		return nil, gov.ErrNotFound
	}
	return cloneTicket(t), nil
}

func (s *Store) ListTickets(_ context.Context, orgID uuid.UUID, filter gov.ListFilter) (gov.Page[gov.Ticket], error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	stateSet := make(map[gov.State]bool, len(filter.States))
	for _, st := range filter.States {
		stateSet[st] = true
	}

	matched := make([]gov.Ticket, 0)
	for _, t := range s.tickets {
		if t.OrgID != orgID {
			continue
		}
		if len(stateSet) > 0 && !stateSet[t.State] {
			continue
		}
		if filter.Permission != "" && t.Permission != filter.Permission {
			continue
		}
		if filter.ScopeID != nil && t.ScopeID != *filter.ScopeID {
			continue
		}
		if filter.RequestedBy != nil && t.RequestedBy != *filter.RequestedBy {
			continue
		}
		if filter.CreatedFrom != nil && t.CreatedAt.Before(*filter.CreatedFrom) {
			continue
		}
		if filter.CreatedTo != nil && t.CreatedAt.After(*filter.CreatedTo) {
			continue
		}
		matched = append(matched, *cloneTicket(t))
	}

	sort.Slice(matched, func(i, j int) bool {
		return matched[i].CreatedAt.After(matched[j].CreatedAt)
	})

	total := len(matched)
	start := (filter.Page - 1) * filter.PageSize
	if start > total {
		start = total
	}
	end := start + filter.PageSize
	if end > total {
		end = total
	}
	totalPages := (total + filter.PageSize - 1) / filter.PageSize
	if totalPages == 0 {
		totalPages = 1
	}

	return gov.Page[gov.Ticket]{
		Items:      matched[start:end],
		Total:      total,
		Page:       filter.Page,
		PageSize:   filter.PageSize,
		TotalPages: totalPages,
	}, nil
}

// -----------------------------------------------------------------------------
// Atomic State Transitions
// -----------------------------------------------------------------------------

func (s *Store) RecordApprovalAndMaybeEnqueue(
	_ context.Context,
	orgID, requestID uuid.UUID,
	decision gov.ApprovalDecision,
	actionKey string,
	now time.Time,
) (gov.RecordApprovalResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	t, ok := s.tickets[requestID]
	if !ok || t.OrgID != orgID {
		return gov.RecordApprovalResult{}, gov.ErrNotFound
	}

	// Idempotent replay by the same approver
	for _, existing := range t.Approvals {
		if existing.ApproverID == decision.ApproverID && existing.Decision == "approved" {
			return gov.RecordApprovalResult{
				Ticket:           cloneTicket(t),
				IdempotentReplay: true,
			}, nil
		}
	}

	if t.State == gov.StateExpired || !t.ExpiresAt.After(now) {
		return gov.RecordApprovalResult{}, gov.ErrExpired
	}
	if t.State != gov.StatePending {
		return gov.RecordApprovalResult{}, gov.ErrStateConflict
	}

	t.Approvals = append(t.Approvals, decision)
	t.ApprovalsCount++
	t.UpdatedAt = now

	thresholdMet := t.ApprovalsCount >= t.RequiredApprovals
	if thresholdMet {
		if !gov.IsLegalTransition(t.State, gov.StateApproved) || !gov.IsLegalTransition(gov.StateApproved, gov.StateExecuting) {
			return gov.RecordApprovalResult{}, gov.ErrStateConflict
		}
		// Atomic pending -> approved -> executing + outbox enqueue
		t.State = gov.StateExecuting
		t.ExecutingAt = &now

		ob := &gov.OutboxItem{
			ID:            uuid.New(),
			RequestID:     t.ID,
			OrgID:         t.OrgID,
			PayloadEnc:    append([]byte(nil), t.PayloadEnc...),
			ActionKey:     actionKey,
			Attempts:      0,
			NextAttemptAt: now,
			CreatedAt:     now,
		}
		s.outbox[ob.ID] = ob
	}

	return gov.RecordApprovalResult{
		Ticket:             cloneTicket(t),
		ThresholdReached:   thresholdMet,
		EnqueuedForExecute: thresholdMet,
	}, nil
}

func (s *Store) RecordRejection(
	_ context.Context,
	orgID, requestID uuid.UUID,
	decision gov.ApprovalDecision,
	now time.Time,
) (*gov.Ticket, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	t, ok := s.tickets[requestID]
	if !ok || t.OrgID != orgID {
		return nil, gov.ErrNotFound
	}
	if t.State == gov.StateExpired || !t.ExpiresAt.After(now) {
		return nil, gov.ErrExpired
	}
	if !gov.IsLegalTransition(t.State, gov.StateRejected) || t.State != gov.StatePending {
		return nil, gov.ErrStateConflict
	}

	t.Approvals = append(t.Approvals, decision)
	t.State = gov.StateRejected
	t.UpdatedAt = now
	return cloneTicket(t), nil
}

func (s *Store) CancelTicket(
	_ context.Context,
	orgID, requestID, actorID uuid.UUID,
	reason string,
	now time.Time,
) (*gov.Ticket, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	t, ok := s.tickets[requestID]
	if !ok || t.OrgID != orgID {
		return nil, gov.ErrNotFound
	}
	if t.State != gov.StatePending {
		return nil, gov.ErrStateConflict
	}
	if t.ApprovalsCount > 0 || len(t.Approvals) > 0 {
		return nil, gov.ErrAlreadyInReview
	}
	if !gov.IsLegalTransition(t.State, gov.StateCancelled) {
		return nil, gov.ErrStateConflict
	}

	t.State = gov.StateCancelled
	t.CancelReason = reason
	t.CancelledBy = &actorID
	t.CancelledAt = &now
	t.UpdatedAt = now
	return cloneTicket(t), nil
}

// -----------------------------------------------------------------------------
// Outbox & Expiry Workers
// -----------------------------------------------------------------------------

func (s *Store) ClaimOutboxBatch(_ context.Context, now time.Time, limit int) ([]gov.OutboxItem, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	due := make([]*gov.OutboxItem, 0)
	for _, ob := range s.outbox {
		if ob.CompletedAt == nil && !ob.NextAttemptAt.After(now) {
			due = append(due, ob)
		}
	}
	sort.Slice(due, func(i, j int) bool {
		return due[i].NextAttemptAt.Before(due[j].NextAttemptAt)
	})
	if len(due) > limit {
		due = due[:limit]
	}

	out := make([]gov.OutboxItem, 0, len(due))
	for _, ob := range due {
		cp := *ob
		cp.PayloadEnc = append([]byte(nil), ob.PayloadEnc...)
		out = append(out, cp)
	}
	return out, nil
}

func (s *Store) GetTicketByIDForWorker(ctx context.Context, orgID, requestID uuid.UUID) (*gov.Ticket, error) {
	return s.GetTicket(ctx, orgID, requestID)
}

func (s *Store) MarkOutboxExecuted(_ context.Context, orgID, requestID uuid.UUID, result gov.ExecutionResult, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	t, ok := s.tickets[requestID]
	if !ok || t.OrgID != orgID {
		return gov.ErrNotFound
	}
	if !gov.IsLegalTransition(t.State, gov.StateExecuted) {
		return gov.ErrStateConflict
	}
	t.State = gov.StateExecuted
	t.ExecutedAt = &now
	t.ExecutionAttempts++
	resCopy := result
	t.ExecutionResult = &resCopy
	t.UpdatedAt = now

	for _, ob := range s.outbox {
		if ob.RequestID == requestID {
			ob.CompletedAt = &now
			ob.Attempts++
		}
	}
	return nil
}

func (s *Store) MarkOutboxRetry(_ context.Context, outboxID uuid.UUID, errMsg string, nextAttempt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	ob, ok := s.outbox[outboxID]
	if !ok {
		return gov.ErrNotFound
	}
	ob.Attempts++
	ob.LastError = errMsg
	ob.NextAttemptAt = nextAttempt
	if t, exists := s.tickets[ob.RequestID]; exists {
		t.ExecutionAttempts++
		t.UpdatedAt = time.Now().UTC()
	}
	return nil
}

func (s *Store) MarkOutboxFailed(_ context.Context, orgID, requestID, outboxID uuid.UUID, result gov.ExecutionResult, errMsg string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	t, ok := s.tickets[requestID]
	if !ok || t.OrgID != orgID {
		return gov.ErrNotFound
	}
	if !gov.IsLegalTransition(t.State, gov.StateFailed) {
		return gov.ErrStateConflict
	}
	t.State = gov.StateFailed
	t.FailedAt = &now
	t.ExecutionAttempts++
	resCopy := result
	t.ExecutionResult = &resCopy
	t.UpdatedAt = now

	if ob, exists := s.outbox[outboxID]; exists {
		ob.Attempts++
		ob.LastError = errMsg
		ob.CompletedAt = &now
	}
	return nil
}

func (s *Store) ExpirePendingTickets(_ context.Context, now time.Time, limit int) ([]gov.Ticket, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	expired := make([]gov.Ticket, 0)
	for _, t := range s.tickets {
		if len(expired) >= limit {
			break
		}
		if t.State == gov.StatePending && !t.ExpiresAt.After(now) {
			t.State = gov.StateExpired
			t.ExpiredAt = &now
			t.UpdatedAt = now
			expired = append(expired, *cloneTicket(t))
		}
	}
	return expired, nil
}

// -----------------------------------------------------------------------------
// Test Helpers for Security & Chaos Testing
// -----------------------------------------------------------------------------

// TamperPayload flips a byte in both the stored ticket and outbox ciphertext to simulate DB tampering.
func (s *Store) TamperPayload(requestID uuid.UUID) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if t, ok := s.tickets[requestID]; ok && len(t.PayloadEnc) > 10 {
		idx := len(t.PayloadEnc) - 3
		t.PayloadEnc[idx] ^= 0x01
	}
	for _, ob := range s.outbox {
		if ob.RequestID == requestID && len(ob.PayloadEnc) > 10 {
			idx := len(ob.PayloadEnc) - 3
			ob.PayloadEnc[idx] ^= 0x01
		}
	}
}

