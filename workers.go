package governance

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// OutboxWorkerConfig configures the async crash-safe execution worker (§6).
type OutboxWorkerConfig struct {
	PollInterval time.Duration // default 5s
	BatchSize    int           // default 20
	MaxAttempts  int           // default 5
	BaseBackoff  time.Duration // default 5s (exponential: base * 2^(attempts-1))
}

// OutboxWorker drains governance_outbox, verifies payload integrity byte-for-byte,
// invokes registered idempotent ActionExecutors, and updates governance_request state.
type OutboxWorker struct {
	engine       *Engine
	pollInterval time.Duration
	batchSize    int
	maxAttempts  int
	baseBackoff  time.Duration
}

func NewOutboxWorker(engine *Engine, cfg OutboxWorkerConfig) *OutboxWorker {
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 5 * time.Second
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 20
	}
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = DefaultOutboxMaxAttempts
	}
	if cfg.BaseBackoff <= 0 {
		cfg.BaseBackoff = DefaultOutboxBaseBackoff
	}
	return &OutboxWorker{
		engine:       engine,
		pollInterval: cfg.PollInterval,
		batchSize:    cfg.BatchSize,
		maxAttempts:  cfg.MaxAttempts,
		baseBackoff:  cfg.BaseBackoff,
	}
}

// Run polls the outbox until ctx is cancelled, then drains the in-flight batch before returning.
func (w *OutboxWorker) Run(ctx context.Context) error {
	ticker := time.NewTicker(w.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			if _, err := w.ProcessOnce(ctx); err != nil && ctx.Err() == nil {
				w.engine.logger.ErrorContext(ctx, "governance outbox poll error", "error", err)
			}
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// ProcessOnce claims up to BatchSize due outbox items and processes them synchronously.
// Returns the number of items processed (useful for deterministic testing and --drain mode).
func (w *OutboxWorker) ProcessOnce(ctx context.Context) (int, error) {
	now := w.engine.clock.Now().UTC()
	items, err := w.engine.store.ClaimOutboxBatch(ctx, now, w.batchSize)
	if err != nil {
		return 0, err
	}
	if len(items) == 0 {
		w.engine.metrics.SetOutboxLagSeconds(0)
		return 0, nil
	}

	// Track oldest due lag
	oldestLag := now.Sub(items[0].NextAttemptAt).Seconds()
	if oldestLag < 0 {
		oldestLag = 0
	}
	w.engine.metrics.SetOutboxLagSeconds(oldestLag)

	for _, item := range items {
		w.processItem(ctx, item)
	}
	return len(items), nil
}

func (w *OutboxWorker) processItem(ctx context.Context, item OutboxItem) {
	start := w.engine.clock.Now().UTC()
	ticket, err := w.engine.store.GetTicketByIDForWorker(ctx, item.OrgID, item.RequestID)
	if err != nil {
		w.engine.logger.ErrorContext(ctx, "outbox: failed loading ticket", "request_id", item.RequestID, "error", err)
		return
	}

	// Step 1: Decrypt & re-verify canonical SHA-256 hash + Ed25519 signature (§5.3)
	payload, integrityErr := w.decryptAndVerify(ticket, item.PayloadEnc)
	if integrityErr != nil {
		// Tamper / integrity failure is terminal immediately (do NOT retry tampered payloads)
		res := ExecutionResult{
			Status:    "failed",
			ErrorCode: string(CodePayloadIntegrityFailure),
			Detail:    integrityErr.Error(),
		}
		w.failTerminal(ctx, ticket, item, res, CodePayloadIntegrityFailure, integrityErr.Error())
		return
	}

	// Step 2: Lookup registered executor (fail closed if missing per §1.3 & §6)
	exec, ok := w.engine.getExecutor(item.ActionKey)
	if !ok {
		res := ExecutionResult{
			Status:    "failed",
			ErrorCode: string(CodeExecutorNotFound),
			Detail:    fmt.Sprintf("no executor registered for action_key %q", item.ActionKey),
		}
		w.failTerminal(ctx, ticket, item, res, CodeExecutorNotFound, res.Detail)
		return
	}

	// Step 3: Execute idempotently with ticket.ID
	result, execErr := exec.Execute(ctx, ticket.ID, payload)
	doneAt := w.engine.clock.Now().UTC()
	if execErr != nil {
		attempts := item.Attempts + 1
		if attempts >= w.maxAttempts {
			errCode := CodeStateConflict
			if c, has := CodeOf(execErr); has {
				errCode = c
			}
			res := ExecutionResult{
				Status:    "failed",
				ErrorCode: string(errCode),
				Detail:    execErr.Error(),
			}
			w.failTerminal(ctx, ticket, item, res, errCode, execErr.Error())
			return
		}
		backoff := w.baseBackoff * (1 << (attempts - 1))
		nextAt := doneAt.Add(backoff)
		if err := w.engine.store.MarkOutboxRetry(ctx, item.ID, execErr.Error(), nextAt); err != nil {
			w.engine.logger.ErrorContext(ctx, "outbox: failed scheduling retry", "outbox_id", item.ID, "error", err)
		}
		return
	}

	if result.Status == "" {
		result.Status = "ok"
	}
	if err := w.engine.store.MarkOutboxExecuted(ctx, ticket.OrgID, ticket.ID, result, doneAt); err != nil {
		w.engine.logger.ErrorContext(ctx, "outbox: failed marking executed", "request_id", ticket.ID, "error", err)
		return
	}

	w.engine.metrics.ObserveExecutionDuration(ticket.Permission, doneAt.Sub(start))
	w.engine.publishEvent(ctx, Event{
		Type:        EventRequestExecuted,
		OrgID:       ticket.OrgID,
		ScopeID:     ticket.ScopeID,
		RequestID:   ticket.ID,
		Permission:  ticket.Permission,
		PayloadHash: ticket.PayloadHashHex,
		OccurredAt:  doneAt,
		Metadata:    map[string]any{"status": result.Status},
	})
	w.engine.dispatchNotification(ctx, Notification{
		EventType:    EventRequestExecuted,
		OrgID:        ticket.OrgID,
		ScopeID:      ticket.ScopeID,
		RequestID:    ticket.ID,
		Permission:   ticket.Permission,
		Title:        ticket.Title,
		RecipientIDs: collectStakeholders(ticket),
		Message:      fmt.Sprintf("Approved request '%s' executed successfully.", ticket.Title),
		OccurredAt:   doneAt,
	})
}

func (w *OutboxWorker) decryptAndVerify(ticket *Ticket, encBytes []byte) (map[string]any, error) {
	// Check both outbox payload_enc and ticket.PayloadEnc if present
	cipherBytes := encBytes
	if len(ticket.PayloadEnc) > 0 && !bytes.Equal(ticket.PayloadEnc, encBytes) {
		return nil, fmt.Errorf("outbox payload ciphertext diverges from ledger ticket")
	}

	plain, err := w.engine.crypto.Decrypt(cipherBytes)
	if err != nil {
		return nil, fmt.Errorf("payload decryption failed (possible tamper): %w", err)
	}

	var payload map[string]any
	if err := json.Unmarshal(plain, &payload); err != nil {
		return nil, fmt.Errorf("payload json decode failed: %w", err)
	}

	canonical, err := w.engine.crypto.Canonicalize(payload)
	if err != nil {
		return nil, fmt.Errorf("payload re-canonicalization failed: %w", err)
	}

	recomputedHash := w.engine.crypto.Hash(canonical)
	if !bytes.Equal(recomputedHash, ticket.PayloadHash) {
		return nil, fmt.Errorf("recomputed payload hash does not match stored hash")
	}

	meta := buildRequestMeta(ticket.OrgID, ticket.Permission, ticket.ScopeID, ticket.TargetResourceType, ticket.TargetResourceID)
	if !w.engine.crypto.Verify(meta, ticket.PayloadHash, ticket.PayloadSig) {
		return nil, fmt.Errorf("payload Ed25519 signature verification failed")
	}

	return payload, nil
}

func (w *OutboxWorker) failTerminal(ctx context.Context, ticket *Ticket, item OutboxItem, res ExecutionResult, errCode ErrorCode, errMsg string) {
	now := w.engine.clock.Now().UTC()
	if err := w.engine.store.MarkOutboxFailed(ctx, ticket.OrgID, ticket.ID, item.ID, res, errMsg, now); err != nil {
		w.engine.logger.ErrorContext(ctx, "outbox: failed marking terminal failure", "request_id", ticket.ID, "error", err)
		return
	}
	w.engine.metrics.IncExecutionError(ticket.Permission, errCode)
	w.engine.publishEvent(ctx, Event{
		Type:        EventRequestFailed,
		OrgID:       ticket.OrgID,
		ScopeID:     ticket.ScopeID,
		RequestID:   ticket.ID,
		Permission:  ticket.Permission,
		PayloadHash: ticket.PayloadHashHex,
		OccurredAt:  now,
		Metadata:    map[string]any{"error_code": string(errCode), "detail": errMsg},
	})
	w.engine.dispatchNotification(ctx, Notification{
		EventType:    EventRequestFailed,
		OrgID:        ticket.OrgID,
		ScopeID:      ticket.ScopeID,
		RequestID:    ticket.ID,
		Permission:   ticket.Permission,
		Title:        ticket.Title,
		RecipientIDs: collectStakeholders(ticket),
		Message:      fmt.Sprintf("Execution failed for '%s' (%s): %s", ticket.Title, errCode, errMsg),
		OccurredAt:   now,
	})
}

func collectStakeholders(t *Ticket) []uuid.UUID {
	seen := map[uuid.UUID]bool{t.RequestedBy: true}
	out := []uuid.UUID{t.RequestedBy}
	for _, a := range t.Approvals {
		if !seen[a.ApproverID] {
			seen[a.ApproverID] = true
			out = append(out, a.ApproverID)
		}
	}
	return out
}

// -----------------------------------------------------------------------------
// Expiry Worker (§1.2, §9)
// -----------------------------------------------------------------------------

// ExpiryWorker sweeps pending tickets past expires_at and transitions them to expired.
type ExpiryWorker struct {
	engine       *Engine
	pollInterval time.Duration
	batchSize    int
}

func NewExpiryWorker(engine *Engine, pollInterval time.Duration, batchSize int) *ExpiryWorker {
	if pollInterval <= 0 {
		pollInterval = 5 * time.Minute
	}
	if batchSize <= 0 {
		batchSize = 100
	}
	return &ExpiryWorker{
		engine:       engine,
		pollInterval: pollInterval,
		batchSize:    batchSize,
	}
}

func (w *ExpiryWorker) Run(ctx context.Context) error {
	ticker := time.NewTicker(w.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			if _, err := w.SweepOnce(ctx); err != nil && ctx.Err() == nil {
				w.engine.logger.ErrorContext(ctx, "governance expiry sweep error", "error", err)
			}
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// SweepOnce expires up to batchSize pending tickets whose expires_at <= now.
func (w *ExpiryWorker) SweepOnce(ctx context.Context) (int, error) {
	now := w.engine.clock.Now().UTC()
	expired, err := w.engine.store.ExpirePendingTickets(ctx, now, w.batchSize)
	if err != nil {
		return 0, err
	}
	for _, t := range expired {
		w.engine.metrics.IncExpired(t.Permission)
		w.engine.publishEvent(ctx, Event{
			Type:        EventRequestExpired,
			OrgID:       t.OrgID,
			ScopeID:     t.ScopeID,
			RequestID:   t.ID,
			Permission:  t.Permission,
			PayloadHash: t.PayloadHashHex,
			OccurredAt:  now,
		})
		w.engine.dispatchNotification(ctx, Notification{
			EventType:    EventRequestExpired,
			OrgID:        t.OrgID,
			ScopeID:      t.ScopeID,
			RequestID:    t.ID,
			Permission:   t.Permission,
			Title:        t.Title,
			RecipientIDs: []uuid.UUID{t.RequestedBy},
			Message:      fmt.Sprintf("Approval request '%s' has expired.", t.Title),
			OccurredAt:   now,
		})
	}
	return len(expired), nil
}
