package tests

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	gov "github.com/Natykufsky/verity-governance"
)

func TestWorkers_OutboxRetryBackoff_AndMissingExecutor_AndExpiry(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)

	_, _ = h.engine.CreateRule(ctx, h.admin, gov.RuleInput{
		ScopeID:        h.parishID,
		Permission:     "finance.disburse",
		CheckerRoles:   []string{"parish_priest"},
		ExpiresInHours: 24,
		RequireStepUp:  boolPtr(false),
	})
	_, _ = h.engine.CreateRule(ctx, h.admin, gov.RuleInput{
		ScopeID:        h.parishID,
		Permission:     "missing.action",
		CheckerRoles:   []string{"parish_priest"},
		ExpiresInHours: 24,
		RequireStepUp:  boolPtr(false),
	})

	// 1. Outbox retry: fails twice, succeeds on 3rd attempt
	var attempts atomic.Int32
	h.engine.RegisterExecutor("finance.disburse", gov.ActionExecutorFunc(
		func(_ context.Context, reqID uuid.UUID, payload map[string]any) (gov.ExecutionResult, error) {
			n := attempts.Add(1)
			if n < 3 {
				return gov.ExecutionResult{}, errors.New("transient bank API timeout")
			}
			return gov.ExecutionResult{Status: "ok", Output: map[string]any{"req_id": reqID.String()}}, nil
		},
	))

	tRetry, _ := h.engine.Submit(ctx, gov.SubmitInput{
		Principal:      h.maker,
		Permission:     "finance.disburse",
		ScopeID:        h.parishID,
		TargetType:     "stipend",
		Title:          "Retryable payout",
		Payload:        map[string]any{"amount": 7500},
		IdempotencyKey: "retry-1",
	})
	_, err := h.engine.Approve(ctx, gov.DecisionInput{
		Principal:      h.checker1,
		RequestID:      tRetry.ID,
		PayloadHashHex: tRetry.PayloadHashHex,
	})
	if err != nil {
		t.Fatalf("approve retry ticket: %v", err)
	}

	worker := gov.NewOutboxWorker(h.engine, gov.OutboxWorkerConfig{
		MaxAttempts: 5,
		BaseBackoff: 10 * time.Second,
	})

	// Attempt 1 -> transient fail, scheduled +10s
	_, _ = worker.ProcessOnce(ctx)
	cur, _ := h.engine.Get(ctx, h.maker, tRetry.ID)
	if cur.State != gov.StateExecuting {
		t.Fatalf("expected still executing after transient failure 1, got %s", cur.State)
	}

	// Attempt 2 after advancing clock +11s -> transient fail, scheduled +20s
	h.clock.Advance(11 * time.Second)
	_, _ = worker.ProcessOnce(ctx)
	cur, _ = h.engine.Get(ctx, h.maker, tRetry.ID)
	if cur.State != gov.StateExecuting {
		t.Fatalf("expected still executing after transient failure 2, got %s", cur.State)
	}

	// Attempt 3 after advancing clock +21s -> succeeds!
	h.clock.Advance(21 * time.Second)
	_, _ = worker.ProcessOnce(ctx)
	cur, _ = h.engine.Get(ctx, h.maker, tRetry.ID)
	if cur.State != gov.StateExecuted || cur.ExecutionResult == nil || cur.ExecutionResult.Status != "ok" {
		t.Fatalf("expected executed after 3rd attempt, got state=%s res=%+v", cur.State, cur.ExecutionResult)
	}

	// 2. Missing executor -> fails closed immediately
	tMissing, _ := h.engine.Submit(ctx, gov.SubmitInput{
		Principal:      h.maker,
		Permission:     "missing.action",
		ScopeID:        h.parishID,
		TargetType:     "unknown",
		Title:          "No executor registered",
		Payload:        map[string]any{"x": 1},
		IdempotencyKey: "missing-1",
	})
	_, _ = h.engine.Approve(ctx, gov.DecisionInput{
		Principal:      h.checker1,
		RequestID:      tMissing.ID,
		PayloadHashHex: tMissing.PayloadHashHex,
	})
	_, _ = worker.ProcessOnce(ctx)
	curM, _ := h.engine.Get(ctx, h.maker, tMissing.ID)
	if curM.State != gov.StateFailed || curM.ExecutionResult.ErrorCode != string(gov.CodeExecutorNotFound) {
		t.Fatalf("expected failed with GOV_EXECUTOR_NOT_FOUND, got state=%s res=%+v", curM.State, curM.ExecutionResult)
	}

	// 3. Expiry worker sweeps tickets past expires_at
	tExp, _ := h.engine.Submit(ctx, gov.SubmitInput{
		Principal:      h.maker,
		Permission:     "finance.disburse",
		ScopeID:        h.parishID,
		TargetType:     "stipend",
		Title:          "Expiring ticket",
		Payload:        map[string]any{"amount": 100},
		IdempotencyKey: "exp-1",
	})

	expWorker := gov.NewExpiryWorker(h.engine, time.Minute, 50)
	// Before expiry: 0 expired
	n, _ := expWorker.SweepOnce(ctx)
	if n != 0 {
		t.Fatalf("expected 0 expired before deadline, got %d", n)
	}

	// Advance clock past 24h -> swept to expired!
	h.clock.Advance(25 * time.Hour)
	n, err = expWorker.SweepOnce(ctx)
	if err != nil || n != 1 {
		t.Fatalf("expected 1 expired ticket, got n=%d err=%v", n, err)
	}
	curExp, _ := h.engine.Get(ctx, h.maker, tExp.ID)
	if curExp.State != gov.StateExpired {
		t.Fatalf("expected state=expired, got %s", curExp.State)
	}

	// Trying to approve expired ticket returns GOV_EXPIRED (410)
	if _, err := h.engine.Approve(ctx, gov.DecisionInput{
		Principal:      h.checker1,
		RequestID:      tExp.ID,
		PayloadHashHex: tExp.PayloadHashHex,
	}); !errors.Is(err, gov.ErrExpired) {
		t.Fatalf("expected GOV_EXPIRED, got %v", err)
	}
}

