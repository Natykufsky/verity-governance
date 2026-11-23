package tests

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
	gov "github.com/Natykufsky/verity-governance"
)

func TestConcurrency_ParallelApproveRace_1of1(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)

	_, err := h.engine.CreateRule(ctx, h.admin, gov.RuleInput{
		ScopeID:           h.parishID,
		Permission:        "finance.disburse",
		CheckerRoles:      []string{"parish_priest"},
		RequiredApprovals: 1,
		RequireStepUp:     boolPtr(false),
	})
	if err != nil {
		t.Fatalf("create rule: %v", err)
	}

	var execCount atomic.Int32
	h.engine.RegisterExecutor("finance.disburse", gov.ActionExecutorFunc(
		func(_ context.Context, _ uuid.UUID, _ map[string]any) (gov.ExecutionResult, error) {
			execCount.Add(1)
			return gov.ExecutionResult{Status: "ok"}, nil
		},
	))

	ticket, err := h.engine.Submit(ctx, gov.SubmitInput{
		Principal:      h.maker,
		Permission:     "finance.disburse",
		ScopeID:        h.parishID,
		TargetType:     "stipend",
		Title:          "Concurrent approve test",
		Payload:        map[string]any{"amount": 25000},
		IdempotencyKey: "race-1",
	})
	if err != nil {
		t.Fatalf("submit: %v", err)
	}

	// Launch 10 distinct checkers approving simultaneously
	const N = 10
	start := make(chan struct{})
	var wg sync.WaitGroup
	var winners, conflicts, others atomic.Int32

	for i := 0; i < N; i++ {
		checker := gov.Principal{ActorID: uuid.New(), OrgID: h.orgID}
		h.roles.Grant(checker.ActorID, h.parishID, "parish_priest")

		wg.Add(1)
		go func(p gov.Principal) {
			defer wg.Done()
			<-start
			_, err := h.engine.Approve(ctx, gov.DecisionInput{
				Principal:      p,
				RequestID:      ticket.ID,
				PayloadHashHex: ticket.PayloadHashHex,
			})
			switch {
			case err == nil:
				winners.Add(1)
			case errors.Is(err, gov.ErrStateConflict):
				conflicts.Add(1)
			default:
				others.Add(1)
			}
		}(checker)
	}
	close(start)
	wg.Wait()

	if winners.Load() != 1 {
		t.Fatalf("expected exactly 1 winner, got winners=%d conflicts=%d others=%d", winners.Load(), conflicts.Load(), others.Load())
	}
	if conflicts.Load() != N-1 {
		t.Fatalf("expected %d GOV_STATE_CONFLICT losers, got %d", N-1, conflicts.Load())
	}

	// Approve handler must NEVER execute inline
	if execCount.Load() != 0 {
		t.Fatalf("approve must not call executor inline, got execCount=%d", execCount.Load())
	}

	// Outbox worker executes exactly once
	worker := gov.NewOutboxWorker(h.engine, gov.OutboxWorkerConfig{})
	if _, err := worker.ProcessOnce(ctx); err != nil {
		t.Fatalf("ProcessOnce: %v", err)
	}
	if execCount.Load() != 1 {
		t.Fatalf("expected exactly 1 execution from outbox worker, got %d", execCount.Load())
	}
}

func TestIdempotency_SubmitAndApproveReplay(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)

	_, _ = h.engine.CreateRule(ctx, h.admin, gov.RuleInput{
		ScopeID:           h.parishID,
		Permission:        "export.request",
		CheckerRoles:      []string{"parish_priest"},
		RequiredApprovals: 1,
		RequireStepUp:     boolPtr(false),
	})

	in := gov.SubmitInput{
		Principal:      h.maker,
		Permission:     "export.request",
		ScopeID:        h.parishID,
		TargetType:     "export",
		Title:          "Idempotent export",
		Payload:        map[string]any{"rows": 100},
		IdempotencyKey: "same-key-99",
	}
	t1, err := h.engine.Submit(ctx, in)
	if err != nil {
		t.Fatalf("submit 1: %v", err)
	}
	t2, err := h.engine.Submit(ctx, in)
	if err != nil {
		t.Fatalf("submit 2: %v", err)
	}
	if t1.ID != t2.ID {
		t.Fatalf("idempotent submit returned different ticket IDs: %s vs %s", t1.ID, t2.ID)
	}

	// Approve twice by the same checker -> second call is an idempotent replay, single execution
	var execCount atomic.Int32
	h.engine.RegisterExecutor("export.request", gov.ActionExecutorFunc(
		func(_ context.Context, _ uuid.UUID, _ map[string]any) (gov.ExecutionResult, error) {
			execCount.Add(1)
			return gov.ExecutionResult{Status: "ok"}, nil
		},
	))

	decIn := gov.DecisionInput{
		Principal:      h.checker1,
		RequestID:      t1.ID,
		PayloadHashHex: t1.PayloadHashHex,
	}
	a1, err := h.engine.Approve(ctx, decIn)
	if err != nil {
		t.Fatalf("approve 1: %v", err)
	}
	a2, err := h.engine.Approve(ctx, decIn)
	if err != nil {
		t.Fatalf("approve 2 replay should succeed idempotently, got: %v", err)
	}
	if a1.ID != a2.ID || a2.ApprovalsCount != 1 {
		t.Fatalf("unexpected replay ticket: %+v", a2)
	}

	worker := gov.NewOutboxWorker(h.engine, gov.OutboxWorkerConfig{})
	_, _ = worker.ProcessOnce(ctx)
	_, _ = worker.ProcessOnce(ctx)
	if execCount.Load() != 1 {
		t.Fatalf("expected exactly 1 execution across replays, got %d", execCount.Load())
	}
}

