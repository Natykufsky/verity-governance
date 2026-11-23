package tests

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
	gov "github.com/Natykufsky/verity-governance"
)

func TestSecurity_TamperDetection_FailsClosed(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)

	_, _ = h.engine.CreateRule(ctx, h.admin, gov.RuleInput{
		ScopeID:           h.parishID,
		Permission:        "finance.disburse",
		CheckerRoles:      []string{"parish_priest"},
		RequiredApprovals: 1,
		RequireStepUp:     boolPtr(false),
	})

	var executed atomic.Bool
	h.engine.RegisterExecutor("finance.disburse", gov.ActionExecutorFunc(
		func(_ context.Context, _ uuid.UUID, _ map[string]any) (gov.ExecutionResult, error) {
			executed.Store(true)
			return gov.ExecutionResult{Status: "ok"}, nil
		},
	))

	ticket, err := h.engine.Submit(ctx, gov.SubmitInput{
		Principal:      h.maker,
		Permission:     "finance.disburse",
		ScopeID:        h.parishID,
		TargetType:     "stipend",
		Title:          "Tamper test",
		Payload:        map[string]any{"bank_acct": "0011223344", "amount": 50000},
		IdempotencyKey: "tamper-1",
	})
	if err != nil {
		t.Fatalf("submit: %v", err)
	}

	if _, err := h.engine.Approve(ctx, gov.DecisionInput{
		Principal:      h.checker1,
		RequestID:      ticket.ID,
		PayloadHashHex: ticket.PayloadHashHex,
	}); err != nil {
		t.Fatalf("approve: %v", err)
	}

	// Simulate rogue DBA flipping a byte in payload_enc between approve and execute
	h.store.TamperPayload(ticket.ID)

	worker := gov.NewOutboxWorker(h.engine, gov.OutboxWorkerConfig{})
	if _, err := worker.ProcessOnce(ctx); err != nil {
		t.Fatalf("worker ProcessOnce: %v", err)
	}

	if executed.Load() {
		t.Fatalf("CRITICAL: executor ran on tampered payload!")
	}

	// Verify ticket moved to terminal failed with PAYLOAD_INTEGRITY_FAILURE
	rawTicket, err := h.store.GetTicket(ctx, h.orgID, ticket.ID)
	if err != nil {
		t.Fatalf("store GetTicket: %v", err)
	}
	if rawTicket.State != gov.StateFailed {
		t.Fatalf("expected state=failed, got %s", rawTicket.State)
	}
	if rawTicket.ExecutionResult == nil || rawTicket.ExecutionResult.ErrorCode != string(gov.CodePayloadIntegrityFailure) {
		t.Fatalf("expected error_code=%s, got %+v", gov.CodePayloadIntegrityFailure, rawTicket.ExecutionResult)
	}
}

func TestSecurity_SelfApproval_DualAccountIdentityGuard_AndStepUp(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)

	// Rule 1: disallow self-approval (default)
	_, _ = h.engine.CreateRule(ctx, h.admin, gov.RuleInput{
		ScopeID:           h.parishID,
		Permission:        "finance.disburse",
		CheckerRoles:      []string{"parish_priest"},
		AllowSelfApproval: false,
		RequireStepUp:     boolPtr(false),
	})

	// Grant maker the checker role too so we specifically test dual-custody, not role check
	h.roles.Grant(h.maker.ActorID, h.parishID, "parish_priest")

	// Give checker1 the SAME verified identity hash as maker (same human, two accounts)
	h.identity.hashes[h.maker.ActorID] = "sha256:same-person-email-hash"
	h.identity.hashes[h.checker1.ActorID] = "sha256:same-person-email-hash"
	h.identity.hashes[h.checker2.ActorID] = "sha256:different-person-hash"

	ticket, err := h.engine.Submit(ctx, gov.SubmitInput{
		Principal:      h.maker,
		Permission:     "finance.disburse",
		ScopeID:        h.parishID,
		TargetType:     "stipend",
		Title:          "Dual custody check",
		Payload:        map[string]any{"amount": 1000},
		IdempotencyKey: "self-1",
	})
	if err != nil {
		t.Fatalf("submit: %v", err)
	}

	// Direct same-account self-approval -> blocked
	if _, err := h.engine.Approve(ctx, gov.DecisionInput{
		Principal:      h.maker,
		RequestID:      ticket.ID,
		PayloadHashHex: ticket.PayloadHashHex,
	}); !errors.Is(err, gov.ErrSelfApprovalForbidden) {
		t.Fatalf("expected GOV_SELF_APPROVAL_FORBIDDEN on same account, got %v", err)
	}

	// Dual-account same-human self-approval -> blocked by IdentityGuard!
	if _, err := h.engine.Approve(ctx, gov.DecisionInput{
		Principal:      h.checker1,
		RequestID:      ticket.ID,
		PayloadHashHex: ticket.PayloadHashHex,
	}); !errors.Is(err, gov.ErrSelfApprovalForbidden) {
		t.Fatalf("expected GOV_SELF_APPROVAL_FORBIDDEN on dual-account identity match, got %v", err)
	}

	// Rule 2: allow_self_approval = true -> MUST still require step-up + mandatory reason + emit self_approved
	_, _ = h.engine.CreateRule(ctx, h.admin, gov.RuleInput{
		ScopeID:           h.parishID,
		Permission:        "org.rename",
		CheckerRoles:      []string{"parish_priest"},
		AllowSelfApproval: true,
		RequireStepUp:     boolPtr(true),
	})

	tSelf, _ := h.engine.Submit(ctx, gov.SubmitInput{
		Principal:      h.maker,
		Permission:     "org.rename",
		ScopeID:        h.parishID,
		TargetType:     "org",
		Title:          "Emergency rename",
		Payload:        map[string]any{"name": "St. Jude"},
		IdempotencyKey: "self-allowed-1",
	})

	// Missing reason -> 422
	if _, err := h.engine.Approve(ctx, gov.DecisionInput{
		Principal:      h.maker,
		RequestID:      tSelf.ID,
		PayloadHashHex: tSelf.PayloadHashHex,
		StepUpToken:    "valid-totp-123",
	}); !errors.Is(err, gov.ErrReasonRequired) {
		t.Fatalf("expected GOV_REASON_REQUIRED for self-approval without reason, got %v", err)
	}

	// Missing / wrong step-up token -> 401
	if _, err := h.engine.Approve(ctx, gov.DecisionInput{
		Principal:      h.maker,
		RequestID:      tSelf.ID,
		PayloadHashHex: tSelf.PayloadHashHex,
		Reason:         "Emergency break-glass",
		StepUpToken:    "wrong-token",
	}); !errors.Is(err, gov.ErrStepUpRequired) {
		t.Fatalf("expected GOV_STEP_UP_REQUIRED for invalid step-up, got %v", err)
	}

	// Valid step-up + reason -> succeeds and emits governance.request.self_approved
	approved, err := h.engine.Approve(ctx, gov.DecisionInput{
		Principal:      h.maker,
		RequestID:      tSelf.ID,
		PayloadHashHex: tSelf.PayloadHashHex,
		Reason:         "Emergency break-glass",
		StepUpToken:    "valid-totp-123",
	})
	if err != nil || approved.State != gov.StateExecuting {
		t.Fatalf("expected self-approval with step-up+reason to succeed, got %+v err=%v", approved, err)
	}
	if !approved.Approvals[0].StepUpUsed {
		t.Fatalf("expected step_up_used=true on approval decision")
	}
	if !h.events.Has(gov.EventRequestSelfApproved) {
		t.Fatalf("expected governance.request.self_approved event to be published")
	}
}

func TestSecurity_RoleEscalation_TenantIsolation_PayloadLimit_HashMismatch(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)

	_, _ = h.engine.CreateRule(ctx, h.admin, gov.RuleInput{
		ScopeID:         h.parishID,
		Permission:      "finance.disburse",
		CheckerRoles:    []string{"parish_priest"},
		MaxPayloadBytes: 1024,
		RequireStepUp:   boolPtr(false),
	})

	// Payload too large -> 413 GOV_PAYLOAD_TOO_LARGE
	_, err := h.engine.Submit(ctx, gov.SubmitInput{
		Principal:      h.maker,
		Permission:     "finance.disburse",
		ScopeID:        h.parishID,
		TargetType:     "stipend",
		Title:          "Huge payload",
		Payload:        map[string]any{"blob": strings.Repeat("A", 2048)},
		IdempotencyKey: "too-big",
	})
	if !errors.Is(err, gov.ErrPayloadTooLarge) {
		t.Fatalf("expected GOV_PAYLOAD_TOO_LARGE, got %v", err)
	}

	ticket, err := h.engine.Submit(ctx, gov.SubmitInput{
		Principal:      h.maker,
		Permission:     "finance.disburse",
		ScopeID:        h.parishID,
		TargetType:     "stipend",
		Title:          "Normal payload",
		Payload:        map[string]any{"amount": 500},
		IdempotencyKey: "sec-1",
	})
	if err != nil {
		t.Fatalf("submit: %v", err)
	}

	// Maker-only user trying to approve -> 403 GOV_ROLE_REQUIRED
	otherMaker := gov.Principal{ActorID: uuid.New(), OrgID: h.orgID}
	h.roles.Grant(otherMaker.ActorID, h.parishID, "parish_admin")
	if _, err := h.engine.Approve(ctx, gov.DecisionInput{
		Principal:      otherMaker,
		RequestID:      ticket.ID,
		PayloadHashHex: ticket.PayloadHashHex,
	}); !errors.Is(err, gov.ErrRoleRequired) {
		t.Fatalf("expected GOV_ROLE_REQUIRED, got %v", err)
	}

	// Cross-tenant access -> 404 GOV_NOT_FOUND (must NOT leak existence with 403)
	otherOrgUser := gov.Principal{ActorID: uuid.New(), OrgID: uuid.New()}
	if _, err := h.engine.Get(ctx, otherOrgUser, ticket.ID); !errors.Is(err, gov.ErrNotFound) {
		t.Fatalf("expected cross-tenant Get to return GOV_NOT_FOUND (404), got %v", err)
	}
	if _, err := h.engine.Approve(ctx, gov.DecisionInput{
		Principal:      otherOrgUser,
		RequestID:      ticket.ID,
		PayloadHashHex: ticket.PayloadHashHex,
	}); !errors.Is(err, gov.ErrNotFound) {
		t.Fatalf("expected cross-tenant Approve to return GOV_NOT_FOUND (404), got %v", err)
	}

	// Wrong payload_hash at approve -> 409 GOV_HASH_MISMATCH
	if _, err := h.engine.Approve(ctx, gov.DecisionInput{
		Principal:      h.checker1,
		RequestID:      ticket.ID,
		PayloadHashHex: "deadbeef",
	}); !errors.Is(err, gov.ErrHashMismatch) {
		t.Fatalf("expected GOV_HASH_MISMATCH, got %v", err)
	}
}

