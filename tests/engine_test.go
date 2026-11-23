package tests

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	gov "github.com/Natykufsky/verity-governance"
	"github.com/Natykufsky/verity-governance/memstore"
)

// -----------------------------------------------------------------------------
// Shared Test Harness
// -----------------------------------------------------------------------------

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

type staticStepUp struct {
	validToken string
}

func (s staticStepUp) VerifyStepUp(_ context.Context, _ gov.Principal, token string) error {
	if token != s.validToken {
		return errors.New("invalid step-up token")
	}
	return nil
}

type mapIdentityGuard struct {
	hashes map[uuid.UUID]string
}

func (g mapIdentityGuard) IdentityHash(_ context.Context, actorID uuid.UUID) (string, error) {
	return g.hashes[actorID], nil
}

type captureEvents struct {
	mu     sync.Mutex
	events []gov.Event
}

func (c *captureEvents) Publish(_ context.Context, ev gov.Event) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, ev)
	return nil
}

func (c *captureEvents) Has(et gov.EventType) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, ev := range c.events {
		if ev.Type == et {
			return true
		}
	}
	return false
}

type harness struct {
	store    *memstore.Store
	scopes   *gov.StaticScopeResolver
	roles    *gov.StaticRoleResolver
	clock    *fakeClock
	events   *captureEvents
	identity *mapIdentityGuard
	engine   *gov.Engine

	orgID      uuid.UUID
	globalID   uuid.UUID
	dioceseID  uuid.UUID
	parishID   uuid.UUID
	admin      gov.Principal
	maker      gov.Principal
	checker1   gov.Principal
	checker2   gov.Principal
	checker3   gov.Principal
}

func newHarness(t *testing.T, opts ...func(*gov.Config)) *harness {
	t.Helper()
	st := memstore.New()
	scopes := gov.NewStaticScopeResolver()
	orgID := uuid.New()
	globalID := uuid.New()
	dioceseID := uuid.New()
	parishID := uuid.New()
	scopes.SetParent(parishID, dioceseID)
	scopes.SetParent(dioceseID, globalID)

	roles := gov.NewStaticRoleResolver(scopes,
		"super_admin", "parish_admin", "accountant", "parish_priest", "chancellor", "diocesan_admin",
	)
	clock := newFakeClock()
	events := &captureEvents{}
	idGuard := &mapIdentityGuard{hashes: make(map[uuid.UUID]string)}
	crypto, err := gov.NewLocalCryptoProvider("unit-test-secret-key")
	if err != nil {
		t.Fatalf("crypto: %v", err)
	}

	h := &harness{
		store:     st,
		scopes:    scopes,
		roles:     roles,
		clock:     clock,
		events:    events,
		identity:  idGuard,
		orgID:     orgID,
		globalID:  globalID,
		dioceseID: dioceseID,
		parishID:  parishID,
		admin:     gov.Principal{ActorID: uuid.New(), OrgID: orgID, Roles: []string{"super_admin"}},
		maker:     gov.Principal{ActorID: uuid.New(), OrgID: orgID, Roles: []string{"parish_admin"}},
		checker1:  gov.Principal{ActorID: uuid.New(), OrgID: orgID, Roles: []string{"parish_priest"}},
		checker2:  gov.Principal{ActorID: uuid.New(), OrgID: orgID, Roles: []string{"chancellor"}},
		checker3:  gov.Principal{ActorID: uuid.New(), OrgID: orgID, Roles: []string{"diocesan_admin"}},
	}

	roles.Grant(h.admin.ActorID, globalID, "super_admin")
	roles.Grant(h.maker.ActorID, parishID, "parish_admin")
	roles.Grant(h.checker1.ActorID, parishID, "parish_priest")
	roles.Grant(h.checker2.ActorID, dioceseID, "chancellor")
	roles.Grant(h.checker3.ActorID, dioceseID, "diocesan_admin")

	cfg := gov.Config{
		Store:          st,
		Scopes:         scopes,
		Roles:          roles,
		Crypto:         crypto,
		IdentityGuard:  idGuard,
		StepUpVerifier: staticStepUp{validToken: "valid-totp-123"},
		Events:         events,
		Clock:          clock,
	}
	for _, fn := range opts {
		fn(&cfg)
	}

	eng, err := gov.NewEngine(cfg)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	h.engine = eng
	return h
}

func boolPtr(b bool) *bool        { return &b }
func floatPtr(v float64) *float64 { return &v }

// -----------------------------------------------------------------------------
// Unit & Integration Tests
// -----------------------------------------------------------------------------

func TestScopeResolution_MostSpecificWins(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)

	// Create global rule (expires 72h) and diocese rule (expires 48h) and parish rule (expires 24h)
	_, err := h.engine.CreateRule(ctx, h.admin, gov.RuleInput{
		ScopeID:        h.globalID,
		Permission:     "finance.disburse",
		CheckerRoles:   []string{"diocesan_admin"},
		ExpiresInHours: 72,
	})
	if err != nil {
		t.Fatalf("create global rule: %v", err)
	}
	dioceseRule, err := h.engine.CreateRule(ctx, h.admin, gov.RuleInput{
		ScopeID:        h.dioceseID,
		Permission:     "finance.disburse",
		CheckerRoles:   []string{"chancellor"},
		ExpiresInHours: 48,
	})
	if err != nil {
		t.Fatalf("create diocese rule: %v", err)
	}

	// Query at parish -> should inherit diocese rule (more specific than global)
	dec, err := h.engine.Preview(ctx, h.maker, "finance.disburse", h.parishID, floatPtr(10000))
	if err != nil || !dec.RequiresApproval || dec.Rule.ID != dioceseRule.ID {
		t.Fatalf("expected diocese rule match, got dec=%+v err=%v", dec, err)
	}

	// Add parish-specific rule -> must override diocese rule immediately (cache invalidated)
	parishRule, err := h.engine.CreateRule(ctx, h.admin, gov.RuleInput{
		ScopeID:        h.parishID,
		Permission:     "finance.disburse",
		CheckerRoles:   []string{"parish_priest"},
		ExpiresInHours: 24,
	})
	if err != nil {
		t.Fatalf("create parish rule: %v", err)
	}

	dec2, err := h.engine.Preview(ctx, h.maker, "finance.disburse", h.parishID, floatPtr(10000))
	if err != nil || !dec2.RequiresApproval || dec2.Rule.ID != parishRule.ID {
		t.Fatalf("expected parish rule override, got dec=%+v err=%v", dec2, err)
	}
}

func TestRuleValidation_RejectsInvalidScopeRoles(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)

	// Parish scope cannot have a "chancellor" role
	h.roles.RestrictScopeRoles(h.parishID, "parish_admin", "parish_priest")

	_, err := h.engine.CreateRule(ctx, h.admin, gov.RuleInput{
		ScopeID:      h.parishID,
		Permission:   "finance.disburse",
		CheckerRoles: []string{"chancellor"},
	})
	if !errors.Is(err, gov.ErrInvalidRule) {
		t.Fatalf("expected GOV_INVALID_RULE (422), got: %v", err)
	}
}

func TestRuleVersioning_AndPolicySnapshotImmutability(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)

	// v1 requires 1 approval, no step-up
	v1, err := h.engine.CreateRule(ctx, h.admin, gov.RuleInput{
		ScopeID:           h.parishID,
		Permission:        "export.request",
		CheckerRoles:      []string{"parish_priest"},
		RequiredApprovals: 1,
		RequireStepUp:     boolPtr(false),
	})
	if err != nil {
		t.Fatalf("create v1: %v", err)
	}

	// Submit ticket under v1
	ticket, err := h.engine.Submit(ctx, gov.SubmitInput{
		Principal:      h.maker,
		Permission:     "export.request",
		ScopeID:        h.parishID,
		TargetType:     "export",
		Title:          "Parish Census CSV",
		Payload:        map[string]any{"format": "csv"},
		IdempotencyKey: "snap-1",
	})
	if err != nil {
		t.Fatalf("submit: %v", err)
	}

	// Update rule to v2 requiring 2 approvals & step-up
	v2, err := h.engine.UpdateRule(ctx, h.admin, v1.RootID, gov.RuleInput{
		ScopeID:           h.parishID,
		Permission:        "export.request",
		CheckerRoles:      []string{"parish_priest", "chancellor"},
		RequiredApprovals: 2,
		RequireStepUp:     boolPtr(true),
	})
	if err != nil || v2.Version != 2 {
		t.Fatalf("expected v2, got v=%+v err=%v", v2, err)
	}

	versions, err := h.engine.ListRuleVersions(ctx, h.admin, v1.RootID)
	if err != nil || len(versions) != 2 {
		t.Fatalf("expected 2 immutable rule versions, got %d err=%v", len(versions), err)
	}

	// Mid-flight ticket MUST still execute under v1 snapshot (1 approval, no step-up)!
	approved, err := h.engine.Approve(ctx, gov.DecisionInput{
		Principal:      h.checker1,
		RequestID:      ticket.ID,
		PayloadHashHex: ticket.PayloadHashHex,
	})
	if err != nil {
		t.Fatalf("approve mid-flight v1 ticket failed: %v", err)
	}
	if approved.State != gov.StateExecuting || approved.PolicySnapshot.Version != 1 {
		t.Fatalf("expected v1 snapshot executing state, got state=%s ver=%d", approved.State, approved.PolicySnapshot.Version)
	}
}

func TestMofN_AndCancelAndReject(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)

	_, err := h.engine.CreateRule(ctx, h.admin, gov.RuleInput{
		ScopeID:           h.parishID,
		Permission:        "finance.disburse",
		CheckerRoles:      []string{"parish_priest", "chancellor", "diocesan_admin"},
		RequiredApprovals: 2,
		RequireStepUp:     boolPtr(false),
	})
	if err != nil {
		t.Fatalf("create rule: %v", err)
	}

	// 1. Cancel before any approval succeeds
	tCancel, err := h.engine.Submit(ctx, gov.SubmitInput{
		Principal:      h.maker,
		Permission:     "finance.disburse",
		ScopeID:        h.parishID,
		TargetType:     "stipend",
		Title:          "Mistaken stipend",
		Payload:        map[string]any{"amount": 500},
		IdempotencyKey: "cancel-ok",
	})
	if err != nil {
		t.Fatalf("submit cancel ticket: %v", err)
	}
	if err := h.engine.Cancel(ctx, h.maker, tCancel.ID, "wrong beneficiary"); err != nil {
		t.Fatalf("cancel pre-approval failed: %v", err)
	}

	// 2. M-of-N (2-of-3): first approval keeps state pending AND blocks maker cancel
	tMofN, err := h.engine.Submit(ctx, gov.SubmitInput{
		Principal:      h.maker,
		Permission:     "finance.disburse",
		ScopeID:        h.parishID,
		TargetType:     "stipend",
		Title:          "Large disbursement",
		Payload:        map[string]any{"amount": 500000},
		IdempotencyKey: "mofn-1",
	})
	if err != nil {
		t.Fatalf("submit mofn: %v", err)
	}

	after1, err := h.engine.Approve(ctx, gov.DecisionInput{
		Principal:      h.checker1,
		RequestID:      tMofN.ID,
		PayloadHashHex: tMofN.PayloadHashHex,
	})
	if err != nil {
		t.Fatalf("approve 1: %v", err)
	}
	if after1.State != gov.StatePending || after1.ApprovalsCount != 1 {
		t.Fatalf("expected pending with 1/2 approvals, got state=%s count=%d", after1.State, after1.ApprovalsCount)
	}

	// Maker cannot cancel once any checker has decided
	if err := h.engine.Cancel(ctx, h.maker, tMofN.ID, "too late"); !errors.Is(err, gov.ErrAlreadyInReview) {
		t.Fatalf("expected GOV_ALREADY_IN_REVIEW, got %v", err)
	}

	// Second distinct checker meets threshold -> state transitions to executing
	after2, err := h.engine.Approve(ctx, gov.DecisionInput{
		Principal:      h.checker2,
		RequestID:      tMofN.ID,
		PayloadHashHex: tMofN.PayloadHashHex,
	})
	if err != nil {
		t.Fatalf("approve 2: %v", err)
	}
	if after2.State != gov.StateExecuting || after2.ApprovalsCount != 2 {
		t.Fatalf("expected executing with 2/2 approvals, got state=%s count=%d", after2.State, after2.ApprovalsCount)
	}

	// 3. Rejection path requires reason and moves to terminal rejected
	tRej, _ := h.engine.Submit(ctx, gov.SubmitInput{
		Principal:      h.maker,
		Permission:     "finance.disburse",
		ScopeID:        h.parishID,
		TargetType:     "stipend",
		Title:          "Unapproved expense",
		Payload:        map[string]any{"amount": 9000},
		IdempotencyKey: "rej-1",
	})
	if _, err := h.engine.Reject(ctx, gov.DecisionInput{Principal: h.checker1, RequestID: tRej.ID}); !errors.Is(err, gov.ErrReasonRequired) {
		t.Fatalf("expected GOV_REASON_REQUIRED on empty reject reason, got %v", err)
	}
	rejected, err := h.engine.Reject(ctx, gov.DecisionInput{Principal: h.checker1, RequestID: tRej.ID, Reason: "missing receipt"})
	if err != nil || rejected.State != gov.StateRejected {
		t.Fatalf("expected rejected state, got %+v err=%v", rejected, err)
	}
}

func TestShadowMode_SelectiveEnforcement(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, func(cfg *gov.Config) {
		cfg.ShadowMode = true
		cfg.EnforcedPermissions = map[string]bool{
			"export.request": true, // Phase 2 enforced
		}
	})

	_, _ = h.engine.CreateRule(ctx, h.admin, gov.RuleInput{
		ScopeID:      h.parishID,
		Permission:   "finance.disburse",
		CheckerRoles: []string{"parish_priest"},
	})
	_, _ = h.engine.CreateRule(ctx, h.admin, gov.RuleInput{
		ScopeID:      h.parishID,
		Permission:   "export.request",
		CheckerRoles: []string{"parish_priest"},
	})

	decShadow, err := h.engine.Preview(ctx, h.maker, "finance.disburse", h.parishID, nil)
	if err != nil || decShadow.RequiresApproval || !decShadow.ShadowMode {
		t.Fatalf("expected shadow mode non-blocking decision, got %+v err=%v", decShadow, err)
	}

	decEnforced, err := h.engine.Preview(ctx, h.maker, "export.request", h.parishID, nil)
	if err != nil || !decEnforced.RequiresApproval || decEnforced.ShadowMode {
		t.Fatalf("expected enforced decision for export.request, got %+v err=%v", decEnforced, err)
	}
}

