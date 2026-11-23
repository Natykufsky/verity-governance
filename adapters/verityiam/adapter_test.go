package verityiam_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	gov "github.com/Natykufsky/verity-governance"
	"github.com/Natykufsky/verity-governance/adapters/verityiam"
	"github.com/Natykufsky/verity-governance/memstore"
	iam "github.com/Natykufsky/verity-iam"
)

func generateTestTOTP(secretBase32 string, at time.Time) string {
	key, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secretBase32)
	counter := uint64(at.Unix() / 30)
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	code := (uint32(sum[offset]&0x7f) << 24) |
		(uint32(sum[offset+1]) << 16) |
		(uint32(sum[offset+2]) << 8) |
		uint32(sum[offset+3])
	return fmt.Sprintf("%06d", code%1000000)
}

func TestVerityIAMAdapter_EndToEnd(t *testing.T) {
	ctx := context.Background()
	iamStore := iam.NewMemoryStore()

	tenantID := uuid.New()
	adminID := uuid.New()
	makerID := uuid.New()
	checkerID := uuid.New()

	_ = iamStore.CreateTenant(ctx, &iam.Tenant{ID: tenantID, Slug: "acme", Name: "Acme", IsActive: true})
	_ = iamStore.CreateUser(ctx, &iam.User{ID: adminID, Email: "admin@acme.test", IsPlatformAdmin: true})
	_ = iamStore.CreateUser(ctx, &iam.User{ID: makerID, Email: "maker@acme.test"})
	_ = iamStore.CreateUser(ctx, &iam.User{ID: checkerID, Email: "checker@acme.test"})

	_ = iamStore.AddMembership(ctx, &iam.Membership{TenantID: tenantID, UserID: makerID, RoleKey: "accountant", IsActive: true})
	_ = iamStore.AddMembership(ctx, &iam.Membership{TenantID: tenantID, UserID: checkerID, RoleKey: "cfo", IsActive: true})

	totpSecret := "JBSWY3DPEHPK3PXP"
	scopes := gov.NewStaticScopeResolver()
	adapter := verityiam.NewAdapter(iamStore, scopes, "accountant", "cfo", "admin").
		WithMFA(verityiam.MFASecretProviderFunc(func(_ context.Context, userID uuid.UUID) (string, bool, error) {
			if userID == checkerID {
				return totpSecret, true, nil
			}
			return "", false, nil
		}))

	crypto, _ := gov.NewLocalCryptoProvider("verity-iam-bridge-secret")

	engine, err := gov.NewEngine(gov.Config{
		Store:          memstore.New(),
		Scopes:         scopes,
		Roles:          adapter,
		Crypto:         crypto,
		IdentityGuard:  adapter,
		StepUpVerifier: adapter,
	})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	adminP := gov.Principal{ActorID: adminID, OrgID: tenantID, Meta: map[string]string{"is_platform_admin": "true"}}
	makerP := gov.Principal{ActorID: makerID, OrgID: tenantID, Roles: []string{"accountant"}}
	checkerP := gov.Principal{ActorID: checkerID, OrgID: tenantID, Roles: []string{"cfo"}}

	if _, err := engine.CreateRule(ctx, adminP, gov.RuleInput{
		ScopeID:      tenantID,
		Permission:   "payout.execute",
		MakerRoles:   []string{"accountant"},
		CheckerRoles: []string{"cfo"},
	}); err != nil {
		t.Fatalf("CreateRule: %v", err)
	}

	ticket, err := engine.Submit(ctx, gov.SubmitInput{
		Principal:      makerP,
		Permission:     "payout.execute",
		ScopeID:        tenantID,
		TargetType:     "payout",
		Title:          "Vendor Wire",
		Payload:        map[string]any{"amount": 150000},
		IdempotencyKey: "wire-001",
	})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}

	totp := generateTestTOTP(totpSecret, time.Now().UTC())
	approved, err := engine.Approve(ctx, gov.DecisionInput{
		Principal:      checkerP,
		RequestID:      ticket.ID,
		PayloadHashHex: ticket.PayloadHashHex,
		StepUpToken:    totp,
	})
	if err != nil {
		t.Fatalf("Approve with verity-iam TOTP failed: %v", err)
	}
	if approved.State != gov.StateExecuting || !approved.Approvals[0].StepUpUsed {
		t.Fatalf("expected executing with step_up_used=true, got state=%s", approved.State)
	}
}
