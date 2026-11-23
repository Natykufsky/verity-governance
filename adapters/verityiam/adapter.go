package verityiam

import (
	"context"
	"crypto/hmac"
	"crypto/sha1" // #nosec G505 -- RFC 6238 TOTP mandates HMAC-SHA1
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	gov "github.com/Natykufsky/verity-governance"
	iam "github.com/Natykufsky/verity-iam"
)

// MFASecretProvider supplies an approver's base32 TOTP secret (e.g. from verity-iam v1.5+ UserMFA).
type MFASecretProvider interface {
	GetTOTPSecret(ctx context.Context, userID uuid.UUID) (secretBase32 string, enabled bool, err error)
}

// MFASecretProviderFunc adapts a plain function to MFASecretProvider.
type MFASecretProviderFunc func(ctx context.Context, userID uuid.UUID) (string, bool, error)

func (f MFASecretProviderFunc) GetTOTPSecret(ctx context.Context, userID uuid.UUID) (string, bool, error) {
	return f(ctx, userID)
}

// PrincipalExtractor extracts a governance.Principal from verity-iam's SessionContext.
// Mount behind verity-iam's RequireAuth() (and optionally RequireTenant()) middleware.
func PrincipalExtractor() func(r *http.Request) (gov.Principal, error) {
	return func(r *http.Request) (gov.Principal, error) {
		sess, ok := iam.SessionFromContext(r.Context())
		if !ok || sess == nil || sess.UserID == uuid.Nil {
			return gov.Principal{}, errors.New("verityiam: unauthenticated request")
		}
		meta := map[string]string{
			"email": sess.Email,
		}
		if sess.IsPlatformAdmin {
			meta["is_platform_admin"] = "true"
		}
		var roles []string
		if sess.RoleKey != "" {
			roles = []string{sess.RoleKey}
		}
		return gov.Principal{
			ActorID: sess.UserID,
			OrgID:   sess.TenantID,
			Roles:   roles,
			Meta:    meta,
		}, nil
	}
}

// Adapter bridges verity-iam's Store to verity-governance's RoleResolver,
// IdentityGuard, and StepUpVerifier interfaces.
type Adapter struct {
	store      iam.Store
	scopes     gov.ScopeResolver
	mfa        MFASecretProvider
	validRoles map[string]bool
	clock      gov.Clock
}

// NewAdapter constructs a verity-iam governance adapter compatible with verity-iam v1.3+.
// validRoles optionally restricts which role keys may be placed into governance rules.
func NewAdapter(store iam.Store, scopes gov.ScopeResolver, validRoles ...string) *Adapter {
	vr := make(map[string]bool, len(validRoles))
	for _, r := range validRoles {
		vr[r] = true
	}
	return &Adapter{
		store:      store,
		scopes:     scopes,
		validRoles: vr,
		clock:      gov.RealClock{},
	}
}

// WithMFA attaches a TOTP secret provider for RFC 6238 step-up verification.
func (a *Adapter) WithMFA(m MFASecretProvider) *Adapter {
	a.mfa = m
	return a
}

// WithClock overrides the clock used for TOTP step-up verification (useful in tests).
func (a *Adapter) WithClock(c gov.Clock) *Adapter {
	if c != nil {
		a.clock = c
	}
	return a
}

// HoldsRole checks whether the principal holds `role` in `scopeID` (or any ancestor scope)
// via verity-iam's tenant membership ledger. Platform admins implicitly satisfy all roles.
func (a *Adapter) HoldsRole(ctx context.Context, p gov.Principal, role string, scopeID uuid.UUID) (bool, error) {
	if p.Meta != nil && p.Meta["is_platform_admin"] == "true" {
		return true, nil
	}
	if a.store == nil {
		for _, r := range p.Roles {
			if r == role {
				return true, nil
			}
		}
		return false, nil
	}

	chain := []uuid.UUID{scopeID}
	if a.scopes != nil {
		if ancestors, err := a.scopes.Ancestors(ctx, p.OrgID, scopeID); err == nil && len(ancestors) > 0 {
			chain = ancestors
		}
	}
	for _, sc := range chain {
		m, err := a.store.FindMembership(ctx, sc, p.ActorID)
		if err != nil || m == nil || !m.IsActive {
			continue
		}
		if strings.EqualFold(m.RoleKey, role) {
			return true, nil
		}
	}
	if p.OrgID != uuid.Nil && p.OrgID != scopeID {
		if m, err := a.store.FindMembership(ctx, p.OrgID, p.ActorID); err == nil && m != nil && m.IsActive {
			if strings.EqualFold(m.RoleKey, role) {
				return true, nil
			}
		}
	}
	return false, nil
}

// ValidateRolesForScope verifies every role in `roles` exists in the configured role catalog.
func (a *Adapter) ValidateRolesForScope(_ context.Context, _, _ uuid.UUID, roles []string) error {
	if len(a.validRoles) == 0 {
		return nil
	}
	for _, role := range roles {
		if !a.validRoles[role] {
			return gov.NewError(gov.CodeInvalidRule, "unknown verity-iam role '"+role+"'")
		}
	}
	return nil
}

// IdentityHash returns a SHA-256 hash of the user's normalized email in verity-iam
// to block dual-account self-approval by the same human.
func (a *Adapter) IdentityHash(ctx context.Context, actorID uuid.UUID) (string, error) {
	if a.store == nil {
		return "", nil
	}
	u, err := a.store.FindUserByID(ctx, actorID)
	if err != nil || u == nil {
		return "", nil
	}
	norm := strings.ToLower(strings.TrimSpace(u.Email))
	if norm == "" {
		return "", nil
	}
	sum := sha256.Sum256([]byte("verity-iam:email:" + norm))
	return hex.EncodeToString(sum[:]), nil
}

// VerifyStepUp validates a 6-digit RFC 6238 TOTP code (±1 30s time-step skew window).
func (a *Adapter) VerifyStepUp(ctx context.Context, p gov.Principal, token string) error {
	if a.mfa == nil {
		return errors.New("verityiam: MFA provider not configured for step-up verification")
	}
	secret, enabled, err := a.mfa.GetTOTPSecret(ctx, p.ActorID)
	if err != nil || !enabled || strings.TrimSpace(secret) == "" {
		return errors.New("verityiam: MFA is not enabled on approver account")
	}
	now := time.Now().UTC()
	if a.clock != nil {
		now = a.clock.Now().UTC()
	}
	if !ValidateTOTP(secret, strings.TrimSpace(token), now) {
		return errors.New("verityiam: invalid TOTP step-up code")
	}
	return nil
}

// ValidateTOTP verifies a 6-digit RFC 6238 TOTP code with ±1 30-second window skew.
func ValidateTOTP(secretBase32, code string, at time.Time) bool {
	if len(code) != 6 {
		return false
	}
	cleanSecret := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(secretBase32), " ", ""))
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.TrimRight(cleanSecret, "="))
	if err != nil || len(key) == 0 {
		return false
	}
	step := at.Unix() / 30
	for _, offset := range []int64{-1, 0, 1} {
		expected := computeTOTP(key, uint64(step+offset)) // #nosec G115 -- unix timestamp >= 0
		if subtle.ConstantTimeCompare([]byte(expected), []byte(code)) == 1 {
			return true
		}
	}
	return false
}

func computeTOTP(key []byte, counter uint64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	code := (uint32(sum[off]&0x7f) << 24) |
		(uint32(sum[off+1]) << 16) |
		(uint32(sum[off+2]) << 8) |
		uint32(sum[off+3])
	return fmt.Sprintf("%06d", code%1000000)
}
