# Verity Governance (`verity-governance`)

A standalone, host-agnostic Go library for **Dynamic Maker–Checker Governance (v2)** — designed to sit cleanly on top of `verity-iam` or any host IAM/RBAC system (Ecclesia, MonakBanker, RexCore, AccountAid, etc.).

## Features

- **Host-Agnostic Pluggable Adapters**: Zero foreign keys to host tables. Plug in `ScopeResolver`, `RoleResolver`, `IdentityGuard`, `StepUpVerifier`, `EventPublisher`, `Notifier`, `CryptoProvider`, and `MetricsRecorder`.
- **Cryptographic Payload Integrity**: RFC 8785-style deterministic JSON canonicalization $\to$ SHA-256 hash $\to$ Ed25519 signature over request metadata + hash $\to$ `enc:v2:<workspace>:<dek_version>:<b64>` AES-256-GCM envelope encryption with AAD header binding and key-version rotation. Re-verified byte-for-byte at both approve and execution time.
- **Explicit 8-State Machine**: `pending` $\to$ `approved` $\to$ `executing` $\to$ `executed`/`failed`, plus `rejected`, `expired`, and `cancelled` — enforced by atomic `WHERE state = expected` updates and a PostgreSQL `BEFORE UPDATE` trigger (`gov_state_guard`).
- **M-of-N Dual-Custody & Identity Guard**: Separate `governance_request_approval` audit trail with `UNIQUE(request_id, approver_id)`, self-approval guard + dual-account `IdentityGuard` (email/phone hash), mandatory step-up auth + reason when `allow_self_approval=true`, and `governance.request.self_approved` alert event.
- **Append-Only Rule Versioning & Policy Snapshots**: Updating a rule creates a new version (`root_id, version+1`) and soft-deactivates the old one. Tickets freeze their own `policy_snapshot` at submit time.
- **Most-Specific Scope Resolution**: Host `ScopeResolver.Ancestors` resolves `[leaf, ..., root]`; PostgreSQL uses `UNNEST WITH ORDINALITY` so parish rules beat diocese rules beat global rules, with TTL caching invalidated on rule changes.
- **Crash-Safe Async Outbox & Expiry Workers**: Approve **never** invokes `ActionExecutor` inline; it atomically transitions to `executing` and enqueues to `governance_outbox`. Workers use `FOR UPDATE SKIP LOCKED`, exponential backoff, and fail-closed verification.
- **Shadow Mode Rollout**: Run in `ShadowMode: true` with selective `EnforcedPermissions` for safe staged production rollout.
- **Embedded SQL Migrations & Stdlib HTTP Adapter**:
  - `pgstore.GetMigrationsFS()`, `pgstore.MigrateUp(ctx, db)`, `pgstore.MigrateUpPool(ctx, pool)`
  - `govhttp.NewHandler(engine, extractor).RegisterRoutes(mux, "/v1/governance")` exposes all 12 REST endpoints and 11 canonical error codes.

## Installation

```bash
go get github.com/Natykufsky/verity-governance@latest
```

## Quick Start

```go
package main

import (
	"context"
	"net/http"

	gov "github.com/Natykufsky/verity-governance"
	"github.com/Natykufsky/verity-governance/govhttp"
	"github.com/Natykufsky/verity-governance/pgstore"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func setup(ctx context.Context, pool *pgxpool.Pool, scopes gov.ScopeResolver, roles gov.RoleResolver) (*gov.Engine, http.Handler, error) {
	// 1. Apply embedded PostgreSQL migrations (4 tables, gov_state enum, state trigger, RLS)
	if err := pgstore.MigrateUpPool(ctx, pool); err != nil {
		return nil, nil, err
	}

	// 2. Initialize crypto provider (AES-256-GCM enc:v2 + Ed25519)
	crypto, err := gov.NewLocalCryptoProvider("your-kms-master-secret")
	if err != nil {
		return nil, nil, err
	}

	// 3. Construct Engine
	engine, err := gov.NewEngine(gov.Config{
		Store:  pgstore.New(pool),
		Scopes: scopes,
		Roles:  roles,
		Crypto: crypto,
	})
	if err != nil {
		return nil, nil, err
	}

	// 4. Register idempotent action executors
	engine.RegisterExecutor("finance.disburse", gov.ActionExecutorFunc(
		func(ctx context.Context, reqID uuid.UUID, payload map[string]any) (gov.ExecutionResult, error) {
			// Pass reqID as Idempotency-Key to downstream ledger / bank API
			return gov.ExecutionResult{Status: "ok", Output: map[string]any{"disbursed": true}}, nil
		},
	))

	// 5. Start background workers
	go gov.NewOutboxWorker(engine, gov.OutboxWorkerConfig{}).Run(ctx)
	go gov.NewExpiryWorker(engine, 0, 0).Run(ctx)

	// 6. Mount all 12 HTTP endpoints
	mux := http.NewServeMux()
	h := govhttp.NewHandler(engine, func(r *http.Request) (gov.Principal, error) {
		// Extract from verity-iam SessionFromContext(r.Context()) or host auth middleware
		return gov.Principal{}, nil
	})
	h.RegisterRoutes(mux, "/v1/governance")
	return engine, mux, nil
}
```

## Testing

```bash
make test-race
make vet
```

