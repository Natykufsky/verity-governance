package pgstore

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	gov "github.com/Natykufsky/verity-governance"
)

// Store is the production PostgreSQL (pgx/v5) implementation of governance.Store.
// It enforces tenant RLS (`SET LOCAL app.current_org_id`), row-level locking (`FOR UPDATE`),
// `FOR UPDATE SKIP LOCKED` outbox leasing, and atomic M-of-N transitions.
type Store struct {
	pool *pgxpool.Pool
}

func New(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

func (s *Store) withTenantTx(ctx context.Context, orgID uuid.UUID, fn func(tx pgx.Tx) error) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("pgstore: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if orgID != uuid.Nil {
		if _, err := tx.Exec(ctx, `SELECT set_config('app.current_org_id', $1, true)`, orgID.String()); err != nil {
			return fmt.Errorf("pgstore: set tenant rls: %w", err)
		}
	}
	if err := fn(tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("pgstore: commit tx: %w", err)
	}
	return nil
}

// -----------------------------------------------------------------------------
// Rules (Append-Only Versioned)
// -----------------------------------------------------------------------------

func (s *Store) CreateRule(ctx context.Context, rule *gov.PolicyRule) (*gov.PolicyRule, error) {
	var out gov.PolicyRule
	err := s.withTenantTx(ctx, rule.OrgID, func(tx pgx.Tx) error {
		const q = `
			INSERT INTO governance_policy_rule (
				id, version, root_id, org_id, scope_id, permission,
				min_amount, max_amount, maker_roles, checker_roles,
				required_approvals, required_reason, allow_self_approval,
				require_step_up, expires_in_hours, max_payload_bytes,
				payload_schema_version, is_active, created_by, created_at, updated_at
			) VALUES (
				$1, $2, $3, $4, $5, $6,
				$7, $8, $9, $10,
				$11, $12, $13,
				$14, $15, $16,
				$17, true, $18, $19, $20
			)
			RETURNING id, version, root_id, org_id, scope_id, permission,
			          min_amount, max_amount, maker_roles, checker_roles,
			          required_approvals, required_reason, allow_self_approval,
			          require_step_up, expires_in_hours, max_payload_bytes,
			          payload_schema_version, is_active, deleted_at, created_by,
			          created_at, updated_by, updated_at
		`
		return scanRule(tx.QueryRow(ctx, q,
			rule.ID, rule.Version, rule.RootID, rule.OrgID, rule.ScopeID, rule.Permission,
			rule.MinAmount, rule.MaxAmount, rule.MakerRoles, rule.CheckerRoles,
			rule.RequiredApprovals, rule.RequiredReason, rule.AllowSelfApproval,
			rule.RequireStepUp, rule.ExpiresInHours, rule.MaxPayloadBytes,
			rule.PayloadSchemaVersion, rule.CreatedBy, rule.CreatedAt, rule.UpdatedAt,
		), &out)
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

func (s *Store) UpdateRuleVersion(ctx context.Context, orgID, rootID uuid.UUID, next *gov.PolicyRule) (*gov.PolicyRule, error) {
	var out gov.PolicyRule
	err := s.withTenantTx(ctx, orgID, func(tx pgx.Tx) error {
		var maxVer int
		if err := tx.QueryRow(ctx, `
			SELECT COALESCE(MAX(version), 0)
			FROM governance_policy_rule
			WHERE org_id = $1 AND root_id = $2
		`, orgID, rootID).Scan(&maxVer); err != nil {
			return err
		}
		if maxVer == 0 {
			return gov.ErrRuleNotFound
		}

		if _, err := tx.Exec(ctx, `
			UPDATE governance_policy_rule
			SET is_active = false, deleted_at = $1, updated_by = $2, updated_at = $1
			WHERE org_id = $3 AND root_id = $4 AND is_active = true AND deleted_at IS NULL
		`, next.UpdatedAt, next.UpdatedBy, orgID, rootID); err != nil {
			return err
		}

		const ins = `
			INSERT INTO governance_policy_rule (
				id, version, root_id, org_id, scope_id, permission,
				min_amount, max_amount, maker_roles, checker_roles,
				required_approvals, required_reason, allow_self_approval,
				require_step_up, expires_in_hours, max_payload_bytes,
				payload_schema_version, is_active, created_by, created_at, updated_by, updated_at
			) VALUES (
				$1, $2, $3, $4, $5, $6,
				$7, $8, $9, $10,
				$11, $12, $13,
				$14, $15, $16,
				$17, true, $18, $19, $20, $21
			)
			RETURNING id, version, root_id, org_id, scope_id, permission,
			          min_amount, max_amount, maker_roles, checker_roles,
			          required_approvals, required_reason, allow_self_approval,
			          require_step_up, expires_in_hours, max_payload_bytes,
			          payload_schema_version, is_active, deleted_at, created_by,
			          created_at, updated_by, updated_at
		`
		return scanRule(tx.QueryRow(ctx, ins,
			next.ID, maxVer+1, rootID, orgID, next.ScopeID, next.Permission,
			next.MinAmount, next.MaxAmount, next.MakerRoles, next.CheckerRoles,
			next.RequiredApprovals, next.RequiredReason, next.AllowSelfApproval,
			next.RequireStepUp, next.ExpiresInHours, next.MaxPayloadBytes,
			next.PayloadSchemaVersion, next.CreatedBy, next.CreatedAt, next.UpdatedBy, next.UpdatedAt,
		), &out)
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

func (s *Store) SoftDeleteRule(ctx context.Context, orgID, rootID, deletedBy uuid.UUID, now time.Time) (*gov.PolicyRule, error) {
	var out gov.PolicyRule
	err := s.withTenantTx(ctx, orgID, func(tx pgx.Tx) error {
		const q = `
			UPDATE governance_policy_rule
			SET is_active = false, deleted_at = $1, updated_by = $2, updated_at = $1
			WHERE org_id = $3 AND root_id = $4 AND is_active = true AND deleted_at IS NULL
			RETURNING id, version, root_id, org_id, scope_id, permission,
			          min_amount, max_amount, maker_roles, checker_roles,
			          required_approvals, required_reason, allow_self_approval,
			          require_step_up, expires_in_hours, max_payload_bytes,
			          payload_schema_version, is_active, deleted_at, created_by,
			          created_at, updated_by, updated_at
		`
		if err := scanRule(tx.QueryRow(ctx, q, now, deletedBy, orgID, rootID), &out); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return gov.ErrRuleNotFound
			}
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

func (s *Store) ListActiveRules(ctx context.Context, orgID uuid.UUID, filter gov.RuleFilter) ([]gov.PolicyRule, error) {
	out := make([]gov.PolicyRule, 0)
	err := s.withTenantTx(ctx, orgID, func(tx pgx.Tx) error {
		var sb strings.Builder
		sb.WriteString(`
			SELECT id, version, root_id, org_id, scope_id, permission,
			       min_amount, max_amount, maker_roles, checker_roles,
			       required_approvals, required_reason, allow_self_approval,
			       require_step_up, expires_in_hours, max_payload_bytes,
			       payload_schema_version, is_active, deleted_at, created_by,
			       created_at, updated_by, updated_at
			FROM governance_policy_rule
			WHERE org_id = $1 AND is_active = true AND deleted_at IS NULL
		`)
		args := []any{orgID}
		argIdx := 2
		if filter.Permission != "" {
			sb.WriteString(fmt.Sprintf(" AND permission = $%d", argIdx))
			args = append(args, filter.Permission)
			argIdx++
		}
		if filter.ScopeID != nil {
			sb.WriteString(fmt.Sprintf(" AND scope_id = $%d", argIdx))
			args = append(args, *filter.ScopeID)
		}
		sb.WriteString(" ORDER BY created_at DESC")

		rows, err := tx.Query(ctx, sb.String(), args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var r gov.PolicyRule
			if err := scanRule(rows, &r); err != nil {
				return err
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	return out, err
}

func (s *Store) ListRuleVersions(ctx context.Context, orgID, rootID uuid.UUID) ([]gov.PolicyRule, error) {
	out := make([]gov.PolicyRule, 0)
	err := s.withTenantTx(ctx, orgID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT id, version, root_id, org_id, scope_id, permission,
			       min_amount, max_amount, maker_roles, checker_roles,
			       required_approvals, required_reason, allow_self_approval,
			       require_step_up, expires_in_hours, max_payload_bytes,
			       payload_schema_version, is_active, deleted_at, created_by,
			       created_at, updated_by, updated_at
			FROM governance_policy_rule
			WHERE org_id = $1 AND root_id = $2
			ORDER BY version DESC
		`, orgID, rootID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var r gov.PolicyRule
			if err := scanRule(rows, &r); err != nil {
				return err
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, gov.ErrRuleNotFound
	}
	return out, nil
}

// ResolveMatchingRule selects the most-specific active rule using UNNEST WITH ORDINALITY
// over the host-supplied ancestor slice (index 1 = most specific), tie-breaking by highest version.
func (s *Store) ResolveMatchingRule(ctx context.Context, orgID uuid.UUID, ancestors []uuid.UUID, permission string, amount *float64) (*gov.PolicyRule, error) {
	var out *gov.PolicyRule
	err := s.withTenantTx(ctx, orgID, func(tx pgx.Tx) error {
		const q = `
			WITH scope_chain AS (
				SELECT scope_id, ord AS depth
				FROM UNNEST($1::uuid[]) WITH ORDINALITY AS t(scope_id, ord)
			)
			SELECT r.id, r.version, r.root_id, r.org_id, r.scope_id, r.permission,
			       r.min_amount, r.max_amount, r.maker_roles, r.checker_roles,
			       r.required_approvals, r.required_reason, r.allow_self_approval,
			       r.require_step_up, r.expires_in_hours, r.max_payload_bytes,
			       r.payload_schema_version, r.is_active, r.deleted_at, r.created_by,
			       r.created_at, r.updated_by, r.updated_at
			FROM governance_policy_rule r
			JOIN scope_chain sc ON r.scope_id = sc.scope_id
			WHERE r.org_id = $2
			  AND r.permission = $3
			  AND r.is_active = true
			  AND r.deleted_at IS NULL
			  AND (r.min_amount IS NULL OR ($4::numeric IS NOT NULL AND $4::numeric >= r.min_amount))
			  AND (r.max_amount IS NULL OR ($4::numeric IS NOT NULL AND $4::numeric <= r.max_amount))
			ORDER BY sc.depth ASC, r.version DESC
			LIMIT 1
		`
		var r gov.PolicyRule
		if err := scanRule(tx.QueryRow(ctx, q, ancestors, orgID, permission, amount), &r); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil
			}
			return err
		}
		out = &r
		return nil
	})
	return out, err
}

// -----------------------------------------------------------------------------
// Tickets / Requests
// -----------------------------------------------------------------------------

func (s *Store) CreateTicketIdempotent(ctx context.Context, ticket *gov.Ticket) (*gov.Ticket, bool, error) {
	var stored gov.Ticket
	var created bool
	err := s.withTenantTx(ctx, ticket.OrgID, func(tx pgx.Tx) error {
		snapJSON, err := json.Marshal(ticket.PolicySnapshot)
		if err != nil {
			return fmt.Errorf("pgstore: marshal policy_snapshot: %w", err)
		}
		var reqIP *string
		if ticket.RequestedFromIP != "" {
			reqIP = &ticket.RequestedFromIP
		}

		const ins = `
			INSERT INTO governance_request (
				id, org_id, scope_id, permission, target_resource_type, target_resource_id,
				title, description, payload_enc, payload_hash, payload_sig, payload_bytes,
				payload_schema_version, policy_rule_id, policy_snapshot,
				required_approvals, approvals_count, state,
				requested_by, requested_from_ip, requested_via,
				idempotency_key, expires_at, created_at, updated_at
			) VALUES (
				$1, $2, $3, $4, $5, $6,
				$7, $8, $9, $10, $11, $12,
				$13, $14, $15,
				$16, 0, 'pending',
				$17, $18::inet, $19,
				$20, $21, $22, $23
			)
			ON CONFLICT (org_id, idempotency_key) DO NOTHING
			RETURNING id
		`
		var insertedID uuid.UUID
		err = tx.QueryRow(ctx, ins,
			ticket.ID, ticket.OrgID, ticket.ScopeID, ticket.Permission, ticket.TargetResourceType, ticket.TargetResourceID,
			ticket.Title, ticket.Description, ticket.PayloadEnc, ticket.PayloadHash, ticket.PayloadSig, ticket.PayloadBytes,
			ticket.PayloadSchemaVersion, ticket.PolicyRuleID, snapJSON,
			ticket.RequiredApprovals,
			ticket.RequestedBy, reqIP, ticket.RequestedVia,
			ticket.IdempotencyKey, ticket.ExpiresAt, ticket.CreatedAt, ticket.UpdatedAt,
		).Scan(&insertedID)
		if err == nil {
			created = true
			return loadTicketTx(ctx, tx, ticket.OrgID, insertedID, &stored)
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}

		// Idempotent replay: fetch existing row by (org_id, idempotency_key)
		var existingID uuid.UUID
		if err := tx.QueryRow(ctx, `
			SELECT id FROM governance_request WHERE org_id = $1 AND idempotency_key = $2
		`, ticket.OrgID, ticket.IdempotencyKey).Scan(&existingID); err != nil {
			return err
		}
		return loadTicketTx(ctx, tx, ticket.OrgID, existingID, &stored)
	})
	if err != nil {
		return nil, false, err
	}
	return &stored, created, nil
}

func (s *Store) GetTicket(ctx context.Context, orgID, requestID uuid.UUID) (*gov.Ticket, error) {
	var out gov.Ticket
	err := s.withTenantTx(ctx, orgID, func(tx pgx.Tx) error {
		return loadTicketTx(ctx, tx, orgID, requestID, &out)
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

func (s *Store) ListTickets(ctx context.Context, orgID uuid.UUID, filter gov.ListFilter) (gov.Page[gov.Ticket], error) {
	var page gov.Page[gov.Ticket]
	page.Page = filter.Page
	page.PageSize = filter.PageSize
	page.Items = make([]gov.Ticket, 0)

	err := s.withTenantTx(ctx, orgID, func(tx pgx.Tx) error {
		where := []string{"org_id = $1"}
		args := []any{orgID}
		idx := 2

		if len(filter.States) > 0 {
			strStates := make([]string, len(filter.States))
			for i, st := range filter.States {
				strStates[i] = string(st)
			}
			where = append(where, fmt.Sprintf("state::text = ANY($%d)", idx))
			args = append(args, strStates)
			idx++
		}
		if filter.Permission != "" {
			where = append(where, fmt.Sprintf("permission = $%d", idx))
			args = append(args, filter.Permission)
			idx++
		}
		if filter.ScopeID != nil {
			where = append(where, fmt.Sprintf("scope_id = $%d", idx))
			args = append(args, *filter.ScopeID)
			idx++
		}
		if filter.RequestedBy != nil {
			where = append(where, fmt.Sprintf("requested_by = $%d", idx))
			args = append(args, *filter.RequestedBy)
			idx++
		}
		if filter.CreatedFrom != nil {
			where = append(where, fmt.Sprintf("created_at >= $%d", idx))
			args = append(args, *filter.CreatedFrom)
			idx++
		}
		if filter.CreatedTo != nil {
			where = append(where, fmt.Sprintf("created_at <= $%d", idx))
			args = append(args, *filter.CreatedTo)
			idx++
		}
		whereSQL := strings.Join(where, " AND ")

		if err := tx.QueryRow(ctx, "SELECT count(*) FROM governance_request WHERE "+whereSQL, args...).Scan(&page.Total); err != nil {
			return err
		}
		page.TotalPages = (page.Total + filter.PageSize - 1) / filter.PageSize
		if page.TotalPages == 0 {
			page.TotalPages = 1
		}

		offset := (filter.Page - 1) * filter.PageSize
		q := fmt.Sprintf(`
			SELECT id FROM governance_request
			WHERE %s
			ORDER BY created_at DESC
			LIMIT $%d OFFSET $%d
		`, whereSQL, idx, idx+1)
		args = append(args, filter.PageSize, offset)

		rows, err := tx.Query(ctx, q, args...)
		if err != nil {
			return err
		}
		var ids []uuid.UUID
		for rows.Next() {
			var id uuid.UUID
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return err
			}
			ids = append(ids, id)
		}
		rows.Close()

		for _, id := range ids {
			var t gov.Ticket
			if err := loadTicketTx(ctx, tx, orgID, id, &t); err != nil {
				return err
			}
			page.Items = append(page.Items, t)
		}
		return nil
	})
	return page, err
}

// -----------------------------------------------------------------------------
// Atomic State Transitions
// -----------------------------------------------------------------------------

func (s *Store) RecordApprovalAndMaybeEnqueue(
	ctx context.Context,
	orgID, requestID uuid.UUID,
	decision gov.ApprovalDecision,
	actionKey string,
	now time.Time,
) (gov.RecordApprovalResult, error) {
	var res gov.RecordApprovalResult
	err := s.withTenantTx(ctx, orgID, func(tx pgx.Tx) error {
		// Row lock to serialize concurrent approvers
		var stateStr string
		var reqApprovals, curApprovals int
		var expiresAt time.Time
		var payloadEnc []byte

		err := tx.QueryRow(ctx, `
			SELECT state::text, required_approvals, approvals_count, expires_at, payload_enc
			FROM governance_request
			WHERE id = $1 AND org_id = $2
			FOR UPDATE
		`, requestID, orgID).Scan(&stateStr, &reqApprovals, &curApprovals, &expiresAt, &payloadEnc)
		if errors.Is(err, pgx.ErrNoRows) {
			return gov.ErrNotFound
		}
		if err != nil {
			return err
		}

		// Idempotent replay check for same approver
		var existingDecision string
		if err := tx.QueryRow(ctx, `
			SELECT decision FROM governance_request_approval
			WHERE request_id = $1 AND approver_id = $2
		`, requestID, decision.ApproverID).Scan(&existingDecision); err == nil {
			if existingDecision == "approved" {
				var t gov.Ticket
				if err := loadTicketTx(ctx, tx, orgID, requestID, &t); err != nil {
					return err
				}
				res = gov.RecordApprovalResult{Ticket: &t, IdempotentReplay: true}
				return nil
			}
			return gov.ErrStateConflict
		}

		if gov.State(stateStr) == gov.StateExpired || !expiresAt.After(now) {
			return gov.ErrExpired
		}
		if gov.State(stateStr) != gov.StatePending {
			return gov.ErrStateConflict
		}

		var decidedIP *string
		if decision.DecidedFromIP != "" {
			decidedIP = &decision.DecidedFromIP
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO governance_request_approval (
				id, request_id, approver_id, decision, reason, decided_via, decided_from_ip, step_up_used, decided_at
			) VALUES ($1, $2, $3, 'approved', $4, $5, $6::inet, $7, $8)
		`, decision.ID, requestID, decision.ApproverID, decision.Reason, decision.DecidedVia, decidedIP, decision.StepUpUsed, now); err != nil {
			return err
		}

		newCount := curApprovals + 1
		if newCount >= reqApprovals {
			// Transition pending -> approved -> executing (honoring gov_state_guard trigger)
			tag, err := tx.Exec(ctx, `
				UPDATE governance_request
				SET approvals_count = $1, state = 'approved', updated_at = $2
				WHERE id = $3 AND org_id = $4 AND state = 'pending'
			`, newCount, now, requestID, orgID)
			if err != nil {
				return err
			}
			if tag.RowsAffected() != 1 {
				return gov.ErrStateConflict
			}

			tag, err = tx.Exec(ctx, `
				UPDATE governance_request
				SET state = 'executing', executing_at = $1, updated_at = $1
				WHERE id = $2 AND org_id = $3 AND state = 'approved'
			`, now, requestID, orgID)
			if err != nil {
				return err
			}
			if tag.RowsAffected() != 1 {
				return gov.ErrStateConflict
			}

			if _, err := tx.Exec(ctx, `
				INSERT INTO governance_outbox (id, request_id, org_id, payload_enc, action_key, attempts, next_attempt_at, created_at)
				VALUES (gen_random_uuid(), $1, $2, $3, $4, 0, $5, $5)
				ON CONFLICT (request_id) DO NOTHING
			`, requestID, orgID, payloadEnc, actionKey, now); err != nil {
				return err
			}
			res.ThresholdReached = true
			res.EnqueuedForExecute = true
		} else {
			tag, err := tx.Exec(ctx, `
				UPDATE governance_request
				SET approvals_count = $1, updated_at = $2
				WHERE id = $3 AND org_id = $4 AND state = 'pending'
			`, newCount, now, requestID, orgID)
			if err != nil {
				return err
			}
			if tag.RowsAffected() != 1 {
				return gov.ErrStateConflict
			}
		}

		var t gov.Ticket
		if err := loadTicketTx(ctx, tx, orgID, requestID, &t); err != nil {
			return err
		}
		res.Ticket = &t
		return nil
	})
	return res, err
}

func (s *Store) RecordRejection(
	ctx context.Context,
	orgID, requestID uuid.UUID,
	decision gov.ApprovalDecision,
	now time.Time,
) (*gov.Ticket, error) {
	var out gov.Ticket
	err := s.withTenantTx(ctx, orgID, func(tx pgx.Tx) error {
		var stateStr string
		var expiresAt time.Time
		err := tx.QueryRow(ctx, `
			SELECT state::text, expires_at FROM governance_request
			WHERE id = $1 AND org_id = $2
			FOR UPDATE
		`, requestID, orgID).Scan(&stateStr, &expiresAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return gov.ErrNotFound
		}
		if err != nil {
			return err
		}
		if gov.State(stateStr) == gov.StateExpired || !expiresAt.After(now) {
			return gov.ErrExpired
		}
		if gov.State(stateStr) != gov.StatePending {
			return gov.ErrStateConflict
		}

		var decidedIP *string
		if decision.DecidedFromIP != "" {
			decidedIP = &decision.DecidedFromIP
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO governance_request_approval (
				id, request_id, approver_id, decision, reason, decided_via, decided_from_ip, step_up_used, decided_at
			) VALUES ($1, $2, $3, 'rejected', $4, $5, $6::inet, false, $7)
		`, decision.ID, requestID, decision.ApproverID, decision.Reason, decision.DecidedVia, decidedIP, now); err != nil {
			return err
		}

		tag, err := tx.Exec(ctx, `
			UPDATE governance_request
			SET state = 'rejected', updated_at = $1
			WHERE id = $2 AND org_id = $3 AND state = 'pending'
		`, now, requestID, orgID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return gov.ErrStateConflict
		}
		return loadTicketTx(ctx, tx, orgID, requestID, &out)
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

func (s *Store) CancelTicket(
	ctx context.Context,
	orgID, requestID, actorID uuid.UUID,
	reason string,
	now time.Time,
) (*gov.Ticket, error) {
	var out gov.Ticket
	err := s.withTenantTx(ctx, orgID, func(tx pgx.Tx) error {
		var stateStr string
		var approvalsCount int
		err := tx.QueryRow(ctx, `
			SELECT state::text, approvals_count FROM governance_request
			WHERE id = $1 AND org_id = $2
			FOR UPDATE
		`, requestID, orgID).Scan(&stateStr, &approvalsCount)
		if errors.Is(err, pgx.ErrNoRows) {
			return gov.ErrNotFound
		}
		if err != nil {
			return err
		}
		if gov.State(stateStr) != gov.StatePending {
			return gov.ErrStateConflict
		}
		if approvalsCount > 0 {
			return gov.ErrAlreadyInReview
		}

		tag, err := tx.Exec(ctx, `
			UPDATE governance_request
			SET state = 'cancelled', cancel_reason = $1, cancelled_by = $2, cancelled_at = $3, updated_at = $3
			WHERE id = $4 AND org_id = $5 AND state = 'pending' AND approvals_count = 0
		`, reason, actorID, now, requestID, orgID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return gov.ErrStateConflict
		}
		return loadTicketTx(ctx, tx, orgID, requestID, &out)
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// -----------------------------------------------------------------------------
// Outbox & Expiry Workers
// -----------------------------------------------------------------------------

func (s *Store) ClaimOutboxBatch(ctx context.Context, now time.Time, limit int) ([]gov.OutboxItem, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Claim and push next_attempt_at forward by a 30s lease so concurrent workers skip locked/leased rows
	rows, err := tx.Query(ctx, `
		WITH due AS (
			SELECT id
			FROM governance_outbox
			WHERE completed_at IS NULL AND next_attempt_at <= $1
			ORDER BY next_attempt_at ASC
			LIMIT $2
			FOR UPDATE SKIP LOCKED
		)
		UPDATE governance_outbox ob
		SET next_attempt_at = $3
		FROM due
		WHERE ob.id = due.id
		RETURNING ob.id, ob.request_id, ob.org_id, ob.payload_enc, ob.action_key,
		          ob.attempts, COALESCE(ob.last_error, ''), ob.next_attempt_at, ob.completed_at, ob.created_at
	`, now, limit, now.Add(30*time.Second))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]gov.OutboxItem, 0)
	for rows.Next() {
		var ob gov.OutboxItem
		if err := rows.Scan(
			&ob.ID, &ob.RequestID, &ob.OrgID, &ob.PayloadEnc, &ob.ActionKey,
			&ob.Attempts, &ob.LastError, &ob.NextAttemptAt, &ob.CompletedAt, &ob.CreatedAt,
		); err != nil {
			return nil, err
		}
		items = append(items, ob)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return items, nil
}

func (s *Store) GetTicketByIDForWorker(ctx context.Context, orgID, requestID uuid.UUID) (*gov.Ticket, error) {
	return s.GetTicket(ctx, orgID, requestID)
}

func (s *Store) MarkOutboxExecuted(ctx context.Context, orgID, requestID uuid.UUID, result gov.ExecutionResult, now time.Time) error {
	return s.withTenantTx(ctx, orgID, func(tx pgx.Tx) error {
		resJSON, err := json.Marshal(result)
		if err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `
			UPDATE governance_request
			SET state = 'executed', executed_at = $1, execution_attempts = execution_attempts + 1,
			    execution_result = $2, updated_at = $1
			WHERE id = $3 AND org_id = $4 AND state = 'executing'
		`, now, resJSON, requestID, orgID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return gov.ErrStateConflict
		}
		_, err = tx.Exec(ctx, `
			UPDATE governance_outbox
			SET attempts = attempts + 1, completed_at = $1
			WHERE request_id = $2
		`, now, requestID)
		return err
	})
}

func (s *Store) MarkOutboxRetry(ctx context.Context, outboxID uuid.UUID, errMsg string, nextAttempt time.Time) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE governance_outbox
		SET attempts = attempts + 1, last_error = $1, next_attempt_at = $2
		WHERE id = $3
	`, errMsg, nextAttempt, outboxID)
	return err
}

func (s *Store) MarkOutboxFailed(ctx context.Context, orgID, requestID, outboxID uuid.UUID, result gov.ExecutionResult, errMsg string, now time.Time) error {
	return s.withTenantTx(ctx, orgID, func(tx pgx.Tx) error {
		resJSON, err := json.Marshal(result)
		if err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `
			UPDATE governance_request
			SET state = 'failed', failed_at = $1, execution_attempts = execution_attempts + 1,
			    execution_result = $2, updated_at = $1
			WHERE id = $3 AND org_id = $4 AND state = 'executing'
		`, now, resJSON, requestID, orgID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return gov.ErrStateConflict
		}
		_, err = tx.Exec(ctx, `
			UPDATE governance_outbox
			SET attempts = attempts + 1, last_error = $1, completed_at = $2
			WHERE id = $3
		`, errMsg, now, outboxID)
		return err
	})
}

func (s *Store) ExpirePendingTickets(ctx context.Context, now time.Time, limit int) ([]gov.Ticket, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	rows, err := tx.Query(ctx, `
		WITH target AS (
			SELECT id
			FROM governance_request
			WHERE state = 'pending' AND expires_at <= $1
			ORDER BY expires_at ASC
			LIMIT $2
			FOR UPDATE SKIP LOCKED
		)
		UPDATE governance_request r
		SET state = 'expired', expired_at = $1, updated_at = $1
		FROM target
		WHERE r.id = target.id AND r.state = 'pending'
		RETURNING r.id, r.org_id, r.scope_id, r.permission, r.title, r.requested_by, r.payload_hash
	`, now, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]gov.Ticket, 0)
	for rows.Next() {
		var t gov.Ticket
		if err := rows.Scan(&t.ID, &t.OrgID, &t.ScopeID, &t.Permission, &t.Title, &t.RequestedBy, &t.PayloadHash); err != nil {
			return nil, err
		}
		t.PayloadHashHex = hex.EncodeToString(t.PayloadHash)
		t.State = gov.StateExpired
		t.ExpiredAt = &now
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return out, nil
}

// -----------------------------------------------------------------------------
// Row Scanners
// -----------------------------------------------------------------------------

type scannable interface {
	Scan(dest ...any) error
}

func scanRule(row scannable, r *gov.PolicyRule) error {
	return row.Scan(
		&r.ID, &r.Version, &r.RootID, &r.OrgID, &r.ScopeID, &r.Permission,
		&r.MinAmount, &r.MaxAmount, &r.MakerRoles, &r.CheckerRoles,
		&r.RequiredApprovals, &r.RequiredReason, &r.AllowSelfApproval,
		&r.RequireStepUp, &r.ExpiresInHours, &r.MaxPayloadBytes,
		&r.PayloadSchemaVersion, &r.IsActive, &r.DeletedAt, &r.CreatedBy,
		&r.CreatedAt, &r.UpdatedBy, &r.UpdatedAt,
	)
}

func loadTicketTx(ctx context.Context, tx pgx.Tx, orgID, requestID uuid.UUID, t *gov.Ticket) error {
	var snapJSON, execResJSON []byte
	var stateStr string
	var desc, targetID, reqIP, cancelReason *string

	err := tx.QueryRow(ctx, `
		SELECT id, org_id, scope_id, permission, target_resource_type, target_resource_id,
		       title, description, payload_enc, payload_hash, payload_sig, payload_bytes,
		       payload_schema_version, policy_rule_id, policy_snapshot,
		       required_approvals, approvals_count, state::text,
		       requested_by, requested_from_ip::text, requested_via,
		       idempotency_key, cancel_reason, cancelled_by, cancelled_at,
		       expires_at, expired_at, executing_at, executed_at, failed_at,
		       execution_attempts, execution_result, created_at, updated_at
		FROM governance_request
		WHERE id = $1 AND org_id = $2
	`, requestID, orgID).Scan(
		&t.ID, &t.OrgID, &t.ScopeID, &t.Permission, &t.TargetResourceType, &targetID,
		&t.Title, &desc, &t.PayloadEnc, &t.PayloadHash, &t.PayloadSig, &t.PayloadBytes,
		&t.PayloadSchemaVersion, &t.PolicyRuleID, &snapJSON,
		&t.RequiredApprovals, &t.ApprovalsCount, &stateStr,
		&t.RequestedBy, &reqIP, &t.RequestedVia,
		&t.IdempotencyKey, &cancelReason, &t.CancelledBy, &t.CancelledAt,
		&t.ExpiresAt, &t.ExpiredAt, &t.ExecutingAt, &t.ExecutedAt, &t.FailedAt,
		&t.ExecutionAttempts, &execResJSON, &t.CreatedAt, &t.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return gov.ErrNotFound
	}
	if err != nil {
		return err
	}

	t.State = gov.State(stateStr)
	t.PayloadHashHex = hex.EncodeToString(t.PayloadHash)
	if targetID != nil {
		t.TargetResourceID = *targetID
	}
	if desc != nil {
		t.Description = *desc
	}
	if reqIP != nil {
		t.RequestedFromIP = *reqIP
	}
	if cancelReason != nil {
		t.CancelReason = *cancelReason
	}
	if len(snapJSON) > 0 {
		_ = json.Unmarshal(snapJSON, &t.PolicySnapshot)
	}
	if len(execResJSON) > 0 {
		var er gov.ExecutionResult
		if err := json.Unmarshal(execResJSON, &er); err == nil {
			t.ExecutionResult = &er
		}
	}

	// Load M-of-N approvals
	rows, err := tx.Query(ctx, `
		SELECT id, request_id, approver_id, decision, COALESCE(reason, ''),
		       decided_via, COALESCE(decided_from_ip::text, ''), step_up_used, decided_at
		FROM governance_request_approval
		WHERE request_id = $1
		ORDER BY decided_at ASC
	`, requestID)
	if err != nil {
		return err
	}
	defer rows.Close()

	t.Approvals = make([]gov.ApprovalDecision, 0)
	for rows.Next() {
		var a gov.ApprovalDecision
		if err := rows.Scan(
			&a.ID, &a.RequestID, &a.ApproverID, &a.Decision, &a.Reason,
			&a.DecidedVia, &a.DecidedFromIP, &a.StepUpUsed, &a.DecidedAt,
		); err != nil {
			return err
		}
		t.Approvals = append(t.Approvals, a)
	}
	return rows.Err()
}

