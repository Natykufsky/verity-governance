package govhttp

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	gov "github.com/Natykufsky/verity-governance"
)

// PrincipalExtractor extracts the authenticated governance.Principal from an incoming HTTP request.
type PrincipalExtractor func(r *http.Request) (gov.Principal, error)

// Handler exposes all 12 canonical governance HTTP endpoints (§8) using standard net/http.
type Handler struct {
	engine    *gov.Engine
	extractor PrincipalExtractor
}

// NewHandler creates a stdlib net/http Handler backed by engine and extractor.
func NewHandler(engine *gov.Engine, extractor PrincipalExtractor) *Handler {
	return &Handler{
		engine:    engine,
		extractor: extractor,
	}
}

// RegisterRoutes mounts all 12 governance endpoints onto a Go 1.22+ *http.ServeMux under prefix
// (e.g. "/v1/governance").
func (h *Handler) RegisterRoutes(mux *http.ServeMux, prefix string) {
	p := strings.TrimRight(prefix, "/")
	mux.HandleFunc("POST "+p+"/evaluate", h.Evaluate)
	mux.HandleFunc("POST "+p+"/requests", h.SubmitRequest)
	mux.HandleFunc("GET "+p+"/requests", h.ListRequests)
	mux.HandleFunc("GET "+p+"/requests/{id}", h.GetRequest)
	mux.HandleFunc("POST "+p+"/requests/{id}/approve", h.ApproveRequest)
	mux.HandleFunc("POST "+p+"/requests/{id}/reject", h.RejectRequest)
	mux.HandleFunc("POST "+p+"/requests/{id}/cancel", h.CancelRequest)
	mux.HandleFunc("GET "+p+"/rules", h.ListRules)
	mux.HandleFunc("POST "+p+"/rules", h.CreateRule)
	mux.HandleFunc("PUT "+p+"/rules/{root_id}", h.UpdateRule)
	mux.HandleFunc("DELETE "+p+"/rules/{root_id}", h.DeleteRule)
	mux.HandleFunc("GET "+p+"/rules/{root_id}/versions", h.ListRuleVersions)
}

// -----------------------------------------------------------------------------
// Endpoints
// -----------------------------------------------------------------------------

func (h *Handler) Evaluate(w http.ResponseWriter, r *http.Request) {
	p, ok := h.extractPrincipal(w, r)
	if !ok {
		return
	}
	var body struct {
		Permission string   `json:"permission"`
		ScopeID    string   `json:"scope_id"`
		Amount     *float64 `json:"amount,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, gov.NewError(gov.CodeInvalidRule, "invalid json body"))
		return
	}
	scopeID, err := uuid.Parse(body.ScopeID)
	if err != nil {
		writeError(w, gov.NewError(gov.CodeInvalidRule, "valid scope_id uuid is required"))
		return
	}
	dec, err := h.engine.Preview(r.Context(), p, body.Permission, scopeID, body.Amount)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, dec)
}

func (h *Handler) SubmitRequest(w http.ResponseWriter, r *http.Request) {
	p, ok := h.extractPrincipal(w, r)
	if !ok {
		return
	}
	idempKey := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if idempKey == "" {
		writeError(w, gov.ErrIdempotencyRequired)
		return
	}
	var body struct {
		Permission         string         `json:"permission"`
		ScopeID            string         `json:"scope_id"`
		Amount             *float64       `json:"amount,omitempty"`
		TargetResourceType string         `json:"target_resource_type"`
		TargetResourceID   string         `json:"target_resource_id,omitempty"`
		Title              string         `json:"title"`
		Description        string         `json:"description,omitempty"`
		Payload            map[string]any `json:"payload"`
		RequestedVia       string         `json:"requested_via,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, gov.NewError(gov.CodeInvalidRule, "invalid json body"))
		return
	}
	scopeID, err := uuid.Parse(body.ScopeID)
	if err != nil {
		writeError(w, gov.NewError(gov.CodeInvalidRule, "valid scope_id uuid is required"))
		return
	}
	ticket, err := h.engine.Submit(r.Context(), gov.SubmitInput{
		Principal:       p,
		Permission:      body.Permission,
		ScopeID:         scopeID,
		Amount:          body.Amount,
		TargetType:      body.TargetResourceType,
		TargetID:        body.TargetResourceID,
		Title:           body.Title,
		Description:     body.Description,
		Payload:         body.Payload,
		RequestedVia:    body.RequestedVia,
		RequestedFromIP: clientIP(r),
		IdempotencyKey:  idempKey,
	})
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, ticket)
}

func (h *Handler) ListRequests(w http.ResponseWriter, r *http.Request) {
	p, ok := h.extractPrincipal(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	filter := gov.ListFilter{
		Permission: q.Get("permission"),
	}
	if statesParam := q.Get("state"); statesParam != "" {
		for _, part := range strings.Split(statesParam, ",") {
			if st := strings.TrimSpace(part); st != "" {
				filter.States = append(filter.States, gov.State(st))
			}
		}
	}
	if sc := q.Get("scope_id"); sc != "" {
		if id, err := uuid.Parse(sc); err == nil {
			filter.ScopeID = &id
		}
	}
	if rb := q.Get("requested_by"); rb != "" {
		if id, err := uuid.Parse(rb); err == nil {
			filter.RequestedBy = &id
		}
	}
	if from := q.Get("created_from"); from != "" {
		if t, err := time.Parse(time.RFC3339, from); err == nil {
			filter.CreatedFrom = &t
		}
	}
	if to := q.Get("created_to"); to != "" {
		if t, err := time.Parse(time.RFC3339, to); err == nil {
			filter.CreatedTo = &t
		}
	}
	if pg, err := strconv.Atoi(q.Get("page")); err == nil && pg > 0 {
		filter.Page = pg
	}
	if ps, err := strconv.Atoi(q.Get("page_size")); err == nil && ps > 0 {
		filter.PageSize = ps
	}

	page, err := h.engine.List(r.Context(), p, filter)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, page)
}

func (h *Handler) GetRequest(w http.ResponseWriter, r *http.Request) {
	p, ok := h.extractPrincipal(w, r)
	if !ok {
		return
	}
	reqID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, gov.ErrNotFound)
		return
	}
	ticket, err := h.engine.Get(r.Context(), p, reqID)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, ticket)
}

func (h *Handler) ApproveRequest(w http.ResponseWriter, r *http.Request) {
	p, ok := h.extractPrincipal(w, r)
	if !ok {
		return
	}
	reqID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, gov.ErrNotFound)
		return
	}
	var body struct {
		PayloadHash string `json:"payload_hash"`
		Reason      string `json:"reason,omitempty"`
		DecidedVia  string `json:"decided_via,omitempty"`
		StepUpToken string `json:"step_up_token,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, gov.NewError(gov.CodeInvalidRule, "invalid json body"))
		return
	}
	stepUp := strings.TrimSpace(r.Header.Get("Step-Up-Token"))
	if stepUp == "" {
		stepUp = strings.TrimSpace(body.StepUpToken)
	}
	ticket, err := h.engine.Approve(r.Context(), gov.DecisionInput{
		Principal:      p,
		RequestID:      reqID,
		StepUpToken:    stepUp,
		Reason:         body.Reason,
		PayloadHashHex: body.PayloadHash,
		DecidedVia:     body.DecidedVia,
		DecidedFromIP:  clientIP(r),
	})
	if err != nil {
		writeError(w, err)
		return
	}
	status := http.StatusOK
	if ticket.State == gov.StateExecuting {
		status = http.StatusAccepted
	}
	writeJSON(w, status, ticket)
}

func (h *Handler) RejectRequest(w http.ResponseWriter, r *http.Request) {
	p, ok := h.extractPrincipal(w, r)
	if !ok {
		return
	}
	reqID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, gov.ErrNotFound)
		return
	}
	var body struct {
		Reason     string `json:"reason"`
		DecidedVia string `json:"decided_via,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, gov.NewError(gov.CodeInvalidRule, "invalid json body"))
		return
	}
	ticket, err := h.engine.Reject(r.Context(), gov.DecisionInput{
		Principal:     p,
		RequestID:     reqID,
		Reason:        body.Reason,
		DecidedVia:    body.DecidedVia,
		DecidedFromIP: clientIP(r),
	})
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, ticket)
}

func (h *Handler) CancelRequest(w http.ResponseWriter, r *http.Request) {
	p, ok := h.extractPrincipal(w, r)
	if !ok {
		return
	}
	reqID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, gov.ErrNotFound)
		return
	}
	var body struct {
		Reason string `json:"reason,omitempty"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	if err := h.engine.Cancel(r.Context(), p, reqID, body.Reason); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "cancelled"})
}

func (h *Handler) ListRules(w http.ResponseWriter, r *http.Request) {
	p, ok := h.extractPrincipal(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	filter := gov.RuleFilter{Permission: q.Get("permission")}
	if sc := q.Get("scope_id"); sc != "" {
		if id, err := uuid.Parse(sc); err == nil {
			filter.ScopeID = &id
		}
	}
	rules, err := h.engine.ListRules(r.Context(), p, filter)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, rules)
}

func (h *Handler) CreateRule(w http.ResponseWriter, r *http.Request) {
	p, ok := h.extractPrincipal(w, r)
	if !ok {
		return
	}
	var in gov.RuleInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, gov.NewError(gov.CodeInvalidRule, "invalid json body"))
		return
	}
	rule, err := h.engine.CreateRule(r.Context(), p, in)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, rule)
}

func (h *Handler) UpdateRule(w http.ResponseWriter, r *http.Request) {
	p, ok := h.extractPrincipal(w, r)
	if !ok {
		return
	}
	rootID, err := uuid.Parse(r.PathValue("root_id"))
	if err != nil {
		writeError(w, gov.ErrRuleNotFound)
		return
	}
	var in gov.RuleInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, gov.NewError(gov.CodeInvalidRule, "invalid json body"))
		return
	}
	rule, err := h.engine.UpdateRule(r.Context(), p, rootID, in)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, rule)
}

func (h *Handler) DeleteRule(w http.ResponseWriter, r *http.Request) {
	p, ok := h.extractPrincipal(w, r)
	if !ok {
		return
	}
	rootID, err := uuid.Parse(r.PathValue("root_id"))
	if err != nil {
		writeError(w, gov.ErrRuleNotFound)
		return
	}
	if err := h.engine.DeleteRule(r.Context(), p, rootID); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (h *Handler) ListRuleVersions(w http.ResponseWriter, r *http.Request) {
	p, ok := h.extractPrincipal(w, r)
	if !ok {
		return
	}
	rootID, err := uuid.Parse(r.PathValue("root_id"))
	if err != nil {
		writeError(w, gov.ErrRuleNotFound)
		return
	}
	versions, err := h.engine.ListRuleVersions(r.Context(), p, rootID)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, versions)
}

// -----------------------------------------------------------------------------
// Response Helpers
// -----------------------------------------------------------------------------

func (h *Handler) extractPrincipal(w http.ResponseWriter, r *http.Request) (gov.Principal, bool) {
	if h.extractor == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"error": map[string]string{"code": "GOV_UNAUTHENTICATED", "message": "principal extractor not configured"},
		})
		return gov.Principal{}, false
	}
	p, err := h.extractor(r)
	if err != nil || p.ActorID == uuid.Nil || p.OrgID == uuid.Nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"error": map[string]string{"code": "GOV_UNAUTHENTICATED", "message": "authentication required"},
		})
		return gov.Principal{}, false
	}
	return p, true
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"data": data})
}

func writeError(w http.ResponseWriter, err error) {
	var ge *gov.Error
	if errors.As(err, &ge) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(ge.HTTPStatus)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": map[string]string{
				"code":    string(ge.Code),
				"message": ge.Message,
			},
		})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusInternalServerError)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]string{
			"code":    "GOV_INTERNAL_ERROR",
			"message": err.Error(),
		},
	})
}

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return strings.TrimSpace(strings.Split(xff, ",")[0])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return ""
	}
	return host
}

