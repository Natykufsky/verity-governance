package tests

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	gov "github.com/Natykufsky/verity-governance"
	"github.com/Natykufsky/verity-governance/govhttp"
)

func TestHTTP_All12EndpointsAndErrorCodes(t *testing.T) {
	h := newHarness(t)

	actors := map[string]gov.Principal{
		"admin":    h.admin,
		"maker":    h.maker,
		"checker1": h.checker1,
	}

	mux := http.NewServeMux()
	handler := govhttp.NewHandler(h.engine, func(r *http.Request) (gov.Principal, error) {
		p, ok := actors[r.Header.Get("X-Test-Actor")]
		if !ok {
			return gov.Principal{}, gov.ErrNotFound
		}
		return p, nil
	})
	handler.RegisterRoutes(mux, "/v1/governance")
	srv := httptest.NewServer(mux)
	defer srv.Close()

	doReq := func(method, path, actor string, headers map[string]string, body any) (*http.Response, map[string]any) {
		t.Helper()
		var buf bytes.Buffer
		if body != nil {
			_ = json.NewEncoder(&buf).Encode(body)
		}
		req, _ := http.NewRequest(method, srv.URL+path, &buf)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Test-Actor", actor)
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		defer resp.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp, out
	}

	// 1. POST /rules -> 201
	resp, res := doReq("POST", "/v1/governance/rules", "admin", nil, map[string]any{
		"scope_id":           h.parishID.String(),
		"permission":         "finance.disburse",
		"checker_roles":      []string{"parish_priest"},
		"required_approvals": 1,
		"require_step_up":    true,
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /rules status=%d body=%+v", resp.StatusCode, res)
	}
	ruleData := res["data"].(map[string]any)
	rootID := ruleData["root_id"].(string)

	// 2. GET /rules -> 200
	resp, _ = doReq("GET", "/v1/governance/rules?permission=finance.disburse", "admin", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /rules status=%d", resp.StatusCode)
	}

	// 3. PUT /rules/{root_id} -> 200 (v2)
	resp, res = doReq("PUT", "/v1/governance/rules/"+rootID, "admin", nil, map[string]any{
		"scope_id":           h.parishID.String(),
		"permission":         "finance.disburse",
		"checker_roles":      []string{"parish_priest"},
		"required_approvals": 1,
		"require_step_up":    true,
	})
	if resp.StatusCode != http.StatusOK || res["data"].(map[string]any)["version"].(float64) != 2 {
		t.Fatalf("PUT /rules status=%d body=%+v", resp.StatusCode, res)
	}

	// 4. GET /rules/{root_id}/versions -> 200 (2 versions)
	resp, res = doReq("GET", "/v1/governance/rules/"+rootID+"/versions", "admin", nil, nil)
	if resp.StatusCode != http.StatusOK || len(res["data"].([]any)) != 2 {
		t.Fatalf("GET /rules/versions status=%d body=%+v", resp.StatusCode, res)
	}

	// 5. POST /evaluate -> 200 requires_approval=true
	resp, res = doReq("POST", "/v1/governance/evaluate", "maker", nil, map[string]any{
		"permission": "finance.disburse",
		"scope_id":   h.parishID.String(),
	})
	if resp.StatusCode != http.StatusOK || res["data"].(map[string]any)["requires_approval"] != true {
		t.Fatalf("POST /evaluate status=%d body=%+v", resp.StatusCode, res)
	}

	// 6. POST /requests without Idempotency-Key -> 400 GOV_IDEMPOTENCY_REQUIRED
	resp, res = doReq("POST", "/v1/governance/requests", "maker", nil, map[string]any{
		"permission":           "finance.disburse",
		"scope_id":             h.parishID.String(),
		"target_resource_type": "stipend",
		"title":                "HTTP Test Stipend",
		"payload":              map[string]any{"amount": 5000},
	})
	if resp.StatusCode != http.StatusBadRequest || res["error"].(map[string]any)["code"] != string(gov.CodeIdempotencyRequired) {
		t.Fatalf("expected 400 GOV_IDEMPOTENCY_REQUIRED, got %d %+v", resp.StatusCode, res)
	}

	// 7. POST /requests with Idempotency-Key -> 202
	resp, res = doReq("POST", "/v1/governance/requests", "maker", map[string]string{"Idempotency-Key": "http-req-1"}, map[string]any{
		"permission":           "finance.disburse",
		"scope_id":             h.parishID.String(),
		"target_resource_type": "stipend",
		"title":                "HTTP Test Stipend",
		"payload":              map[string]any{"amount": 5000},
	})
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("POST /requests status=%d body=%+v", resp.StatusCode, res)
	}
	tData := res["data"].(map[string]any)
	reqID := tData["id"].(string)
	payloadHash := tData["payload_hash"].(string)

	// 8. GET /requests & GET /requests/{id}
	resp, _ = doReq("GET", "/v1/governance/requests?state=pending", "checker1", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /requests status=%d", resp.StatusCode)
	}
	resp, _ = doReq("GET", "/v1/governance/requests/"+reqID, "checker1", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /requests/{id} status=%d", resp.StatusCode)
	}

	// 9. POST /requests/{id}/approve without Step-Up-Token -> 401 GOV_STEP_UP_REQUIRED
	resp, res = doReq("POST", "/v1/governance/requests/"+reqID+"/approve", "checker1", nil, map[string]any{
		"payload_hash": payloadHash,
	})
	if resp.StatusCode != http.StatusUnauthorized || res["error"].(map[string]any)["code"] != string(gov.CodeStepUpRequired) {
		t.Fatalf("expected 401 GOV_STEP_UP_REQUIRED, got %d %+v", resp.StatusCode, res)
	}

	// 10. POST /requests/{id}/approve with valid Step-Up-Token -> 202 executing
	resp, res = doReq("POST", "/v1/governance/requests/"+reqID+"/approve", "checker1",
		map[string]string{"Step-Up-Token": "valid-totp-123"},
		map[string]any{"payload_hash": payloadHash},
	)
	if resp.StatusCode != http.StatusAccepted || res["data"].(map[string]any)["state"] != string(gov.StateExecuting) {
		t.Fatalf("expected 202 executing, got %d %+v", resp.StatusCode, res)
	}

	// 11. Submit + Cancel & Submit + Reject
	_, rCan := doReq("POST", "/v1/governance/requests", "maker", map[string]string{"Idempotency-Key": "http-can-" + uuid.NewString()}, map[string]any{
		"permission": "finance.disburse", "scope_id": h.parishID.String(), "target_resource_type": "stipend", "title": "Cancel me", "payload": map[string]any{"a": 1},
	})
	canID := rCan["data"].(map[string]any)["id"].(string)
	resp, _ = doReq("POST", "/v1/governance/requests/"+canID+"/cancel", "maker", nil, map[string]any{"reason": "oops"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /cancel status=%d", resp.StatusCode)
	}

	_, rRej := doReq("POST", "/v1/governance/requests", "maker", map[string]string{"Idempotency-Key": "http-rej-" + uuid.NewString()}, map[string]any{
		"permission": "finance.disburse", "scope_id": h.parishID.String(), "target_resource_type": "stipend", "title": "Reject me", "payload": map[string]any{"a": 2},
	})
	rejID := rRej["data"].(map[string]any)["id"].(string)
	resp, _ = doReq("POST", "/v1/governance/requests/"+rejID+"/reject", "checker1", nil, map[string]any{"reason": "invalid"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /reject status=%d", resp.StatusCode)
	}

	// 12. DELETE /rules/{root_id} -> 200
	resp, _ = doReq("DELETE", "/v1/governance/rules/"+rootID, "admin", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("DELETE /rules status=%d", resp.StatusCode)
	}
}

