package governance

import (
	"errors"
	"fmt"
	"net/http"
)

// ErrorCode represents canonical machine-readable governance error codes (§8.1).
type ErrorCode string

const (
	CodeRuleNotFound            ErrorCode = "GOV_RULE_NOT_FOUND"
	CodeStateConflict           ErrorCode = "GOV_STATE_CONFLICT"
	CodeExpired                 ErrorCode = "GOV_EXPIRED"
	CodeSelfApprovalForbidden   ErrorCode = "GOV_SELF_APPROVAL_FORBIDDEN"
	CodeRoleRequired            ErrorCode = "GOV_ROLE_REQUIRED"
	CodeHashMismatch            ErrorCode = "GOV_HASH_MISMATCH"
	CodeStepUpRequired          ErrorCode = "GOV_STEP_UP_REQUIRED"
	CodeReasonRequired          ErrorCode = "GOV_REASON_REQUIRED"
	CodeIdempotencyRequired     ErrorCode = "GOV_IDEMPOTENCY_REQUIRED"
	CodePayloadTooLarge         ErrorCode = "GOV_PAYLOAD_TOO_LARGE"
	CodePayloadIntegrityFailure ErrorCode = "GOV_PAYLOAD_INTEGRITY_FAILURE"

	// Additional structural errors
	CodeNotFound         ErrorCode = "GOV_NOT_FOUND"
	CodeAlreadyInReview  ErrorCode = "GOV_ALREADY_IN_REVIEW"
	CodeInvalidRule      ErrorCode = "GOV_INVALID_RULE"
	CodeExecutorNotFound ErrorCode = "GOV_EXECUTOR_NOT_FOUND"
	CodeForbidden        ErrorCode = "GOV_FORBIDDEN"
)

// Error is the typed governance error carrying canonical code and HTTP status.
type Error struct {
	Code       ErrorCode `json:"code"`
	HTTPStatus int       `json:"-"`
	Message    string    `json:"message"`
	Cause      error     `json:"-"`
}

func (e *Error) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %s: %v", e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

func (e *Error) Unwrap() error { return e.Cause }

// Is allows errors.Is(err, &Error{Code: CodeStateConflict}) matching by Code.
func (e *Error) Is(target error) bool {
	var t *Error
	if errors.As(target, &t) {
		return e.Code == t.Code
	}
	return false
}

// NewError builds a canonical *Error with the standard HTTP status for the given code.
func NewError(code ErrorCode, msg string, cause ...error) *Error {
	var c error
	if len(cause) > 0 {
		c = cause[0]
	}
	return &Error{
		Code:       code,
		HTTPStatus: HTTPStatusForCode(code),
		Message:    msg,
		Cause:      c,
	}
}

// HTTPStatusForCode returns the canonical HTTP status code per §8.1.
func HTTPStatusForCode(code ErrorCode) int {
	switch code {
	case CodeRuleNotFound, CodeNotFound:
		return http.StatusNotFound
	case CodeStateConflict, CodeHashMismatch, CodeAlreadyInReview:
		return http.StatusConflict
	case CodeExpired:
		return http.StatusGone
	case CodeSelfApprovalForbidden, CodeRoleRequired, CodeForbidden:
		return http.StatusForbidden
	case CodeStepUpRequired:
		return http.StatusUnauthorized
	case CodeReasonRequired, CodeInvalidRule:
		return http.StatusUnprocessableEntity
	case CodeIdempotencyRequired:
		return http.StatusBadRequest
	case CodePayloadTooLarge:
		return http.StatusRequestEntityTooLarge
	case CodePayloadIntegrityFailure, CodeExecutorNotFound:
		return http.StatusInternalServerError
	default:
		return http.StatusInternalServerError
	}
}

// CodeOf extracts the ErrorCode from err if it is (or wraps) a *Error.
func CodeOf(err error) (ErrorCode, bool) {
	var ge *Error
	if errors.As(err, &ge) {
		return ge.Code, true
	}
	return "", false
}

// Sentinel errors for convenient errors.Is checks.
var (
	ErrRuleNotFound            = NewError(CodeRuleNotFound, "governance policy rule not found")
	ErrNotFound                = NewError(CodeNotFound, "governance resource not found")
	ErrStateConflict           = NewError(CodeStateConflict, "governance request state conflict")
	ErrExpired                 = NewError(CodeExpired, "governance request has expired")
	ErrSelfApprovalForbidden   = NewError(CodeSelfApprovalForbidden, "self-approval is forbidden by policy")
	ErrRoleRequired            = NewError(CodeRoleRequired, "caller does not hold a required checker role")
	ErrHashMismatch            = NewError(CodeHashMismatch, "payload hash mismatch")
	ErrStepUpRequired          = NewError(CodeStepUpRequired, "step-up authentication is required")
	ErrReasonRequired          = NewError(CodeReasonRequired, "decision reason is required")
	ErrIdempotencyRequired     = NewError(CodeIdempotencyRequired, "idempotency key is required")
	ErrPayloadTooLarge         = NewError(CodePayloadTooLarge, "payload exceeds rule max_payload_bytes")
	ErrPayloadIntegrityFailure = NewError(CodePayloadIntegrityFailure, "payload integrity verification failed")
	ErrAlreadyInReview         = NewError(CodeAlreadyInReview, "request has already received decisions and cannot be cancelled")
	ErrInvalidRule             = NewError(CodeInvalidRule, "invalid governance policy rule")
	ErrExecutorNotFound        = NewError(CodeExecutorNotFound, "no action executor registered for permission")
)

