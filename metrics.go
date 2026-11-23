package governance

import "time"

// MetricsRecorder captures the 7 canonical governance metrics (§12) plus shadow-mode holds (§14).
// Implement with Prometheus, OpenTelemetry, or StatsD in your host service.
type MetricsRecorder interface {
	IncRequestsCreated(permission string, state State)
	IncRequestsDecided(permission string, decision string)
	ObserveApprovalDuration(permission string, d time.Duration)
	ObserveExecutionDuration(permission string, d time.Duration)
	IncExpired(permission string)
	IncExecutionError(permission string, errorCode ErrorCode)
	IncShadowHold(permission string)
	SetOutboxLagSeconds(seconds float64)
}

// NoopMetrics is the default MetricsRecorder when no telemetry backend is supplied.
type NoopMetrics struct{}

func (NoopMetrics) IncRequestsCreated(string, State)               {}
func (NoopMetrics) IncRequestsDecided(string, string)              {}
func (NoopMetrics) ObserveApprovalDuration(string, time.Duration)  {}
func (NoopMetrics) ObserveExecutionDuration(string, time.Duration) {}
func (NoopMetrics) IncExpired(string)                              {}
func (NoopMetrics) IncExecutionError(string, ErrorCode)            {}
func (NoopMetrics) IncShadowHold(string)                           {}
func (NoopMetrics) SetOutboxLagSeconds(float64)                    {}

