// Package audit emits a structured, append-only trail of every tool
// invocation. Two events are recorded per request:
//
//   - authorization_decision: the access-control verdict, written BEFORE the
//     call is dispatched. Present even when the call is denied or the caller
//     fails authentication.
//   - tool_outcome: the result of dispatching an allowed call, written AFTER
//     the downstream returns.
//
// Records never contain the raw token or downstream payloads; only metadata
// needed for forensics and policy debugging is logged.
package audit

import (
	"encoding/json"
	"io"
	"sync"
	"time"
)

// EventType names the two audit events.
const (
	EventDecision = "authorization_decision"
	EventOutcome  = "tool_outcome"
)

// Decision is the access-control verdict for a request.
type Decision struct {
	Event         string    `json:"event"`
	Time          time.Time `json:"ts"`
	RequestID     string    `json:"request_id"`
	SourceIP      string    `json:"source_ip,omitempty"`
	Subject       string    `json:"subject,omitempty"`
	Issuer        string    `json:"issuer,omitempty"`
	Groups        []string  `json:"groups,omitempty"`
	Tool          string    `json:"tool"`
	Allowed       bool      `json:"allowed"`
	Effect        string    `json:"effect"`
	Reason        string    `json:"reason"`
	MatchedAllows []string  `json:"matched_allows,omitempty"`
	MatchedDenies []string  `json:"matched_denies,omitempty"`
	PolicyDigest  string    `json:"policy_digest,omitempty"`
}

// Outcome is the result of dispatching an allowed call.
type Outcome struct {
	Event      string        `json:"event"`
	Time       time.Time     `json:"ts"`
	RequestID  string        `json:"request_id"`
	Subject    string        `json:"subject,omitempty"`
	Tool       string        `json:"tool"`
	Status     string        `json:"status"` // "ok" | "error"
	Error      string        `json:"error,omitempty"`
	DurationMS int64         `json:"duration_ms"`
	duration   time.Duration // unexported staging field, not serialized
}

// Logger records audit events.
type Logger interface {
	LogDecision(d Decision)
	LogOutcome(o Outcome)
}

// jsonlLogger writes one JSON object per line to an io.Writer.
type jsonlLogger struct {
	mu  sync.Mutex
	enc *json.Encoder
	now func() time.Time
}

// NewJSONL returns a Logger that writes JSON lines to w.
func NewJSONL(w io.Writer, now func() time.Time) Logger {
	if now == nil {
		now = time.Now
	}
	return &jsonlLogger{enc: json.NewEncoder(w), now: now}
}

func (l *jsonlLogger) LogDecision(d Decision) {
	d.Event = EventDecision
	if d.Time.IsZero() {
		d.Time = l.now().UTC()
	}
	l.write(d)
}

func (l *jsonlLogger) LogOutcome(o Outcome) {
	o.Event = EventOutcome
	if o.Time.IsZero() {
		o.Time = l.now().UTC()
	}
	if o.duration > 0 {
		o.DurationMS = o.duration.Milliseconds()
	}
	l.write(o)
}

func (l *jsonlLogger) write(v any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	_ = l.enc.Encode(v) // best-effort; audit failures must not break the request path
}

// WithDuration sets the measured call duration on an Outcome.
func (o Outcome) WithDuration(d time.Duration) Outcome {
	o.duration = d
	return o
}
