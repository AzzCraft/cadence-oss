// Package textdelta implements the new bounded text-only JSON Pointer transport.
// It grants no authority over external resources and does not change StreamFrame v1.
package textdelta

import (
	"encoding/json"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/AzzCraft/cadence-oss/cadence-core/internal/exactjson"
)

const TransportIdentity = "das-text-jsonl/v1"
const FrameIdentity = "das-text-delta/v1"
const EndIdentity = "das-text-delta-end/v1"

var idPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

type TaskKey struct{ AuthorityDomain, ProjectID, ChangeID, TaskID string }
type Binding struct {
	Task                      TaskKey
	Revision, Cycle           int64
	StreamID, CandidateDigest string
	Lanes                     []string
}
type Limits struct {
	FrameBytes, TotalBytes, Frames, StringBytes, DocumentBytes, Lanes, Reconnects int64
	Duration                                                                      time.Duration
}
type clockSample struct {
	instance string
	ticks    time.Duration
}
type lane struct {
	last int64
	seen map[int64]string
}
type Engine struct {
	mu                        sync.Mutex
	binding                   Binding
	limits                    Limits
	document                  any
	allowed                   [][]string
	expected                  map[string]bool
	lanes                     map[string]*lane
	writers                   map[string]string
	state                     string
	bytes, frames, reconnects int64
	start, last               clockSample
	clock                     func() (clockSample, error)
	endDigest                 string
}

func New(document any, binding Binding, allowedPaths []string, limits Limits) (*Engine, error) {
	if limits.FrameBytes <= 0 || limits.FrameBytes > exactjson.MaxBytes || limits.TotalBytes <= 0 || limits.TotalBytes > 64*1024*1024 || limits.Frames <= 0 || limits.Frames > 100000 || limits.StringBytes <= 0 || limits.StringBytes > exactjson.MaxBytes || limits.DocumentBytes <= 0 || limits.DocumentBytes > exactjson.MaxBytes || limits.Lanes <= 0 || limits.Lanes > 64 || limits.Reconnects < 0 || limits.Reconnects > 64 || limits.Duration <= 0 || limits.Duration > 10*time.Minute {
		return nil, errors.New("textdelta: unsupported operation limits")
	}
	for _, part := range []string{binding.Task.AuthorityDomain, binding.Task.ProjectID, binding.Task.ChangeID, binding.Task.TaskID} {
		if len(part) == 0 || len(part) > 256 || strings.ContainsRune(part, 0) {
			return nil, errors.New("textdelta: invalid complete task key")
		}
	}
	if binding.Revision <= 0 || binding.Cycle <= 0 || binding.Revision > exactjson.MaxSafeInteger || binding.Cycle > exactjson.MaxSafeInteger || !idPattern.MatchString(binding.StreamID) || !digestPattern.MatchString(binding.CandidateDigest) {
		return nil, errors.New("textdelta: invalid binding")
	}
	raw, err := exactjson.Canonical(document)
	if err != nil || int64(len(raw)) > limits.DocumentBytes {
		return nil, errors.New("textdelta: invalid initial document")
	}
	copy, err := exactjson.Parse(raw)
	if err != nil {
		return nil, err
	}
	expected := map[string]bool{}
	if len(binding.Lanes) == 0 || int64(len(binding.Lanes)) > limits.Lanes {
		return nil, errors.New("textdelta: invalid planned lane set")
	}
	for _, id := range binding.Lanes {
		if !idPattern.MatchString(id) || expected[id] {
			return nil, errors.New("textdelta: duplicate or invalid planned lane")
		}
		expected[id] = true
	}
	allowed := [][]string{}
	if len(allowedPaths) == 0 || len(allowedPaths) > 64 {
		return nil, errors.New("textdelta: missing bounded allowed roots")
	}
	for _, path := range allowedPaths {
		tokens, err := Pointer(path)
		if err != nil || len(tokens) == 0 {
			return nil, errors.New("textdelta: invalid allowed root")
		}
		allowed = append(allowed, tokens)
	}
	sample, err := runtimeClock()
	if err != nil {
		return nil, err
	}
	binding.Lanes = append([]string(nil), binding.Lanes...)
	return &Engine{binding: binding, limits: limits, document: copy, allowed: allowed, expected: expected, lanes: map[string]*lane{}, writers: map[string]string{}, state: "running", start: sample, last: sample, clock: runtimeClock}, nil
}

// Pointer decodes the JSON string representation exactly once. Object numeric
// keys stay strings; array index syntax is checked only while traversing arrays.
func Pointer(path string) ([]string, error) {
	if path == "" {
		return []string{}, nil
	}
	if !strings.HasPrefix(path, "/") || len(path) > 4096 {
		return nil, errors.New("textdelta: invalid pointer representation")
	}
	parts := strings.Split(path[1:], "/")
	if len(parts) > 64 {
		return nil, errors.New("textdelta: pointer depth exceeded")
	}
	for i, part := range parts {
		for at := 0; at < len(part); at++ {
			if part[at] == '~' {
				if at+1 >= len(part) || (part[at+1] != '0' && part[at+1] != '1') {
					return nil, errors.New("textdelta: invalid pointer escape")
				}
				at++
			}
		}
		parts[i] = strings.ReplaceAll(strings.ReplaceAll(part, "~1", "/"), "~0", "~")
	}
	return parts, nil
}

func (e *Engine) fail(message string) error {
	if e.state != "complete" {
		e.state = "interrupted"
	}
	return errors.New("textdelta: " + message)
}
func (e *Engine) meter(size int) error {
	if e.state == "interrupted" {
		return e.fail("operation already interrupted")
	}
	sample, err := e.clock()
	if err != nil || sample.instance != e.start.instance || sample.ticks < e.last.ticks || sample.ticks-e.start.ticks >= e.limits.Duration {
		return e.fail("deadline or clock instance invalid")
	}
	e.last = sample
	// Counters include rejected frames and replay traffic; they never refund.
	if int64(size) > e.limits.FrameBytes || e.frames >= e.limits.Frames || int64(size) > e.limits.TotalBytes-e.bytes {
		return e.fail("operation budget exceeded")
	}
	e.bytes += int64(size)
	e.frames++
	return nil
}

func (e *Engine) match(object map[string]any) error {
	task, err := exactjson.Object(object["taskKey"], []string{"authorityDomain", "projectId", "changeId", "taskId"}, nil)
	if err != nil {
		return e.fail("invalid complete task key")
	}
	want := map[string]string{"authorityDomain": e.binding.Task.AuthorityDomain, "projectId": e.binding.Task.ProjectID, "changeId": e.binding.Task.ChangeID, "taskId": e.binding.Task.TaskID}
	for key, value := range want {
		if task[key] != value {
			return e.fail("task namespace mismatch")
		}
	}
	revision, err := exactjson.SafeInteger(object["taskRevision"])
	if err != nil || revision != e.binding.Revision {
		return e.fail("task revision mismatch")
	}
	cycle, err := exactjson.SafeInteger(object["taskCycle"])
	if err != nil || cycle != e.binding.Cycle {
		return e.fail("task cycle mismatch")
	}
	if object["streamId"] != e.binding.StreamID || object["candidateDigest"] != e.binding.CandidateDigest {
		return e.fail("stream or candidate mismatch")
	}
	return nil
}

// Accept receives one complete JSONL record without its terminating LF. The
// LF is included in transport metering. Gaps fail explicitly; no hidden buffer.
func (e *Engine) Accept(data []byte) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.meter(len(data) + 1); err != nil {
		return err
	}
	if strings.ContainsAny(string(data), "\r\n") {
		return e.fail("multiline JSONL record")
	}
	value, err := exactjson.Parse(data)
	if err != nil {
		return e.fail("invalid exact JSON record")
	}
	object, ok := value.(map[string]any)
	if !ok {
		return e.fail("record is not an object")
	}
	if object["contractIdentity"] == EndIdentity {
		return e.end(object)
	}
	object, err = exactjson.Object(value, []string{"contractIdentity", "taskKey", "taskRevision", "taskCycle", "streamId", "candidateDigest", "laneId", "seq", "path", "op", "text"}, nil)
	if err != nil || object["contractIdentity"] != FrameIdentity {
		return e.fail("invalid delta contract")
	}
	if err := e.match(object); err != nil {
		return err
	}
	laneID, ok := object["laneId"].(string)
	if !ok || !e.expected[laneID] {
		return e.fail("lane not in approved transport plan")
	}
	seq, err := exactjson.SafeInteger(object["seq"])
	if err != nil || seq < 0 {
		return e.fail("invalid exact sequence")
	}
	identity, err := exactjson.Digest(object)
	if err != nil {
		return e.fail("invalid frame content identity")
	}
	l := e.lanes[laneID]
	if l != nil {
		if previous, seen := l.seen[seq]; seen {
			if previous == identity {
				return nil
			}
			return e.fail("duplicate sequence content conflict")
		}
	}
	if e.state == "complete" {
		return e.fail("new delta after complete")
	}
	if (l == nil && seq != 0) || (l != nil && (l.last == exactjson.MaxSafeInteger || seq != l.last+1)) {
		return e.fail("lane sequence gap")
	}
	path, ok := object["path"].(string)
	if !ok {
		return e.fail("path is not a string")
	}
	tokens, err := Pointer(path)
	if err != nil || !e.authorized(tokens) {
		return e.fail("pointer outside allowed node roots")
	}
	text, ok := object["text"].(string)
	if !ok || int64(len(text)) > e.limits.StringBytes {
		return e.fail("text outside contract domain")
	}
	op, ok := object["op"].(string)
	if !ok || (op != "append" && op != "replace") {
		return e.fail("unsupported text operation")
	}
	keyBytes, _ := json.Marshal(tokens)
	key := string(keyBytes)
	if previous, ok := e.writers[key]; ok && previous != laneID {
		return e.fail("cross-lane target conflict")
	}
	before, err := exactjson.Canonical(e.document)
	if err != nil {
		return e.fail("invalid stored document")
	}
	candidate, err := exactjson.Parse(before)
	if err != nil {
		return e.fail("cannot stage document")
	}
	if err := replaceText(candidate, tokens, text, op, e.limits.StringBytes); err != nil {
		return e.fail("target missing, wrong type, or string limit exceeded")
	}
	encoded, err := exactjson.Canonical(candidate)
	if err != nil || int64(len(encoded)) > e.limits.DocumentBytes {
		return e.fail("materialized document limit exceeded")
	}
	// Publish document and watermark only after every check succeeds.
	e.document = candidate
	e.writers[key] = laneID
	if l == nil {
		l = &lane{last: -1, seen: map[int64]string{}}
		e.lanes[laneID] = l
	}
	l.last = seq
	l.seen[seq] = identity
	return nil
}

func (e *Engine) authorized(tokens []string) bool {
	if len(tokens) == 0 {
		return false
	}
	for _, prefix := range e.allowed {
		if len(tokens) < len(prefix) {
			continue
		}
		matches := true
		for i, token := range prefix {
			if tokens[i] != token {
				matches = false
				break
			}
		}
		if matches {
			return true
		}
	}
	return false
}

func replaceText(document any, tokens []string, text, operation string, max int64) error {
	current := document
	for i, token := range tokens {
		var child any
		var assign func(any)
		switch container := current.(type) {
		case map[string]any:
			value, present := container[token]
			if !present {
				return errors.New("missing node")
			}
			child = value
			assign = func(value any) { container[token] = value }
		case []any:
			if token == "" || (len(token) > 1 && token[0] == '0') {
				return errors.New("invalid array index")
			}
			for _, char := range token {
				if char < '0' || char > '9' {
					return errors.New("invalid array index")
				}
			}
			index, err := strconv.ParseUint(token, 10, 31)
			if err != nil || index >= uint64(len(container)) {
				return errors.New("array index out of range")
			}
			child = container[index]
			assign = func(value any) { container[index] = value }
		default:
			return errors.New("not a JSON container")
		}
		if i == len(tokens)-1 {
			old, ok := child.(string)
			if !ok {
				return errors.New("not an existing string")
			}
			if operation == "append" {
				if int64(len(old)) > max-int64(len(text)) {
					return errors.New("string limit")
				}
				text = old + text
			}
			if int64(len(text)) > max {
				return errors.New("string limit")
			}
			assign(text)
			return nil
		}
		current = child
	}
	return errors.New("root replacement forbidden")
}

func (e *Engine) end(value map[string]any) error {
	object, err := exactjson.Object(value, []string{"contractIdentity", "taskKey", "taskRevision", "taskCycle", "streamId", "candidateDigest", "laneWatermarks", "finalDigest"}, nil)
	if err != nil {
		return e.fail("invalid end contract")
	}
	if err := e.match(object); err != nil {
		return err
	}
	identity, err := exactjson.Digest(object)
	if err != nil {
		return e.fail("invalid end identity")
	}
	if e.state == "complete" {
		if identity == e.endDigest {
			return nil
		}
		return e.fail("end content conflict")
	}
	watermarks, ok := object["laneWatermarks"].([]any)
	if !ok || len(watermarks) != len(e.expected) {
		return e.fail("incomplete lane watermarks")
	}
	seen := map[string]bool{}
	for _, raw := range watermarks {
		mark, err := exactjson.Object(raw, []string{"laneId", "seq"}, nil)
		if err != nil {
			return e.fail("invalid watermark")
		}
		id, ok := mark["laneId"].(string)
		if !ok || seen[id] || !e.expected[id] || e.lanes[id] == nil {
			return e.fail("missing or duplicate planned lane")
		}
		seq, err := exactjson.SafeInteger(mark["seq"])
		if err != nil || seq != e.lanes[id].last {
			return e.fail("watermark mismatch")
		}
		seen[id] = true
	}
	digest, err := exactjson.Digest(e.document)
	if err != nil || object["finalDigest"] != digest {
		return e.fail("final materialization digest mismatch")
	}
	e.endDigest = identity
	e.state = "complete"
	return nil
}

func (e *Engine) Reconnect() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.state == "interrupted" {
		return e.fail("operation already interrupted")
	}
	if e.reconnects >= e.limits.Reconnects {
		return e.fail("reconnect budget exceeded")
	}
	if err := e.checkClock(); err != nil {
		return err
	}
	e.reconnects++
	return nil
}
func (e *Engine) checkClock() error {
	sample, err := e.clock()
	if err != nil || sample.instance != e.start.instance || sample.ticks < e.last.ticks || sample.ticks-e.start.ticks >= e.limits.Duration {
		return e.fail("deadline or clock instance invalid")
	}
	e.last = sample
	return nil
}
func (e *Engine) EOF() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.state != "complete" {
		return e.fail("EOF without validated end")
	}
	return nil
}
func (e *Engine) Snapshot() (any, string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	raw, err := exactjson.Canonical(e.document)
	if err != nil {
		return nil, e.state, err
	}
	copy, err := exactjson.Parse(raw)
	return copy, e.state, err
}
