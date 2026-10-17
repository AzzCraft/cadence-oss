package textdelta

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/AzzCraft/cadence-oss/cadence-core/internal/exactjson"
)

func fixture(t *testing.T, lanes ...string) *Engine {
	t.Helper()
	binding := Binding{Task: TaskKey{"authority", "project", "change", "T-1"}, Revision: 1, Cycle: 1, StreamID: "stream:1", CandidateDigest: "sha256:" + strings.Repeat("0", 64), Lanes: lanes}
	doc := map[string]any{"output": map[string]any{"text": "start", "01": "number-key", "~1": "tilde-key", "a/b": "slash-key", "": "empty-key", "array": []any{"zero", "one"}, "number": 1}, "outputX": "outside"}
	engine, err := New(doc, binding, []string{"/output"}, Limits{FrameBytes: 4096, TotalBytes: 65536, Frames: 100, StringBytes: 128, DocumentBytes: 4096, Lanes: 4, Reconnects: 2, Duration: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	return engine
}

func frame(e *Engine, id string, seq int64, path, text string) map[string]any {
	return map[string]any{"contractIdentity": FrameIdentity, "taskKey": map[string]any{"authorityDomain": e.binding.Task.AuthorityDomain, "projectId": e.binding.Task.ProjectID, "changeId": e.binding.Task.ChangeID, "taskId": e.binding.Task.TaskID}, "taskRevision": e.binding.Revision, "taskCycle": e.binding.Cycle, "streamId": e.binding.StreamID, "candidateDigest": e.binding.CandidateDigest, "laneId": id, "seq": seq, "path": path, "op": "append", "text": text}
}

func accept(e *Engine, record map[string]any) error {
	raw, err := json.Marshal(record)
	if err != nil {
		return err
	}
	return e.Accept(raw)
}

func end(e *Engine) map[string]any {
	digest, _ := exactjson.Digest(e.document)
	record := frame(e, "", 0, "", "")
	for _, key := range []string{"laneId", "seq", "path", "op", "text"} {
		delete(record, key)
	}
	marks := []any{}
	for _, id := range e.binding.Lanes {
		if l := e.lanes[id]; l != nil {
			marks = append(marks, map[string]any{"laneId": id, "seq": l.last})
		}
	}
	record["contractIdentity"] = EndIdentity
	record["laneWatermarks"] = marks
	record["finalDigest"] = digest
	return record
}

func TestTextOperationsDeduplicationAndValidatedEnd(t *testing.T) {
	e := fixture(t, "a", "b")
	first := frame(e, "a", 0, "/output/text", " + delta")
	if err := accept(e, first); err != nil {
		t.Fatal(err)
	}
	if err := accept(e, first); err != nil {
		t.Fatal(err)
	}
	second := frame(e, "b", 0, "/output/01", "replacement")
	second["op"] = "replace"
	if err := accept(e, second); err != nil {
		t.Fatal(err)
	}
	if err := accept(e, end(e)); err != nil {
		t.Fatal(err)
	}
	if err := e.EOF(); err != nil {
		t.Fatal(err)
	}
	if err := accept(e, first); err != nil {
		t.Fatal(err)
	}
	doc, state, err := e.Snapshot()
	if err != nil || state != "complete" {
		t.Fatal(err, state)
	}
	output := doc.(map[string]any)["output"].(map[string]any)
	if output["text"] != "start + delta" || output["01"] != "replacement" {
		t.Fatal("wrong text materialization")
	}
	if err := accept(e, frame(e, "a", 1, "/output/text", "late")); err == nil {
		t.Fatal("accepted new delta after end")
	}
	_, state, _ = e.Snapshot()
	if state != "complete" {
		t.Fatal("late error erased a historical completed stream")
	}
}

func TestPointerTokenAuthorizationAndContainerTypes(t *testing.T) {
	for _, path := range []string{"/output/01", "/output/~01", "/output/a~1b", "/output/", "/output/array/0"} {
		e := fixture(t, "a")
		if err := accept(e, frame(e, "a", 0, path, "ok")); err != nil {
			t.Fatalf("legal pointer %s: %v", path, err)
		}
	}
	for _, path := range []string{"", "/outputX", "/output/array/01", "/output/array/-", "/output/array/+1", "/output/array/99", "/output/number", "/output/missing", "/output/~2", "#/output/text", "output.text"} {
		e := fixture(t, "a")
		before, _, _ := e.Snapshot()
		if err := accept(e, frame(e, "a", 0, path, "bad")); err == nil {
			t.Fatalf("illegal pointer accepted: %s", path)
		}
		after, state, _ := e.Snapshot()
		if !reflect.DeepEqual(before, after) || state != "interrupted" || len(e.lanes) != 0 {
			t.Fatal("failed frame changed document or watermark")
		}
	}
}

func TestSequenceGapConflictMissingEndAndWrongBinding(t *testing.T) {
	for _, mutation := range []string{"gap", "duplicate-conflict", "cross-lane", "missing-lane", "wrong-digest", "wrong-task", "wrong-candidate", "wrong-cycle", "unknown-field", "fractional-seq", "unknown-lane", "unsupported-op", "end-gap"} {
		t.Run(mutation, func(t *testing.T) {
			e := fixture(t, "a", "b")
			first := frame(e, "a", 0, "/output/text", " x")
			if err := accept(e, first); err != nil {
				t.Fatal(err)
			}
			if mutation == "wrong-digest" || mutation == "end-gap" {
				if err := accept(e, frame(e, "b", 0, "/output/01", " b")); err != nil {
					t.Fatal(err)
				}
			}
			before, _, _ := e.Snapshot()
			record := frame(e, "a", 1, "/output/text", " y")
			switch mutation {
			case "gap":
				record["seq"] = 2
			case "duplicate-conflict":
				record["seq"] = 0
			case "cross-lane":
				record["laneId"] = "b"
				record["seq"] = 0
			case "missing-lane":
				record = end(e)
			case "wrong-digest":
				record = end(e)
				record["finalDigest"] = "sha256:" + strings.Repeat("1", 64)
			case "wrong-task":
				record["taskKey"].(map[string]any)["projectId"] = "other"
			case "wrong-candidate":
				record["candidateDigest"] = "sha256:" + strings.Repeat("1", 64)
			case "wrong-cycle":
				record["taskCycle"] = 2
			case "unknown-field":
				record["approved"] = true
			case "fractional-seq":
				record["seq"] = json.Number("1.0000000000000000001")
			case "unknown-lane":
				record["laneId"] = "c"
			case "unsupported-op":
				record["op"] = "add"
			case "end-gap":
				record = end(e)
				record["laneWatermarks"] = []any{map[string]any{"laneId": "a", "seq": 1}, map[string]any{"laneId": "b", "seq": 0}}
			}
			if err := accept(e, record); err == nil {
				t.Fatal("invalid stream accepted")
			}
			after, _, _ := e.Snapshot()
			if !reflect.DeepEqual(before, after) || e.lanes["a"].last != 0 {
				t.Fatal("failed validation changed atomic state")
			}
		})
	}
	e := fixture(t, "a")
	if err := accept(e, frame(e, "a", 0, "/output/text", "ok")); err != nil {
		t.Fatal(err)
	}
	if e.EOF() == nil {
		t.Fatal("EOF fabricated complete")
	}
}

func TestCumulativeBudgetsClockAndReconnectNeverReset(t *testing.T) {
	e := fixture(t, "a")
	record := frame(e, "a", 0, "/output/text", "x")
	if err := accept(e, record); err != nil {
		t.Fatal(err)
	}
	e.limits.Frames = 2
	if err := e.Reconnect(); err != nil {
		t.Fatal(err)
	}
	if err := accept(e, record); err != nil {
		t.Fatal(err)
	}
	if accept(e, record) == nil || e.frames != 2 {
		t.Fatal("replay did not consume frame budget")
	}
	if e.Reconnect() == nil {
		t.Fatal("interrupted operation reconnected")
	}
	for _, mutation := range []string{"deadline", "clock-backward", "instance", "string-limit", "document-limit", "bytes-limit", "reconnect-limit"} {
		t.Run(mutation, func(t *testing.T) {
			e := fixture(t, "a")
			before, _, _ := e.Snapshot()
			switch mutation {
			case "deadline":
				e.clock = func() (clockSample, error) { return clockSample{e.start.instance, e.start.ticks + time.Minute}, nil }
			case "clock-backward":
				e.clock = func() (clockSample, error) { return clockSample{e.start.instance, e.start.ticks - 1}, nil }
			case "instance":
				e.clock = func() (clockSample, error) { return clockSample{"restored-instance", e.start.ticks}, nil }
			case "string-limit":
				e.limits.StringBytes = 5
			case "document-limit":
				e.limits.DocumentBytes = 1
			case "bytes-limit":
				e.limits.TotalBytes = 1
			case "reconnect-limit":
				e.limits.Reconnects = 0
				if e.Reconnect() == nil {
					t.Fatal("reconnect allowed")
				}
				return
			}
			if accept(e, frame(e, "a", 0, "/output/text", "longer")) == nil {
				t.Fatal("limit did not stop stream")
			}
			after, _, _ := e.Snapshot()
			if !reflect.DeepEqual(before, after) || len(e.lanes) != 0 {
				t.Fatal("limit committed partial materialization")
			}
		})
	}
}

func TestSmallFramesAndReplayConsumeCumulativeBytesAtomically(t *testing.T) {
	e := fixture(t, "a")
	first := frame(e, "a", 0, "/output/text", "x")
	raw, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	// Each individual frame is legal; the replay consumes the same operation's
	// byte budget after reconnect, without applying the text again.
	e.limits.TotalBytes = 2 * int64(len(raw)+1)
	if err = e.Accept(raw); err != nil {
		t.Fatal(err)
	}
	before, _, _ := e.Snapshot()
	if err = e.Reconnect(); err != nil {
		t.Fatal(err)
	}
	if err = e.Accept(raw); err != nil {
		t.Fatal(err)
	}
	if e.frames != 2 || e.bytes != e.limits.TotalBytes || e.lanes["a"].last != 0 {
		t.Fatal("replay reset metering or advanced watermark")
	}
	if accept(e, frame(e, "a", 1, "/output/text", "y")) == nil {
		t.Fatal("cumulative small frames exceeded operation byte budget")
	}
	after, state, _ := e.Snapshot()
	if !reflect.DeepEqual(before, after) || state != "interrupted" || e.lanes["a"].last != 0 || e.EOF() == nil {
		t.Fatal("overrun published partial text/watermark or fabricated completion")
	}
	// Independent healthy recovery control with sufficient original budget.
	e = fixture(t, "a")
	for _, step := range []func() error{
		func() error { return accept(e, first) }, e.Reconnect,
		func() error { return accept(e, first) },
		func() error { return accept(e, frame(e, "a", 1, "/output/text", "y")) },
		func() error { return accept(e, end(e)) }, e.EOF,
	} {
		if err = step(); err != nil {
			t.Fatal(err)
		}
	}
	doc, state, err := e.Snapshot()
	if err != nil || state != "complete" || doc.(map[string]any)["output"].(map[string]any)["text"] != "startxy" || e.lanes["a"].last != 1 || e.frames != 4 {
		t.Fatal("legal replay/reconnect recovery lost text, end or watermark")
	}
}

func TestIndependentProducerConsumerVectors(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "cadence-protocol", "fixtures", "das_v1_5", "text_delta_vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Cases []struct {
			ID      string
			Initial map[string]any
			Records []json.RawMessage
			Final   map[string]any
			Reject  bool
		}
	}
	if err = json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	for _, vector := range vectors.Cases {
		t.Run(vector.ID, func(t *testing.T) {
			e := fixture(t, "a")
			e, err = New(vector.Initial, e.binding, []string{"/output"}, e.limits)
			if err != nil {
				t.Fatal(err)
			}
			var rejected bool
			for _, record := range vector.Records {
				var line bytes.Buffer
				if err = json.Compact(&line, record); err != nil {
					t.Fatal(err)
				}
				if err = e.Accept(line.Bytes()); err != nil {
					rejected = true
					break
				}
			}
			if !rejected {
				rejected = e.EOF() != nil
			}
			if rejected != vector.Reject {
				t.Fatalf("rejection mismatch: %v", err)
			}
			if !vector.Reject {
				actual, _ := exactjson.Canonical(e.document)
				expected, _ := exactjson.Canonical(vector.Final)
				if string(actual) != string(expected) {
					t.Fatal("independent gold differs")
				}
			}
		})
	}
}
