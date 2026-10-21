// Package cassette — record/replay HTTP and tool-call interactions for
// deterministic plugin tests.
//
// A cassette is a JSON file containing an ordered list of recorded
// interactions keyed by a stable hash of (method, url, body). On replay
// the next matching interaction is consumed in order.
package cassette

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"sync"
)

// Interaction is one recorded request / response pair.
type Interaction struct {
	Method   string            `json:"method"`
	URL      string            `json:"url"`
	Body     string            `json:"body,omitempty"`
	Status   int               `json:"status"`
	RespBody string            `json:"respBody,omitempty"`
	Headers  map[string]string `json:"headers,omitempty"`
}

// Cassette holds an ordered list of interactions.
type Cassette struct {
	mu           sync.Mutex
	Interactions []Interaction `json:"interactions"`
	cursor       int
}

// Load reads a cassette JSON file from disk.
func Load(path string) (*Cassette, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	c := &Cassette{}
	if err := json.Unmarshal(b, c); err != nil {
		return nil, err
	}
	return c, nil
}

// Save writes the cassette to disk in canonical form.
func (c *Cassette) Save(path string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

// Record appends an interaction.
func (c *Cassette) Record(i Interaction) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Interactions = append(c.Interactions, i)
}

// Next returns the next matching interaction by (method, url) in order.
func (c *Cassette) Next(method, url string) (Interaction, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for c.cursor < len(c.Interactions) {
		it := c.Interactions[c.cursor]
		c.cursor++
		if it.Method == method && it.URL == url {
			return it, nil
		}
	}
	return Interaction{}, ErrNoMatch
}

// HashIdentity names the ordered replay-content identity. Legacy sorted hashes
// were not replay identities and must not be reinterpreted as this version.
const HashIdentity = "cadence-cassette-ordered/v2"

// Hash preserves interaction order, which controls Next; JSON sorts header keys.
func (c *Cassette) Hash() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	payload := struct {
		Identity     string        `json:"identity"`
		Interactions []Interaction `json:"interactions"`
	}{HashIdentity, c.Interactions}
	b, _ := json.Marshal(payload)
	h := sha256.Sum256(b)
	return HashIdentity + ":sha256:" + hex.EncodeToString(h[:])
}

// ErrNoMatch is returned when no remaining interaction matches.
var ErrNoMatch = errors.New("cassette: no matching interaction")
