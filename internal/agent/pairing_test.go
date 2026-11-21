package agent

import (
	"testing"
	"time"
)

// After a reconnect the relay starts without pairing windows, so the agent must
// announce every window that is still open, with its remaining lifetime.
func TestOpenPairingsAfterReconnect(t *testing.T) {
	now := time.Now()
	a := &Agent{pending: map[string]*pending{
		"open":    {name: "phone", expires: now.Add(90*time.Second + 300*time.Millisecond)},
		"expired": {name: "old", expires: now.Add(-time.Second)},
	}}
	msgs := a.openPairings(now)
	if len(msgs) != 1 {
		t.Fatalf("got %d messages, want 1: %+v", len(msgs), msgs)
	}
	m := msgs[0]
	if m.Op != "pair_open" || m.Hash != "open" || m.TTL != 91 {
		t.Fatalf("unexpected message %+v", m)
	}
}
