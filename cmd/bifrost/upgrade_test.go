package main

import "testing"

func TestDebVersionToTag(t *testing.T) {
	for in, want := range map[string]string{"0.2.0": "0.2.0", "1:0.3.1": "0.3.1", " 1:1.0.0\n": "1.0.0"} {
		if got := debVersionToTag(in); got != want {
			t.Errorf("debVersionToTag(%q) = %q, want %q", in, got, want)
		}
	}
}
