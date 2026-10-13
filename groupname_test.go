package pocketid_test

import (
	"strings"
	"testing"

	"github.com/paisans-software/paisans-stack/internal/pocketid"
)

// Pocket ID binds no character pattern to a group name, only a length, and
// CreateGroup sends the name as the friendly name too, which is held to 2 to
// 50 characters. So a space is fine and a single character is not.
func TestValidGroupName(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		{"members", true},
		{"wiki-editors_2.0", true},
		{"mod team", true},
		{"ab", true},
		{"éé", true}, // two characters, four bytes
		{strings.Repeat("a", 50), true},
		{"", false},
		{"a", false},
		{"é", false},
		{strings.Repeat("a", 51), false},
	}
	for _, tc := range cases {
		if got := pocketid.ValidGroupName(tc.name); got != tc.want {
			t.Errorf("ValidGroupName(%q) = %v, want %v", tc.name, got, tc.want)
		}
	}
}
