package cli

import (
	"reflect"
	"testing"
)

func TestParseNamedPriorities(t *testing.T) {
	for _, tc := range []struct {
		input string
		want  []int
	}{
		{"no-filter,no-log,dnssec", []int{1, 2, 3}},
		{" DNSSEC, no-filter,NO-LOG ", []int{3, 1, 2}},
	} {
		got, err := ParsePriorities(tc.input)
		if err != nil || !reflect.DeepEqual(got, tc.want) {
			t.Fatalf("%q: %v %v", tc.input, got, err)
		}
	}
	for _, input := range []string{"1,2,3", "no-filter,no-filter,dnssec", "dnssec,no-log", "dnssec,no-log,no-filter,extra", "no-filter,no-log,unknown"} {
		if _, err := ParsePriorities(input); err == nil {
			t.Fatalf("accepted %q", input)
		}
	}
}
