package cli

import (
	"fmt"
	"strings"
)

var priorityNames = [4]string{"", "no-filter", "no-log", "dnssec"}

// ParsePriorities parses the names accepted by command-line flags.
func ParsePriorities(raw string) ([]int, error) {
	parts := strings.Split(raw, ",")
	if len(parts) != 3 {
		return nil, fmt.Errorf("priorities must list no-filter,no-log,dnssec once each")
	}
	order := make([]int, 0, 3)
	seen := [4]bool{}
	for _, part := range parts {
		name := strings.ToLower(strings.TrimSpace(part))
		priority := 0
		for i := 1; i < len(priorityNames); i++ {
			if name == priorityNames[i] {
				priority = i
				break
			}
		}
		if priority == 0 || seen[priority] {
			return nil, fmt.Errorf("priorities must list no-filter,no-log,dnssec once each")
		}
		seen[priority] = true
		order = append(order, priority)
	}
	return order, nil
}

func priorityText(order []int) string {
	parts := make([]string, 0, len(order))
	for _, value := range order {
		if value > 0 && value < len(priorityNames) {
			parts = append(parts, priorityNames[value])
		}
	}
	return strings.Join(parts, ",")
}
