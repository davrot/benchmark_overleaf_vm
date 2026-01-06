package testhelpers

import (
	"fmt"
	"strings"
	"time"
)

// ListRunningContainers returns containers whose names contain any of the targets.
func ListRunningContainers(targets []string) ([]string, error) {
	out, err := RunWithTimeout(5*time.Second, "bash", "-lc", "docker ps --format '{{.Names}}'")
	if err != nil {
		return nil, fmt.Errorf("docker ps failed: %w", err)
	}
	out = strings.TrimSpace(out)
	if out == "" {
		return nil, nil
	}
	lines := strings.Split(out, "\n")
	var found []string
	for _, l := range lines {
		for _, t := range targets {
			if strings.Contains(l, t) {
				found = append(found, l)
				break
			}
		}
	}
	return found, nil
}

// ForceRemoveContainers attempts docker rm -f on each container name.
func ForceRemoveContainers(names []string) {
	for _, c := range names {
		RunWithTimeout(10*time.Second, "bash", "-lc", fmt.Sprintf("docker rm -f %s || true", c))
	}
}
