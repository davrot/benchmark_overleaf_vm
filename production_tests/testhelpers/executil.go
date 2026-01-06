package testhelpers

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"time"
)

// RunWithTimeout runs a command with the given timeout and returns combined stdout+stderr.
func RunWithTimeout(timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		return out.String(), fmt.Errorf("command timed out after %s", timeout)
	}
	if err != nil {
		return out.String(), fmt.Errorf("command failed: %w output:\n%s", err, out.String())
	}
	return out.String(), nil
}
