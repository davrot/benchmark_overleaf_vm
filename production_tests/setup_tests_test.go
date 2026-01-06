package main

import (
	"bytes"
	"context"
	"io"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"

	testhelpers "github.com/overleaf/production_tests/testhelpers"
)

// TestEnv_StopAndClean ensures no relevant containers are running and cleans DB/mail dirs.
func TestEnv_StopAndClean(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Targets we care about for shutdown
	targets := []string{"mailsink", "overleafmongo", "overleafredis", "overleafserver", "nginx"}

	// Use `docker ps` to determine which relevant containers are running, stop them, and verify none remain.
	var out string
	var err error
	out, err = testhelpers.RunWithTimeout(10*time.Second, "bash", "-lc", "docker ps --format '{{.Names}}'")
	if err != nil {
		t.Logf("warning: docker ps failed: %v output=%s", err, out)
	} else {
		t.Logf("docker ps output: %q", out)
	}

	// Parse names and select targets
	var initial []string
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if s := strings.TrimSpace(line); s != "" {
			for _, tname := range targets {
				if strings.Contains(s, tname) {
					initial = append(initial, s)
					break
				}
			}
		}
	}

	if len(initial) > 0 {
		t.Logf("containers found running: %v", initial)
		for _, c := range initial {
			if out, err := testhelpers.RunWithTimeout(20*time.Second, "bash", "-lc", "docker stop "+c+" || true"); err != nil {
				t.Logf("docker stop %s returned error: %v output=%s", c, err, out)
			}
		}

		// Wait up to 60s for containers to disappear
		deadline := time.Now().Add(60 * time.Second)
		for time.Now().Before(deadline) {
			out2, _ := testhelpers.RunWithTimeout(5*time.Second, "bash", "-lc", "docker ps --format '{{.Names}}'")
			var remaining []string
			for _, line := range strings.Split(strings.TrimSpace(out2), "\n") {
				if s := strings.TrimSpace(line); s != "" {
					for _, tname := range targets {
						if strings.Contains(s, tname) {
							remaining = append(remaining, s)
							break
						}
					}
				}
			}
			if len(remaining) == 0 {
				break
			}
			t.Logf("still running after stop: %v", remaining)
			time.Sleep(2 * time.Second)
		}

		// Final verification
		out3, _ := testhelpers.RunWithTimeout(5*time.Second, "bash", "-lc", "docker ps --format '{{.Names}}'")
		var remaining []string
		for _, line := range strings.Split(strings.TrimSpace(out3), "\n") {
			if s := strings.TrimSpace(line); s != "" {
				for _, tname := range targets {
					if strings.Contains(s, tname) {
						remaining = append(remaining, s)
						break
					}
				}
			}
		}
		if len(remaining) > 0 {
			t.Fatalf("containers did not stop: %v", remaining)
		}
	} else {
		t.Log("no target containers running")
	}

	// Try to find containers created by this compose project first
	var found []string
	if out, err := testhelpers.RunWithTimeout(10*time.Second, "bash", "-lc", "docker ps --filter label=com.docker.compose.project=production --format '{{.Names}}'"); err == nil {
		// Log raw output for diagnostics
		t.Logf("label-based docker ps output: %q", out)
		for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
			if s := strings.TrimSpace(line); s != "" {
				found = append(found, s)
			}
		}
	} else {
		t.Logf("warning: listing production-labeled containers failed: %v output=%s", err, out)
	}

	// Fallback: check by name substrings if nothing found by label
	if len(found) == 0 {
		running, err := dockerListNames(ctx)
		if err != nil {
			t.Fatalf("failed to check running containers: %v", err)
		}
		for _, n := range running {
			for _, tname := range targets {
				if strings.Contains(n, tname) {
					found = append(found, n)
					break
				}
			}
		}
	}

	if len(found) > 0 {
		t.Logf("containers targeted for shutdown: %v", found)
		// attempt a graceful stop first
		for _, c := range found {
			if out, err := testhelpers.RunWithTimeout(20*time.Second, "bash", "-lc", "docker stop "+c+" || true"); err != nil {
				t.Logf("docker stop %s returned error: %v output=%s", c, err, out)
			}
		}

		// Force-remove with retries until none remain
		deadline := time.Now().Add(60 * time.Second)
		for time.Now().Before(deadline) {
			// re-evaluate remaining
			stillOut, _ := testhelpers.RunWithTimeout(10*time.Second, "bash", "-lc", "docker ps --filter label=com.docker.compose.project=production --format '{{.Names}}'")
			var remaining []string
			for _, line := range strings.Split(strings.TrimSpace(stillOut), "\n") {
				if s := strings.TrimSpace(line); s != "" {
					remaining = append(remaining, s)
				}
			}
			// Fallback name-substring matching if labels not present
			if len(remaining) == 0 {
				all, _ := dockerListNames(ctx)
				for _, n := range all {
					for _, tname := range targets {
						if strings.Contains(n, tname) {
							remaining = append(remaining, n)
						}
					}
				}
			}
			// If none remain, we're done
			if len(remaining) == 0 {
				break
			}
			// Try a removal pass
			for _, c := range remaining {
				if out, err := testhelpers.RunWithTimeout(20*time.Second, "bash", "-lc", "docker rm -f "+c+" || true"); err != nil {
					t.Logf("failed to force remove container %s: %v output=%s", c, err, out)
				}
			}
			t.Logf("still running: %v", remaining)
			time.Sleep(3 * time.Second)
		}

		// final verification
		stillOut, _ := testhelpers.RunWithTimeout(10*time.Second, "bash", "-lc", "docker ps --filter label=com.docker.compose.project=production --format '{{.Names}}'")
		var remaining []string
		for _, line := range strings.Split(strings.TrimSpace(stillOut), "\n") {
			if s := strings.TrimSpace(line); s != "" {
				remaining = append(remaining, s)
			}
		}
		if len(remaining) > 0 {
			t.Fatalf("containers did not stop after attempts: %v", remaining)
		}
	} else {
		t.Log("no target containers running")
	}

	// Clean expected directories if they exist
	paths := []string{"/workspace/production/overleafmongo/data_db", "/workspace/production/overleafmongo/data_configdb", "/workspace/production/overleafredis/data", "/workspace/production/mailsink/mails", "/workspace/production/overleafserver/data"}
	for _, p := range paths {
		if _, err := exec.CommandContext(ctx, "bash", "-lc", "stat "+p).Output(); err != nil {
			t.Logf("path %s missing, skipping", p)
			continue
		}
		if out, err := exec.CommandContext(ctx, "bash", "-lc", "sudo find "+p+" -mindepth 1 -maxdepth 1 -exec rm -rf '{}' +").CombinedOutput(); err != nil {
			t.Fatalf("failed to clean %s: %v output=%s", p, err, string(out))
		}
		// verify empty
		entries, err := exec.CommandContext(ctx, "bash", "-lc", "ls -A "+p).Output()
		if err != nil {
			t.Fatalf("failed to read dir %s: %v", p, err)
		}
		if len(bytes.TrimSpace(entries)) != 0 {
			t.Fatalf("directory %s is not empty after cleanup: %s", p, string(entries))
		}
		t.Logf("cleaned and verified empty: %s", p)
	}
}

// TestServices_StartAndHealthy brings the stack up and verifies launchpad and login form are available.
func TestServices_StartAndHealthy(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	client := clientWithResolve()

	out, err := testhelpers.RunWithTimeout(3*time.Minute, "bash", "../production/up_clean_databases.sh")
	if err != nil {
		t.Fatalf("failed to bring up production stack: %v\noutput:\n%s", err, out)
	}

	// wait for launchpad
	if _, err := waitForURL(ctx, client, "https://overleaf.local/launchpad", 120*time.Second); err != nil {
		t.Fatalf("launchpad did not become available: %v", err)
	}
	// check page content
	resp, err := client.Get("https://overleaf.local/launchpad")
	if err != nil {
		t.Fatalf("failed to GET launchpad: %v", err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !regexp.MustCompile("Create the first Admin account").Match(b) {
		t.Fatalf("launchpad page did not show admin form")
	}
	// login form should be available too
	resp, err = client.Get("https://overleaf.local/login")
	if err != nil {
		t.Fatalf("failed to GET login page: %v", err)
	}
	b, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if !regexp.MustCompile("Login").Match(b) {
		t.Fatalf("login page missing expected content")
	}
}

// TestAdmin_CreateAdminAccount runs the provided script to create the first admin account.
func TestAdmin_CreateAdminAccount(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, "bash", "../production/make_overleaf_admin_user.bash")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("failed to run make_overleaf_admin_user.bash: %v\noutput:\n%s", err, out.String())
	}
	// Basic verification: ensure /login is reachable and contains "Login"
	client := clientWithResolve()
	resp, err := client.Get("https://overleaf.local/login")
	if err != nil {
		t.Fatalf("GET /login failed: %v", err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !regexp.MustCompile("Login").Match(b) {
		t.Fatalf("login page did not show expected content after admin creation")
	}
}
