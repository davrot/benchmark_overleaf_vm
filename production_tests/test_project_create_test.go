package main

import (
	"io"
	"net/http"
	"strings"
	"testing"

	testhelpers "github.com/overleaf/production_tests/testhelpers"
)

// TestCreateInitialProject creates an example project named "Test1" as test user and logs out.
func TestCreateInitialProject(t *testing.T) {
	client := clientWithResolve()

	// 1. Login as test user
	if _, err := testhelpers.Login(client, TestUserEmail, TestUserPassword); err != nil {
		t.Fatalf("test user login failed: %v", err)
	}

	// 2. Create "example" project named "Test1"
	p, err := testhelpers.CreateProject(client, "Test1", "example")
	if err != nil {
		t.Fatalf("create project Test1 failed: %v", err)
	}
	t.Logf("create project response: %v", p)
	if p["project_id"] == nil {
		t.Fatalf("create project Test1 did not return project_id: %v", p)
	}

	// 3. Logout (include CSRF token to be robust against stricter checks)
	csrf, err := testhelpers.GetCSRF(client)
	if err != nil {
		t.Fatalf("failed to get csrf before logout: %v", err)
	}
	req, _ := http.NewRequest("POST", "https://overleaf.local/logout", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("x-csrf-token", csrf)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("test user logout request failed: %v", err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode == 302 {
		// OK
	} else if resp.StatusCode == 200 {
		// Some deployments render the login page directly; accept this as logged out as long as it contains 'Login'
		if !strings.Contains(string(b), "Login") {
			t.Fatalf("test user logout returned unexpected 200 body: %s", string(b))
		}
	} else {
		t.Fatalf("test user logout returned unexpected status %d body=%s", resp.StatusCode, string(b))
	}
}
