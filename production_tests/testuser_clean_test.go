package main

import (
	"testing"
	"time"

	testhelpers "github.com/overleaf/production_tests/testhelpers"
)

// TestTestUserClean deletes the test user by email using server script and verifies login fails.
func TestTestUserClean(t *testing.T) {
	client := clientWithResolve()
	testEmail := TestUserEmail
	pw := TestUserPassword

	// Run delete-user script inside overleafserver container (skip email to avoid notifications)
	if out, err := testhelpers.RunWithTimeout(60*time.Second, "bash", "-lc", "docker exec overleafserver bash -lc \"cd /overleaf/services/web && node ./modules/server-ce-scripts/scripts/delete-user.mjs --skip-email --email='"+testEmail+"'\""); err != nil {
		t.Fatalf("delete-user script failed: %v output=%s", err, out)
	} else {
		t.Logf("delete-user output: %s", out)
	}

	// After deletion, login as test user should fail
	if _, err := testhelpers.Login(client, testEmail, pw); err == nil {
		t.Fatalf("expected login to fail for deleted user %s but it succeeded", testEmail)
	} else {
		t.Logf("login correctly failed for deleted user: %v", err)
	}
}
