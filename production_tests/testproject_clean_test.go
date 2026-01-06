package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"

	testhelpers "github.com/overleaf/production_tests/testhelpers"
)

// TestProjectClean trashes projects named "Test1" created by the test user and verifies removal from project list.
func TestProjectClean(t *testing.T) {
	client := clientWithResolve()
	testEmail := TestUserEmail
	pw := TestUserPassword

	// Login as test user
	if _, err := testhelpers.Login(client, testEmail, pw); err != nil {
		t.Fatalf("login as test user failed: %v", err)
	}

	// Fetch user's projects
	resp, err := client.Get("https://overleaf.local/user/projects")
	if err != nil {
		t.Fatalf("failed to GET /user/projects: %v", err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("GET /user/projects returned status %d body=%s", resp.StatusCode, string(b))
	}
	var got struct {
		Projects []map[string]interface{} `json:"projects"`
	}
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("failed to decode /user/projects response: %v body=%s", err, string(b))
	}

	// Collect project ids for projects named Test1 (or Test2 optionally)
	var toDelete []string
	for _, p := range got.Projects {
		if name, ok := p["name"].(string); ok && (name == "Test1" || name == "Test2") {
			if id, ok := p["_id"].(string); ok {
				toDelete = append(toDelete, id)
			}
		}
	}

	if len(toDelete) == 0 {
		t.Log("no Test1/Test2 projects found for cleanup")
		return
	}

	// Trash each project
	csrf, err := testhelpers.GetCSRF(client)
	if err != nil {
		t.Fatalf("failed to get csrf for trash: %v", err)
	}
	for _, id := range toDelete {
		url := fmt.Sprintf("https://overleaf.local/project/%s/trash", id)
		req, _ := http.NewRequest("POST", url, bytes.NewReader([]byte("")))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("x-csrf-token", csrf)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("failed to POST %s: %v", url, err)
		}
		io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			b, _ := io.ReadAll(resp.Body)
			t.Fatalf("trash project %s failed: status=%d body=%s", id, resp.StatusCode, string(b))
		}
	}

	// Verify they are gone from project list
	resp, err = client.Get("https://overleaf.local/user/projects")
	if err != nil {
		t.Fatalf("failed to GET /user/projects after trash: %v", err)
	}
	b, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("GET /user/projects returned status %d body=%s", resp.StatusCode, string(b))
	}
	var got2 struct {
		Projects []map[string]interface{} `json:"projects"`
	}
	if err := json.Unmarshal(b, &got2); err != nil {
		t.Fatalf("failed to decode /user/projects response: %v body=%s", err, string(b))
	}
	for _, p := range got2.Projects {
		if name, ok := p["name"].(string); ok && (name == "Test1" || name == "Test2") {
			t.Fatalf("project %s still present after trash: %v", name, p)
		}
	}

	// Success
	t.Logf("trashed projects: %v", toDelete)
}
