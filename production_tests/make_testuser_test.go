package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
	"fmt"
	"os/exec"

	testhelpers "github.com/overleaf/production_tests/testhelpers"
)

// TestMakeTestUser: create a test user via admin register, set password from mailsink, and login as test user.
func TestMakeTestUser(t *testing.T) {

	client := clientWithResolve()

	// Pre-delete existing test user to ensure password-reset can succeed
	testEmail := TestUserEmail
	{
		cmd := exec.Command("bash", "-lc", fmt.Sprintf("docker exec overleafserver bash -lc 'cd /overleaf/services/web && node ./modules/server-ce-scripts/scripts/delete-user.mjs --skip-email --email=%s'", testEmail))
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Logf("pre-delete-user returned error (may be non-existent): %v out=%s", err, string(out))
		} else {
			t.Logf("pre-delete-user output: %s", string(out))
		}
	}

	// 1. Login as admin
	if _, err := testhelpers.Login(client, AdminEmail, AdminPassword); err != nil {
		t.Fatalf("admin login failed: %v", err)
	}

	// 2. Create test user via admin /admin/register
	testEmail = TestUserEmail
	setURL, err := testhelpers.CreateUserViaAdmin(client, testEmail)
	if err != nil {
		t.Fatalf("admin register failed: %v", err)
	}
	t.Logf("admin/register returned setNewPasswordUrl: %s", setURL)
	if setURL == "" {
		t.Log("admin/register did not return setNewPasswordUrl; will rely on mailsink email")
	}

	// 3. Admin logs out
	resp, err := client.Post("https://overleaf.local/logout", "application/x-www-form-urlencoded", strings.NewReader(""))
	if err != nil {
		t.Fatalf("logout request failed: %v", err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()

	// 4. Prefer the URL returned by the API, otherwise wait for email in mailsink and extract activation link
	mailDir := "/workspace/production/mailsink/mails"
	var activationLink string
	if setURL != "" {
		activationLink = setURL
		t.Logf("using setNewPasswordUrl from API as activation link: %s", activationLink)
	} else {
		for i := 0; i < 120; i++ {
			time.Sleep(1 * time.Second)
			entries, err := os.ReadDir(mailDir)
			if err != nil {
				continue
			}
			var names []string
			for _, e := range entries {
				names = append(names, e.Name())
			}
			// Log only every 5 attempts to avoid noisy logs unless verbose
			if i%5 == 0 {
				t.Logf("mailsink entries (attempt %d): %v", i+1, names)
			}
			for _, e := range entries {
				if e.IsDir() {
					continue
				}
				p := filepath.Join(mailDir, e.Name())
				content, err := os.ReadFile(p)
				if err != nil {
					continue
				}
				if strings.Contains(string(content), testEmail) {
					// try absolute URL first
					re := regexp.MustCompile(`https?://[^\s'"<>]*/user/activate\?[^\s'"<>]+`)
					m := re.FindString(string(content))
					if m != "" {
						activationLink = m
						break
					}
					// fallback: relative path
					re2 := regexp.MustCompile(`/user/activate\?[^\s'"<>]+`)
					m2 := re2.FindString(string(content))
					if m2 != "" {
						activationLink = "https://overleaf.local" + m2
						break
					}
				}
			}
			if activationLink != "" {
				break
			}
		}
	}
	if activationLink == "" {
		t.Fatalf("activation email not found in mailsink directory %s", mailDir)
	}

	// If setURL was returned, check consistency
	if setURL != "" {
		if !strings.Contains(activationLink, setURL[strings.Index(setURL, "/user/activate"):]) {
			t.Logf("warning: activation link from mail does not match setNewPasswordUrl. mail=%s api=%s", activationLink, setURL)
		}
	}

	// 5. Visit activation link to set session flag
	resp, err = client.Get(activationLink)
	if err != nil {
		t.Fatalf("failed to GET activation link: %v", err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()

	// Extract token from query
	u, err := url.Parse(activationLink)
	if err != nil {
		t.Fatalf("failed to parse activation link: %v", err)
	}
	token := u.Query().Get("token")
	if token == "" {
		t.Fatalf("no token found in activation link: %s", activationLink)
	}

	// Need csrf for session
	resp, err = client.Get("https://overleaf.local/dev/csrf")
	if err != nil {
		t.Fatalf("failed to get csrf for password set: %v", err)
	}
	csrfBytes, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	csrf := strings.Map(func(r rune) rune {
		if r < 32 {
			return -1
		}
		return r
	}, string(csrfBytes))
	csrf = strings.TrimSpace(csrf)

	pw := TestUserPassword
	pwBody := map[string]string{"passwordResetToken": token, "password": pw}
	b, _ := json.Marshal(pwBody)
	req, _ := http.NewRequest("POST", "https://overleaf.local/user/password/set", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("x-csrf-token", csrf)

	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("password set request failed: %v", err)
	}
	b, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		t.Fatalf("password set failed: status=%d body=%s", resp.StatusCode, string(b))
	}

	// 6. Login as test user
	if _, err := testhelpers.Login(client, testEmail, pw); err != nil {
		t.Fatalf("test user login failed: %v", err)
	}
}
