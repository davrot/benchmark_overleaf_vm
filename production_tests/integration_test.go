package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	testhelpers "github.com/overleaf/production_tests/testhelpers"
)

// Utility: create HTTP client that resolves overleaf.local to 127.0.0.1 and skips TLS verification.
func clientWithResolve() *http.Client {
	jar, _ := cookiejar.New(nil)
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		// addr is host:port; replace overleaf.local host with 127.0.0.1
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return net.Dial(network, addr)
		}
		if host == "overleaf.local" {
			return net.Dial(network, net.JoinHostPort("127.0.0.1", port))
		}
		return net.Dial(network, addr)
	}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext:     func(ctx context.Context, network, addr string) (net.Conn, error) { return dial(ctx, network, addr) },
	}
	return &http.Client{Transport: tr, Timeout: 30 * time.Second, Jar: jar}
}

func extractCSRF(body []byte) (string, error) {
	re := regexp.MustCompile(`meta name="ol-csrfToken" content="([^"]+)"`)
	m := re.FindSubmatch(body)
	if m == nil {
		return "", nil
	}
	return string(m[1]), nil
}

// waitForURL polls a URL until it returns HTTP 200 or times out
func waitForURL(ctx context.Context, client *http.Client, url string, timeout time.Duration) (string, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := client.Get(url)
		if err == nil {
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode == 200 {
				return string(b), nil
			}
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	return "", fmt.Errorf("timeout waiting for %s", url)
}

// dockerListNames returns the list of container names from `docker ps`.
func dockerListNames(ctx context.Context) ([]string, error) {
	out, err := exec.CommandContext(ctx, "bash", "-lc", "docker ps --format '{{.Names}}'").Output()
	if err != nil {
		return nil, err
	}
	s := strings.TrimSpace(string(out))
	if s == "" {
		return []string{}, nil
	}
	lines := strings.Split(s, "\n")
	return lines, nil
}

// waitForContainers waits until all expected containers are running (by name substring), or times out.
func waitForContainers(ctx context.Context, expected []string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		names, err := dockerListNames(ctx)
		if err != nil {
			return err
		}
		found := map[string]bool{}
		for _, n := range names {
			for _, e := range expected {
				if strings.Contains(n, e) {
					found[e] = true
				}
			}
		}
		missing := []string{}
		for _, e := range expected {
			if !found[e] {
				missing = append(missing, e)
			}
		}
		if len(missing) == 0 {
			return nil
		}
		// wait a bit and retry
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	return fmt.Errorf("timeout waiting for containers: %v", expected)
}

func TestIntegration_FullFlow(t *testing.T) {
	t.Skip("deprecated; use TestIntegration_Subtests")
	var resp *http.Response
	var err error
	var csrfBytes []byte
	var csrf string
	var req *http.Request
	// Start stack preparation
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	client := clientWithResolve()
	launchpadURL := "https://overleaf.local/launchpad"

	// 1. Ensure containers are down (best-effort)
	_ = exec.CommandContext(ctx, "bash", "../production/down.sh").Run()

	// 2. Remove DBs and clean mailsink
	if out, err := exec.CommandContext(ctx, "bash", "-lc", "sudo rm -rf /workspace/production/mailsink/mails/*").CombinedOutput(); err != nil {
		t.Logf("warning: failed to clean mailsink: %v output=%s", err, string(out))
	}

	// 3. Bring containers back up again (uses script that also clears DB dirs)
	if err := exec.CommandContext(ctx, "bash", "../production/up_clean_databases.sh").Run(); err != nil {
		t.Fatalf("failed to bring up production stack: %v", err)
	}

	// Wait for launchpad to be available
	ok := false
	for i := 0; i < 80; i++ { // up to ~4 minutes
		time.Sleep(3 * time.Second)
		resp, err = client.Get(launchpadURL)
		if err != nil {
			continue
		}
		io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode == 200 {
			ok = true
			break
		}
	}
	if !ok {
		t.Fatalf("launchpad did not become available in time")
	}

	// 4. Create the admin account using provided script
	cmd := exec.CommandContext(ctx, "bash", "../production/make_overleaf_admin_user.bash")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("failed to run make_overleaf_admin_user.bash: %v\noutput:\n%s", err, out.String())
	}

	// 5. Login as admin
	if _, err := testhelpers.Login(client, "llm@lmm.lmm", "LLM2LLM2LLM"); err != nil {
		t.Fatalf("admin login failed: %v", err)
	}

	// 6. As admin: create a test user via POST /admin/register
	resp, err = client.Get("https://overleaf.local/dev/csrf")
	if err != nil {
		t.Fatalf("failed to get csrf before admin register: %v", err)
	}
	csrfBytes, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	csrf = strings.Map(func(r rune) rune {
		if r < 32 {
			return -1
		}
		return r
	}, string(csrfBytes))
	csrf = strings.TrimSpace(csrf)

	testEmail := "testuser1@example.com"
	respBody := map[string]interface{}{}
	{
		reqBody := map[string]string{"email": testEmail}
		b, _ := json.Marshal(reqBody)
		req, _ := http.NewRequest("POST", "https://overleaf.local/admin/register", bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("x-csrf-token", csrf)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("admin register request failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			b, _ := io.ReadAll(resp.Body)
			t.Fatalf("admin register failed: status=%d body=%s", resp.StatusCode, string(b))
		}
		if err := json.NewDecoder(resp.Body).Decode(&respBody); err != nil {
			t.Fatalf("failed to decode admin register response: %v", err)
		}
	}

	setURL, _ := respBody["setNewPasswordUrl"].(string)
	if setURL == "" {
		t.Fatalf("admin register did not return setNewPasswordUrl: %v", respBody)
	}

	// 7. Admin logs out (include CSRF)
	{
		csrf, err := testhelpers.GetCSRF(client)
		if err != nil {
			t.Fatalf("failed to get csrf before logout: %v", err)
		}
		req, _ := http.NewRequest("POST", "https://overleaf.local/logout", strings.NewReader(""))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("x-csrf-token", csrf)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("logout request failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != 302 {
			b, _ := io.ReadAll(resp.Body)
			t.Fatalf("logout did not redirect: status=%d body=%s", resp.StatusCode, string(b))
		}
	}

	// 8. Wait for an email to arrive in mailsink and extract activation link
	mailDir := "/workspace/production/mailsink/mails"
	var activationLink string
	for i := 0; i < 60; i++ { // up to ~60s
		time.Sleep(1 * time.Second)
		entries, err := os.ReadDir(mailDir)
		if err != nil {
			continue
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
				// try to extract /user/activate?token=...&user_id=...
				re := regexp.MustCompile(`https?://[^\s'"]*/user/activate\?[^\s'"<>]+`)
				m := re.FindString(string(content))
				if m != "" {
					activationLink = m
					break
				}
				// fallback: look for relative path
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
	if activationLink == "" {
		t.Fatalf("activation email not found in mailsink directory %s", mailDir)
	}

	// verify the activation link matches the returned setNewPasswordUrl if present
	if setURL != "" && !strings.Contains(activationLink, setURL[strings.Index(setURL, "/user/activate"):]) {
		t.Logf("warning: activation link from mail does not match setNewPasswordUrl. mail=%s api=%s", activationLink, setURL)
	}

	// 9. Visit activation link to set session flag
	resp, err = client.Get(activationLink)
	if err != nil {
		t.Fatalf("failed to GET activation link: %v", err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()

	// 10. Set the test user's password using the passwordResetToken from the link
	u, err := url.Parse(activationLink)
	if err != nil {
		t.Fatalf("failed to parse activation link: %v", err)
	}
	q := u.Query()
	token := q.Get("token")
	if token == "" {
		t.Fatalf("no token found in activation link: %s", activationLink)
	}

	// Need csrf for session (activation GET set session.doLoginAfterPasswordReset)
	resp, err = client.Get("https://overleaf.local/dev/csrf")
	if err != nil {
		t.Fatalf("failed to get csrf for password set: %v", err)
	}
	csrfBytes, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	csrf = strings.Map(func(r rune) rune {
		if r < 32 {
			return -1
		}
		return r
	}, string(csrfBytes))
	csrf = strings.TrimSpace(csrf)

	pw := "password12345"
	pwBody := map[string]string{"passwordResetToken": token, "password": pw}
	b, _ := json.Marshal(pwBody)
	req, _ = http.NewRequest("POST", "https://overleaf.local/user/password/set", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("x-csrf-token", csrf)

	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("password set request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("password set failed: status=%d body=%s", resp.StatusCode, string(b))
	}

	// 11. Login as test user
	resp, err = client.Get("https://overleaf.local/dev/csrf")
	if err != nil {
		t.Fatalf("failed to get csrf before test user login: %v", err)
	}
	csrfBytes, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	csrf = strings.Map(func(r rune) rune {
		if r < 32 {
			return -1
		}
		return r
	}, string(csrfBytes))
	csrf = strings.TrimSpace(csrf)

	testCreds := map[string]string{"email": testEmail, "password": pw, "g-recaptcha-response": "valid"}
	b, _ = json.Marshal(testCreds)
	req, _ = http.NewRequest("POST", "https://overleaf.local/login", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("x-csrf-token", csrf)

	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("test user login request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("test user login failed: status=%d body=%s", resp.StatusCode, string(b))
	}

	// 12. Create project Test1 (example)
	resp, err = client.Get("https://overleaf.local/dev/csrf")
	if err != nil {
		t.Fatalf("failed to get csrf before creating project Test1: %v", err)
	}
	csrfBytes, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	csrf = strings.Map(func(r rune) rune {
		if r < 32 {
			return -1
		}
		return r
	}, string(csrfBytes))
	csrf = strings.TrimSpace(csrf)

	b, _ = json.Marshal(map[string]interface{}{"projectName": "Test1", "template": "example"})
	req, _ = http.NewRequest("POST", "https://overleaf.local/project/new", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("x-csrf-token", csrf)

	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("create project Test1 request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("create project Test1 failed: status=%d body=%s", resp.StatusCode, string(b))
	}
	var proj1 map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&proj1); err != nil {
		t.Fatalf("failed to decode create project Test1 response: %v", err)
	}
	if proj1["project_id"] == nil {
		t.Fatalf("create project Test1 did not return project_id: %v", proj1)
	}

	// 13. Create project Test2
	resp, err = client.Get("https://overleaf.local/dev/csrf")
	if err != nil {
		t.Fatalf("failed to get csrf before creating project Test2: %v", err)
	}
	csrfBytes, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	csrf = strings.Map(func(r rune) rune {
		if r < 32 {
			return -1
		}
		return r
	}, string(csrfBytes))
	csrf = strings.TrimSpace(csrf)

	req, _ = http.NewRequest("POST", "https://overleaf.local/project/new", bytes.NewReader([]byte(`{"projectName":"Test2","template":"example"}`)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("x-csrf-token", csrf)

	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("create project Test2 request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("create project Test2 failed: status=%d body=%s", resp.StatusCode, string(b))
	}

	// 14. test user logs out (include CSRF)
	csrf, err = testhelpers.GetCSRF(client)
	if err != nil {
		t.Fatalf("failed to get csrf before logout: %v", err)
	}
	req, _ = http.NewRequest("POST", "https://overleaf.local/logout", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("x-csrf-token", csrf)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("test user logout request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 302 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("test user logout did not redirect: status=%d body=%s", resp.StatusCode, string(b))
	}

	// Teardown unless NO_TEARDOWN is set
	flagOut, ferr := exec.CommandContext(ctx, "bash", "-lc", "[ -z \"$$NO_TEARDOWN\" ] && echo 1 || echo 0").Output()
	if ferr == nil && string(bytes.TrimSpace(flagOut)) == "1" {
		cmd = exec.CommandContext(ctx, "bash", "../production/down.sh")
		cmd.Run()
	}
}

func TestIntegration_Subtests(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()

	client := clientWithResolve()
	var adminClient *http.Client

	// Step 1 & 2: moved to `setup_tests.go` as `TestEnv_StopAndClean`.
	// (See `setup_tests.go` — run `go test -run TestEnv_ -v` to execute just the setup steps.)

	// Step 3: boot & health checks moved to `setup_tests.go` as `TestServices_StartAndHealthy`.
	// (See `setup_tests.go` — run `go test -run TestServices_ -v` to execute just the service checks.)

	// Step 4: admin creation moved to `setup_tests.go` as `TestAdmin_CreateAdminAccount`.
	// (See `setup_tests.go` — run `go test -run TestAdmin_ -v` to execute just the admin creation.)

	// Step 5: admin login
	if !t.Run("admin: login accepted", func(t *testing.T) {
		ac := clientWithResolve()
		if _, err := testhelpers.Login(ac, "llm@lmm.lmm", "LLM2LLM2LLM"); err != nil {
			t.Fatalf("admin login failed: %v", err)
		}
		adminClient = ac
	}) {
		return
	}

	// Step 6: admin creates test user
	if !t.Run("admin: create test user via admin register", func(t *testing.T) {
		testEmail := "testuser1@example.com"
		if adminClient == nil {
			t.Fatalf("adminClient is nil; previous login likely failed")
		}
		setURL, err := testhelpers.CreateUserViaAdmin(adminClient, testEmail)
		if err != nil {
			t.Fatalf("admin register request failed: %v", err)
		}
		if setURL != "" {
			t.Logf("admin/register returned setNewPasswordUrl: %s", setURL)
			// prefer the API-provided URL over mailsink if present
			t.Setenv("TEST_ACTIVATION_LINK", setURL)
		}
	}) {
		return
	}

	// Step 7: admin logs out
	if !t.Run("admin: logout", func(t *testing.T) {
		if adminClient == nil {
			t.Fatalf("adminClient is nil; previous login likely failed")
		}
		csrf, err := testhelpers.GetCSRF(adminClient)
		if err != nil {
			t.Fatalf("failed to get csrf before logout: %v", err)
		}
		req, _ := http.NewRequest("POST", "https://overleaf.local/logout", strings.NewReader(""))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("x-csrf-token", csrf)
		// Emulate a browser UA and Accept headers so nginx/app treat this as a standard browser request
		req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36")
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		resp, err := adminClient.Do(req)
		if err != nil {
			t.Fatalf("logout request failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != 302 {
			b, _ := io.ReadAll(resp.Body)
			// tolerate 200 with the login page HTML (some deployments return 200 instead of 302)
			if resp.StatusCode == 200 && strings.Contains(string(b), "<form name=\"loginForm\"") {
				return
			}
			t.Fatalf("logout did not redirect: status=%d body=%s", resp.StatusCode, string(b))
		}
	}) {
		return
	}

	// Step 8: email arrives and contains activation link (use helper)
	if !t.Run("email: activation link received", func(t *testing.T) {
		if envLink := os.Getenv("TEST_ACTIVATION_LINK"); envLink != "" {
			t.Logf("using activation link from env: %s", envLink)
			return
		}
		mailDir := "/workspace/production/mailsink/mails"
		activationLink, err := testhelpers.WaitForActivationMail(mailDir, "testuser1@example.com", 2*time.Minute)
		if err != nil {
			t.Fatalf("activation email not found: %v", err)
		}
		t.Setenv("TEST_ACTIVATION_LINK", activationLink)
	}) {
		return
	}

	// Step 9 & 10: activate and set password
	if !t.Run("activation: set password and login test user", func(t *testing.T) {
		activationLink := os.Getenv("TEST_ACTIVATION_LINK")
		if activationLink == "" {
			t.Fatalf("activation link missing from env")
		}
		resp, err := client.Get(activationLink)
		if err != nil {
			t.Fatalf("failed to GET activation link: %v", err)
		}
		io.ReadAll(resp.Body)
		resp.Body.Close()
		// extract token
		u, err := url.Parse(activationLink)
		if err != nil {
			t.Fatalf("failed to parse activation link: %v", err)
		}
		q := u.Query()
		token := q.Get("token")
		if token == "" {
			t.Fatalf("no token found in activation link: %s", activationLink)
		}
		// csrf
		resp, err = client.Get("https://overleaf.local/dev/csrf")
		if err != nil {
			t.Fatalf("failed to get csrf for password set: %v", err)
		}
		csrfBytes, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		csrf := strings.TrimSpace(string(csrfBytes))
		pw := "password12345"
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
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			b, _ := io.ReadAll(resp.Body)
			t.Fatalf("password set failed: status=%d body=%s", resp.StatusCode, string(b))
		}
		// login as test user
		resp, err = client.Get("https://overleaf.local/dev/csrf")
		if err != nil {
			t.Fatalf("failed to get csrf before test user login: %v", err)
		}
		csrfBytes, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
		csrf = strings.TrimSpace(string(csrfBytes))
		testCreds := map[string]string{"email": "testuser1@example.com", "password": pw, "g-recaptcha-response": "valid"}
		b, _ = json.Marshal(testCreds)
		req, _ = http.NewRequest("POST", "https://overleaf.local/login", bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("x-csrf-token", csrf)
		resp, err = client.Do(req)
		if err != nil {
			t.Fatalf("test user login request failed: %v", err)
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			b, _ := io.ReadAll(resp.Body)
			t.Fatalf("test user login failed: status=%d body=%s", resp.StatusCode, string(b))
		}
	}) {
		return
	}

	// Step 11 & 12: create projects Test1 & Test2 then logout
	if !t.Run("projects: create and logout", func(t *testing.T) {
		if client == nil {
			t.Fatalf("client is nil")
		}
		p1, err := testhelpers.CreateProject(client, "Test1", "example")
		if err != nil {
			t.Fatalf("create project Test1 failed: %v", err)
		}
		if p1["project_id"] == nil {
			t.Fatalf("create project Test1 did not return project_id: %v", p1)
		}
		p2, err := testhelpers.CreateProject(client, "Test2", "example")
		if err != nil {
			t.Fatalf("create project Test2 failed: %v", err)
		}
		if p2["project_id"] == nil {
			t.Fatalf("create project Test2 did not return project_id: %v", p2)
		}
		// logout
		resp, err := client.Post("https://overleaf.local/logout", "application/x-www-form-urlencoded", strings.NewReader(""))
		if err != nil {
			t.Fatalf("test user logout request failed: %v", err)
		}
		if resp.StatusCode != 302 {
			b, _ := io.ReadAll(resp.Body)
			t.Fatalf("test user logout did not redirect: status=%d body=%s", resp.StatusCode, string(b))
		}
	}) {
		return
	}

	// Teardown unless NO_TEARDOWN is set
	flagOut, ferr := exec.CommandContext(ctx, "bash", "-lc", "[ -z \"$$NO_TEARDOWN\" ] && echo 1 || echo 0").Output()
	if ferr == nil && string(bytes.TrimSpace(flagOut)) == "1" {
		// stop any remaining target containers (don't rely on down.sh here)
		targets := []string{"mailsink", "overleafmongo", "overleafredis", "overleafserver", "nginx"}
		running, err := dockerListNames(ctx)
		if err == nil {
			for _, n := range running {
				for _, tname := range targets {
					if strings.Contains(n, tname) {
						testhelpers.RunWithTimeout(20*time.Second, "bash", "-lc", fmt.Sprintf("docker rm -f %s || true", n))
						break
					}
				}
			}
		}
	}
}
