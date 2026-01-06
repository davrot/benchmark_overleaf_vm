package testhelpers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"os"
	"strings"
	"time"
)

var debugEnabled = os.Getenv("TESTHELPERS_DEBUG") == "1"

const browserUA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36"

// GetCSRF fetches /dev/csrf from the canonical site (https://overleaf.local) and returns the token string.
func GetCSRF(client *http.Client) (string, error) {
	return GetCSRFAt(client, "https://overleaf.local/dev/csrf")
}

// GetCSRFAt fetches /dev/csrf at a specific URL (useful for direct-server HTTP endpoint) and returns the token string.
func GetCSRFAt(client *http.Client, urlStr string) (string, error) {
	req, _ := http.NewRequest("GET", urlStr, nil)
	req.Header.Set("User-Agent", browserUA)
	req.Header.Set("Accept", "text/plain, */*")
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("GET %s failed: %w", urlStr, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("GET %s returned status %d body=%s", urlStr, resp.StatusCode, string(b))
	}
	b, _ := io.ReadAll(resp.Body)
	bStr := string(b)
	// If the endpoint returned HTML (eg. a redirect to /login), try to extract the CSRF token from the page
	trim := strings.TrimSpace(bStr)
	if strings.HasPrefix(trim, "<") {
		// Try meta tag: <meta name="ol-csrfToken" content="...">
		if idx := strings.Index(bStr, `meta name="ol-csrfToken" content="`); idx != -1 {
			start := idx + len(`meta name="ol-csrfToken" content="`)
			rest := bStr[start:]
			if end := strings.Index(rest, `"`); end != -1 {
				return rest[:end], nil
			}
		}
		// Try hidden input: <input name="_csrf" type="hidden" value="...">
		if idx := strings.Index(bStr, `name="_csrf" type="hidden" value="`); idx != -1 {
			start := idx + len(`name="_csrf" type="hidden" value="`)
			rest := bStr[start:]
			if end := strings.Index(rest, `"`); end != -1 {
				return rest[:end], nil
			}
		}
		return "", fmt.Errorf("GET %s returned HTML instead of token; body starts with HTML", urlStr)
	}
	return bStr, nil
}

// PostJSON performs a JSON POST with optional x-csrf-token header and returns response body as bytes.
func PostJSON(client *http.Client, url string, body interface{}, csrf string) ([]byte, int, error) {
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", url, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", browserUA)
	if csrf != "" {
		csrf = strings.TrimSpace(csrf)
		csrf = strings.ReplaceAll(csrf, "\n", "")
		csrf = strings.ReplaceAll(csrf, "\r", "")
		// Remove control characters that would make the header invalid
		csrf = strings.Map(func(r rune) rune {
			if r < 32 {
				return -1
			}
			return r
		}, csrf)
		req.Header.Set("x-csrf-token", csrf)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("POST %s failed: %w", url, err)
	}
	defer resp.Body.Close()
	bodyBytes, _ := io.ReadAll(resp.Body)
	return bodyBytes, resp.StatusCode, nil
}

// Login posts credentials and returns decoded JSON map.
func Login(client *http.Client, email, password string) (map[string]interface{}, error) {
	// retry logic to handle transient nginx 400 header/cookie-too-large errors
	var lastErr error
	nginxRestarted := false
	for attempt := 0; attempt < 5; attempt++ {
		// Perform a simple GET /login first to ensure the server sets a small session cookie
		_ = func() error {
			resp, err := client.Get("https://overleaf.local/login")
			if err != nil {
				return err
			}
			io.ReadAll(resp.Body)
			resp.Body.Close()
			return nil
		}()
		csrf, err := GetCSRF(client)
		if err != nil {
			lastErr = err
			time.Sleep(time.Duration(attempt+1) * time.Second)
			continue
		}
		creds := map[string]string{"email": email, "password": password, "g-recaptcha-response": "valid"}
		// Construct login request manually so we can inspect headers in failures
		payloadBytes, _ := json.Marshal(creds)
		req, _ := http.NewRequest("POST", "https://overleaf.local/login", bytes.NewReader(payloadBytes))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", browserUA)
		if csrf != "" {
			csrfClean := strings.TrimSpace(csrf)
			csrfClean = strings.ReplaceAll(csrfClean, "\n", "")
			csrfClean = strings.ReplaceAll(csrfClean, "\r", "")
			csrfClean = strings.Map(func(r rune) rune {
				if r < 32 {
					return -1
				}
				return r
			}, csrfClean)
			req.Header.Set("x-csrf-token", csrfClean)
		}
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			time.Sleep(time.Duration(attempt+1) * time.Second)
			continue
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		status := resp.StatusCode
		if status == 400 && strings.Contains(string(b), "Request Header Or Cookie Too Large") {
			// emit request headers for debugging (enabled via TESTHELPERS_DEBUG=1)
			if debugEnabled {
				log.Printf("LOGIN-DEBUG-HEADERS: %v", req.Header)
			}
		}
		if status == 400 && strings.Contains(string(b), "Request Header Or Cookie Too Large") {
			// Reset cookie jar and perform a minimal, browser-like GET to establish a clean session
			if jar, _ := cookiejar.New(nil); jar != nil {
				client.Jar = jar
			}
			// perform a simple GET to clear server side expectations or set small cookies
			_ = func() error {
				resp, err := client.Get("https://overleaf.local/login")
				if err != nil {
					return err
				}
				io.ReadAll(resp.Body)
				resp.Body.Close()
				return nil
			}()
			// Collect diagnostics to help debug persistent nginx 400 errors
			diagParts := []string{}
			if out, err := RunWithTimeout(5*time.Second, "bash", "-lc", "docker ps -a --filter name=nginx --format '{{.ID}} {{.Names}} {{.Status}} {{.Ports}}'"); err == nil {
				diagParts = append(diagParts, "docker ps nginx: "+strings.TrimSpace(out))
			} else {
				diagParts = append(diagParts, "docker ps nginx failed: "+err.Error())
			}
			if out, err := RunWithTimeout(5*time.Second, "bash", "-lc", "docker inspect nginx"); err == nil {
				diagParts = append(diagParts, "docker inspect nginx: "+strings.TrimSpace(out))
			} else {
				diagParts = append(diagParts, "docker inspect nginx failed: "+err.Error())
			}
			if out, err := RunWithTimeout(5*time.Second, "bash", "-lc", "docker logs nginx --tail 200"); err == nil {
				diagParts = append(diagParts, "docker logs nginx: "+strings.TrimSpace(out))
			} else {
				diagParts = append(diagParts, "docker logs nginx failed: "+err.Error())
			}
			if out, err := RunWithTimeout(5*time.Second, "bash", "-lc", "docker ps -a --filter name=overleafserver --format '{{.ID}} {{.Names}} {{.Status}} {{.Ports}}'"); err == nil {
				diagParts = append(diagParts, "docker ps overleafserver: "+strings.TrimSpace(out))
			}
			if out, err := RunWithTimeout(5*time.Second, "bash", "-lc", "docker inspect overleafserver"); err == nil {
				diagParts = append(diagParts, "docker inspect overleafserver: "+strings.TrimSpace(out))
			}
			if out, err := RunWithTimeout(5*time.Second, "bash", "-lc", "docker exec nginx ss -ltnp 2>/dev/null || true"); err == nil {
				diagParts = append(diagParts, "nginx ss: "+strings.TrimSpace(out))
			}
			lastErr = fmt.Errorf("login returned 400 Request Header Or Cookie Too Large: %s\nDIAG:\n%s", string(b), strings.Join(diagParts, "\n\n"))
			// Removed bypass/curl fallbacks; retry via nginx only (diagnostics above will help if this persists).			time.Sleep(3 * time.Second)
			// Try restarting nginx once as a last resort to clear header/cookie issues.
			if !nginxRestarted {
				if out, err := RunWithTimeout(20*time.Second, "bash", "-lc", "docker restart nginx"); err == nil {
					nginxRestarted = true
					// Give nginx a moment to restart
					time.Sleep(5 * time.Second)
					continue // retry the login loop
				} else {
					lastErr = fmt.Errorf("nginx restart failed: %v output=%s; lastErr=%v", err, out, lastErr)
				}
			}
			continue
		}
		if status < 200 || status >= 300 {
			return nil, fmt.Errorf("login returned status %d: %s", status, string(b))
		}
		var got map[string]interface{}
		if err := json.Unmarshal(b, &got); err != nil {
			return nil, fmt.Errorf("failed to decode login response: %w body=%s", err, string(b))
		}
		return got, nil
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("login failed after retries")
}

// CreateProject creates a project and returns the decoded response.
func CreateProject(client *http.Client, projectName, template string) (map[string]interface{}, error) {
	csrf, err := GetCSRF(client)
	if err != nil {
		return nil, err
	}
	payload := map[string]interface{}{"projectName": projectName, "template": template}
	b, status, err := PostJSON(client, "https://overleaf.local/project/new", payload, csrf)
	if err != nil {
		return nil, err
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("create project returned status %d: %s", status, string(b))
	}
	var got map[string]interface{}
	if err := json.Unmarshal(b, &got); err != nil {
		return nil, fmt.Errorf("failed to decode create project response: %w body=%s", err, string(b))
	}
	return got, nil
}

// CreateUserViaAdmin registers an email via /admin/register and returns the setNewPasswordUrl.
func CreateUserViaAdmin(client *http.Client, email string) (string, error) {
	csrf, err := GetCSRF(client)
	if err != nil {
		return "", err
	}
	payload := map[string]string{"email": email}
	b, status, err := PostJSON(client, "https://overleaf.local/admin/register", payload, csrf)
	if err != nil {
		return "", err
	}
	if status < 200 || status >= 300 {
		return "", fmt.Errorf("admin/register returned status %d: %s", status, string(b))
	}
	var got map[string]interface{}
	if err := json.Unmarshal(b, &got); err != nil {
		return "", fmt.Errorf("failed to decode admin register response: %w body=%s", err, string(b))
	}
	if u, ok := got["setNewPasswordUrl"].(string); ok {
		return u, nil
	}
	return "", fmt.Errorf("setNewPasswordUrl not present in response: %v", got)
}
