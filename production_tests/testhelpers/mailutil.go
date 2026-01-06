package testhelpers

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// WaitForActivationMail polls mailDir until it finds an email containing targetEmail and returns the activation link.
func WaitForActivationMail(mailDir, targetEmail string, timeout time.Duration) (string, error) {
	deadline := time.Now().Add(timeout)
	re := regexp.MustCompile(`https?://[^\s'\"]*/user/activate\?[^\s'"<>]+`)
	re2 := regexp.MustCompile(`/user/activate\?[^\s'"<>]+`)
	for time.Now().Before(deadline) {
		entries, err := os.ReadDir(mailDir)
		if err != nil {
			// if dir does not exist yet, wait
			time.Sleep(1 * time.Second)
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
			s := string(content)
			if !strings.Contains(s, targetEmail) {
				continue
			}
			m := re.FindString(s)
			if m != "" {
				return m, nil
			}
			m2 := re2.FindString(s)
			if m2 != "" {
				return "https://overleaf.local" + m2, nil
			}
		}
		time.Sleep(1 * time.Second)
	}
	return "", fmt.Errorf("activation email for %s not found within %s in %s", targetEmail, timeout, mailDir)
}
