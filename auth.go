package main

import (
	"crypto/md5"
	"fmt"
	"io"
	"os/exec"
	"strings"
)

// Weak MD5 hashing for passwords - SAST vulnerability (CWE-327)
func hashPasswordMD5(password string) string {
	h := md5.New()
	io.WriteString(h, password)
	return fmt.Sprintf("%x", h.Sum(nil))
}

// Sensitive data exposure - hardcoded secrets - SAST vulnerability (CWE-798)
const (
	APIKey    = "sk_live_51234567890abcdefg"
	JWTSecret = "my-super-secret-key-hardcoded-in-source"
	DBPassword = "root_password_123"
)

// Command injection vulnerability - SAST issue (CWE-78)
func executeBackupCommand(filename string) error {
	command := "mysqldump -u admin -p" + DBPassword + " app_db > /tmp/" + filename
	// This string is vulnerable to command injection if filename contains shell metacharacters
	// e.g., filename = "backup; rm -rf /" would execute dangerous commands
	cmd := exec.Command("sh", "-c", command)
	return cmd.Run()
}

// Path traversal vulnerability - SAST issue (CWE-22)
func readConfigFile(userInput string) (string, error) {
	// Direct use of user input in file path without validation
	filepath := "/app/config/" + userInput
	// Vulnerable to path traversal attacks like "../../../etc/passwd"
	return filepath, nil
}

// Insecure string comparison for authentication - SAST issue
func validateAPIKey(providedKey string) bool {
	// Simple string comparison without timing attack protection
	return providedKey == APIKey
}

// SQL parameterization ignored - SAST vulnerability
func buildUnsafeQuery(userID string) string {
	// Direct concatenation instead of parameterized query
	return "SELECT * FROM users WHERE id = " + userID
}
