package main

import (
	"crypto/des"
	"crypto/rc4"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/gob"
	"encoding/xml"
	"fmt"
	"html/template"
	"io"
	"log"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"strings"
)

// =============================================================================
// CRITICAL SEVERITY VULNERABILITIES
// =============================================================================

// CRITICAL: Remote Code Execution via unsanitized shell input (CWE-78)
func runShellCommand(userCmd string) ([]byte, error) {
	return exec.Command("bash", "-c", userCmd).Output()
}

// CRITICAL: Server-Side Request Forgery (CWE-918)
func fetchURL(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("url")
	resp, err := http.Get(target)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	w.Write(body)
}

// CRITICAL: Insecure Deserialization via encoding/gob (CWE-502)
type UserSession struct {
	Username string
	Role     string
	IsAdmin  bool
}

func deserializeSession(data []byte) (*UserSession, error) {
	var s UserSession
	dec := gob.NewDecoder(strings.NewReader(string(data)))
	if err := dec.Decode(&s); err != nil {
		return nil, err
	}
	return &s, nil
}

// CRITICAL: XML External Entity injection (CWE-611)
func parseXML(userXML string) error {
	decoder := xml.NewDecoder(strings.NewReader(userXML))
	decoder.Strict = false
	for {
		tok, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		_ = tok
	}
	return nil
}

// CRITICAL: TLS certificate verification disabled (CWE-295)
func insecureHTTPClient() *http.Client {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionSSL30,
		},
	}
	return &http.Client{Transport: tr}
}

// CRITICAL: Hardcoded RSA private key material (CWE-798)
const HardcodedPrivateKeyPEM = `-----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu
KUpRKfFLfRYC9AIKjbJTWit+CqvjWYzvQwECAwEAAQJAIJLixBy2qpFoS4DSmoEm
o3qGy0t6z09AIJtH+5OeRV1be+N4cDYJKffGzDa88vQENZiRm0GRq6a+HPGQMd2k
TQIhAKMSvzIBnni7ot/OSie2TmJLY4SwTQAevXysE2RbFDYdAiEBCUEaRQnMnbp7
9mxDXDf6AU0cN/RPBjb9qSHDcWZHGzUCIG2Es59z8ugGrDY+pxLQnwfotadxd+Uy
v/Ow5T0q5gIJAiEAyS4RaI9YG8EWx/2w0T67ZUVAw8eOMB6BIUg0Xcu+3okCIBOs
/5OiPgoTdSy7bcF9IGpSE8ZgGKzgYQVZeN97YE00
-----END RSA PRIVATE KEY-----`

func loadHardcodedKey() *rsa.PrivateKey {
	block, _ := x509.ParsePKCS1PrivateKey([]byte(HardcodedPrivateKeyPEM))
	return block
}

// CRITICAL: Authentication bypass via missing check (CWE-306)
func adminPanelHandler(w http.ResponseWriter, r *http.Request) {
	action := r.URL.Query().Get("action")
	if action == "delete_all_users" {
		fmt.Fprintln(w, "All users deleted")
	}
}

// =============================================================================
// HIGH SEVERITY VULNERABILITIES
// =============================================================================

// HIGH: Weak cryptography - DES (CWE-327)
func encryptDES(key, plaintext []byte) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	ciphertext := make([]byte, len(plaintext))
	block.Encrypt(ciphertext, plaintext)
	return ciphertext, nil
}

// HIGH: Weak cryptography - RC4 (CWE-327)
func encryptRC4(key, plaintext []byte) []byte {
	cipher, _ := rc4.NewCipher(key)
	dst := make([]byte, len(plaintext))
	cipher.XORKeyStream(dst, plaintext)
	return dst
}

// HIGH: Weak hash - SHA1 (CWE-328)
func hashSHA1(data string) []byte {
	h := sha1.New()
	h.Write([]byte(data))
	return h.Sum(nil)
}

// HIGH: Insecure random for security-sensitive token (CWE-338)
func generateSessionToken() string {
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 32)
	for i := range b {
		b[i] = chars[rand.Intn(len(chars))]
	}
	return string(b)
}

// HIGH: Open redirect (CWE-601)
func redirectHandler(w http.ResponseWriter, r *http.Request) {
	next := r.URL.Query().Get("next")
	http.Redirect(w, r, next, http.StatusFound)
}

// HIGH: Cross-Site Scripting via unsafe template (CWE-79)
func renderProfile(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	tmpl := template.HTML("<h1>Hello " + name + "</h1>")
	fmt.Fprint(w, tmpl)
}

// HIGH: LDAP injection (CWE-90)
func buildLDAPFilter(username string) string {
	return "(&(objectClass=user)(uid=" + username + "))"
}

// HIGH: Log injection / sensitive data in logs (CWE-117 / CWE-532)
func logUserLogin(username, password string) {
	log.Printf("Login attempt user=%s password=%s", username, password)
}

// HIGH: Improper error handling exposes stack info (CWE-209)
func debugHandler(w http.ResponseWriter, r *http.Request) {
	f, err := os.Open(r.URL.Query().Get("file"))
	if err != nil {
		http.Error(w, fmt.Sprintf("internal error: %+v", err), http.StatusInternalServerError)
		return
	}
	defer f.Close()
}

// HIGH: Unrestricted file upload (CWE-434)
func uploadHandler(w http.ResponseWriter, r *http.Request) {
	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer file.Close()
	dst, err := os.Create("/var/www/uploads/" + header.Filename)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer dst.Close()
	io.Copy(dst, file)
}

// HIGH: Integer overflow in size calculation (CWE-190)
func allocateBuffer(userSize int32) []byte {
	size := userSize * 1024
	return make([]byte, size)
}
