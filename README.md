# Go SAST and SCA Demo Project

This is an **educational project** designed to demonstrate common security vulnerabilities that SAST (Static Application Security Testing) and SCA (Software Composition Analysis) tools can detect.

⚠️ **This code is intentionally vulnerable for learning purposes. DO NOT use in production.**

## Project Purpose

This repository contains intentional security vulnerabilities organized into two categories:
- **SAST Issues**: Code-level vulnerabilities detectable through static analysis
- **SCA Issues**: Dependency vulnerabilities from outdated/vulnerable packages

## SAST Vulnerabilities Included

### 1. SQL Injection (CWE-89)
**Files**: `database.go`, `main.go`

Vulnerable code directly concatenates user input into SQL queries:
```go
// VULNERABLE
query := "SELECT * FROM users WHERE id = " + userID
db.QueryRow(query)

// SECURE
query := "SELECT * FROM users WHERE id = ?"
db.QueryRow(query, userID)
```

**Impact**: Attackers can execute arbitrary SQL commands, read/modify data, or delete databases.

---

### 2. Hardcoded Credentials (CWE-798)
**Files**: `auth.go`, `main.go`

Sensitive credentials hardcoded in source code:
```go
// VULNERABLE
const (
    APIKey    = "sk_live_51234567890abcdefg"
    JWTSecret = "my-super-secret-key-hardcoded"
    DBPassword = "root_password_123"
)

// SECURE
apiKey := os.Getenv("API_KEY")
dbPassword := os.Getenv("DB_PASSWORD")
```

**Impact**: Exposed credentials in version control allow unauthorized access to systems.

---

### 3. Weak Cryptography (CWE-327)
**File**: `auth.go`

Using MD5 for password hashing:
```go
// VULNERABLE - MD5 is cryptographically broken
h := md5.New()
io.WriteString(h, password)

// SECURE - Use bcrypt, scrypt, or Argon2
bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
```

**Impact**: Weak hashing allows attackers to quickly crack passwords using rainbow tables.

---

### 4. Command Injection (CWE-78)
**File**: `auth.go`

User input directly concatenated into shell commands:
```go
// VULNERABLE
command := "mysqldump -u admin -p" + password + " db > /tmp/" + filename
exec.Command("sh", "-c", command).Run()

// SECURE
cmd := exec.Command("mysqldump", "-u", "admin", "-p" + password, "db")
cmd.Stdout = outputFile
cmd.Run()
```

**Impact**: Attackers can execute arbitrary system commands with application privileges.

---

### 5. Path Traversal (CWE-22)
**File**: `auth.go`

User input used directly in file paths:
```go
// VULNERABLE
filepath := "/app/config/" + userInput
content := os.ReadFile(filepath)

// SECURE
filepath := filepath.Join("/app/config", filepath.Base(userInput))
// Verify it's within allowed directory
abs, _ := filepath.Abs(filepath)
if !strings.HasPrefix(abs, "/app/config") {
    return errors.New("invalid path")
}
```

**Impact**: Attackers can read/write files outside intended directories (e.g., `/etc/passwd`).

---

## SCA Vulnerabilities Included

### Outdated Dependencies (from `go.mod`)

| Package | Version | Issues |
|---------|---------|--------|
| `golang.org/x/crypto` | v0.0.0-20200622213623-75b288015ac9 | 5+ CVEs, elliptic curve vulnerabilities |
| `gorilla/mux` | v1.7.4 | Outdated, newer versions have security fixes |
| `gorm` | v1.20.0 | Old version, SQL injection risks |
| `go-sql-driver/mysql` | v1.5.1 | Known vulnerabilities |

**Check vulnerabilities**:
```bash
go list -json -m all | nancy sleuth
# or
go list -u -m all
```

---

## Running Security Scans

### SAST Tools

**GoSec** (Go-specific):
```bash
go install github.com/securego/gosec/v2/cmd/gosec@latest
gosec ./...
```

**Semgrep** (Multi-language):
```bash
semgrep --config=p/golang --config=p/security-audit .
```

**GitHub CodeQL** (Built-in with GitHub Advanced Security):
- Automatically scans on push (if enabled)
- Check Security → Code scanning alerts

---

### SCA Tools

**Go Audit**:
```bash
go list -json -m all | nancy sleuth
```

**OWASP Dependency-Check**:
```bash
dependency-check --scan .
```

**Snyk**:
```bash
snyk test
```

**GitHub Dependency Scanning** (Built-in):
- Check Security → Dependabot alerts

---

## Expected Findings

### High Severity Issues
- ❌ SQL Injection in multiple functions
- ❌ Hardcoded database credentials
- ❌ Command injection vulnerability
- ❌ Multiple CVEs in `golang.org/x/crypto`

### Medium Severity Issues
- ⚠️ Path traversal vulnerabilities
- ⚠️ Weak password hashing (MD5)
- ⚠️ Outdated dependencies

---

## Security Improvements

To fix these vulnerabilities:

1. **SQL Injection**: Use prepared statements
   ```go
   stmt, _ := db.Prepare("SELECT * FROM users WHERE id = ?")
   stmt.QueryRow(userID)
   ```

2. **Hardcoded Secrets**: Use environment variables
   ```go
   dbPassword := os.Getenv("DB_PASSWORD")
   ```

3. **Weak Crypto**: Use bcrypt
   ```go
   bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
   ```

4. **Command Injection**: Use exec with separate args
   ```go
   exec.Command("mysqldump", "-u", user, "-p"+pass)
   ```

5. **Path Traversal**: Validate paths
   ```go
   abs, _ := filepath.Abs(filepath.Join(baseDir, filepath.Base(userInput)))
   ```

6. **Dependencies**: Update to latest
   ```bash
   go get -u ./...
   ```

---

## Learning Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE/SANS Top 25](https://cwe.mitre.org/top25/)
- [Go Security Best Practices](https://golang.org/doc/security)
- [CERT Secure Coding Guidelines](https://wiki.sei.cmu.edu/confluence/display/java/SEI+CERT+Secure+Coding+Guidelines)

---

## References

- [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)
- [CWE-798: Hardcoded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [CWE-327: Weak Cryptography](https://cwe.mitre.org/data/definitions/327.html)
- [CWE-78: Command Injection](https://cwe.mitre.org/data/definitions/78.html)
- [CWE-22: Path Traversal](https://cwe.mitre.org/data/definitions/22.html)

---

## Disclaimer

⚠️ **This project is strictly for educational purposes.** It demonstrates vulnerabilities that SHOULD NOT be replicated in production code. Always follow secure coding practices and conduct proper security reviews before deploying any application.
