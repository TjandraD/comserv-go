# Security Fix Plan: main.go

## Context

`main.go` contains 6 confirmed security vulnerabilities. We follow a **test-first** approach:

1. Write `main_test.go` with tests that describe secure behavior → they currently **fail**, proving each vulnerability is real
2. User reviews the tests
3. Implement fixes until all tests pass

---

## Vulnerabilities & Tests

### 1. SQL Injection — CWE-89 (Critical)

**Location:** `main.go:45`
**Issue:** Query built by string concatenation; `' OR '1'='1' --` bypasses auth entirely.

**Tests (both must FAIL on current code):**
```
TestLoginRejectsSQLInjectionInUsername
TestLoginRejectsSQLInjectionInPassword
```

**Fix:** Replace concatenation with parameterized query using `?` placeholders.

---

### 2. Plaintext Password Storage — CWE-256 (Critical)

**Location:** `main.go:28` (seed INSERT)
**Issue:** `password123` stored verbatim; a DB leak exposes all credentials immediately.

**Test (must FAIL on current code):**
```
TestPasswordsAreNotStoredAsPlaintext
```

**Fix:** Hash with `bcrypt.GenerateFromPassword` before INSERT; verify with `bcrypt.CompareHashAndPassword` on login.
**New dependency:** `golang.org/x/crypto/bcrypt`

---

### 3. Reflected XSS — CWE-79 (High)

**Location:** `main.go:50`
**Issue:** Raw `username` interpolated into HTML response; `<script>` tags can be injected via the login form.

**Test (must FAIL on current code):**
```
TestLoginFailureEscapesUsernameInResponse
```

**Fix:** Wrap with `html.EscapeString(username)` (import `html`).

---

### 4. Missing HTTP Method Enforcement — CWE-650 (Medium)

**Location:** `main.go:41`
**Issue:** `/login` accepts GET requests; credentials end up in the URL and are captured by browser history, proxy logs, and server access logs.

**Test (must FAIL on current code):**
```
TestLoginRejectsGETRequests
```

**Fix:** Return `http.StatusMethodNotAllowed` if `r.Method != http.MethodPost`.

---

### 5. Hardcoded Secrets — CWE-798 (High)

**Location:** `main.go:13-15`
**Issue:** `secretKey` and unused `dbPassword` are hardcoded constants committed to git history.
**No unit test** — not runtime-testable; addressed by code review + env-var migration.

**Fix:** Replace with `os.Getenv("JWT_SECRET_KEY")`; remove `dbPassword` entirely.

---

### 6. Unchecked DB Errors — CWE-391 (Medium)

**Location:** `main.go:27-28`
**Issue:** Both `db.Exec()` calls silently discard errors; schema creation failures are invisible.
**No unit test** — integration concern; addressed structurally.

**Fix:** Check errors and `log.Fatal` on failure.

---

## Baseline Tests (pass before AND after fixes)

```
TestLoginSucceedsWithValidCredentials
TestLoginFailsWithWrongPassword
```

---

## Files to Create / Modify

| File | Action |
|---|---|
| `main_test.go` | **Create** — 7 tests covering all 4 testable vulnerabilities + 2 baselines |
| `main.go` | **Modify** — apply fixes after tests are reviewed and confirmed failing |
| `go.mod` / `go.sum` | **Modify** — add `golang.org/x/crypto` for bcrypt |

---

## Test File Structure (`main_test.go`)

```
setupTestDB(t)              — in-memory SQLite, mirrors main() seed logic
postLogin(t, user, pass)    — helper: POST to loginHandler via httptest

Baseline:
  TestLoginSucceedsWithValidCredentials
  TestLoginFailsWithWrongPassword

SQL Injection:
  TestLoginRejectsSQLInjectionInUsername     ← FAILS today
  TestLoginRejectsSQLInjectionInPassword     ← FAILS today

XSS:
  TestLoginFailureEscapesUsernameInResponse  ← FAILS today

Plaintext password:
  TestPasswordsAreNotStoredAsPlaintext       ← FAILS today

Method enforcement:
  TestLoginRejectsGETRequests                ← FAILS today
```

---

## Verification

```bash
# Step 1: run tests — expect 5 failures (proving vulnerabilities are real)
go test ./... -v

# Step 2: implement fixes in main.go + add bcrypt dependency
go get golang.org/x/crypto/bcrypt

# Step 3: run tests again — expect all 7 to pass
go test ./... -v
```
