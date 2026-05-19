package main

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

// setupTestDB wires the global db to an in-memory SQLite instance and returns
// a cleanup function. Mirrors the seed logic in main() exactly so tests
// reflect what production does.
func setupTestDB(t *testing.T) func() {
	t.Helper()
	var err error
	db, err = sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password TEXT)`); err != nil {
		t.Fatal(err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`INSERT OR IGNORE INTO users VALUES ('admin', ?)`, string(hash)); err != nil {
		t.Fatal(err)
	}
	return func() { db.Close() }
}

func postLogin(t *testing.T, username, password string) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{"username": {username}, "password": {password}}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	loginHandler(w, req)
	return w
}

// --- Baseline: these should pass before and after fixes ---

func TestLoginSucceedsWithValidCredentials(t *testing.T) {
	defer setupTestDB(t)()
	w := postLogin(t, "admin", "password123")
	if !strings.Contains(w.Body.String(), "Welcome") {
		t.Errorf("expected welcome message for valid credentials, got: %s", w.Body.String())
	}
}

func TestLoginFailsWithWrongPassword(t *testing.T) {
	defer setupTestDB(t)()
	w := postLogin(t, "admin", "notthepassword")
	if strings.Contains(w.Body.String(), "Welcome") {
		t.Errorf("expected login failure for wrong password, got: %s", w.Body.String())
	}
}

// --- Vulnerability: SQL Injection (CWE-89) ---
// Both tests below FAIL on the current code, proving the injection is exploitable.
// They should PASS after parameterized queries are introduced.

func TestLoginRejectsSQLInjectionInUsername(t *testing.T) {
	defer setupTestDB(t)()
	// Closes the username string and short-circuits the WHERE clause to always-true.
	// Resulting query: SELECT ... WHERE username = '' OR '1'='1' --' AND password = '...'
	w := postLogin(t, "' OR '1'='1' --", "anything")
	if strings.Contains(w.Body.String(), "Welcome") {
		t.Errorf("SQL injection via username bypassed authentication; response: %s", w.Body.String())
	}
}

func TestLoginRejectsSQLInjectionInPassword(t *testing.T) {
	defer setupTestDB(t)()
	// Targets the password clause: WHERE ... AND password = '' OR '1'='1' --'
	w := postLogin(t, "admin", "' OR '1'='1' --")
	if strings.Contains(w.Body.String(), "Welcome") {
		t.Errorf("SQL injection via password bypassed authentication; response: %s", w.Body.String())
	}
}

// --- Vulnerability: Reflected XSS (CWE-79) ---
// FAILS on the current code because username is interpolated raw into the HTML response.
// Should PASS once html.EscapeString (or html/template) is used.

func TestLoginFailureEscapesUsernameInResponse(t *testing.T) {
	defer setupTestDB(t)()
	xssPayload := `<script>alert('xss')</script>`
	w := postLogin(t, xssPayload, "wrongpassword")
	if strings.Contains(w.Body.String(), xssPayload) {
		t.Errorf("XSS payload reflected unescaped in response body; got: %s", w.Body.String())
	}
}

// --- Vulnerability: Plaintext Password Storage (CWE-256) ---
// FAILS on the current code because 'password123' is seeded and stored verbatim.
// Should PASS once bcrypt hashing is applied before INSERT.

func TestPasswordsAreNotStoredAsPlaintext(t *testing.T) {
	defer setupTestDB(t)()
	var stored string
	if err := db.QueryRow("SELECT password FROM users WHERE username = 'admin'").Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored == "password123" {
		t.Errorf("password stored as plaintext %q — must be a bcrypt hash", stored)
	}
}

// --- Vulnerability: Missing HTTP Method Enforcement (CWE-650) ---
// FAILS on the current code because GET is accepted and credentials travel in the URL
// (browser history, proxy logs, server access logs).
// Should PASS once the handler enforces POST-only.

func TestLoginRejectsGETRequests(t *testing.T) {
	defer setupTestDB(t)()
	req := httptest.NewRequest(http.MethodGet, "/login?username=admin&password=password123", nil)
	w := httptest.NewRecorder()
	loginHandler(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 Method Not Allowed for GET, got %d", w.Code)
	}
}
