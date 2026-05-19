package main

import (
	"database/sql"
	"fmt"
	"html"
	"log"
	"net/http"
	"os"

	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

var (
	db        *sql.DB
	secretKey = os.Getenv("JWT_SECRET_KEY")
)

func main() {
	var err error
	db, err = sql.Open("sqlite", "./users.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	if _, err = db.Exec(`CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password TEXT)`); err != nil {
		log.Fatal(err)
	}

	adminPass := os.Getenv("ADMIN_INITIAL_PASSWORD")
	if adminPass == "" {
		adminPass = "password123"
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(adminPass), bcrypt.DefaultCost)
	if err != nil {
		log.Fatal(err)
	}
	if _, err = db.Exec(`INSERT OR IGNORE INTO users VALUES ('admin', ?)`, string(hash)); err != nil {
		log.Fatal(err)
	}

	http.HandleFunc("/health", healthHandler)
	http.HandleFunc("/login", loginHandler)

	fmt.Println("Server listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "OK")
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	var storedHash string
	err := db.QueryRow("SELECT password FROM users WHERE username = ?", username).Scan(&storedHash)
	if err != nil {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, "<html><body><p>Login failed for user: %s</p></body></html>", html.EscapeString(username))
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(password)); err != nil {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, "<html><body><p>Login failed for user: %s</p></body></html>", html.EscapeString(username))
		return
	}

	fmt.Fprintf(w, "Welcome, %s!", username)
}
