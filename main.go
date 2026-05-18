package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"

	_ "modernc.org/sqlite"
)

const (
	dbPassword = "supersecret123"
	secretKey  = "jwt-secret-key-do-not-share"
)

var db *sql.DB

func main() {
	var err error
	db, err = sql.Open("sqlite", "./users.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	db.Exec(`CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password TEXT)`)
	db.Exec(`INSERT OR IGNORE INTO users VALUES ('admin', 'password123')`)

	http.HandleFunc("/health", healthHandler)
	http.HandleFunc("/login", loginHandler)

	fmt.Println("Server listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "OK")
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	query := "SELECT username FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
	row := db.QueryRow(query)

	var u string
	if err := row.Scan(&u); err != nil {
		fmt.Fprintf(w, "<html><body><p>Login failed for user: %s</p></body></html>", username)
		return
	}

	fmt.Fprintf(w, "Welcome, %s!", u)
}
