// main.go
package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	_ "github.com/lib/pq"
)

// User represents a row from the accounts table.
type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func main() {
	// Connection string
	dsn := fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		os.Getenv("DB_HOST"),
		os.Getenv("DB_PORT"),
		os.Getenv("DB_USER"),
		os.Getenv("DB_PASSWORD"),
		os.Getenv("DB_NAME"),
	)
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		log.Fatalf("error opening database: %v", err)
	}
	// Ensure the connection is usable before proceeding.
	if err = db.Ping(); err != nil {
		log.Fatalf("cannot connect to database: %v", err)
	}

	// /users endpoint – both list and single‑user look‑ups
	http.HandleFunc("/users", func(w http.ResponseWriter, r *http.Request) {
		// Grab the username from the query string (if present).
		username := r.URL.Query().Get("username")

		if username == "" {
			// ---------- Return all users ----------
			rows, err := db.Query("SELECT username, password FROM accounts")
			if err != nil {
				http.Error(w, fmt.Sprintf("query error: %v", err), http.StatusInternalServerError)
				return
			}
			defer rows.Close()

			var users []User
			for rows.Next() {
				var u User
				if err := rows.Scan(&u.Username, &u.Password); err != nil {
					// Skip rows that fail to scan; they are most likely corrupt.
					continue
				}
				users = append(users, u)
			}
			// Check for errors that happened during iteration.
			if err := rows.Err(); err != nil {
				http.Error(w, fmt.Sprintf("row iteration error: %v", err), http.StatusInternalServerError)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(users); err != nil {
				http.Error(w, fmt.Sprintf("encoding error: %v", err), http.StatusInternalServerError)
			}
			return
		}

		var u User
		err := db.QueryRow(
			"SELECT username, password FROM accounts WHERE username = $1", // safe
			username,
		).Scan(&u.Username, &u.Password)

		query1 := fmt.Sprintf(
			"SELECT username, password FROM accounts WHERE username = '%s'",	 // bad
			username,
		)
		query2 := fmt.Sprintf(
			"SELECT username, password FROM accounts WHERE username = %s",		// bad
			username,
		)

		db.QueryRow(query1).Scan(&u.Username, &u.Password)
		db.QueryRow(query2).Scan(&u.Username, &u.Password)

		switch {
		case err == sql.ErrNoRows:
			http.Error(w, "user not found", http.StatusNotFound)
			return
		case err != nil:
			http.Error(w, fmt.Sprintf("query error: %v", err), http.StatusInternalServerError)
			return
		}

		// Return the user as a single‑object JSON response.
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(u); err != nil {
			http.Error(w, fmt.Sprintf("encoding error: %v", err), http.StatusInternalServerError)
		}
	})

	certFile := "certificate.crt"
	keyFile := "private.key"

	fmt.Println("Server starting on :8080…")
	if err := http.ListenAndServeTLS(":8080", certFile, keyFile, nil); err != nil {
		log.Fatal(err)
	}
}
