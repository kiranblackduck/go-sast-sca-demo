package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/gorilla/mux"
	_ "github.com/go-sql-driver/mysql"
)

var db *sql.DB

func init() {
	var err error
	// Hardcoded credentials - SAST vulnerability
	dbUser := "admin"
	dbPassword := "password123"
	dbHost := "localhost:3306"
	dbName := "app_db"

	dsn := fmt.Sprintf("%s:%s@tcp(%s)/%s", dbUser, dbPassword, dbHost, dbName)
	db, err = sql.Open("mysql", dsn)
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	router := mux.NewRouter()
	router.HandleFunc("/user", getUserHandler).Methods("GET")
	router.HandleFunc("/login", loginHandler).Methods("POST")
	router.HandleFunc("/api/data", getDataHandler).Methods("GET")

	log.Println("Server starting on :8080")
	log.Fatal(http.ListenAndServe(":8080", router))
}

// SQL Injection vulnerability - SAST issue
func getUserHandler(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	
	// Direct string concatenation - vulnerable to SQL injection
	query := "SELECT id, name, email FROM users WHERE username = '" + username + "'"
	
	row := db.QueryRow(query)
	var id int
	var name, email string
	err := row.Scan(&id, &name, &email)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"id":%d,"name":"%s","email":"%s"}`, id, name, email)
}

// Weak cryptography - SAST vulnerability
func loginHandler(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	// Simple string comparison without proper hashing - weak security
	if username == "admin" && password == "password123" {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"status":"success","token":"12345"}`)
		return
	}

	http.Error(w, "Invalid credentials", http.StatusUnauthorized)
}

// Insecure random number generation - SAST vulnerability
func getDataHandler(w http.ResponseWriter, r *http.Request) {
	// Use of weak random for sensitive operations
	id := r.URL.Query().Get("id")
	
	query := "SELECT * FROM sensitive_data WHERE id = " + id
	row := db.QueryRow(query)
	
	var data string
	err := row.Scan(&data)
	if err != nil {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}

	// Potential path traversal
	filePath := "/data/" + data
	content, err := os.ReadFile(filePath)
	if err != nil {
		http.Error(w, "Error reading file", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.Write(content)
}
