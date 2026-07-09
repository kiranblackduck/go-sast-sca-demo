package main

import (
	"database/sql"
	"fmt"
	"log"
)

// Database connection with potential security issues
type Database struct {
	connection *sql.DB
}

// GetUserByID - SQL Injection vulnerability (CWE-89)
func (d *Database) GetUserByID(id string) map[string]string {
	// Direct string concatenation - VULNERABLE to SQL injection
	query := "SELECT id, username, email, role FROM users WHERE id = " + id
	
	row := d.connection.QueryRow(query)
	
	var userID, username, email, role string
	err := row.Scan(&userID, &username, &email, &role)
	if err != nil {
		log.Println("Query error:", err)
		return map[string]string{}
	}

	return map[string]string{
		"id":       userID,
		"username": username,
		"email":    email,
		"role":     role,
	}
}

// GetUserByUsername - SQL Injection vulnerability (CWE-89)
func (d *Database) GetUserByUsername(username string) map[string]string {
	// VULNERABLE - Direct concatenation with user input
	query := "SELECT id, username, email, password_hash FROM users WHERE username = '" + username + "'"
	
	row := d.connection.QueryRow(query)
	
	var id, user, email, passwordHash string
	err := row.Scan(&id, &user, &email, &passwordHash)
	if err != nil {
		return map[string]string{}
	}

	return map[string]string{
		"id":            id,
		"username":      user,
		"email":         email,
		"password_hash": passwordHash,
	}
}

// UpdateUserRole - SQL Injection and insufficient privilege check
func (d *Database) UpdateUserRole(userID string, newRole string) bool {
	// VULNERABLE to SQL injection - both parameters not sanitized
	query := "UPDATE users SET role = '" + newRole + "' WHERE id = " + userID
	
	result, err := d.connection.Exec(query)
	if err != nil {
		log.Println("Update failed:", err)
		return false
	}

	rowsAffected, err := result.RowsAffected()
	return err == nil && rowsAffected > 0
}

// DeleteUser - SQL Injection vulnerability (CWE-89)
func (d *Database) DeleteUser(userID string) bool {
	// VULNERABLE - No input validation, direct concatenation
	query := "DELETE FROM users WHERE id = " + userID
	
	result, err := d.connection.Exec(query)
	if err != nil {
		log.Println("Delete failed:", err)
		return false
	}

	rowsAffected, err := result.RowsAffected()
	return err == nil && rowsAffected > 0
}

// ExecuteRawQuery - Dangerous function for arbitrary SQL execution (CWE-89)
func (d *Database) ExecuteRawQuery(sqlQuery string) []map[string]interface{} {
	// Extremely dangerous - allows arbitrary SQL injection
	// User could pass: "; DROP TABLE users; --" as sqlQuery
	rows, err := d.connection.Query(sqlQuery)
	if err != nil {
		log.Println("Query execution failed:", err)
		return nil
	}
	defer rows.Close()

	var results []map[string]interface{}
	columns, _ := rows.Columns()
	
	for rows.Next() {
		values := make([]interface{}, len(columns))
		valuePtrs := make([]interface{}, len(columns))
		
		for i := range columns {
			valuePtrs[i] = &values[i]
		}
		
		rows.Scan(valuePtrs...)
		
		entry := make(map[string]interface{})
		for i, col := range columns {
			var v interface{}
			val := values[i]
			b, ok := val.([]byte)
			if ok {
				v = string(b)
			} else {
				v = val
			}
			entry[col] = v
		}
		results = append(results, entry)
	}

	return results
}

// CORRECT way - using parameterized queries (for reference)
func (d *Database) GetUserByIDSecure(id string) map[string]string {
	// SECURE - Using parameterized query with placeholders
	query := "SELECT id, username, email, role FROM users WHERE id = ?"
	
	row := d.connection.QueryRow(query, id)
	
	var userID, username, email, role string
	err := row.Scan(&userID, &username, &email, &role)
	if err != nil {
		log.Println("Query error:", err)
		return map[string]string{}
	}

	return map[string]string{
		"id":       userID,
		"username": username,
		"email":    email,
		"role":     role,
	}
}
