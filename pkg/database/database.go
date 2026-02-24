// Package database provides embedded SQLite storage for user management and authentication.
// Uses modernc.org/sqlite — pure Go, no CGO required — maintaining the "Zero Install" single-binary requirement.

package database

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log"
	"sync"
	"time"

	_ "modernc.org/sqlite"
	"golang.org/x/crypto/bcrypt"
)

// UserRole defines the role-based access control levels.
type UserRole string

const (
	RoleAdmin   UserRole = "admin"
	RoleAnalyst UserRole = "analyst"
	RoleViewer  UserRole = "viewer"
)

// User represents a user record in the database.
type User struct {
	ID           int64    `json:"id"`
	Username     string   `json:"username"`
	PasswordHash string   `json:"-"`
	Role         UserRole `json:"role"`
	CreatedAt    string   `json:"created_at"`
	UpdatedAt    string   `json:"updated_at"`
	LastLogin    *string  `json:"last_login,omitempty"`
	IsActive     bool     `json:"is_active"`
}

// DB wraps the SQLite connection with user management methods.
type DB struct {
	conn *sql.DB
	mu   sync.RWMutex
}

// Open initializes the SQLite database at the given path, creates tables, and seeds defaults.
func Open(dbPath string) (*DB, error) {
	conn, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// SQLite performance pragmas
	pragmas := []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA synchronous=NORMAL",
		"PRAGMA busy_timeout=5000",
		"PRAGMA foreign_keys=ON",
	}
	for _, p := range pragmas {
		if _, err := conn.Exec(p); err != nil {
			conn.Close()
			return nil, fmt.Errorf("failed to set pragma %q: %w", p, err)
		}
	}

	db := &DB{conn: conn}

	if err := db.migrate(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("migration failed: %w", err)
	}

	if err := db.seedDefaultAdmin(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("seeding failed: %w", err)
	}

	return db, nil
}

// Close closes the database connection.
func (db *DB) Close() error {
	return db.conn.Close()
}

// migrate creates the schema if it doesn't exist.
func (db *DB) migrate() error {
	schema := `
	CREATE TABLE IF NOT EXISTS users (
		id          INTEGER PRIMARY KEY AUTOINCREMENT,
		username    TEXT    NOT NULL UNIQUE,
		password_hash TEXT NOT NULL,
		role        TEXT    NOT NULL DEFAULT 'viewer',
		created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
		updated_at  TEXT    NOT NULL DEFAULT (datetime('now')),
		last_login  TEXT,
		is_active   INTEGER NOT NULL DEFAULT 1
	);

	CREATE TABLE IF NOT EXISTS sessions (
		id         TEXT PRIMARY KEY,
		user_id    INTEGER NOT NULL,
		created_at TEXT    NOT NULL DEFAULT (datetime('now')),
		expires_at TEXT    NOT NULL,
		revoked    INTEGER NOT NULL DEFAULT 0,
		FOREIGN KEY (user_id) REFERENCES users(id)
	);

	CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
	CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
	`
	_, err := db.conn.Exec(schema)
	return err
}

// seedDefaultAdmin creates the default admin user if the users table is empty.
func (db *DB) seedDefaultAdmin() error {
	var count int
	if err := db.conn.QueryRow("SELECT COUNT(*) FROM users").Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return nil
	}

	hash, err := bcrypt.GenerateFromPassword([]byte("admin"), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash default password: %w", err)
	}

	_, err = db.conn.Exec(
		"INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
		"admin", string(hash), string(RoleAdmin),
	)
	if err != nil {
		return fmt.Errorf("failed to insert default admin: %w", err)
	}

	log.Println("╔══════════════════════════════════════════════════════════════╗")
	log.Println("║  ⚠  WARNING: Default admin user created.                    ║")
	log.Println("║  Username: admin  |  Password: admin                        ║")
	log.Println("║  PLEASE CHANGE THE PASSWORD IMMEDIATELY.                    ║")
	log.Println("╚══════════════════════════════════════════════════════════════╝")

	return nil
}

// Authenticate validates credentials and returns the user if valid.
func (db *DB) Authenticate(username, password string) (*User, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	user := &User{}
	err := db.conn.QueryRow(
		"SELECT id, username, password_hash, role, created_at, updated_at, last_login, is_active FROM users WHERE username = ?",
		username,
	).Scan(&user.ID, &user.Username, &user.PasswordHash, &user.Role, &user.CreatedAt, &user.UpdatedAt, &user.LastLogin, &user.IsActive)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("invalid credentials")
	}
	if err != nil {
		return nil, fmt.Errorf("database error: %w", err)
	}

	if !user.IsActive {
		return nil, fmt.Errorf("account is disabled")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}

	// Update last login timestamp
	now := time.Now().UTC().Format(time.RFC3339)
	db.conn.Exec("UPDATE users SET last_login = ?, updated_at = ? WHERE id = ?", now, now, user.ID)

	return user, nil
}

// GetUserByID retrieves a user by their ID.
func (db *DB) GetUserByID(id int64) (*User, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	user := &User{}
	err := db.conn.QueryRow(
		"SELECT id, username, password_hash, role, created_at, updated_at, last_login, is_active FROM users WHERE id = ?",
		id,
	).Scan(&user.ID, &user.Username, &user.PasswordHash, &user.Role, &user.CreatedAt, &user.UpdatedAt, &user.LastLogin, &user.IsActive)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("user not found")
	}
	if err != nil {
		return nil, fmt.Errorf("database error: %w", err)
	}
	return user, nil
}

// CreateUser adds a new user to the database.
func (db *DB) CreateUser(username, password string, role UserRole) (*User, error) {
	db.mu.Lock()
	defer db.mu.Unlock()

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	result, err := db.conn.Exec(
		"INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
		username, string(hash), string(role),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	id, _ := result.LastInsertId()
	return db.GetUserByID(id)
}

// ChangePassword updates a user's password.
func (db *DB) ChangePassword(userID int64, newPassword string) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	now := time.Now().UTC().Format(time.RFC3339)
	_, err = db.conn.Exec(
		"UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?",
		string(hash), now, userID,
	)
	return err
}

// ListUsers returns all users (without password hashes).
func (db *DB) ListUsers() ([]*User, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	rows, err := db.conn.Query(
		"SELECT id, username, password_hash, role, created_at, updated_at, last_login, is_active FROM users ORDER BY id",
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []*User
	for rows.Next() {
		u := &User{}
		if err := rows.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Role, &u.CreatedAt, &u.UpdatedAt, &u.LastLogin, &u.IsActive); err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

// GenerateSessionID creates a cryptographically random session identifier.
func GenerateSessionID() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}
