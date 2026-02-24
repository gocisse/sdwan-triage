package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/gocisse/sdwan-triage/pkg/database"
	"github.com/gocisse/sdwan-triage/pkg/middleware"
)

// handleLogin returns a Gin handler for POST /api/login.
// Accepts JSON: {"username": "...", "password": "..."}
// Returns JWT token on success, 401 on failure.
func handleLogin(authCfg *middleware.AuthConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			Username string `json:"username" binding:"required"`
			Password string `json:"password" binding:"required"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Username and password are required",
			})
			return
		}

		user, err := authCfg.DB.Authenticate(req.Username, req.Password)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid credentials",
			})
			return
		}

		token, expiresAt, err := authCfg.GenerateToken(user)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to generate token",
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"token":      token,
			"expires_at": expiresAt,
			"user": gin.H{
				"id":       user.ID,
				"username": user.Username,
				"role":     user.Role,
			},
		})
	}
}

// handleMe returns a Gin handler for GET /api/auth/me.
// Returns the current authenticated user's profile.
func handleMe(authCfg *middleware.AuthConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, exists := c.Get(middleware.ContextKeyUserID)
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
			return
		}

		user, err := authCfg.DB.GetUserByID(userID.(int64))
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"id":         user.ID,
			"username":   user.Username,
			"role":       user.Role,
			"created_at": user.CreatedAt,
			"last_login": user.LastLogin,
		})
	}
}

// handleChangePassword returns a Gin handler for POST /api/auth/change-password.
// Accepts JSON: {"current_password": "...", "new_password": "..."}
func handleChangePassword(authCfg *middleware.AuthConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			CurrentPassword string `json:"current_password" binding:"required"`
			NewPassword     string `json:"new_password" binding:"required,min=6"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Current password and new password (min 6 chars) are required",
			})
			return
		}

		username, _ := c.Get(middleware.ContextKeyUser)
		userID, _ := c.Get(middleware.ContextKeyUserID)

		// Verify current password
		_, err := authCfg.DB.Authenticate(username.(string), req.CurrentPassword)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Current password is incorrect",
			})
			return
		}

		if err := authCfg.DB.ChangePassword(userID.(int64), req.NewPassword); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to change password",
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"message": "Password changed successfully",
		})
	}
}

// handleListUsers returns a Gin handler for GET /api/auth/users (admin only).
func handleListUsers(authCfg *middleware.AuthConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		users, err := authCfg.DB.ListUsers()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to list users",
			})
			return
		}

		// Strip password hashes from response
		type safeUser struct {
			ID        int64             `json:"id"`
			Username  string            `json:"username"`
			Role      database.UserRole `json:"role"`
			CreatedAt string            `json:"created_at"`
			LastLogin *string           `json:"last_login,omitempty"`
			IsActive  bool              `json:"is_active"`
		}

		result := make([]safeUser, 0, len(users))
		for _, u := range users {
			result = append(result, safeUser{
				ID:        u.ID,
				Username:  u.Username,
				Role:      u.Role,
				CreatedAt: u.CreatedAt,
				LastLogin: u.LastLogin,
				IsActive:  u.IsActive,
			})
		}

		c.JSON(http.StatusOK, gin.H{"users": result})
	}
}

// handleCreateUser returns a Gin handler for POST /api/auth/users (admin only).
// Accepts JSON: {"username": "...", "password": "...", "role": "admin|analyst|viewer"}
func handleCreateUser(authCfg *middleware.AuthConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			Username string `json:"username" binding:"required,min=3"`
			Password string `json:"password" binding:"required,min=6"`
			Role     string `json:"role" binding:"required,oneof=admin analyst viewer"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Valid username (min 3), password (min 6), and role (admin/analyst/viewer) are required",
			})
			return
		}

		user, err := authCfg.DB.CreateUser(req.Username, req.Password, database.UserRole(req.Role))
		if err != nil {
			c.JSON(http.StatusConflict, gin.H{
				"error": "Failed to create user: " + err.Error(),
			})
			return
		}

		c.JSON(http.StatusCreated, gin.H{
			"id":       user.ID,
			"username": user.Username,
			"role":     user.Role,
		})
	}
}
