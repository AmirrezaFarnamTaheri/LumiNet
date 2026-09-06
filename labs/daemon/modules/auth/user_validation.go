package auth

import (
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
)

// ConsoleUser represents the user model ported from local database schemas.
type ConsoleUser struct {
	Id            int64        `json:"id"`
	Subject       uuid.UUID    `json:"subject"`
	Username      string       `json:"username"`
	Email         string       `json:"email"`
	EmailVerified bool         `json:"email_verified"`
	GivenName     string       `json:"given_name"`
	FamilyName    string       `json:"family_name"`
	Enabled       bool         `json:"enabled"`
	CreatedAt     time.Time    `json:"created_at"`
	UpdatedAt     time.Time    `json:"updated_at"`
	BirthDate     sql.NullTime `json:"birth_date"`
	PhoneNumber   string       `json:"phone_number"`
}

var (
	rxUsername = regexp.MustCompile(`^[a-zA-Z0-9_-]{3,30}$`)
	rxEmail    = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
)

// ValidateConsoleUser validates a user instance against local database schemas.
func ValidateConsoleUser(u *ConsoleUser) error {
	if !rxUsername.MatchString(u.Username) {
		return errors.New("invalid username: must be 3-30 chars and contain only alphanumeric, underscores, or hyphens")
	}
	if !rxEmail.MatchString(u.Email) {
		return errors.New("invalid email address format")
	}
	if len(strings.TrimSpace(u.GivenName)) == 0 {
		return errors.New("given name cannot be empty")
	}
	if len(strings.TrimSpace(u.FamilyName)) == 0 {
		return errors.New("family name cannot be empty")
	}
	if u.Subject == uuid.Nil {
		return errors.New("subject UUID cannot be nil")
	}
	return nil
}

// GetFullName returns the formatted full name of the user.
func (u *ConsoleUser) GetFullName() string {
	return strings.TrimSpace(fmt.Sprintf("%s %s", u.GivenName, u.FamilyName))
}

// ValidatePasswordStrength checks if the password meets security requirements.
func ValidatePasswordStrength(password string) error {
	if len(password) < 8 {
		return errors.New("password must be at least 8 characters long")
	}
	hasDigit := false
	hasLetter := false
	for _, char := range password {
		if char >= '0' && char <= '9' {
			hasDigit = true
		} else if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') {
			hasLetter = true
		}
	}
	if !hasDigit || !hasLetter {
		return errors.New("password must contain both letters and digits")
	}
	return nil
}
