package auth

import (
	"database/sql"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestValidateConsoleUser(t *testing.T) {
	validUser := &ConsoleUser{
		Id:            1,
		Subject:       uuid.New(),
		Username:      "john_doe",
		Email:         "john@example.com",
		EmailVerified: true,
		GivenName:     "John",
		FamilyName:    "Doe",
		Enabled:       true,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
		BirthDate:     sql.NullTime{Time: time.Now(), Valid: true},
		PhoneNumber:   "+1234567890",
	}

	if err := ValidateConsoleUser(validUser); err != nil {
		t.Fatalf("expected valid user to pass validation: %v", err)
	}

	invalidUser := *validUser
	invalidUser.Username = "jo"
	if err := ValidateConsoleUser(&invalidUser); err == nil {
		t.Fatal("expected validation to fail for short username")
	}

	invalidUser = *validUser
	invalidUser.Email = "invalid-email"
	if err := ValidateConsoleUser(&invalidUser); err == nil {
		t.Fatal("expected validation to fail for invalid email format")
	}

	invalidUser = *validUser
	invalidUser.GivenName = ""
	if err := ValidateConsoleUser(&invalidUser); err == nil {
		t.Fatal("expected validation to fail for empty given name")
	}
}

func TestValidatePasswordStrength(t *testing.T) {
	tests := []struct {
		password string
		valid    bool
	}{
		{"Short1", false},      // too short
		{"NoDigitsHere", false}, // no digits
		{"12345678", false},     // no letters
		{"Pass1234", true},      // valid
	}

	for _, tt := range tests {
		err := ValidatePasswordStrength(tt.password)
		if tt.valid && err != nil {
			t.Errorf("expected password %q to be valid, got error: %v", tt.password, err)
		}
		if !tt.valid && err == nil {
			t.Errorf("expected password %q to be invalid, but got no error", tt.password)
		}
	}
}
