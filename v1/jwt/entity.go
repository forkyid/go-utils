package jwt

import (
	"time"

	"github.com/dgrijalva/jwt-go"
)

type UserClaims struct {
	ID          string    `json:"id"`
	RoleID      string    `json:"role_id"`
	Username    string    `json:"username"`
	Nickname    string    `json:"nickname"`
	Email       string    `json:"email"`
	PhoneCode   string    `json:"phone_code"`
	PhoneNumber string    `json:"phone_number"`
	DateOfBirth time.Time `json:"date_of_birth"`
	Language    string    `json:"language"`
}

type RefreshClaims struct {
	jwt.StandardClaims
	Type string `json:"type"`
}

type AccessClaims struct {
	jwt.StandardClaims
	Type string `json:"type"`
	UserClaims
}
