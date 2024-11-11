package jwt

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/forkyid/go-utils/v1/aes"
)

// extractClaims extracts claims from JWT, returns claims as map
func extractClaims(tokenStr string) (jwt.MapClaims, error) {
	hmacSecretString := os.Getenv("JWT_ACCESS_SIGNATURE_KEY")
	hmacSecret := []byte(hmacSecretString)
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		// check token signing method etc
		return hmacSecret, nil
	})

	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		err = errors.New("invalid JWT Token")
		return nil, err
	}

	return claims, nil
}

// ExtractID extracts only the id from JWT
func ExtractID(ah string) (int, error) {
	ts := strings.Replace(ah, "Bearer ", "", -1)
	claimsMap, err := extractClaims(ts)
	if err != nil {
		return -1, fmt.Errorf("failed on claiming token")
	}
	id := aes.Decrypt(claimsMap["id"].(string))
	if id == -1 {
		return -1, fmt.Errorf("invalid ID")
	}
	return id, nil
}

// ExtractClient extracts only the id from JWT
func ExtractClient(ah string) (*AccessClaims, error) {
	ts := strings.Replace(ah, "Bearer ", "", -1)
	claims := AccessClaims{}

	claimsMap, err := extractClaims(ts)
	if err != nil {
		return nil, fmt.Errorf("failed on claiming token")
	}

	j, err := json.Marshal(&claimsMap)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(j, &claims)
	if err != nil {
		return nil, err
	}

	return &claims, nil
}
