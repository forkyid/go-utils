package jwt

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/forkyid/go-utils/v1/aes"
	"github.com/pkg/errors"
)

// extractClaims extracts claims from JWT, returns claims as map
func extractClaims(tokenStr string, skipClaimsValidation ...bool) (jwt.MapClaims, error) {
	hmacSecretString := os.Getenv("JWT_ACCESS_SIGNATURE_KEY")
	hmacSecret := []byte(hmacSecretString)
	parser := new(jwt.Parser)
	parser.SkipClaimsValidation = skipClaimsValidation[0]
	token, err := parser.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
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
func ExtractID(ah string, skipClaimsValidation ...bool) (int, error) {
	ts := strings.Replace(ah, "Bearer ", "", -1)
	claimsMap, err := extractClaims(ts, append(skipClaimsValidation, true)[0])
	if err != nil {
		return -1, errors.Wrap(err, "extract claims")
	}

	id := aes.Decrypt(claimsMap["id"].(string))
	if id == -1 {
		return -1, fmt.Errorf("invalid ID")
	}

	return int(id), nil
}

// ExtractClient extracts only the id from JWT
func ExtractClient(ah string, skipClaimsValidation ...bool) (*AccessClaims, error) {
	ts := strings.Replace(ah, "Bearer ", "", -1)
	claims := AccessClaims{}
	claimsMap, err := extractClaims(ts, append(skipClaimsValidation, true)[0])
	if err != nil {
		return nil, errors.Wrap(err, "extract claims")
	}

	j, err := json.Marshal(&claimsMap)
	if err != nil {
		return nil, errors.Wrap(err, "marshal")
	}

	err = json.Unmarshal(j, &claims)
	if err != nil {
		return nil, errors.Wrap(err, "unmarshal")
	}

	return &claims, nil
}
