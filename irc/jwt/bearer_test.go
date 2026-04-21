package jwt

import (
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
)

const (
	rsaTestPubKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwhcCcXrfR/GmoPKxBi0H
cUl2pUl4acq2m3abFtMMoYTydJdEhgYWfsXuragyEIVkJU1ZnrgedW0QJUcANRGO
hP/B+MjBevDNsRXQECfhyjfzhz6KWZb4i7C2oImJuAjq/F4qGLdEGQDBpAzof8qv
9Zt5iN3GXY/EQtQVMFyR/7BPcbPLbHlOtzZ6tVEioXuUxQoai7x3Kc0jIcPWuyGa
Q04IvsgdaWO6oH4fhPfyVsmX37rYUn79zcqPHS4ieWM1KN9qc7W+/UJIeiwAStpJ
8gv+OSMrijRZGgQGCeOO5U59GGJC4mqUczB+JFvrlAIv0rggNpl+qalngosNxukB
uQIDAQAB
-----END PUBLIC KEY-----`

	rsaTestPrivKey = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDCFwJxet9H8aag
8rEGLQdxSXalSXhpyrabdpsW0wyhhPJ0l0SGBhZ+xe6tqDIQhWQlTVmeuB51bRAl
RwA1EY6E/8H4yMF68M2xFdAQJ+HKN/OHPopZlviLsLagiYm4COr8XioYt0QZAMGk
DOh/yq/1m3mI3cZdj8RC1BUwXJH/sE9xs8tseU63Nnq1USKhe5TFChqLvHcpzSMh
w9a7IZpDTgi+yB1pY7qgfh+E9/JWyZffuthSfv3Nyo8dLiJ5YzUo32pztb79Qkh6
LABK2knyC/45IyuKNFkaBAYJ447lTn0YYkLiapRzMH4kW+uUAi/SuCA2mX6pqWeC
iw3G6QG5AgMBAAECggEARaAnejoP2ykvE1G8e3Cv2M33x/eBQMI9m6uCmz9+qnqc
14JkTIfmjffHVXie7RpNAKys16lJE+rZ/eVoh6EStVdiaDLsZYP45evjRcho0Tgd
Hokq7FSiOMpd2V09kE1yrrHA/DjSLv38eTNAPIejc8IgaR7VyD6Is0iNiVnL7iLa
mj1zB6+dSeQ5ICYkrihb1gA+SvECsjLZ/5XESXEdHJvxhC0vLAdHmdQf3BPPlrGg
VHondxL5gt6MFykpOxTFA6f5JkSefhUR/2OcCDpMs6a5GUytjl3rA3aGT6v3CbnR
ykD6PzyC20EUADQYF2pmJfzbxyRqfNdbSJwQv5QQYQKBgQD4rFdvgZC97L7WhZ5T
axW8hRW2dH24GIqFT4ZnCg0suyMNshyGvDMuBfGvokN/yACmvsdE0/f57esar+ye
l9RC+CzGUch08Ke5WdqwACOCNDpx0kJcXKTuLIgkvthdla/oAQQ9T7OgEwDrvaR0
m8s/Z7Hb3hLD3xdOt6Xjrv/6xQKBgQDHzvbcIkhmWdvaPDT9NEu7psR/fxF5UjqU
Cca/bfHhySRQs3A1CF57pfwpUqAcSivNf7O+3NI62AKoyMDYv0ek2h6hGk6g5GJ1
SuXYfjcbkL6SWNV0InsgmzCjvxhyms83xZq7uMClEBvkiKVMdt6zFkwW9eRKtUuZ
pzVK5RfqZQKBgF5SME/xGw+O7su7ntQROAtrh1LPWKgtVs093sLSgzDGQoN9XWiV
lewNASEXMPcUy3pzvm2S4OoBnj1fISb+e9py+7i1aI1CgrvBIzvCsbU/TjPCBr21
vjFA3trhMHw+vJwJVqxSwNUkoCLKqcg5F5yTHllBIGj/A34uFlQIGrvpAoGAextm
d+1bhExbLBQqZdOh0cWHjjKBVqm2U93OKcYY4Q9oI5zbRqGYbUCwo9k3sxZz9JJ4
8eDmWsEaqlm+kA0SnFyTwJkP1wvAKhpykTf6xi4hbNP0+DACgu17Q3iLHJmLkQZc
Nss3TrwlI2KZzgnzXo4fZYotFWasZMhkCngqiw0CgYEAmz2D70RYEauUNE1+zLhS
6Ox5+PF/8Z0rZOlTghMTfqYcDJa+qQe9pJp7RPgilsgemqo0XtgLKz3ATE5FmMa4
HRRGXPkMNu6Hzz4Yk4eM/yJqckoEc8azV25myqQ+7QXTwZEvxVbtUWZtxfImGwq+
s/uzBKNwWf9UPTeIt+4JScg=
-----END PRIVATE KEY-----`
)

func TestJWTBearerAuth(t *testing.T) {
	j := JWTAuthConfig{
		Enabled: true,
		Tokens: []JWTAuthTokenConfig{
			{
				Algorithm:     "rsa",
				KeyString:     rsaTestPubKey,
				AccountClaims: []string{"preferred_username", "email", "account"},
				StripDomain:   "example.com",
			},
		},
	}

	if err := j.Postprocess(); err != nil {
		t.Fatal(err)
	}

	// fixed test vector signed with the RSA privkey:
	token := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhY2NvdW50Ijoic2xpbmdhbW4iLCJhdWQiOiJodHRwczovL2V4YW1wbGUuY29tL2ZpbGVob3N0IiwiZXhwIjo4MDgzODY1NDkyLCJpc3MiOiJlcmdvLnRlc3QiLCJzcnYiOiJGSUxFSE9TVCJ9.d_tMt4UWuuq3KDgKF4wCyL0tKaeKTCqrKgFZdogOetqmp9qVxi05sMlXawmheWAf3cjQG1ZxCvoc0TovI8H5d5DsVW5txNAXEhYlFKp8Vbd86J04VH2fn32brv5BH9oMPu60bnaEyv_vkKuFMANJzNgQOlMbNTo1IBKYmppi0dVbaBPtylMfL2jTQBwNj6m2_Bv_7N3tf9IgTIRX-Z2VbniHjTB9sEZaFgk6mxj-kwjxqu-lTAxmsPy4H5CBQb-Ea47LBFPmoLt6caxA4VCZyDq1chxcU5DLtv8ec9Sk1XvrGlyWtZ6pD9rT93jpSN6e5r5ceirkvgh20sUIWOOsHg"
	accountName, err := j.Validate(token)
	if err != nil {
		t.Errorf("could not validate valid token: %v", err)
	}
	if accountName != "slingamn" {
		t.Errorf("incorrect account name for token: `%s`", accountName)
	}

	// programmatically sign a new token, validate it
	privKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(rsaTestPrivKey))
	if err != nil {
		t.Fatal(err)
	}
	exp := time.Now().Add(time.Hour).Unix()
	token = signTokenForTesting(jwt.SigningMethodRS256, privKey, jwt.MapClaims(map[string]any{"preferred_username": "slingamn", "exp": exp}))
	accountName, err = j.Validate(token)
	if err != nil {
		t.Errorf("could not validate valid token: %v", err)
	}
	if accountName != "slingamn" {
		t.Errorf("incorrect account name for token: `%s`", accountName)
	}

	// test expiration
	token = signTokenForTesting(jwt.SigningMethodRS256, privKey, jwt.MapClaims(map[string]any{"preferred_username": "slingamn", "exp": 1675740865}))
	accountName, err = j.Validate(token)
	if err == nil {
		t.Errorf("validated expired token")
	}

	// test for the infamous algorithm confusion bug
	token = signTokenForTesting(jwt.SigningMethodHS256, []byte(rsaTestPubKey), jwt.MapClaims(map[string]any{"preferred_username": "slingamn"}))
	accountName, err = j.Validate(token)
	if err == nil {
		t.Errorf("validated HS256 token despite RSA being required")
	}

	// test no valid claims
	token = signTokenForTesting(jwt.SigningMethodRS256, privKey, jwt.MapClaims(map[string]any{"sub": "slingamn", "exp": exp}))
	accountName, err = j.Validate(token)
	if err != ErrNoValidAccountClaim {
		t.Errorf("expected ErrNoValidAccountClaim, got: %v", err)
	}

	// test email addresses
	token = signTokenForTesting(jwt.SigningMethodRS256, privKey, jwt.MapClaims(map[string]any{"email": "Slingamn@example.com", "exp": exp}))
	accountName, err = j.Validate(token)
	if err != nil {
		t.Errorf("could not validate valid token: %v", err)
	}
	if accountName != "Slingamn" {
		t.Errorf("incorrect account name for token: `%s`", accountName)
	}
}

func signTokenForTesting(method jwt.SigningMethod, key any, claims jwt.MapClaims) (token string) {
	jTok := jwt.NewWithClaims(method, claims)
	token, err := jTok.SignedString(key)
	if err != nil {
		panic(err)
	}
	return token
}

func TestJWTBearerAudValidation(t *testing.T) {
	key := []byte("MowTTyXKkN58DG2uNMsoCgAa6CM6ElFlcq_7Ocl6wsU")
	j := JWTAuthConfig{
		Enabled: true,
		Tokens: []JWTAuthTokenConfig{
			{
				Algorithm:     "hmac",
				KeyString:     string(key),
				AccountClaims: []string{"account"},
				ValidateAud:   []string{"irc.ergo.chat", "https://irc.ergo.chat"},
			},
		},
	}

	if err := j.Postprocess(); err != nil {
		t.Fatal(err)
	}

	exp := time.Now().Add(time.Hour).Unix()

	token := signTokenForTesting(jwt.SigningMethodHS256, key, jwt.MapClaims(map[string]any{"account": "slingamn", "exp": exp}))
	if _, err := j.Validate(token); err == nil {
		t.Errorf("validated token with missing aud")
	}

	token = signTokenForTesting(jwt.SigningMethodHS256, key, jwt.MapClaims(map[string]any{"account": "slingamn", "exp": exp, "aud": "irc.ergo.chat"}))
	if _, err := j.Validate(token); err != nil {
		t.Errorf("failed to validate token with string aud: %v", err)
	}

	token = signTokenForTesting(jwt.SigningMethodHS256, key, jwt.MapClaims(map[string]any{"account": "slingamn", "exp": exp, "aud": "ergo.chat"}))
	if _, err := j.Validate(token); err == nil {
		t.Errorf("validated token with invalid string aud")
	}

	token = signTokenForTesting(jwt.SigningMethodHS256, key, jwt.MapClaims(map[string]any{
		"account": "slingamn",
		"exp":     exp,
		"aud":     []string{"https://example.com", "irc.ergo.chat"},
	}))
	if _, err := j.Validate(token); err != nil {
		t.Errorf("failed to validate token with list aud: %v", err)
	}

	token = signTokenForTesting(jwt.SigningMethodHS256, key, jwt.MapClaims(map[string]any{
		"account": "slingamn",
		"exp":     exp,
		"aud":     []string{"https://example.com", "ergo.chat"},
	}))
	if _, err := j.Validate(token); err == nil {
		t.Errorf("validated token with invalid list aud")
	}

	token = signTokenForTesting(jwt.SigningMethodHS256, key, jwt.MapClaims(map[string]any{
		"account": "slingamn",
		"exp":     exp,
		"aud":     make([]string, 0),
	}))
	if _, err := j.Validate(token); err == nil {
		t.Errorf("validated token with invalid list aud")
	}

	token = signTokenForTesting(jwt.SigningMethodHS256, key, jwt.MapClaims(map[string]any{
		"account": "slingamn",
		"exp":     exp,
		"aud":     []int{1, 2},
	}))
	if _, err := j.Validate(token); err == nil {
		t.Errorf("validated token with invalid list aud")
	}
}
