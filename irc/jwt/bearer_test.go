package jwt

import (
	"testing"

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
		Enabled:       true,
		Algorithm:     "rsa",
		KeyString:     rsaTestPubKey,
		AccountClaims: []string{"preferred_username", "email"},
		StripDomain:   "example.com",
	}

	if err := j.Postprocess(); err != nil {
		t.Fatal(err)
	}

	privKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(rsaTestPrivKey))
	if err != nil {
		t.Fatal(err)
	}
	jTok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims(map[string]any{"preferred_username": "slingamn"}))
	token, err := jTok.SignedString(privKey)
	if err != nil {
		t.Fatal(err)
	}

	accountName, err := j.Validate(token)
	if err != nil {
		t.Errorf("could not validate valid token: %v", err)
	}
	if accountName != "slingamn" {
		t.Errorf("incorrect account name for token: `%s`", accountName)
	}

	// test for the infamous algorithm confusion bug
	jTok = jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims(map[string]any{"preferred_username": "slingamn"}))
	token, err = jTok.SignedString([]byte(rsaTestPrivKey))
	if err != nil {
		t.Fatal(err)
	}

	accountName, err = j.Validate(token)
	if err == nil {
		t.Errorf("validated HS256 token despite RSA being required")
	}

	// test no valid claims
	jTok = jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims(map[string]any{"sub": "slingamn"}))
	token, err = jTok.SignedString(privKey)
	if err != nil {
		t.Fatal(err)
	}

	accountName, err = j.Validate(token)
	if err != ErrNoValidAccountClaim {
		t.Errorf("expected ErrNoValidAccountClaim, got: %v", err)
	}

	// test email addresses
	jTok = jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims(map[string]any{"email": "Slingamn@example.com"}))
	token, err = jTok.SignedString(privKey)
	if err != nil {
		t.Fatal(err)
	}

	accountName, err = j.Validate(token)
	if err != nil {
		t.Errorf("could not validate valid token: %v", err)
	}
	if accountName != "Slingamn" {
		t.Errorf("incorrect account name for token: `%s`", accountName)
	}
}
