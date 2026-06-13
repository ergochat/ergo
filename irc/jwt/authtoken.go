package jwt

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/ergochat/ergo/irc/utils"

	jwt "github.com/golang-jwt/jwt/v5"
)

const (
	AuthTokenPartLength = 300
	MaxAuthTokenLength  = 2048 // TODO check this
)

var (
	ErrInvalidToken = errors.New("invalid token")
	ErrNoService    = errors.New("invalid authtoken service")

	parser = jwt.NewParser(jwt.WithExpirationRequired())
)

type AuthTokensConfig struct {
	Enabled                 bool
	VerificationIPWhitelist []string `yaml:"verification-ip-whitelist"`
	verificationIPWhitelist []net.IPNet

	Services map[string]JwtServiceConfig
}

// AuthToken is the internal representation of an auth token's data,
// implemented as a stateless signed JWT.
type AuthToken struct {
	ServerName  string
	Service     string
	URL         string
	AccountName string
	Scope       string
	ChannelMode string
}

func (t *AuthTokensConfig) Postprocess() (err error) {
	if !t.Enabled {
		return nil
	}

	t.verificationIPWhitelist, err = utils.ParseNetList(t.VerificationIPWhitelist)
	if err != nil {
		return err
	}

	services := make(map[string]JwtServiceConfig, len(t.Services))
	for srv, conf := range t.Services {
		if err := conf.Postprocess(); err != nil {
			return fmt.Errorf("TOKEN service %s is misconfigured: %w", srv, err)
		}
		if !conf.Enabled() {
			return fmt.Errorf("TOKEN service %s lacks necessary configuration", srv)
		}
		if conf.URL == "" {
			return fmt.Errorf("TOKEN service %s lacks a URL", srv)
		}
		services[strings.ToUpper(srv)] = conf
	}
	t.Services = services
	return nil
}

func (t *AuthTokensConfig) getService(service string) (result JwtServiceConfig, err error) {
	if !t.Enabled {
		err = ErrNoService
		return
	}

	result, ok := t.Services[service]
	if !ok || !result.Enabled() {
		err = ErrNoService
		return
	}

	return result, nil
}

func (t *AuthTokensConfig) AllowIP(ip net.IP) bool {
	return utils.IPInNets(ip, t.verificationIPWhitelist)
}

func (t *AuthTokensConfig) Issue(token AuthToken) (result string, err error) {
	service := strings.ToUpper(token.Service)
	conf, err := t.getService(service)
	if err != nil {
		return
	}

	claims := make(jwt.MapClaims)
	// standard claims:
	claims["iss"] = token.ServerName
	claims["exp"] = time.Now().Unix() + int64(conf.Expiration/time.Second)
	claims["aud"] = conf.URL
	// ergo-specific claims
	claims["srv"] = service
	claims["acc"] = token.AccountName
	if token.Scope != "" {
		claims["scope"] = token.Scope
	}
	if token.ChannelMode != "" {
		claims["chmode"] = token.ChannelMode
	}
	// TODO include operclass if available?

	j := jwt.NewWithClaims(conf.signingMethod, jwt.MapClaims(claims))
	return j.SignedString(conf.signingKey)
}

func (t *AuthTokensConfig) Verify(service, url, token string) (result AuthToken, err error) {
	service = strings.ToUpper(service)
	conf, err := t.getService(service)
	if err != nil {
		return
	}
	// since we looked up the service, we now know the correct signing key
	tok, err := parser.Parse(token, conf.verifyKeyFunc)
	if err != nil {
		return
	}

	// validate the exact signing method just in case (although it should be impossible
	// to, e.g. validate a HS256 token with a *rsa.PrivateKey signing key)
	if tok.Method != conf.signingMethod {
		err = ErrInvalidToken
		return
	}

	mc := tok.Claims.(jwt.MapClaims)

	srvClaim := extractStringClaim(mc, "srv")
	if service != srvClaim {
		err = ErrInvalidToken
		return
	}
	audClaim := extractStringClaim(mc, "aud")
	if url != audClaim {
		err = ErrInvalidToken
		return
	}

	return AuthToken{
		// don't care about iss / ServerName
		Service:     srvClaim,
		URL:         audClaim,
		AccountName: extractStringClaim(mc, "acc"),
		Scope:       extractStringClaim(mc, "scope"),
		// don't return channel mode, revalidate it from runtime data
	}, nil
}

func extractStringClaim(claims jwt.MapClaims, key string) string {
	if result, ok := claims[key]; ok {
		if strResult, ok := result.(string); ok {
			return strResult
		}
	}
	return ""
}
