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
	// aud is probably a waste of bits for our use case, but the spec says we should publish it
	claims["aud"] = conf.URL
	// ergo-specific claims
	claims["srv"] = service
	claims["account"] = token.AccountName
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

func (t *AuthTokensConfig) Verify(token string) (result AuthToken, err error) {
	var conf JwtServiceConfig

	// parse the token; extract the unvalidated srv claim; retrieve the corresponding
	// JWT service definition and verify the signature against the defined key
	tok, err := parser.Parse(token, func(tok *jwt.Token) (key any, err error) {
		srvClaim := tok.Claims.(jwt.MapClaims)["srv"] // Parse always returns a MapClaims
		if serviceName, ok := srvClaim.(string); ok {
			conf, err = t.getService(serviceName)
			if err == nil {
				return conf.verifyKey, nil
			} else {
				return nil, err
			}
		} else {
			return nil, ErrInvalidToken
		}
	})
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
	extractStringClaim := func(claims jwt.MapClaims, key string) string {
		if result, ok := claims[key]; ok {
			if strResult, ok := result.(string); ok {
				return strResult
			}
		}
		return ""
	}
	return AuthToken{
		// don't care about ServerName
		Service:     extractStringClaim(mc, "srv"),
		AccountName: extractStringClaim(mc, "account"),
		Scope:       extractStringClaim(mc, "scope"),
		// don't return channel mode, revalidate it from runtime data
	}, nil
}
