// Copyright (c) 2020 Shivaram Lingamneni
// released under the MIT license

package email

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"

	"github.com/ergochat/ergo/irc/smtp"
)

var (
	ErrBlacklistedAddress = errors.New("Email address is blacklisted")
	ErrInvalidAddress     = errors.New("Email address is blacklisted")
	ErrNoMXRecord         = errors.New("Couldn't resolve MX record")
)

type MTAConfig struct {
	Server   string
	Port     int
	Username string
	Password string
}

type MailtoConfig struct {
	// legacy config format assumed the use of an MTA/smarthost,
	// so server, port, etc. appear directly at top level
	// XXX: see https://github.com/go-yaml/yaml/issues/63
	MTAConfig            `yaml:",inline"`
	Enabled              bool
	Sender               string
	HeloDomain           string `yaml:"helo-domain"`
	RequireTLS           bool   `yaml:"require-tls"`
	VerifyMessageSubject string `yaml:"verify-message-subject"`
	DKIM                 DKIMConfig
	MTAReal              MTAConfig `yaml:"mta"`
	BlacklistRegexes     []string  `yaml:"blacklist-regexes"`
	blacklistRegexes     []*regexp.Regexp
}

func (config *MailtoConfig) Postprocess(heloDomain string) (err error) {
	if config.Sender == "" {
		return errors.New("Invalid mailto sender address")
	}

	// check for MTA config fields at top level,
	// copy to MTAReal if present
	if config.Server != "" && config.MTAReal.Server == "" {
		config.MTAReal = config.MTAConfig
	}

	if config.HeloDomain == "" {
		config.HeloDomain = heloDomain
	}

	for _, reg := range config.BlacklistRegexes {
		compiled, err := regexp.Compile(fmt.Sprintf("^%s$", reg))
		if err != nil {
			return err
		}
		config.blacklistRegexes = append(config.blacklistRegexes, compiled)
	}

	if config.MTAConfig.Server != "" {
		// smarthost, nothing more to validate
		return nil
	}

	return config.DKIM.Postprocess()
}

// get the preferred MX record hostname, "" on error
func lookupMX(domain string) (server string) {
	var minPref uint16
	results, err := net.LookupMX(domain)
	if err != nil {
		return
	}
	for _, result := range results {
		if minPref == 0 || result.Pref < minPref {
			server, minPref = result.Host, result.Pref
		}
	}
	return
}

func SendMail(config MailtoConfig, recipient string, msg []byte) (err error) {
	for _, reg := range config.blacklistRegexes {
		if reg.MatchString(recipient) {
			return ErrBlacklistedAddress
		}
	}

	if config.DKIM.Domain != "" {
		msg, err = DKIMSign(msg, config.DKIM)
		if err != nil {
			return
		}
	}

	var addr string
	var auth smtp.Auth
	if config.MTAReal.Server != "" {
		addr = fmt.Sprintf("%s:%d", config.MTAReal.Server, config.MTAReal.Port)
		if config.MTAReal.Username != "" && config.MTAReal.Password != "" {
			auth = smtp.PlainAuth("", config.MTAReal.Username, config.MTAReal.Password, config.MTAReal.Server)
		}
	} else {
		idx := strings.IndexByte(recipient, '@')
		if idx == -1 {
			return ErrInvalidAddress
		}
		mx := lookupMX(recipient[idx+1:])
		if mx == "" {
			return ErrNoMXRecord
		}
		addr = fmt.Sprintf("%s:smtp", mx)
	}

	return smtp.SendMail(addr, auth, config.HeloDomain, config.Sender, []string{recipient}, msg, config.RequireTLS)
}
