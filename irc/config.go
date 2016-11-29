// Copyright (c) 2012-2014 Jeremy Latt
// Copyright (c) 2014-2015 Edmund Huber
// Copyright (c) 2016- Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"strings"
	"time"

	"gopkg.in/yaml.v2"
)

type PassConfig struct {
	Password string
}

// TLSListenConfig defines configuration options for listening on TLS
type TLSListenConfig struct {
	Cert string
	Key  string
}

// Certificate returns the TLS certificate assicated with this TLSListenConfig
func (conf *TLSListenConfig) Config() (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(conf.Cert, conf.Key)
	if err != nil {
		return nil, errors.New("tls cert+key: invalid pair")
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
	}, err
}

func (conf *PassConfig) PasswordBytes() []byte {
	bytes, err := DecodePasswordHash(conf.Password)
	if err != nil {
		log.Fatal("decode password error: ", err)
	}
	return bytes
}

type AccountRegistrationConfig struct {
	Enabled          bool
	EnabledCallbacks []string `yaml:"enabled-callbacks"`
	Callbacks        struct {
		Mailto struct {
			Server string
			Port   int
			TLS    struct {
				Enabled            bool
				InsecureSkipVerify bool   `yaml:"insecure_skip_verify"`
				ServerName         string `yaml:"servername"`
			}
			Username             string
			Password             string
			Sender               string
			VerifyMessageSubject string `yaml:"verify-message-subject"`
			VerifyMessage        string `yaml:"verify-message"`
		}
	}
}

type OperClassConfig struct {
	Title        string
	WhoisLine    string
	Extends      string
	Capabilities []string
}

type OperConfig struct {
	Class     string
	Vhost     string
	WhoisLine string `yaml:"whois-line"`
	Password  string
}

func (conf *OperConfig) PasswordBytes() []byte {
	bytes, err := DecodePasswordHash(conf.Password)
	if err != nil {
		log.Fatal("decode password error: ", err)
	}
	return bytes
}

type RestAPIConfig struct {
	Enabled bool
	Listen  string
}

type ConnectionLimitsConfig struct {
	Enabled     bool
	CidrLenIPv4 int `yaml:"cidr-len-ipv4"`
	CidrLenIPv6 int `yaml:"cidr-len-ipv6"`
	IPsPerCidr  int `yaml:"ips-per-subnet"`
	Exempted    []string
}

type ConnectionThrottleConfig struct {
	Enabled            bool
	CidrLenIPv4        int           `yaml:"cidr-len-ipv4"`
	CidrLenIPv6        int           `yaml:"cidr-len-ipv6"`
	ConnectionsPerCidr int           `yaml:"max-connections"`
	DurationString     string        `yaml:"duration"`
	Duration           time.Duration `yaml:"duration-time"`
	BanDurationString  string        `yaml:"ban-duration"`
	BanDuration        time.Duration
	BanMessage         string `yaml:"ban-message"`
	Exempted           []string
}

type Config struct {
	Network struct {
		Name string
	}

	Server struct {
		PassConfig
		Password           string
		Name               string
		Listen             []string
		Wslisten           string                      `yaml:"ws-listen"`
		TLSListeners       map[string]*TLSListenConfig `yaml:"tls-listeners"`
		RestAPI            RestAPIConfig               `yaml:"rest-api"`
		CheckIdent         bool                        `yaml:"check-ident"`
		Log                string
		MOTD               string
		ConnectionLimits   ConnectionLimitsConfig   `yaml:"connection-limits"`
		ConnectionThrottle ConnectionThrottleConfig `yaml:"connection-throttling"`
	}

	Datastore struct {
		Path string
	}

	AuthenticationEnabled bool `yaml:"authentication-enabled"`

	Registration struct {
		Accounts AccountRegistrationConfig
	}

	OperClasses map[string]*OperClassConfig `yaml:"oper-classes"`

	Opers map[string]*OperConfig

	Limits struct {
		AwayLen        uint `yaml:"awaylen"`
		ChanListModes  uint `yaml:"chan-list-modes"`
		ChannelLen     uint `yaml:"channellen"`
		KickLen        uint `yaml:"kicklen"`
		LineLen        uint `yaml:"linelen"`
		MonitorEntries uint `yaml:"monitor-entries"`
		NickLen        uint `yaml:"nicklen"`
		TopicLen       uint `yaml:"topiclen"`
		WhowasEntries  uint `yaml:"whowas-entries"`
	}
}

type OperClass struct {
	Title        string
	WhoisLine    string          `yaml:"whois-line"`
	Capabilities map[string]bool // map to make lookups much easier
}

func (conf *Config) OperatorClasses() (*map[string]OperClass, error) {
	ocs := make(map[string]OperClass)

	// loop from no extends to most extended, breaking if we can't add any more
	lenOfLastOcs := -1
	for {
		if lenOfLastOcs == len(ocs) {
			return nil, errors.New("OperClasses contains a looping dependency, or a class extends from a class that doesn't exist")
		}
		lenOfLastOcs = len(ocs)

		var anyMissing bool
		for name, info := range conf.OperClasses {
			_, exists := ocs[name]
			_, extendsExists := ocs[info.Extends]
			if exists {
				// class already exists
				continue
			} else if len(info.Extends) > 0 && !extendsExists {
				// class we extend on doesn't exist
				_, exists := conf.OperClasses[info.Extends]
				if !exists {
					return nil, fmt.Errorf("Operclass [%s] extends [%s], which doesn't exist", name, info.Extends)
				}
				anyMissing = true
				continue
			}

			// create new operclass
			var oc OperClass
			oc.Capabilities = make(map[string]bool)

			// get inhereted info from other operclasses
			if len(info.Extends) > 0 {
				einfo, _ := ocs[info.Extends]

				for capab := range einfo.Capabilities {
					oc.Capabilities[capab] = true
				}
			}

			// add our own info
			oc.Title = info.Title
			for _, capab := range info.Capabilities {
				oc.Capabilities[capab] = true
			}
			if len(info.WhoisLine) > 0 {
				oc.WhoisLine = info.WhoisLine
			} else {
				oc.WhoisLine = "is a"
				if strings.Contains(strings.ToLower(string(oc.Title[0])), "aeiou") {
					oc.WhoisLine += "n"
				}
				oc.WhoisLine += " "
				oc.WhoisLine += oc.Title
			}

			ocs[name] = oc
		}

		if !anyMissing {
			// we've got every operclass!
			break
		}
	}

	return &ocs, nil
}

type Oper struct {
	Class     *OperClass
	WhoisLine string
	Vhost     string
	Pass      []byte
}

func (conf *Config) Operators(oc *map[string]OperClass) (map[string]Oper, error) {
	operators := make(map[string]Oper)
	for name, opConf := range conf.Opers {
		var oper Oper

		// oper name
		name, err := CasefoldName(name)
		if err != nil {
			return nil, fmt.Errorf("Could not casefold oper name: %s", err.Error())
		}

		oper.Pass = opConf.PasswordBytes()
		oper.Vhost = opConf.Vhost
		class, exists := (*oc)[opConf.Class]
		if !exists {
			return nil, fmt.Errorf("Could not load operator [%s] - they use operclass [%s] which does not exist", name, opConf.Class)
		}
		oper.Class = &class
		if len(opConf.WhoisLine) > 0 {
			oper.WhoisLine = opConf.WhoisLine
		} else {
			oper.WhoisLine = class.WhoisLine
		}

		// successful, attach to list of opers
		operators[name] = oper
	}
	return operators, nil
}

func (conf *Config) TLSListeners() map[string]*tls.Config {
	tlsListeners := make(map[string]*tls.Config)
	for s, tlsListenersConf := range conf.Server.TLSListeners {
		config, err := tlsListenersConf.Config()
		if err != nil {
			log.Fatal(err)
		}
		name, err := CasefoldName(s)
		if err == nil {
			tlsListeners[name] = config
		} else {
			log.Println("Could not casefold TLS listener:", err.Error())
		}
	}
	return tlsListeners
}

func LoadConfig(filename string) (config *Config, err error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return nil, err
	}

	// we need this so PasswordBytes returns the correct info
	if config.Server.Password != "" {
		config.Server.PassConfig.Password = config.Server.Password
	}

	if config.Network.Name == "" {
		return nil, errors.New("Network name missing")
	}
	if config.Server.Name == "" {
		return nil, errors.New("Server name missing")
	}
	if !IsHostname(config.Server.Name) {
		return nil, errors.New("Server name must match the format of a hostname")
	}
	if config.Datastore.Path == "" {
		return nil, errors.New("Datastore path missing")
	}
	if len(config.Server.Listen) == 0 {
		return nil, errors.New("Server listening addresses missing")
	}
	if config.Limits.NickLen < 1 || config.Limits.ChannelLen < 2 || config.Limits.AwayLen < 1 || config.Limits.KickLen < 1 || config.Limits.TopicLen < 1 {
		return nil, errors.New("Limits aren't setup properly, check them and make them sane")
	}
	if config.Server.ConnectionThrottle.Enabled {
		config.Server.ConnectionThrottle.Duration, err = time.ParseDuration(config.Server.ConnectionThrottle.DurationString)
		if err != nil {
			return nil, fmt.Errorf("Could not parse connection-throttle duration: %s", err.Error())
		}
		config.Server.ConnectionThrottle.BanDuration, err = time.ParseDuration(config.Server.ConnectionThrottle.BanDurationString)
		if err != nil {
			return nil, fmt.Errorf("Could not parse connection-throttle ban-duration: %s", err.Error())
		}
	}
	if config.Limits.LineLen < 512 {
		return nil, errors.New("Line length must be 512 or greater")
	}

	return config, nil
}
