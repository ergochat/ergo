// Copyright (c) 2012-2014 Jeremy Latt
// Copyright (c) 2014-2015 Edmund Huber
// Copyright (c) 2016-2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"code.cloudfoundry.org/bytefmt"
	"github.com/oragono/oragono/irc/connection_limits"
	"github.com/oragono/oragono/irc/custime"
	"github.com/oragono/oragono/irc/isupport"
	"github.com/oragono/oragono/irc/languages"
	"github.com/oragono/oragono/irc/logger"
	"github.com/oragono/oragono/irc/modes"
	"github.com/oragono/oragono/irc/passwd"
	"github.com/oragono/oragono/irc/utils"
	"gopkg.in/yaml.v2"
)

// here's how this works: exported (capitalized) members of the config structs
// are defined in the YAML file and deserialized directly from there. They may
// be postprocessed and overwritten by LoadConfig. Unexported (lowercase) members
// are derived from the exported members in LoadConfig.

// TLSListenConfig defines configuration options for listening on TLS.
type TLSListenConfig struct {
	Cert string
	Key  string
}

// Config returns the TLS contiguration assicated with this TLSListenConfig.
func (conf *TLSListenConfig) Config() (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(conf.Cert, conf.Key)
	if err != nil {
		return nil, ErrInvalidCertKeyPair
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
	}, err
}

type AccountConfig struct {
	Registration          AccountRegistrationConfig
	AuthenticationEnabled bool `yaml:"authentication-enabled"`
	RequireSasl           struct {
		Enabled      bool
		Exempted     []string
		exemptedNets []net.IPNet
	} `yaml:"require-sasl"`
	LoginThrottling struct {
		Enabled     bool
		Duration    time.Duration
		MaxAttempts int `yaml:"max-attempts"`
	} `yaml:"login-throttling"`
	SkipServerPassword bool                  `yaml:"skip-server-password"`
	NickReservation    NickReservationConfig `yaml:"nick-reservation"`
	Bouncer            struct {
		Enabled          bool
		AllowedByDefault bool `yaml:"allowed-by-default"`
	}
	VHosts VHostConfig
}

// AccountRegistrationConfig controls account registration.
type AccountRegistrationConfig struct {
	Enabled                bool
	EnabledCallbacks       []string      `yaml:"enabled-callbacks"`
	EnabledCredentialTypes []string      `yaml:"-"`
	VerifyTimeout          time.Duration `yaml:"verify-timeout"`
	Callbacks              struct {
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
	BcryptCost uint `yaml:"bcrypt-cost"`
}

type VHostConfig struct {
	Enabled        bool
	MaxLength      int    `yaml:"max-length"`
	ValidRegexpRaw string `yaml:"valid-regexp"`
	ValidRegexp    *regexp.Regexp
	UserRequests   struct {
		Enabled  bool
		Channel  string
		Cooldown time.Duration
	} `yaml:"user-requests"`
}

type NickReservationMethod int

const (
	// NickReservationOptional is the zero value; it serializes to
	// "optional" in the yaml config, and "default" as an arg to `NS ENFORCE`.
	// in both cases, it means "defer to the other source of truth", i.e.,
	// in the config, defer to the user's custom setting, and as a custom setting,
	// defer to the default in the config. if both are NickReservationOptional then
	// there is no enforcement.
	NickReservationOptional NickReservationMethod = iota
	NickReservationNone
	NickReservationWithTimeout
	NickReservationStrict
)

func nickReservationToString(method NickReservationMethod) string {
	switch method {
	case NickReservationOptional:
		return "default"
	case NickReservationNone:
		return "none"
	case NickReservationWithTimeout:
		return "timeout"
	case NickReservationStrict:
		return "strict"
	default:
		return ""
	}
}

func nickReservationFromString(method string) (NickReservationMethod, error) {
	switch method {
	case "default":
		return NickReservationOptional, nil
	case "optional":
		return NickReservationOptional, nil
	case "none":
		return NickReservationNone, nil
	case "timeout":
		return NickReservationWithTimeout, nil
	case "strict":
		return NickReservationStrict, nil
	default:
		return NickReservationOptional, fmt.Errorf("invalid nick-reservation.method value: %s", method)
	}
}

func (nr *NickReservationMethod) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var orig, raw string
	var err error
	if err = unmarshal(&orig); err != nil {
		return err
	}
	if raw, err = Casefold(orig); err != nil {
		return err
	}
	method, err := nickReservationFromString(raw)
	if err == nil {
		*nr = method
	}
	return err
}

type NickReservationConfig struct {
	Enabled                bool
	AdditionalNickLimit    int `yaml:"additional-nick-limit"`
	Method                 NickReservationMethod
	AllowCustomEnforcement bool          `yaml:"allow-custom-enforcement"`
	RenameTimeout          time.Duration `yaml:"rename-timeout"`
	RenamePrefix           string        `yaml:"rename-prefix"`
}

// ChannelRegistrationConfig controls channel registration.
type ChannelRegistrationConfig struct {
	Enabled               bool
	MaxChannelsPerAccount int `yaml:"max-channels-per-account"`
}

// OperClassConfig defines a specific operator class.
type OperClassConfig struct {
	Title        string
	WhoisLine    string
	Extends      string
	Capabilities []string
}

// OperConfig defines a specific operator's configuration.
type OperConfig struct {
	Class     string
	Vhost     string
	WhoisLine string `yaml:"whois-line"`
	Password  string
	Modes     string
}

// LineLenConfig controls line lengths.
type LineLenLimits struct {
	Rest int
}

// Various server-enforced limits on data size.
type Limits struct {
	AwayLen        int           `yaml:"awaylen"`
	ChanListModes  int           `yaml:"chan-list-modes"`
	ChannelLen     int           `yaml:"channellen"`
	IdentLen       int           `yaml:"identlen"`
	KickLen        int           `yaml:"kicklen"`
	LineLen        LineLenLimits `yaml:"linelen"`
	MonitorEntries int           `yaml:"monitor-entries"`
	NickLen        int           `yaml:"nicklen"`
	TopicLen       int           `yaml:"topiclen"`
	WhowasEntries  int           `yaml:"whowas-entries"`
}

// STSConfig controls the STS configuration/
type STSConfig struct {
	Enabled        bool
	Duration       time.Duration `yaml:"duration-real"`
	DurationString string        `yaml:"duration"`
	Port           int
	Preload        bool
}

// Value returns the STS value to advertise in CAP
func (sts *STSConfig) Value() string {
	val := fmt.Sprintf("duration=%d", int(sts.Duration.Seconds()))
	if sts.Enabled && sts.Port > 0 {
		val += fmt.Sprintf(",port=%d", sts.Port)
	}
	if sts.Enabled && sts.Preload {
		val += ",preload"
	}
	return val
}

type FakelagConfig struct {
	Enabled           bool
	Window            time.Duration
	BurstLimit        uint `yaml:"burst-limit"`
	MessagesPerWindow uint `yaml:"messages-per-window"`
	Cooldown          time.Duration
}

type TorListenersConfig struct {
	Listeners                 []string
	RequireSasl               bool `yaml:"require-sasl"`
	Vhost                     string
	MaxConnections            int           `yaml:"max-connections"`
	ThrottleDuration          time.Duration `yaml:"throttle-duration"`
	MaxConnectionsPerDuration int           `yaml:"max-connections-per-duration"`
}

// Config defines the overall configuration.
type Config struct {
	Network struct {
		Name string
	}

	Server struct {
		Password             string
		passwordBytes        []byte
		Name                 string
		nameCasefolded       string
		Listen               []string
		UnixBindMode         os.FileMode                 `yaml:"unix-bind-mode"`
		TLSListeners         map[string]*TLSListenConfig `yaml:"tls-listeners"`
		TorListeners         TorListenersConfig          `yaml:"tor-listeners"`
		STS                  STSConfig
		CheckIdent           bool `yaml:"check-ident"`
		MOTD                 string
		motdLines            []string
		MOTDFormatting       bool     `yaml:"motd-formatting"`
		ProxyAllowedFrom     []string `yaml:"proxy-allowed-from"`
		proxyAllowedFromNets []net.IPNet
		WebIRC               []webircConfig `yaml:"webirc"`
		MaxSendQString       string         `yaml:"max-sendq"`
		MaxSendQBytes        int
		AllowPlaintextResume bool `yaml:"allow-plaintext-resume"`
		Compatibility        struct {
			ForceTrailing      *bool `yaml:"force-trailing"`
			forceTrailing      bool
			SendUnprefixedSasl bool `yaml:"send-unprefixed-sasl"`
		}
		isupport            isupport.List
		ConnectionLimiter   connection_limits.LimiterConfig   `yaml:"connection-limits"`
		ConnectionThrottler connection_limits.ThrottlerConfig `yaml:"connection-throttling"`
	}

	Languages struct {
		Enabled bool
		Path    string
		Default string
	}

	languageManager *languages.Manager

	Datastore struct {
		Path        string
		AutoUpgrade bool
	}

	Accounts AccountConfig

	Channels struct {
		DefaultModes         *string `yaml:"default-modes"`
		defaultModes         modes.Modes
		MaxChannelsPerClient int `yaml:"max-channels-per-client"`
		Registration         ChannelRegistrationConfig
	}

	OperClasses map[string]*OperClassConfig `yaml:"oper-classes"`

	Opers map[string]*OperConfig

	// parsed operator definitions, unexported so they can't be defined
	// directly in YAML:
	operators map[string]*Oper

	Logging []logger.LoggingConfig

	Debug struct {
		RecoverFromErrors *bool   `yaml:"recover-from-errors"`
		PprofListener     *string `yaml:"pprof-listener"`
	}

	Limits Limits

	Fakelag FakelagConfig

	History struct {
		Enabled          bool
		ChannelLength    int `yaml:"channel-length"`
		ClientLength     int `yaml:"client-length"`
		AutoreplayOnJoin int `yaml:"autoreplay-on-join"`
		ChathistoryMax   int `yaml:"chathistory-maxmessages"`
	}

	Filename string
}

// OperClass defines an assembled operator class.
type OperClass struct {
	Title        string
	WhoisLine    string          `yaml:"whois-line"`
	Capabilities map[string]bool // map to make lookups much easier
}

// OperatorClasses returns a map of assembled operator classes from the given config.
func (conf *Config) OperatorClasses() (map[string]*OperClass, error) {
	ocs := make(map[string]*OperClass)

	// loop from no extends to most extended, breaking if we can't add any more
	lenOfLastOcs := -1
	for {
		if lenOfLastOcs == len(ocs) {
			return nil, ErrOperClassDependencies
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
				einfo := ocs[info.Extends]

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

			ocs[name] = &oc
		}

		if !anyMissing {
			// we've got every operclass!
			break
		}
	}

	return ocs, nil
}

// Oper represents a single assembled operator's config.
type Oper struct {
	Name      string
	Class     *OperClass
	WhoisLine string
	Vhost     string
	Pass      []byte
	Modes     []modes.ModeChange
}

// Operators returns a map of operator configs from the given OperClass and config.
func (conf *Config) Operators(oc map[string]*OperClass) (map[string]*Oper, error) {
	operators := make(map[string]*Oper)
	for name, opConf := range conf.Opers {
		var oper Oper

		// oper name
		name, err := CasefoldName(name)
		if err != nil {
			return nil, fmt.Errorf("Could not casefold oper name: %s", err.Error())
		}
		oper.Name = name

		oper.Pass, err = decodeLegacyPasswordHash(opConf.Password)
		if err != nil {
			return nil, err
		}

		oper.Vhost = opConf.Vhost
		class, exists := oc[opConf.Class]
		if !exists {
			return nil, fmt.Errorf("Could not load operator [%s] - they use operclass [%s] which does not exist", name, opConf.Class)
		}
		oper.Class = class
		if len(opConf.WhoisLine) > 0 {
			oper.WhoisLine = opConf.WhoisLine
		} else {
			oper.WhoisLine = class.WhoisLine
		}
		modeStr := strings.TrimSpace(opConf.Modes)
		modeChanges, unknownChanges := modes.ParseUserModeChanges(strings.Split(modeStr, " ")...)
		if len(unknownChanges) > 0 {
			return nil, fmt.Errorf("Could not load operator [%s] due to unknown modes %v", name, unknownChanges)
		}
		oper.Modes = modeChanges

		// successful, attach to list of opers
		operators[name] = &oper
	}
	return operators, nil
}

// TLSListeners returns a list of TLS listeners and their configs.
func (conf *Config) TLSListeners() (map[string]*tls.Config, error) {
	tlsListeners := make(map[string]*tls.Config)
	for s, tlsListenersConf := range conf.Server.TLSListeners {
		config, err := tlsListenersConf.Config()
		if err != nil {
			return nil, err
		}
		config.ClientAuth = tls.RequestClientCert
		tlsListeners[s] = config
	}
	return tlsListeners, nil
}

// LoadConfig loads the given YAML configuration file.
func LoadConfig(filename string) (config *Config, err error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return nil, err
	}

	config.Filename = filename

	if config.Network.Name == "" {
		return nil, ErrNetworkNameMissing
	}
	if config.Server.Name == "" {
		return nil, ErrServerNameMissing
	}
	if !utils.IsHostname(config.Server.Name) {
		return nil, ErrServerNameNotHostname
	}
	if config.Datastore.Path == "" {
		return nil, ErrDatastorePathMissing
	}
	if len(config.Server.Listen) == 0 {
		return nil, ErrNoListenersDefined
	}
	//dan: automagically fix identlen until a few releases in the future (from now, 0.12.0), being a newly-introduced limit
	if config.Limits.IdentLen < 1 {
		config.Limits.IdentLen = 20
	}
	if config.Limits.NickLen < 1 || config.Limits.ChannelLen < 2 || config.Limits.AwayLen < 1 || config.Limits.KickLen < 1 || config.Limits.TopicLen < 1 {
		return nil, ErrLimitsAreInsane
	}
	if config.Server.STS.Enabled {
		config.Server.STS.Duration, err = custime.ParseDuration(config.Server.STS.DurationString)
		if err != nil {
			return nil, fmt.Errorf("Could not parse STS duration: %s", err.Error())
		}
		if config.Server.STS.Port < 0 || config.Server.STS.Port > 65535 {
			return nil, fmt.Errorf("STS port is incorrect, should be 0 if disabled: %d", config.Server.STS.Port)
		}
	}
	if config.Server.ConnectionThrottler.Enabled {
		config.Server.ConnectionThrottler.Duration, err = time.ParseDuration(config.Server.ConnectionThrottler.DurationString)
		if err != nil {
			return nil, fmt.Errorf("Could not parse connection-throttle duration: %s", err.Error())
		}
		config.Server.ConnectionThrottler.BanDuration, err = time.ParseDuration(config.Server.ConnectionThrottler.BanDurationString)
		if err != nil {
			return nil, fmt.Errorf("Could not parse connection-throttle ban-duration: %s", err.Error())
		}
	}
	// process webirc blocks
	var newWebIRC []webircConfig
	for _, webirc := range config.Server.WebIRC {
		// skip webirc blocks with no hosts (such as the example one)
		if len(webirc.Hosts) == 0 {
			continue
		}

		err = webirc.Populate()
		if err != nil {
			return nil, fmt.Errorf("Could not parse WebIRC config: %s", err.Error())
		}
		newWebIRC = append(newWebIRC, webirc)
	}
	config.Server.WebIRC = newWebIRC
	// process limits
	if config.Limits.LineLen.Rest < 512 {
		config.Limits.LineLen.Rest = 512
	}
	var newLogConfigs []logger.LoggingConfig
	for _, logConfig := range config.Logging {
		// methods
		methods := make(map[string]bool)
		for _, method := range strings.Split(logConfig.Method, " ") {
			if len(method) > 0 {
				methods[strings.ToLower(method)] = true
			}
		}
		if methods["file"] && logConfig.Filename == "" {
			return nil, ErrLoggerFilenameMissing
		}
		logConfig.MethodFile = methods["file"]
		logConfig.MethodStdout = methods["stdout"]
		logConfig.MethodStderr = methods["stderr"]

		// levels
		level, exists := logger.LogLevelNames[strings.ToLower(logConfig.LevelString)]
		if !exists {
			return nil, fmt.Errorf("Could not translate log leve [%s]", logConfig.LevelString)
		}
		logConfig.Level = level

		// types
		for _, typeStr := range strings.Split(logConfig.TypeString, " ") {
			if len(typeStr) == 0 {
				continue
			}
			if typeStr == "-" {
				return nil, ErrLoggerExcludeEmpty
			}
			if typeStr[0] == '-' {
				typeStr = typeStr[1:]
				logConfig.ExcludedTypes = append(logConfig.ExcludedTypes, typeStr)
			} else {
				logConfig.Types = append(logConfig.Types, typeStr)
			}
		}
		if len(logConfig.Types) < 1 {
			return nil, ErrLoggerHasNoTypes
		}

		newLogConfigs = append(newLogConfigs, logConfig)
	}
	config.Logging = newLogConfigs

	// hardcode this for now
	config.Accounts.Registration.EnabledCredentialTypes = []string{"passphrase", "certfp"}
	for i, name := range config.Accounts.Registration.EnabledCallbacks {
		if name == "none" {
			// we store "none" as "*" internally
			config.Accounts.Registration.EnabledCallbacks[i] = "*"
		}
	}
	sort.Strings(config.Accounts.Registration.EnabledCallbacks)

	config.Accounts.RequireSasl.exemptedNets, err = utils.ParseNetList(config.Accounts.RequireSasl.Exempted)
	if err != nil {
		return nil, fmt.Errorf("Could not parse require-sasl exempted nets: %v", err.Error())
	}

	config.Server.proxyAllowedFromNets, err = utils.ParseNetList(config.Server.ProxyAllowedFrom)
	if err != nil {
		return nil, fmt.Errorf("Could not parse proxy-allowed-from nets: %v", err.Error())
	}

	rawRegexp := config.Accounts.VHosts.ValidRegexpRaw
	if rawRegexp != "" {
		regexp, err := regexp.Compile(rawRegexp)
		if err == nil {
			config.Accounts.VHosts.ValidRegexp = regexp
		} else {
			log.Printf("invalid vhost regexp: %s\n", err.Error())
		}
	}
	if config.Accounts.VHosts.ValidRegexp == nil {
		config.Accounts.VHosts.ValidRegexp = defaultValidVhostRegex
	}

	if !config.Accounts.LoginThrottling.Enabled {
		config.Accounts.LoginThrottling.MaxAttempts = 0 // limit of 0 means disabled
	}

	maxSendQBytes, err := bytefmt.ToBytes(config.Server.MaxSendQString)
	if err != nil {
		return nil, fmt.Errorf("Could not parse maximum SendQ size (make sure it only contains whole numbers): %s", err.Error())
	}
	config.Server.MaxSendQBytes = int(maxSendQBytes)

	config.languageManager, err = languages.NewManager(config.Languages.Enabled, config.Languages.Path, config.Languages.Default)
	if err != nil {
		return nil, fmt.Errorf("Could not load languages: %s", err.Error())
	}

	// RecoverFromErrors defaults to true
	if config.Debug.RecoverFromErrors == nil {
		config.Debug.RecoverFromErrors = new(bool)
		*config.Debug.RecoverFromErrors = true
	}

	// casefold/validate server name
	config.Server.nameCasefolded, err = Casefold(config.Server.Name)
	if err != nil {
		return nil, fmt.Errorf("Server name isn't valid [%s]: %s", config.Server.Name, err.Error())
	}

	// process operator definitions, store them to config.operators
	operclasses, err := config.OperatorClasses()
	if err != nil {
		return nil, err
	}
	opers, err := config.Operators(operclasses)
	if err != nil {
		return nil, err
	}
	config.operators = opers

	// parse default channel modes
	config.Channels.defaultModes = ParseDefaultChannelModes(config.Channels.DefaultModes)

	if config.Server.Password != "" {
		config.Server.passwordBytes, err = decodeLegacyPasswordHash(config.Server.Password)
		if err != nil {
			return nil, err
		}
	}

	if config.Accounts.Registration.BcryptCost == 0 {
		config.Accounts.Registration.BcryptCost = passwd.DefaultCost
	}

	if config.Channels.MaxChannelsPerClient == 0 {
		config.Channels.MaxChannelsPerClient = 100
	}
	if config.Channels.Registration.MaxChannelsPerAccount == 0 {
		config.Channels.Registration.MaxChannelsPerAccount = 15
	}

	forceTrailingPtr := config.Server.Compatibility.ForceTrailing
	if forceTrailingPtr != nil {
		config.Server.Compatibility.forceTrailing = *forceTrailingPtr
	} else {
		config.Server.Compatibility.forceTrailing = true
	}

	config.loadMOTD()

	err = config.generateISupport()
	if err != nil {
		return nil, err
	}

	// in the current implementation, we disable history by creating a history buffer
	// with zero capacity. but the `enabled` config option MUST be respected regardless
	// of this detail
	if !config.History.Enabled {
		config.History.ChannelLength = 0
		config.History.ClientLength = 0
	}

	for _, listenAddress := range config.Server.TorListeners.Listeners {
		found := false
		for _, configuredListener := range config.Server.Listen {
			if listenAddress == configuredListener {
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("%s is configured as a Tor listener, but is not in server.listen", listenAddress)
		}
	}

	return config, nil
}
