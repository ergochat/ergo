// Copyright (c) 2012-2014 Jeremy Latt
// Copyright (c) 2014-2015 Edmund Huber
// Copyright (c) 2016-2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"code.cloudfoundry.org/bytefmt"
	"github.com/goshuirc/irc-go/ircfmt"
	"gopkg.in/yaml.v2"

	"github.com/oragono/oragono/irc/caps"
	"github.com/oragono/oragono/irc/cloaks"
	"github.com/oragono/oragono/irc/connection_limits"
	"github.com/oragono/oragono/irc/custime"
	"github.com/oragono/oragono/irc/email"
	"github.com/oragono/oragono/irc/isupport"
	"github.com/oragono/oragono/irc/jwt"
	"github.com/oragono/oragono/irc/languages"
	"github.com/oragono/oragono/irc/logger"
	"github.com/oragono/oragono/irc/modes"
	"github.com/oragono/oragono/irc/mysql"
	"github.com/oragono/oragono/irc/passwd"
	"github.com/oragono/oragono/irc/utils"
)

// here's how this works: exported (capitalized) members of the config structs
// are defined in the YAML file and deserialized directly from there. They may
// be postprocessed and overwritten by LoadConfig. Unexported (lowercase) members
// are derived from the exported members in LoadConfig.

// TLSListenConfig defines configuration options for listening on TLS.
type TLSListenConfig struct {
	Cert  string
	Key   string
	Proxy bool
}

// This is the YAML-deserializable type of the value of the `Server.Listeners` map
type listenerConfigBlock struct {
	TLS       TLSListenConfig
	Tor       bool
	STSOnly   bool `yaml:"sts-only"`
	WebSocket bool
}

type PersistentStatus uint

const (
	PersistentUnspecified PersistentStatus = iota
	PersistentDisabled
	PersistentOptIn
	PersistentOptOut
	PersistentMandatory
)

func persistentStatusToString(status PersistentStatus) string {
	switch status {
	case PersistentUnspecified:
		return "default"
	case PersistentDisabled:
		return "disabled"
	case PersistentOptIn:
		return "opt-in"
	case PersistentOptOut:
		return "opt-out"
	case PersistentMandatory:
		return "mandatory"
	default:
		return ""
	}
}

func persistentStatusFromString(status string) (PersistentStatus, error) {
	switch strings.ToLower(status) {
	case "default":
		return PersistentUnspecified, nil
	case "":
		return PersistentDisabled, nil
	case "opt-in":
		return PersistentOptIn, nil
	case "opt-out":
		return PersistentOptOut, nil
	case "mandatory":
		return PersistentMandatory, nil
	default:
		b, err := utils.StringToBool(status)
		if b {
			return PersistentMandatory, err
		} else {
			return PersistentDisabled, err
		}
	}
}

func (ps *PersistentStatus) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var orig string
	var err error
	if err = unmarshal(&orig); err != nil {
		return err
	}
	result, err := persistentStatusFromString(orig)
	if err == nil {
		if result == PersistentUnspecified {
			result = PersistentDisabled
		}
		*ps = result
	}
	return err
}

func persistenceEnabled(serverSetting, clientSetting PersistentStatus) (enabled bool) {
	if serverSetting == PersistentDisabled {
		return false
	} else if serverSetting == PersistentMandatory {
		return true
	} else if clientSetting == PersistentDisabled {
		return false
	} else if clientSetting == PersistentMandatory {
		return true
	} else if serverSetting == PersistentOptOut {
		return true
	} else {
		return false
	}
}

type HistoryStatus uint

const (
	HistoryDefault HistoryStatus = iota
	HistoryDisabled
	HistoryEphemeral
	HistoryPersistent
)

func historyStatusFromString(str string) (status HistoryStatus, err error) {
	switch strings.ToLower(str) {
	case "default":
		return HistoryDefault, nil
	case "ephemeral":
		return HistoryEphemeral, nil
	case "persistent":
		return HistoryPersistent, nil
	default:
		b, err := utils.StringToBool(str)
		if b {
			return HistoryPersistent, err
		} else {
			return HistoryDisabled, err
		}
	}
}

func historyStatusToString(status HistoryStatus) string {
	switch status {
	case HistoryDefault:
		return "default"
	case HistoryDisabled:
		return "disabled"
	case HistoryEphemeral:
		return "ephemeral"
	case HistoryPersistent:
		return "persistent"
	default:
		return ""
	}
}

// XXX you must have already checked History.Enabled before calling this
func historyEnabled(serverSetting PersistentStatus, localSetting HistoryStatus) (result HistoryStatus) {
	switch serverSetting {
	case PersistentMandatory:
		return HistoryPersistent
	case PersistentOptOut:
		if localSetting == HistoryDefault {
			return HistoryPersistent
		} else {
			return localSetting
		}
	case PersistentOptIn:
		switch localSetting {
		case HistoryPersistent:
			return HistoryPersistent
		case HistoryEphemeral, HistoryDefault:
			return HistoryEphemeral
		default:
			return HistoryDisabled
		}
	case PersistentDisabled:
		if localSetting == HistoryDisabled {
			return HistoryDisabled
		} else {
			return HistoryEphemeral
		}
	default:
		// PersistentUnspecified: shouldn't happen because the deserializer converts it
		// to PersistentDisabled
		if localSetting == HistoryDefault {
			return HistoryEphemeral
		} else {
			return localSetting
		}
	}
}

type MulticlientConfig struct {
	Enabled          bool
	AllowedByDefault bool             `yaml:"allowed-by-default"`
	AlwaysOn         PersistentStatus `yaml:"always-on"`
	AutoAway         PersistentStatus `yaml:"auto-away"`
}

type throttleConfig struct {
	Enabled     bool
	Duration    time.Duration
	MaxAttempts int `yaml:"max-attempts"`
}

type ThrottleConfig struct {
	throttleConfig
}

func (t *ThrottleConfig) UnmarshalYAML(unmarshal func(interface{}) error) (err error) {
	// note that this technique only works if the zero value of the struct
	// doesn't need any postprocessing (because if the field is omitted entirely
	// from the YAML, then UnmarshalYAML won't be called at all)
	if err = unmarshal(&t.throttleConfig); err != nil {
		return
	}
	if !t.Enabled {
		t.MaxAttempts = 0 // limit of 0 means disabled
	}
	return
}

type AccountConfig struct {
	Registration          AccountRegistrationConfig
	AuthenticationEnabled bool `yaml:"authentication-enabled"`
	RequireSasl           struct {
		Enabled      bool
		Exempted     []string
		exemptedNets []net.IPNet
	} `yaml:"require-sasl"`
	DefaultUserModes    *string `yaml:"default-user-modes"`
	defaultUserModes    modes.Modes
	LoginThrottling     ThrottleConfig `yaml:"login-throttling"`
	SkipServerPassword  bool           `yaml:"skip-server-password"`
	LoginViaPassCommand bool           `yaml:"login-via-pass-command"`
	NickReservation     struct {
		Enabled                bool
		AdditionalNickLimit    int `yaml:"additional-nick-limit"`
		Method                 NickEnforcementMethod
		AllowCustomEnforcement bool          `yaml:"allow-custom-enforcement"`
		RenameTimeout          time.Duration `yaml:"rename-timeout"`
		// RenamePrefix is the legacy field, GuestFormat is the new version
		RenamePrefix           string `yaml:"rename-prefix"`
		GuestFormat            string `yaml:"guest-nickname-format"`
		guestRegexp            *regexp.Regexp
		guestRegexpFolded      *regexp.Regexp
		ForceGuestFormat       bool `yaml:"force-guest-format"`
		ForceNickEqualsAccount bool `yaml:"force-nick-equals-account"`
	} `yaml:"nick-reservation"`
	Multiclient MulticlientConfig
	Bouncer     *MulticlientConfig // # handle old name for 'multiclient'
	VHosts      VHostConfig
	AuthScript  AuthScriptConfig `yaml:"auth-script"`
}

type AuthScriptConfig struct {
	Enabled     bool
	Command     string
	Args        []string
	Autocreate  bool
	Timeout     time.Duration
	KillTimeout time.Duration `yaml:"kill-timeout"`
}

// AccountRegistrationConfig controls account registration.
type AccountRegistrationConfig struct {
	Enabled                bool
	Throttling             ThrottleConfig
	EnabledCallbacks       []string         `yaml:"enabled-callbacks"`
	EnabledCredentialTypes []string         `yaml:"-"`
	VerifyTimeout          custime.Duration `yaml:"verify-timeout"`
	Callbacks              struct {
		Mailto email.MailtoConfig
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
		Cooldown custime.Duration
	} `yaml:"user-requests"`
	OfferList []string `yaml:"offer-list"`
}

type NickEnforcementMethod int

const (
	// NickEnforcementOptional is the zero value; it serializes to
	// "optional" in the yaml config, and "default" as an arg to `NS ENFORCE`.
	// in both cases, it means "defer to the other source of truth", i.e.,
	// in the config, defer to the user's custom setting, and as a custom setting,
	// defer to the default in the config. if both are NickEnforcementOptional then
	// there is no enforcement.
	// XXX: these are serialized as numbers in the database, so beware of collisions
	// when refactoring (any numbers currently in use must keep their meanings, or
	// else be fixed up by a schema change)
	NickEnforcementOptional NickEnforcementMethod = iota
	NickEnforcementNone
	NickEnforcementStrict
)

func nickReservationToString(method NickEnforcementMethod) string {
	switch method {
	case NickEnforcementOptional:
		return "default"
	case NickEnforcementNone:
		return "none"
	case NickEnforcementStrict:
		return "strict"
	default:
		return ""
	}
}

func nickReservationFromString(method string) (NickEnforcementMethod, error) {
	switch strings.ToLower(method) {
	case "default":
		return NickEnforcementOptional, nil
	case "optional":
		return NickEnforcementOptional, nil
	case "none":
		return NickEnforcementNone, nil
	case "strict":
		return NickEnforcementStrict, nil
	default:
		return NickEnforcementOptional, fmt.Errorf("invalid nick-reservation.method value: %s", method)
	}
}

func (nr *NickEnforcementMethod) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var orig string
	var err error
	if err = unmarshal(&orig); err != nil {
		return err
	}
	method, err := nickReservationFromString(orig)
	if err == nil {
		*nr = method
	}
	return err
}

func (cm *Casemapping) UnmarshalYAML(unmarshal func(interface{}) error) (err error) {
	var orig string
	if err = unmarshal(&orig); err != nil {
		return err
	}

	var result Casemapping
	switch strings.ToLower(orig) {
	case "ascii":
		result = CasemappingASCII
	case "precis", "rfc7613", "rfc8265":
		result = CasemappingPRECIS
	case "permissive", "fun":
		result = CasemappingPermissive
	default:
		return fmt.Errorf("invalid casemapping value: %s", orig)
	}
	*cm = result
	return nil
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
	Class       string
	Vhost       string
	WhoisLine   string `yaml:"whois-line"`
	Password    string
	Fingerprint *string // legacy name for certfp, #1050
	Certfp      string
	Auto        bool
	Modes       string
}

// Various server-enforced limits on data size.
type Limits struct {
	AwayLen              int `yaml:"awaylen"`
	ChanListModes        int `yaml:"chan-list-modes"`
	ChannelLen           int `yaml:"channellen"`
	IdentLen             int `yaml:"identlen"`
	KickLen              int `yaml:"kicklen"`
	MonitorEntries       int `yaml:"monitor-entries"`
	NickLen              int `yaml:"nicklen"`
	TopicLen             int `yaml:"topiclen"`
	WhowasEntries        int `yaml:"whowas-entries"`
	RegistrationMessages int `yaml:"registration-messages"`
	Multiline            struct {
		MaxBytes int `yaml:"max-bytes"`
		MaxLines int `yaml:"max-lines"`
	}
}

// STSConfig controls the STS configuration/
type STSConfig struct {
	Enabled       bool
	Duration      custime.Duration
	Port          int
	Preload       bool
	STSOnlyBanner string `yaml:"sts-only-banner"`
	bannerLines   []string
}

// Value returns the STS value to advertise in CAP
func (sts *STSConfig) Value() string {
	val := fmt.Sprintf("duration=%d", int(time.Duration(sts.Duration).Seconds()))
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
	Listeners                 []string // legacy only
	RequireSasl               bool     `yaml:"require-sasl"`
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
		Password       string
		passwordBytes  []byte
		Name           string
		nameCasefolded string
		// Listeners is the new style for configuring listeners:
		Listeners    map[string]listenerConfigBlock
		UnixBindMode os.FileMode        `yaml:"unix-bind-mode"`
		TorListeners TorListenersConfig `yaml:"tor-listeners"`
		WebSockets   struct {
			AllowedOrigins       []string `yaml:"allowed-origins"`
			allowedOriginRegexps []*regexp.Regexp
		}
		// they get parsed into this internal representation:
		trueListeners           map[string]utils.ListenerConfig
		STS                     STSConfig
		LookupHostnames         *bool `yaml:"lookup-hostnames"`
		lookupHostnames         bool
		ForwardConfirmHostnames bool `yaml:"forward-confirm-hostnames"`
		CheckIdent              bool `yaml:"check-ident"`
		MOTD                    string
		motdLines               []string
		MOTDFormatting          bool     `yaml:"motd-formatting"`
		ProxyAllowedFrom        []string `yaml:"proxy-allowed-from"`
		proxyAllowedFromNets    []net.IPNet
		WebIRC                  []webircConfig `yaml:"webirc"`
		MaxSendQString          string         `yaml:"max-sendq"`
		MaxSendQBytes           int
		AllowPlaintextResume    bool `yaml:"allow-plaintext-resume"`
		Compatibility           struct {
			ForceTrailing      *bool `yaml:"force-trailing"`
			forceTrailing      bool
			SendUnprefixedSasl bool `yaml:"send-unprefixed-sasl"`
		}
		isupport      isupport.List
		IPLimits      connection_limits.LimiterConfig `yaml:"ip-limits"`
		Cloaks        cloaks.CloakConfig              `yaml:"ip-cloaking"`
		SecureNetDefs []string                        `yaml:"secure-nets"`
		secureNets    []net.IPNet
		supportedCaps *caps.Set
		capValues     caps.Values
		Casemapping   Casemapping
		EnforceUtf8   bool   `yaml:"enforce-utf8"`
		OutputPath    string `yaml:"output-path"`
	}

	Roleplay struct {
		Enabled        *bool
		enabled        bool
		RequireChanops bool  `yaml:"require-chanops"`
		RequireOper    bool  `yaml:"require-oper"`
		AddSuffix      *bool `yaml:"add-suffix"`
		addSuffix      bool
	}

	Extjwt struct {
		Default  jwt.JwtServiceConfig            `yaml:",inline"`
		Services map[string]jwt.JwtServiceConfig `yaml:"services"`
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
		MySQL       mysql.Config
	}

	Accounts AccountConfig

	Channels struct {
		DefaultModes         *string `yaml:"default-modes"`
		defaultModes         modes.Modes
		MaxChannelsPerClient int  `yaml:"max-channels-per-client"`
		OpOnlyCreation       bool `yaml:"operator-only-creation"`
		Registration         struct {
			Enabled               bool
			OperatorOnly          bool `yaml:"operator-only"`
			MaxChannelsPerAccount int  `yaml:"max-channels-per-account"`
		}
		ListDelay time.Duration `yaml:"list-delay"`
	}

	OperClasses map[string]*OperClassConfig `yaml:"oper-classes"`

	Opers map[string]*OperConfig

	// parsed operator definitions, unexported so they can't be defined
	// directly in YAML:
	operators map[string]*Oper

	Logging []logger.LoggingConfig

	Debug struct {
		RecoverFromErrors *bool `yaml:"recover-from-errors"`
		recoverFromErrors bool
		PprofListener     *string `yaml:"pprof-listener"`
	}

	Limits Limits

	Fakelag FakelagConfig

	History struct {
		Enabled          bool
		ChannelLength    int              `yaml:"channel-length"`
		ClientLength     int              `yaml:"client-length"`
		AutoresizeWindow custime.Duration `yaml:"autoresize-window"`
		AutoreplayOnJoin int              `yaml:"autoreplay-on-join"`
		ChathistoryMax   int              `yaml:"chathistory-maxmessages"`
		ZNCMax           int              `yaml:"znc-maxmessages"`
		Restrictions     struct {
			ExpireTime              custime.Duration `yaml:"expire-time"`
			EnforceRegistrationDate bool             `yaml:"enforce-registration-date"`
			GracePeriod             custime.Duration `yaml:"grace-period"`
		}
		Persistent struct {
			Enabled              bool
			UnregisteredChannels bool             `yaml:"unregistered-channels"`
			RegisteredChannels   PersistentStatus `yaml:"registered-channels"`
			DirectMessages       PersistentStatus `yaml:"direct-messages"`
		}
		Retention struct {
			AllowIndividualDelete bool `yaml:"allow-individual-delete"`
			EnableAccountIndexing bool `yaml:"enable-account-indexing"`
		}
	}

	Filename string
}

// OperClass defines an assembled operator class.
type OperClass struct {
	Title        string
	WhoisLine    string    `yaml:"whois-line"`
	Capabilities StringSet // map to make lookups much easier
}

// OperatorClasses returns a map of assembled operator classes from the given config.
func (conf *Config) OperatorClasses() (map[string]*OperClass, error) {
	fixupCapability := func(capab string) string {
		return strings.TrimPrefix(capab, "oper:") // #868
	}

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
			oc.Capabilities = make(StringSet)

			// get inhereted info from other operclasses
			if len(info.Extends) > 0 {
				einfo := ocs[info.Extends]

				for capab := range einfo.Capabilities {
					oc.Capabilities.Add(fixupCapability(capab))
				}
			}

			// add our own info
			oc.Title = info.Title
			for _, capab := range info.Capabilities {
				oc.Capabilities.Add(fixupCapability(capab))
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
	Certfp    string
	Auto      bool
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

		if opConf.Password != "" {
			oper.Pass, err = decodeLegacyPasswordHash(opConf.Password)
			if err != nil {
				return nil, fmt.Errorf("Oper %s has an invalid password hash: %s", oper.Name, err.Error())
			}
		}
		certfp := opConf.Certfp
		if certfp == "" && opConf.Fingerprint != nil {
			certfp = *opConf.Fingerprint
		}
		if certfp != "" {
			oper.Certfp, err = utils.NormalizeCertfp(certfp)
			if err != nil {
				return nil, fmt.Errorf("Oper %s has an invalid fingerprint: %s", oper.Name, err.Error())
			}
		}
		oper.Auto = opConf.Auto

		if oper.Pass == nil && oper.Certfp == "" {
			return nil, fmt.Errorf("Oper %s has neither a password nor a fingerprint", name)
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

func loadTlsConfig(config TLSListenConfig, webSocket bool) (tlsConfig *tls.Config, err error) {
	cert, err := tls.LoadX509KeyPair(config.Cert, config.Key)
	if err != nil {
		return nil, &CertKeyError{Err: err}
	}
	clientAuth := tls.RequestClientCert
	if webSocket {
		// if Chrome receives a server request for a client certificate
		// on a websocket connection, it will immediately disconnect:
		// https://bugs.chromium.org/p/chromium/issues/detail?id=329884
		// work around this behavior:
		clientAuth = tls.NoClientCert
	}
	result := tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   clientAuth,
	}
	return &result, nil
}

// prepareListeners populates Config.Server.trueListeners
func (conf *Config) prepareListeners() (err error) {
	if len(conf.Server.Listeners) == 0 {
		return fmt.Errorf("No listeners were configured")
	}

	conf.Server.trueListeners = make(map[string]utils.ListenerConfig)
	for addr, block := range conf.Server.Listeners {
		var lconf utils.ListenerConfig
		lconf.ProxyDeadline = RegisterTimeout
		lconf.Tor = block.Tor
		lconf.STSOnly = block.STSOnly
		if lconf.STSOnly && !conf.Server.STS.Enabled {
			return fmt.Errorf("%s is configured as a STS-only listener, but STS is disabled", addr)
		}
		if block.TLS.Cert != "" {
			tlsConfig, err := loadTlsConfig(block.TLS, block.WebSocket)
			if err != nil {
				return err
			}
			lconf.TLSConfig = tlsConfig
			lconf.RequireProxy = block.TLS.Proxy
		}
		lconf.WebSocket = block.WebSocket
		conf.Server.trueListeners[addr] = lconf
	}
	return nil
}

func (config *Config) processExtjwt() (err error) {
	// first process the default service, which may be disabled
	err = config.Extjwt.Default.Postprocess()
	if err != nil {
		return
	}
	// now process the named services. it is an error if any is disabled
	// also, normalize the service names to lowercase
	services := make(map[string]jwt.JwtServiceConfig, len(config.Extjwt.Services))
	for service, sConf := range config.Extjwt.Services {
		err := sConf.Postprocess()
		if err != nil {
			return err
		}
		if !sConf.Enabled() {
			return fmt.Errorf("no keys enabled for extjwt service %s", service)
		}
		services[strings.ToLower(service)] = sConf
	}
	config.Extjwt.Services = services
	return nil
}

// LoadRawConfig loads the config without doing any consistency checks or postprocessing
func LoadRawConfig(filename string) (config *Config, err error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return nil, err
	}
	return
}

// LoadConfig loads the given YAML configuration file.
func LoadConfig(filename string) (config *Config, err error) {
	config, err = LoadRawConfig(filename)
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
	if !utils.IsServerName(config.Server.Name) {
		return nil, ErrServerNameNotHostname
	}
	config.Server.nameCasefolded = strings.ToLower(config.Server.Name)
	if config.Datastore.Path == "" {
		return nil, ErrDatastorePathMissing
	}
	//dan: automagically fix identlen until a few releases in the future (from now, 0.12.0), being a newly-introduced limit
	if config.Limits.IdentLen < 1 {
		config.Limits.IdentLen = 20
	}
	if config.Limits.NickLen < 1 || config.Limits.ChannelLen < 2 || config.Limits.AwayLen < 1 || config.Limits.KickLen < 1 || config.Limits.TopicLen < 1 {
		return nil, ErrLimitsAreInsane
	}
	if config.Limits.RegistrationMessages == 0 {
		config.Limits.RegistrationMessages = 1024
	}
	if config.Datastore.MySQL.Enabled {
		if config.Limits.NickLen > mysql.MaxTargetLength || config.Limits.ChannelLen > mysql.MaxTargetLength {
			return nil, fmt.Errorf("to use MySQL, nick and channel length limits must be %d or lower", mysql.MaxTargetLength)
		}
	}

	config.Server.supportedCaps = caps.NewCompleteSet()
	config.Server.capValues = make(caps.Values)

	err = config.prepareListeners()
	if err != nil {
		return nil, fmt.Errorf("failed to prepare listeners: %v", err)
	}

	for _, glob := range config.Server.WebSockets.AllowedOrigins {
		globre, err := utils.CompileGlob(glob, false)
		if err != nil {
			return nil, fmt.Errorf("invalid websocket allowed-origin expression: %s", glob)
		}
		config.Server.WebSockets.allowedOriginRegexps = append(config.Server.WebSockets.allowedOriginRegexps, globre)
	}

	if config.Server.STS.Enabled {
		if config.Server.STS.Port < 0 || config.Server.STS.Port > 65535 {
			return nil, fmt.Errorf("STS port is incorrect, should be 0 if disabled: %d", config.Server.STS.Port)
		}
		if config.Server.STS.STSOnlyBanner != "" {
			for _, line := range strings.Split(config.Server.STS.STSOnlyBanner, "\n") {
				config.Server.STS.bannerLines = append(config.Server.STS.bannerLines, strings.TrimSpace(line))
			}
		} else {
			config.Server.STS.bannerLines = []string{fmt.Sprintf("This server is only accessible over TLS. Please reconnect using TLS on port %d.", config.Server.STS.Port)}
		}
	} else {
		config.Server.supportedCaps.Disable(caps.STS)
		config.Server.STS.Duration = 0
	}
	// set this even if STS is disabled
	config.Server.capValues[caps.STS] = config.Server.STS.Value()

	config.Server.lookupHostnames = utils.BoolDefaultTrue(config.Server.LookupHostnames)

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

	if config.Limits.Multiline.MaxBytes <= 0 {
		config.Server.supportedCaps.Disable(caps.Multiline)
	} else {
		var multilineCapValue string
		if config.Limits.Multiline.MaxLines == 0 {
			multilineCapValue = fmt.Sprintf("max-bytes=%d", config.Limits.Multiline.MaxBytes)
		} else {
			multilineCapValue = fmt.Sprintf("max-bytes=%d,max-lines=%d", config.Limits.Multiline.MaxBytes, config.Limits.Multiline.MaxLines)
		}
		config.Server.capValues[caps.Multiline] = multilineCapValue
	}

	// handle legacy name 'bouncer' for 'multiclient' section:
	if config.Accounts.Bouncer != nil {
		config.Accounts.Multiclient = *config.Accounts.Bouncer
	}

	if !config.Accounts.Multiclient.Enabled {
		config.Accounts.Multiclient.AlwaysOn = PersistentDisabled
	} else if config.Accounts.Multiclient.AlwaysOn >= PersistentOptOut {
		config.Accounts.Multiclient.AllowedByDefault = true
	}

	if config.Accounts.NickReservation.ForceNickEqualsAccount && !config.Accounts.Multiclient.Enabled {
		return nil, errors.New("force-nick-equals-account requires enabling multiclient as well")
	}

	// handle guest format, including the legacy key rename-prefix
	if config.Accounts.NickReservation.GuestFormat == "" {
		renamePrefix := config.Accounts.NickReservation.RenamePrefix
		if renamePrefix == "" {
			renamePrefix = "Guest-"
		}
		config.Accounts.NickReservation.GuestFormat = renamePrefix + "*"
	}
	config.Accounts.NickReservation.guestRegexp, config.Accounts.NickReservation.guestRegexpFolded, err = compileGuestRegexp(config.Accounts.NickReservation.GuestFormat, config.Server.Casemapping)
	if err != nil {
		return nil, err
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
	mailtoEnabled := false
	for i, name := range config.Accounts.Registration.EnabledCallbacks {
		if name == "none" {
			// we store "none" as "*" internally
			config.Accounts.Registration.EnabledCallbacks[i] = "*"
		} else if name == "mailto" {
			mailtoEnabled = true
		}
	}
	sort.Strings(config.Accounts.Registration.EnabledCallbacks)

	if mailtoEnabled {
		err := config.Accounts.Registration.Callbacks.Mailto.Postprocess(config.Server.Name)
		if err != nil {
			return nil, err
		}
	}

	config.Accounts.defaultUserModes = ParseDefaultUserModes(config.Accounts.DefaultUserModes)

	config.Accounts.RequireSasl.exemptedNets, err = utils.ParseNetList(config.Accounts.RequireSasl.Exempted)
	if err != nil {
		return nil, fmt.Errorf("Could not parse require-sasl exempted nets: %v", err.Error())
	}

	config.Server.proxyAllowedFromNets, err = utils.ParseNetList(config.Server.ProxyAllowedFrom)
	if err != nil {
		return nil, fmt.Errorf("Could not parse proxy-allowed-from nets: %v", err.Error())
	}

	config.Server.secureNets, err = utils.ParseNetList(config.Server.SecureNetDefs)
	if err != nil {
		return nil, fmt.Errorf("Could not parse secure-nets: %v\n", err.Error())
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

	for _, vhost := range config.Accounts.VHosts.OfferList {
		if !config.Accounts.VHosts.ValidRegexp.MatchString(vhost) {
			return nil, fmt.Errorf("invalid offered vhost: %s", vhost)
		}
	}

	config.Server.capValues[caps.SASL] = "PLAIN,EXTERNAL"
	if !config.Accounts.AuthenticationEnabled {
		config.Server.supportedCaps.Disable(caps.SASL)
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
	config.Server.capValues[caps.Languages] = config.languageManager.CapValue()

	config.Debug.recoverFromErrors = utils.BoolDefaultTrue(config.Debug.RecoverFromErrors)

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
		if config.Accounts.LoginViaPassCommand && !config.Accounts.SkipServerPassword {
			return nil, errors.New("Using a server password and login-via-pass-command requires skip-server-password as well")
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

	config.Server.Compatibility.forceTrailing = utils.BoolDefaultTrue(config.Server.Compatibility.ForceTrailing)

	config.loadMOTD()

	// in the current implementation, we disable history by creating a history buffer
	// with zero capacity. but the `enabled` config option MUST be respected regardless
	// of this detail
	if !config.History.Enabled {
		config.History.ChannelLength = 0
		config.History.ClientLength = 0
	}

	if !config.History.Enabled || !config.History.Persistent.Enabled {
		config.History.Persistent.UnregisteredChannels = false
		config.History.Persistent.RegisteredChannels = PersistentDisabled
		config.History.Persistent.DirectMessages = PersistentDisabled
	}

	if config.History.ZNCMax == 0 {
		config.History.ZNCMax = config.History.ChathistoryMax
	}

	config.Roleplay.enabled = utils.BoolDefaultTrue(config.Roleplay.Enabled)
	config.Roleplay.addSuffix = utils.BoolDefaultTrue(config.Roleplay.AddSuffix)

	config.Datastore.MySQL.ExpireTime = time.Duration(config.History.Restrictions.ExpireTime)
	config.Datastore.MySQL.TrackAccountMessages = config.History.Retention.EnableAccountIndexing

	config.Server.Cloaks.Initialize()
	if config.Server.Cloaks.Enabled {
		if !utils.IsHostname(config.Server.Cloaks.Netname) {
			return nil, fmt.Errorf("Invalid netname for cloaked hostnames: %s", config.Server.Cloaks.Netname)
		}
	}

	err = config.processExtjwt()
	if err != nil {
		return nil, err
	}

	// now that all postprocessing is complete, regenerate ISUPPORT:
	err = config.generateISupport()
	if err != nil {
		return nil, err
	}

	err = config.prepareListeners()
	if err != nil {
		return nil, fmt.Errorf("failed to prepare listeners: %v", err)
	}

	return config, nil
}

func (config *Config) getOutputPath(filename string) string {
	return filepath.Join(config.Server.OutputPath, filename)
}

// setISupport sets up our RPL_ISUPPORT reply.
func (config *Config) generateISupport() (err error) {
	maxTargetsString := strconv.Itoa(maxTargets)

	// add RPL_ISUPPORT tokens
	isupport := &config.Server.isupport
	isupport.Initialize()
	isupport.Add("AWAYLEN", strconv.Itoa(config.Limits.AwayLen))
	isupport.Add("BOT", "B")
	isupport.Add("CASEMAPPING", "ascii")
	isupport.Add("CHANLIMIT", fmt.Sprintf("%s:%d", chanTypes, config.Channels.MaxChannelsPerClient))
	isupport.Add("CHANMODES", strings.Join([]string{modes.Modes{modes.BanMask, modes.ExceptMask, modes.InviteMask}.String(), modes.Modes{modes.Key}.String(), modes.Modes{modes.UserLimit}.String(), modes.Modes{modes.InviteOnly, modes.Moderated, modes.NoOutside, modes.OpOnlyTopic, modes.ChanRoleplaying, modes.Secret, modes.NoCTCP, modes.RegisteredOnly}.String()}, ","))
	if config.History.Enabled && config.History.ChathistoryMax > 0 {
		isupport.Add("draft/CHATHISTORY", strconv.Itoa(config.History.ChathistoryMax))
	}
	isupport.Add("CHANNELLEN", strconv.Itoa(config.Limits.ChannelLen))
	isupport.Add("CHANTYPES", chanTypes)
	isupport.Add("ELIST", "U")
	isupport.Add("EXCEPTS", "")
	if config.Extjwt.Default.Enabled() || len(config.Extjwt.Services) != 0 {
		isupport.Add("EXTJWT", "1")
	}
	isupport.Add("INVEX", "")
	isupport.Add("KICKLEN", strconv.Itoa(config.Limits.KickLen))
	isupport.Add("MAXLIST", fmt.Sprintf("beI:%s", strconv.Itoa(config.Limits.ChanListModes)))
	isupport.Add("MAXTARGETS", maxTargetsString)
	isupport.Add("MODES", "")
	isupport.Add("MONITOR", strconv.Itoa(config.Limits.MonitorEntries))
	isupport.Add("NETWORK", config.Network.Name)
	isupport.Add("NICKLEN", strconv.Itoa(config.Limits.NickLen))
	isupport.Add("PREFIX", "(qaohv)~&@%+")
	if config.Roleplay.enabled {
		isupport.Add("RPCHAN", "E")
		isupport.Add("RPUSER", "E")
	}
	isupport.Add("STATUSMSG", "~&@%+")
	isupport.Add("TARGMAX", fmt.Sprintf("NAMES:1,LIST:1,KICK:1,WHOIS:1,USERHOST:10,PRIVMSG:%s,TAGMSG:%s,NOTICE:%s,MONITOR:%d", maxTargetsString, maxTargetsString, maxTargetsString, config.Limits.MonitorEntries))
	isupport.Add("TOPICLEN", strconv.Itoa(config.Limits.TopicLen))
	if config.Server.Casemapping == CasemappingPRECIS {
		isupport.Add("UTF8MAPPING", precisUTF8MappingToken)
	}
	isupport.Add("WHOX", "")

	err = isupport.RegenerateCachedReply()
	return
}

// Diff returns changes in supported caps across a rehash.
func (config *Config) Diff(oldConfig *Config) (addedCaps, removedCaps *caps.Set) {
	addedCaps = caps.NewSet()
	removedCaps = caps.NewSet()
	if oldConfig == nil {
		return
	}

	if oldConfig.Server.capValues[caps.Languages] != config.Server.capValues[caps.Languages] {
		// XXX updated caps get a DEL line and then a NEW line with the new value
		addedCaps.Add(caps.Languages)
		removedCaps.Add(caps.Languages)
	}

	if !oldConfig.Accounts.AuthenticationEnabled && config.Accounts.AuthenticationEnabled {
		addedCaps.Add(caps.SASL)
	} else if oldConfig.Accounts.AuthenticationEnabled && !config.Accounts.AuthenticationEnabled {
		removedCaps.Add(caps.SASL)
	}

	if oldConfig.Limits.Multiline.MaxBytes != 0 && config.Limits.Multiline.MaxBytes == 0 {
		removedCaps.Add(caps.Multiline)
	} else if oldConfig.Limits.Multiline.MaxBytes == 0 && config.Limits.Multiline.MaxBytes != 0 {
		addedCaps.Add(caps.Multiline)
	} else if oldConfig.Limits.Multiline != config.Limits.Multiline {
		removedCaps.Add(caps.Multiline)
		addedCaps.Add(caps.Multiline)
	}

	if oldConfig.Server.STS.Enabled != config.Server.STS.Enabled || oldConfig.Server.capValues[caps.STS] != config.Server.capValues[caps.STS] {
		// XXX: STS is always removed by CAP NEW sts=duration=0, not CAP DEL
		// so the appropriate notify is always a CAP NEW; put it in addedCaps for any change
		addedCaps.Add(caps.STS)
	}

	return
}

func compileGuestRegexp(guestFormat string, casemapping Casemapping) (standard, folded *regexp.Regexp, err error) {
	if strings.Count(guestFormat, "?") != 0 || strings.Count(guestFormat, "*") != 1 {
		err = errors.New("guest format must contain 1 '*' and no '?'s")
		return
	}

	standard, err = utils.CompileGlob(guestFormat, true)
	if err != nil {
		return
	}

	starIndex := strings.IndexByte(guestFormat, '*')
	initial := guestFormat[:starIndex]
	final := guestFormat[starIndex+1:]
	initialFolded, err := casefoldWithSetting(initial, casemapping)
	if err != nil {
		return
	}
	finalFolded, err := casefoldWithSetting(final, casemapping)
	if err != nil {
		return
	}
	folded, err = utils.CompileGlob(fmt.Sprintf("%s*%s", initialFolded, finalFolded), false)
	return
}

func (config *Config) loadMOTD() error {
	if config.Server.MOTD != "" {
		file, err := os.Open(config.Server.MOTD)
		if err != nil {
			return err
		}
		defer file.Close()
		contents, err := ioutil.ReadAll(file)
		if err != nil {
			return err
		}

		lines := bytes.Split(contents, []byte{'\n'})
		for i, line := range lines {
			lineToSend := string(bytes.TrimRight(line, "\r\n"))
			if len(lineToSend) == 0 && i == len(lines)-1 {
				// if the last line of the MOTD was properly terminated with \n,
				// there's no need to send a blank line to clients
				continue
			}
			if config.Server.MOTDFormatting {
				lineToSend = ircfmt.Unescape(lineToSend)
			}
			// "- " is the required prefix for MOTD
			lineToSend = fmt.Sprintf("- %s", lineToSend)
			config.Server.motdLines = append(config.Server.motdLines, lineToSend)
		}
	}
	return nil
}
