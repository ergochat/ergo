// Copyright (c) 2012-2014 Jeremy Latt
// Copyright (c) 2014-2015 Edmund Huber
// Copyright (c) 2016-2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"code.cloudfoundry.org/bytefmt"
	"github.com/ergochat/irc-go/ircfmt"
	"gopkg.in/yaml.v2"

	"github.com/ergochat/ergo/irc/caps"
	"github.com/ergochat/ergo/irc/cloaks"
	"github.com/ergochat/ergo/irc/connection_limits"
	"github.com/ergochat/ergo/irc/custime"
	"github.com/ergochat/ergo/irc/email"
	"github.com/ergochat/ergo/irc/isupport"
	"github.com/ergochat/ergo/irc/jwt"
	"github.com/ergochat/ergo/irc/languages"
	"github.com/ergochat/ergo/irc/logger"
	"github.com/ergochat/ergo/irc/modes"
	"github.com/ergochat/ergo/irc/mysql"
	"github.com/ergochat/ergo/irc/oauth2"
	"github.com/ergochat/ergo/irc/passwd"
	"github.com/ergochat/ergo/irc/utils"
	"github.com/ergochat/ergo/irc/webpush"
)

// here's how this works: exported (capitalized) members of the config structs
// are defined in the YAML file and deserialized directly from there. They may
// be postprocessed and overwritten by LoadConfig. Unexported (lowercase) members
// are derived from the exported members in LoadConfig.

// TLSListenConfig defines configuration options for listening on TLS.
type TLSListenConfig struct {
	Cert  string
	Key   string
	Proxy bool // XXX: legacy key: it's preferred to specify this directly in listenerConfigBlock
}

// This is the YAML-deserializable type of the value of the `Server.Listeners` map
type listenerConfigBlock struct {
	// normal TLS configuration, with a single certificate:
	TLS TLSListenConfig
	// SNI configuration, with multiple certificates:
	TLSCertificates []TLSListenConfig `yaml:"tls-certificates"`
	MinTLSVersion   string            `yaml:"min-tls-version"`
	Proxy           bool
	Tor             bool
	STSOnly         bool `yaml:"sts-only"`
	WebSocket       bool
	HideSTS         bool `yaml:"hide-sts"`
}

type HistoryCutoff uint

const (
	HistoryCutoffDefault HistoryCutoff = iota
	HistoryCutoffNone
	HistoryCutoffRegistrationTime
	HistoryCutoffJoinTime
)

func historyCutoffToString(restriction HistoryCutoff) string {
	switch restriction {
	case HistoryCutoffDefault:
		return "default"
	case HistoryCutoffNone:
		return "none"
	case HistoryCutoffRegistrationTime:
		return "registration-time"
	case HistoryCutoffJoinTime:
		return "join-time"
	default:
		return ""
	}
}

func historyCutoffFromString(str string) (result HistoryCutoff, err error) {
	switch strings.ToLower(str) {
	case "default":
		return HistoryCutoffDefault, nil
	case "none", "disabled", "off", "false":
		return HistoryCutoffNone, nil
	case "registration-time":
		return HistoryCutoffRegistrationTime, nil
	case "join-time":
		return HistoryCutoffJoinTime, nil
	default:
		return HistoryCutoffDefault, errInvalidParams
	}
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
	} else {
		err = fmt.Errorf("invalid value `%s` for server persistence status: %w", orig, err)
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
	Enabled            bool
	AllowedByDefault   bool             `yaml:"allowed-by-default"`
	AlwaysOn           PersistentStatus `yaml:"always-on"`
	AutoAway           PersistentStatus `yaml:"auto-away"`
	AlwaysOnExpiration custime.Duration `yaml:"always-on-expiration"`
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
	AdvertiseSCRAM        bool `yaml:"advertise-scram"`
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
		AllowCustomEnforcement bool `yaml:"allow-custom-enforcement"`
		// RenamePrefix is the legacy field, GuestFormat is the new version
		RenamePrefix           string `yaml:"rename-prefix"`
		GuestFormat            string `yaml:"guest-nickname-format"`
		guestRegexp            *regexp.Regexp
		guestRegexpFolded      *regexp.Regexp
		ForceGuestFormat       bool `yaml:"force-guest-format"`
		ForceNickEqualsAccount bool `yaml:"force-nick-equals-account"`
		ForbidAnonNickChanges  bool `yaml:"forbid-anonymous-nick-changes"`
	} `yaml:"nick-reservation"`
	Multiclient MulticlientConfig
	Bouncer     *MulticlientConfig // # handle old name for 'multiclient'
	VHosts      VHostConfig
	AuthScript  AuthScriptConfig          `yaml:"auth-script"`
	OAuth2      oauth2.OAuth2BearerConfig `yaml:"oauth2"`
	JWTAuth     jwt.JWTAuthConfig         `yaml:"jwt-auth"`
}

type ScriptConfig struct {
	Enabled        bool
	Command        string
	Args           []string
	Timeout        time.Duration
	KillTimeout    time.Duration `yaml:"kill-timeout"`
	MaxConcurrency uint          `yaml:"max-concurrency"`
}

type AuthScriptConfig struct {
	ScriptConfig `yaml:",inline"`
	Autocreate   bool
}

type IPCheckScriptConfig struct {
	ScriptConfig `yaml:",inline"`
	ExemptSASL   bool `yaml:"exempt-sasl"`
}

// AccountRegistrationConfig controls account registration.
type AccountRegistrationConfig struct {
	Enabled            bool
	AllowBeforeConnect bool `yaml:"allow-before-connect"`
	Throttling         ThrottleConfig
	// new-style (v2.4 email verification config):
	EmailVerification email.MailtoConfig `yaml:"email-verification"`
	// old-style email verification config, with "callbacks":
	LegacyEnabledCallbacks []string `yaml:"enabled-callbacks"`
	LegacyCallbacks        struct {
		Mailto email.MailtoConfig
	} `yaml:"callbacks"`
	VerifyTimeout custime.Duration `yaml:"verify-timeout"`
	BcryptCost    uint             `yaml:"bcrypt-cost"`
}

type VHostConfig struct {
	Enabled        bool
	MaxLength      int    `yaml:"max-length"`
	ValidRegexpRaw string `yaml:"valid-regexp"`
	validRegexp    *regexp.Regexp
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
	} else {
		err = fmt.Errorf("invalid value `%s` for nick enforcement method: %w", orig, err)
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
	case "rfc1459":
		result = CasemappingRFC1459
	case "rfc1459-strict":
		result = CasemappingRFC1459Strict
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
	Hidden      bool
	Modes       string
}

// Various server-enforced limits on data size.
type Limits struct {
	AwayLen              int `yaml:"awaylen"`
	ChanListModes        int `yaml:"chan-list-modes"`
	ChannelLen           int `yaml:"channellen"`
	IdentLen             int `yaml:"identlen"`
	RealnameLen          int `yaml:"realnamelen"`
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
	CommandBudgets    map[string]int `yaml:"command-budgets"`
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
	AllowEnvironmentOverrides bool `yaml:"allow-environment-overrides"`

	Network struct {
		Name string
	}

	Server struct {
		Password       string
		passwordBytes  []byte
		Name           string
		nameCasefolded string
		Listeners      map[string]listenerConfigBlock
		UnixBindMode   os.FileMode        `yaml:"unix-bind-mode"`
		TorListeners   TorListenersConfig `yaml:"tor-listeners"`
		WebSockets     struct {
			AllowedOrigins       []string `yaml:"allowed-origins"`
			allowedOriginRegexps []*regexp.Regexp
		}
		// they get parsed into this internal representation:
		trueListeners           map[string]utils.ListenerConfig
		STS                     STSConfig
		LookupHostnames         *bool `yaml:"lookup-hostnames"`
		lookupHostnames         bool
		ForwardConfirmHostnames bool   `yaml:"forward-confirm-hostnames"`
		CheckIdent              bool   `yaml:"check-ident"`
		CoerceIdent             string `yaml:"coerce-ident"`
		MOTD                    string
		motdLines               []string
		MOTDFormatting          bool `yaml:"motd-formatting"`
		Relaymsg                struct {
			Enabled            bool
			Separators         string
			AvailableToChanops bool `yaml:"available-to-chanops"`
		}
		ProxyAllowedFrom     []string `yaml:"proxy-allowed-from"`
		proxyAllowedFromNets []net.IPNet
		WebIRC               []webircConfig `yaml:"webirc"`
		MaxSendQString       string         `yaml:"max-sendq"`
		MaxSendQBytes        int
		Compatibility        struct {
			ForceTrailing      *bool `yaml:"force-trailing"`
			forceTrailing      bool
			SendUnprefixedSasl bool  `yaml:"send-unprefixed-sasl"`
			AllowTruncation    *bool `yaml:"allow-truncation"`
			allowTruncation    bool
		}
		isupport                 isupport.List
		IPLimits                 connection_limits.LimiterConfig `yaml:"ip-limits"`
		Cloaks                   cloaks.CloakConfig              `yaml:"ip-cloaking"`
		SecureNetDefs            []string                        `yaml:"secure-nets"`
		secureNets               []net.IPNet
		supportedCaps            *caps.Set
		supportedCapsWithoutSTS  *caps.Set
		capValues                caps.Values
		Casemapping              Casemapping
		EnforceUtf8              bool                `yaml:"enforce-utf8"`
		OutputPath               string              `yaml:"output-path"`
		IPCheckScript            IPCheckScriptConfig `yaml:"ip-check-script"`
		OverrideServicesHostname string              `yaml:"override-services-hostname"`
		MaxLineLen               int                 `yaml:"max-line-len"`
		SuppressLusers           bool                `yaml:"suppress-lusers"`
	}

	Roleplay struct {
		Enabled        bool
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

	LockFile string `yaml:"lock-file"`

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
		ListDelay        time.Duration    `yaml:"list-delay"`
		InviteExpiration custime.Duration `yaml:"invite-expiration"`
		AutoJoin         []string         `yaml:"auto-join"`
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
		PprofListener     string `yaml:"pprof-listener"`
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
			ExpireTime custime.Duration `yaml:"expire-time"`
			// legacy key, superceded by QueryCutoff:
			EnforceRegistrationDate_ bool   `yaml:"enforce-registration-date"`
			QueryCutoff              string `yaml:"query-cutoff"`
			queryCutoff              HistoryCutoff
			GracePeriod              custime.Duration `yaml:"grace-period"`
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
		TagmsgStorage struct {
			Default   bool
			Whitelist []string
			Blacklist []string
		} `yaml:"tagmsg-storage"`
	}

	WebPush struct {
		Enabled          bool
		Timeout          time.Duration
		Delay            time.Duration
		Subscriber       string
		MaxSubscriptions int `yaml:"max-subscriptions"`
		Expiration       custime.Duration
		vapidKeys        *webpush.VAPIDKeys
	} `yaml:"webpush"`

	Filename string
}

// OperClass defines an assembled operator class.
type OperClass struct {
	Title        string
	WhoisLine    string                `yaml:"whois-line"`
	Capabilities utils.HashSet[string] // map to make lookups much easier
}

// OperatorClasses returns a map of assembled operator classes from the given config.
func (conf *Config) OperatorClasses() (map[string]*OperClass, error) {
	fixupCapability := func(capab string) string {
		return strings.TrimPrefix(strings.TrimPrefix(capab, "oper:"), "local_") // #868, #1442
	}

	ocs := make(map[string]*OperClass)

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
			oc.Capabilities = make(utils.HashSet[string])

			// get inhereted info from other operclasses
			if len(info.Extends) > 0 {
				einfo := ocs[info.Extends]

				for capab := range einfo.Capabilities {
					oc.Capabilities.Add(fixupCapability(capab))
				}
			}

			// add our own info
			oc.Title = info.Title
			if oc.Title == "" {
				oc.Title = "IRC operator"
			}
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
	Hidden    bool
	Modes     []modes.ModeChange
}

func (oper *Oper) HasRoleCapab(capab string) bool {
	return oper != nil && oper.Class.Capabilities.Has(capab)
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
		oper.Hidden = opConf.Hidden

		if oper.Pass == nil && oper.Certfp == "" {
			return nil, fmt.Errorf("Oper %s has neither a password nor a fingerprint", name)
		}

		oper.Vhost = opConf.Vhost
		if oper.Vhost != "" && !conf.Accounts.VHosts.validRegexp.MatchString(oper.Vhost) {
			return nil, fmt.Errorf("Oper %s has an invalid vhost: `%s`", name, oper.Vhost)
		}
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

func loadTlsConfig(config listenerConfigBlock) (tlsConfig *tls.Config, err error) {
	var certificates []tls.Certificate
	if len(config.TLSCertificates) != 0 {
		// SNI configuration with multiple certificates
		for _, certPairConf := range config.TLSCertificates {
			cert, err := loadCertWithLeaf(certPairConf.Cert, certPairConf.Key)
			if err != nil {
				return nil, err
			}
			certificates = append(certificates, cert)
		}
	} else if config.TLS.Cert != "" {
		// normal configuration with one certificate
		cert, err := loadCertWithLeaf(config.TLS.Cert, config.TLS.Key)
		if err != nil {
			return nil, err
		}
		certificates = append(certificates, cert)
	} else {
		// plaintext!
		return nil, nil
	}
	clientAuth := tls.RequestClientCert
	if config.WebSocket {
		// if Chrome receives a server request for a client certificate
		// on a websocket connection, it will immediately disconnect:
		// https://bugs.chromium.org/p/chromium/issues/detail?id=329884
		// work around this behavior:
		clientAuth = tls.NoClientCert
	}
	result := tls.Config{
		Certificates: certificates,
		ClientAuth:   clientAuth,
		MinVersion:   tlsMinVersionFromString(config.MinTLSVersion),
	}
	return &result, nil
}

func tlsMinVersionFromString(version string) uint16 {
	version = strings.ToLower(version)
	version = strings.TrimPrefix(version, "v")
	switch version {
	case "1", "1.0":
		return tls.VersionTLS10
	case "1.1":
		return tls.VersionTLS11
	case "1.2":
		return tls.VersionTLS12
	case "1.3":
		return tls.VersionTLS13
	default:
		// tls package will fill in a sane value, currently 1.0
		return 0
	}
}

func loadCertWithLeaf(certFile, keyFile string) (cert tls.Certificate, err error) {
	// LoadX509KeyPair: "On successful return, Certificate.Leaf will be nil because
	// the parsed form of the certificate is not retained." tls.Config:
	// "Note: if there are multiple Certificates, and they don't have the
	// optional field Leaf set, certificate selection will incur a significant
	// per-handshake performance cost."
	cert, err = tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return
	}
	cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
	return
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
		lconf.TLSConfig, err = loadTlsConfig(block)
		if err != nil {
			return &CertKeyError{Err: err}
		}
		lconf.RequireProxy = block.TLS.Proxy || block.Proxy
		lconf.WebSocket = block.WebSocket
		if lconf.WebSocket && !conf.Server.EnforceUtf8 {
			return fmt.Errorf("enabling a websocket listener requires the use of server.enforce-utf8")
		}
		lconf.HideSTS = block.HideSTS
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
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return nil, err
	}
	return
}

// convert, e.g., "ALLOWED_ORIGINS" to "allowed-origins"
func screamingSnakeToKebab(in string) (out string) {
	var buf strings.Builder
	for i := 0; i < len(in); i++ {
		c := in[i]
		switch {
		case c == '_':
			buf.WriteByte('-')
		case 'A' <= c && c <= 'Z':
			buf.WriteByte(c + ('a' - 'A'))
		default:
			buf.WriteByte(c)
		}
	}
	return buf.String()
}

func isExported(field reflect.StructField) bool {
	return field.PkgPath == "" // https://golang.org/pkg/reflect/#StructField
}

// errors caused by config overrides
type configPathError struct {
	name     string
	desc     string
	fatalErr error
}

func (ce *configPathError) Error() string {
	if ce.fatalErr != nil {
		return fmt.Sprintf("Couldn't apply config override `%s`: %s: %v", ce.name, ce.desc, ce.fatalErr)
	}
	return fmt.Sprintf("Couldn't apply config override `%s`: %s", ce.name, ce.desc)
}

func mungeFromEnvironment(config *Config, envPair string) (applied bool, name string, err *configPathError) {
	equalIdx := strings.IndexByte(envPair, '=')
	name, value := envPair[:equalIdx], envPair[equalIdx+1:]
	if strings.HasPrefix(name, "ERGO__") {
		name = strings.TrimPrefix(name, "ERGO__")
	} else if strings.HasPrefix(name, "ORAGONO__") {
		name = strings.TrimPrefix(name, "ORAGONO__")
	} else {
		return false, "", nil
	}
	pathComponents := strings.Split(name, "__")
	for i, pathComponent := range pathComponents {
		pathComponents[i] = screamingSnakeToKebab(pathComponent)
	}

	v := reflect.Indirect(reflect.ValueOf(config))
	t := v.Type()
	for _, component := range pathComponents {
		if component == "" {
			return false, "", &configPathError{name, "invalid", nil}
		}
		if v.Kind() != reflect.Struct {
			return false, "", &configPathError{name, "index into non-struct", nil}
		}
		var nextField reflect.StructField
		success := false
		n := t.NumField()
		// preferentially get a field with an exact yaml tag match,
		// then fall back to case-insensitive comparison of field names
		for i := 0; i < n; i++ {
			field := t.Field(i)
			if isExported(field) && field.Tag.Get("yaml") == component {
				nextField = field
				success = true
				break
			}
		}
		if !success {
			for i := 0; i < n; i++ {
				field := t.Field(i)
				if isExported(field) && strings.ToLower(field.Name) == component {
					nextField = field
					success = true
					break
				}
			}
		}
		if !success {
			return false, "", &configPathError{name, fmt.Sprintf("couldn't resolve path component: `%s`", component), nil}
		}
		v = v.FieldByName(nextField.Name)
		// dereference pointer field if necessary, initialize new value if necessary
		if v.Kind() == reflect.Ptr {
			if v.IsNil() {
				v.Set(reflect.New(v.Type().Elem()))
			}
			v = reflect.Indirect(v)
		}
		t = v.Type()
	}
	yamlErr := yaml.Unmarshal([]byte(value), v.Addr().Interface())
	if yamlErr != nil {
		return false, "", &configPathError{name, "couldn't deserialize YAML", yamlErr}
	}
	return true, name, nil
}

// LoadConfig loads the given YAML configuration file.
func LoadConfig(filename string) (config *Config, err error) {
	config, err = LoadRawConfig(filename)
	if err != nil {
		return nil, err
	}

	if config.AllowEnvironmentOverrides {
		for _, envPair := range os.Environ() {
			applied, name, envErr := mungeFromEnvironment(config, envPair)
			if envErr != nil {
				if envErr.fatalErr != nil {
					return nil, envErr
				} else {
					log.Println(envErr.Error())
				}
			} else if applied {
				log.Printf("applied environment override: %s\n", name)
			}
		}
	}

	config.Filename = filename

	if config.Network.Name == "" {
		return nil, errors.New("Network name missing")
	}
	if config.Server.Name == "" {
		return nil, errors.New("Server name missing")
	}
	if !utils.IsServerName(config.Server.Name) {
		return nil, errors.New("Server name must match the format of a hostname")
	}
	config.Server.nameCasefolded = strings.ToLower(config.Server.Name)
	if config.Datastore.Path == "" {
		return nil, errors.New("Datastore path missing")
	}
	//dan: automagically fix identlen until a few releases in the future (from now, 0.12.0), being a newly-introduced limit
	if config.Limits.IdentLen < 1 {
		config.Limits.IdentLen = 20
	}
	if config.Limits.NickLen < 1 || config.Limits.ChannelLen < 2 || config.Limits.AwayLen < 1 || config.Limits.KickLen < 1 || config.Limits.TopicLen < 1 {
		return nil, errors.New("One or more limits values are too low")
	}
	if config.Limits.RegistrationMessages == 0 {
		config.Limits.RegistrationMessages = 1024
	}
	if config.Server.MaxLineLen < DefaultMaxLineLen {
		config.Server.MaxLineLen = DefaultMaxLineLen
	}
	if config.Datastore.MySQL.Enabled {
		if config.Limits.NickLen > mysql.MaxTargetLength || config.Limits.ChannelLen > mysql.MaxTargetLength {
			return nil, fmt.Errorf("to use MySQL, nick and channel length limits must be %d or lower", mysql.MaxTargetLength)
		}
	}

	if config.Server.CoerceIdent != "" {
		if config.Server.CheckIdent {
			return nil, errors.New("Can't configure both check-ident and coerce-ident")
		}
		if config.Server.CoerceIdent[0] != '~' {
			return nil, errors.New("coerce-ident value must start with a ~")
		}
		if !isIdent(config.Server.CoerceIdent[1:]) {
			return nil, errors.New("coerce-ident must be valid as an IRC user/ident field")
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

	if !config.Accounts.NickReservation.Enabled {
		config.Accounts.NickReservation.ForceNickEqualsAccount = false
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
			return nil, errors.New("Logging configuration specifies 'file' method but 'filename' is empty")
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
				return nil, errors.New("Encountered logging type '-' with no type to exclude")
			}
			if typeStr[0] == '-' {
				typeStr = typeStr[1:]
				logConfig.ExcludedTypes = append(logConfig.ExcludedTypes, typeStr)
			} else {
				logConfig.Types = append(logConfig.Types, typeStr)
			}
		}
		if len(logConfig.Types) < 1 {
			return nil, errors.New("Logger has no types to log")
		}

		newLogConfigs = append(newLogConfigs, logConfig)
	}
	config.Logging = newLogConfigs

	if config.Accounts.Registration.EmailVerification.Enabled {
		err := config.Accounts.Registration.EmailVerification.Postprocess(config.Server.Name)
		if err != nil {
			return nil, err
		}
	} else {
		// TODO: this processes the legacy "callback" config, clean this up in 2.5 or later
		// TODO: also clean up the legacy "inline" MTA config format (from ee05a4324dfde)
		mailtoEnabled := false
		for _, name := range config.Accounts.Registration.LegacyEnabledCallbacks {
			if name == "mailto" {
				mailtoEnabled = true
				break
			}
		}
		if mailtoEnabled {
			config.Accounts.Registration.EmailVerification = config.Accounts.Registration.LegacyCallbacks.Mailto
			config.Accounts.Registration.EmailVerification.Enabled = true
			err := config.Accounts.Registration.EmailVerification.Postprocess(config.Server.Name)
			if err != nil {
				return nil, err
			}
		}
	}

	config.Accounts.defaultUserModes = ParseDefaultUserModes(config.Accounts.DefaultUserModes)

	if config.Server.Password != "" {
		config.Server.passwordBytes, err = decodeLegacyPasswordHash(config.Server.Password)
		if err != nil {
			return nil, err
		}
		if config.Accounts.LoginViaPassCommand && !config.Accounts.SkipServerPassword {
			return nil, errors.New("Using a server password and login-via-pass-command requires skip-server-password as well")
		}
		// #1634: accounts.registration.allow-before-connect is an auth bypass
		// for configurations that start from default and then enable server.password
		config.Accounts.Registration.AllowBeforeConnect = false
	}

	if config.Accounts.RequireSasl.Enabled {
		// minor gotcha: Tor listeners will typically be loopback and
		// therefore exempted from require-sasl. if require-sasl is enabled
		// for non-Tor (non-local) connections, enable it for Tor as well:
		config.Server.TorListeners.RequireSasl = true
	}
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
			config.Accounts.VHosts.validRegexp = regexp
		} else {
			log.Printf("invalid vhost regexp: %s\n", err.Error())
		}
	}
	if config.Accounts.VHosts.validRegexp == nil {
		config.Accounts.VHosts.validRegexp = defaultValidVhostRegex
	}

	if config.Accounts.AuthenticationEnabled {
		saslCapValues := []string{"PLAIN", "EXTERNAL"}
		if config.Accounts.AdvertiseSCRAM {
			saslCapValues = append(saslCapValues, "SCRAM-SHA-256")
		}
		if config.Accounts.OAuth2.Enabled {
			saslCapValues = append(saslCapValues, "OAUTHBEARER")
		}
		if config.Accounts.OAuth2.Enabled || config.Accounts.JWTAuth.Enabled {
			saslCapValues = append(saslCapValues, "IRCV3BEARER")
		}
		config.Server.capValues[caps.SASL] = strings.Join(saslCapValues, ",")
	} else {
		config.Server.supportedCaps.Disable(caps.SASL)
	}

	if err := config.Accounts.OAuth2.Postprocess(); err != nil {
		return nil, err
	}

	if err := config.Accounts.JWTAuth.Postprocess(); err != nil {
		return nil, err
	}

	if config.Accounts.OAuth2.Enabled && config.Accounts.OAuth2.AuthScript && !config.Accounts.AuthScript.Enabled {
		return nil, fmt.Errorf("oauth2 is enabled with auth-script, but no auth-script is enabled")
	}

	if !config.Accounts.Registration.Enabled {
		config.Server.supportedCaps.Disable(caps.AccountRegistration)
	} else {
		var registerValues []string
		if config.Accounts.Registration.AllowBeforeConnect {
			registerValues = append(registerValues, "before-connect")
		}
		if config.Accounts.Registration.EmailVerification.Enabled {
			registerValues = append(registerValues, "email-required")
		}
		if config.Accounts.RequireSasl.Enabled {
			registerValues = append(registerValues, "account-required")
		}
		if len(registerValues) != 0 {
			config.Server.capValues[caps.AccountRegistration] = strings.Join(registerValues, ",")
		}
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

	if len(config.Fakelag.CommandBudgets) != 0 {
		// normalize command names to uppercase:
		commandBudgets := make(map[string]int, len(config.Fakelag.CommandBudgets))
		for command, budget := range config.Fakelag.CommandBudgets {
			commandBudgets[strings.ToUpper(command)] = budget
		}
		config.Fakelag.CommandBudgets = commandBudgets
	} else {
		config.Fakelag.CommandBudgets = nil
	}

	if config.Server.Relaymsg.Enabled {
		for _, char := range protocolBreakingNameCharacters {
			if strings.ContainsRune(config.Server.Relaymsg.Separators, char) {
				return nil, fmt.Errorf("RELAYMSG separators cannot include the characters %s", protocolBreakingNameCharacters)
			}
		}
		config.Server.capValues[caps.Relaymsg] = config.Server.Relaymsg.Separators
	} else {
		config.Server.supportedCaps.Disable(caps.Relaymsg)
	}

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
	config.Server.Compatibility.allowTruncation = utils.BoolDefaultTrue(config.Server.Compatibility.AllowTruncation)

	config.loadMOTD()

	// in the current implementation, we disable history by creating a history buffer
	// with zero capacity. but the `enabled` config option MUST be respected regardless
	// of this detail
	if !config.History.Enabled {
		config.History.ChannelLength = 0
		config.History.ClientLength = 0
		config.Server.supportedCaps.Disable(caps.Chathistory)
		config.Server.supportedCaps.Disable(caps.EventPlayback)
		config.Server.supportedCaps.Disable(caps.ZNCPlayback)
	}

	if !config.History.Enabled || !config.History.Persistent.Enabled {
		config.History.Persistent.Enabled = false
		config.History.Persistent.UnregisteredChannels = false
		config.History.Persistent.RegisteredChannels = PersistentDisabled
		config.History.Persistent.DirectMessages = PersistentDisabled
	}

	if config.History.Persistent.Enabled && !config.Datastore.MySQL.Enabled {
		return nil, fmt.Errorf("You must configure a MySQL server in order to enable persistent history")
	}

	if config.History.ZNCMax == 0 {
		config.History.ZNCMax = config.History.ChathistoryMax
	}

	if config.History.Restrictions.QueryCutoff != "" {
		config.History.Restrictions.queryCutoff, err = historyCutoffFromString(config.History.Restrictions.QueryCutoff)
		if err != nil {
			return nil, fmt.Errorf("invalid value of history.query-restrictions: %w", err)
		}
	} else {
		if config.History.Restrictions.EnforceRegistrationDate_ {
			config.History.Restrictions.queryCutoff = HistoryCutoffRegistrationTime
		} else {
			config.History.Restrictions.queryCutoff = HistoryCutoffNone
		}
	}

	config.Roleplay.addSuffix = utils.BoolDefaultTrue(config.Roleplay.AddSuffix)

	config.Datastore.MySQL.ExpireTime = time.Duration(config.History.Restrictions.ExpireTime)
	config.Datastore.MySQL.TrackAccountMessages = config.History.Retention.EnableAccountIndexing
	if config.Datastore.MySQL.MaxConns == 0 {
		// #1622: not putting an upper limit on the number of MySQL connections is
		// potentially dangerous. as a naive heuristic, assume they're running on the
		// same machine:
		config.Datastore.MySQL.MaxConns = runtime.NumCPU()
	}

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

	if config.WebPush.Enabled {
		if config.Accounts.Multiclient.AlwaysOn == PersistentDisabled {
			return nil, fmt.Errorf("Cannot enable webpush if always-on is disabled")
		}
		if config.WebPush.Timeout == 0 {
			config.WebPush.Timeout = 10 * time.Second
		}
		if config.WebPush.Subscriber == "" {
			config.WebPush.Subscriber = "https://ergo.chat/about"
		}
		if config.WebPush.MaxSubscriptions <= 0 {
			config.WebPush.MaxSubscriptions = 1
		}
		if config.WebPush.Expiration == 0 {
			config.WebPush.Expiration = custime.Duration(14 * 24 * time.Hour)
		} else if config.WebPush.Expiration < custime.Duration(3*24*time.Hour) {
			return nil, fmt.Errorf("webpush.expiration is too short (should be several days)")
		}
	} else {
		config.Server.supportedCaps.Disable(caps.WebPush)
		config.Server.supportedCaps.Disable(caps.SojuWebPush)
	}

	// now that all postprocessing is complete, regenerate ISUPPORT:
	err = config.generateISupport()
	if err != nil {
		return nil, err
	}

	// #1428: Tor listeners should never see STS
	config.Server.supportedCapsWithoutSTS = caps.NewSet()
	config.Server.supportedCapsWithoutSTS.Union(config.Server.supportedCaps)
	config.Server.supportedCapsWithoutSTS.Disable(caps.STS)

	return config, nil
}

func (config *Config) getOutputPath(filename string) string {
	return filepath.Join(config.Server.OutputPath, filename)
}

func (config *Config) isRelaymsgIdentifier(nick string) bool {
	if !config.Server.Relaymsg.Enabled {
		return false
	}

	if strings.HasPrefix(nick, "#") {
		return false // #2114
	}

	for _, char := range config.Server.Relaymsg.Separators {
		if strings.ContainsRune(nick, char) {
			return true
		}
	}
	return false
}

// setISupport sets up our RPL_ISUPPORT reply.
func (config *Config) generateISupport() (err error) {
	maxTargetsString := strconv.Itoa(maxTargets)

	// add RPL_ISUPPORT tokens
	isupport := &config.Server.isupport
	isupport.Initialize()
	isupport.Add("AWAYLEN", strconv.Itoa(config.Limits.AwayLen))
	isupport.Add("BOT", "B")
	var casemappingToken string
	switch config.Server.Casemapping {
	default:
		casemappingToken = "ascii" // this is published for ascii, precis, or permissive
	case CasemappingRFC1459:
		casemappingToken = "rfc1459"
	case CasemappingRFC1459Strict:
		casemappingToken = "rfc1459-strict"
	}
	isupport.Add("CASEMAPPING", casemappingToken)
	isupport.Add("CHANLIMIT", fmt.Sprintf("%s:%d", chanTypes, config.Channels.MaxChannelsPerClient))
	isupport.Add("CHANMODES", chanmodesToken)
	if config.History.Enabled && config.History.ChathistoryMax > 0 {
		isupport.Add("CHATHISTORY", strconv.Itoa(config.History.ChathistoryMax))
		// Kiwi expects this legacy token name:
		isupport.Add("draft/CHATHISTORY", strconv.Itoa(config.History.ChathistoryMax))
	}
	isupport.Add("CHANNELLEN", strconv.Itoa(config.Limits.ChannelLen))
	isupport.Add("CHANTYPES", chanTypes)
	isupport.Add("ELIST", "U")
	isupport.Add("EXCEPTS", "")
	if config.Extjwt.Default.Enabled() || len(config.Extjwt.Services) != 0 {
		isupport.Add("EXTJWT", "1")
	}
	isupport.Add("EXTBAN", ",m")
	isupport.Add("FORWARD", "f")
	isupport.Add("INVEX", "")
	isupport.Add("KICKLEN", strconv.Itoa(config.Limits.KickLen))
	isupport.Add("MAXLIST", fmt.Sprintf("beI:%s", strconv.Itoa(config.Limits.ChanListModes)))
	isupport.Add("MAXTARGETS", maxTargetsString)
	isupport.Add("MSGREFTYPES", "msgid,timestamp")
	isupport.Add("MODES", "")
	isupport.Add("MONITOR", strconv.Itoa(config.Limits.MonitorEntries))
	isupport.Add("NETWORK", config.Network.Name)
	isupport.Add("NICKLEN", strconv.Itoa(config.Limits.NickLen))
	isupport.Add("PREFIX", "(qaohv)~&@%+")
	if config.Roleplay.Enabled {
		isupport.Add("RPCHAN", "E")
		isupport.Add("RPUSER", "E")
	}
	isupport.Add("SAFELIST", "")
	isupport.Add("STATUSMSG", "~&@%+")
	isupport.Add("TARGMAX", fmt.Sprintf("NAMES:1,LIST:1,KICK:,WHOIS:1,USERHOST:10,PRIVMSG:%s,TAGMSG:%s,NOTICE:%s,MONITOR:%d", maxTargetsString, maxTargetsString, maxTargetsString, config.Limits.MonitorEntries))
	isupport.Add("TOPICLEN", strconv.Itoa(config.Limits.TopicLen))
	if config.Server.Casemapping == CasemappingPRECIS {
		isupport.Add("UTF8MAPPING", precisUTF8MappingToken)
	}
	if config.Server.EnforceUtf8 {
		isupport.Add("UTF8ONLY", "")
	}
	if config.WebPush.Enabled {
		// XXX we typically don't have this at config parse time, so we'll have to regenerate
		// the cached reply later
		if config.WebPush.vapidKeys != nil {
			isupport.Add("VAPID", config.WebPush.vapidKeys.PublicKeyString())
		}
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

// determine whether we need to resize / create / destroy
// the in-memory history buffers:
func (config *Config) historyChangedFrom(oldConfig *Config) bool {
	return config.History.Enabled != oldConfig.History.Enabled ||
		config.History.ChannelLength != oldConfig.History.ChannelLength ||
		config.History.ClientLength != oldConfig.History.ClientLength ||
		config.History.AutoresizeWindow != oldConfig.History.AutoresizeWindow ||
		config.History.Persistent != oldConfig.History.Persistent
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
		contents, err := io.ReadAll(file)
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
