// Copyright (c) 2016-2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/ergochat/irc-go/ircutils"
	"github.com/tidwall/buntdb"
	"github.com/xdg-go/scram"

	"github.com/ergochat/ergo/irc/connection_limits"
	"github.com/ergochat/ergo/irc/email"
	"github.com/ergochat/ergo/irc/migrations"
	"github.com/ergochat/ergo/irc/modes"
	"github.com/ergochat/ergo/irc/oauth2"
	"github.com/ergochat/ergo/irc/passwd"
	"github.com/ergochat/ergo/irc/utils"
)

const (
	keyAccountExists           = "account.exists %s"
	keyAccountVerified         = "account.verified %s"
	keyAccountUnregistered     = "account.unregistered %s"
	keyAccountVerificationCode = "account.verificationcode %s"
	keyAccountName             = "account.name %s" // stores the 'preferred name' of the account, not casemapped
	keyAccountRegTime          = "account.registered.time %s"
	keyAccountCredentials      = "account.credentials %s"
	keyAccountAdditionalNicks  = "account.additionalnicks %s"
	keyAccountSettings         = "account.settings %s"
	keyAccountVHost            = "account.vhost %s"
	keyCertToAccount           = "account.creds.certfp %s"
	keyAccountLastSeen         = "account.lastseen %s"
	keyAccountReadMarkers      = "account.readmarkers %s"
	keyAccountModes            = "account.modes %s"     // user modes for the always-on client as a string
	keyAccountRealname         = "account.realname %s"  // client realname stored as string
	keyAccountSuspended        = "account.suspended %s" // client realname stored as string
	keyAccountPwReset          = "account.pwreset %s"
	keyAccountEmailChange      = "account.emailchange %s"
	// for an always-on client, a map of channel names they're in to their current modes
	// (not to be confused with their amodes, which a non-always-on client can have):
	keyAccountChannelToModes    = "account.channeltomodes %s"
	keyAccountPushSubscriptions = "account.pushsubscriptions %s"

	maxCertfpsPerAccount = 5
)

// everything about accounts is persistent; therefore, the database is the authoritative
// source of truth for all account information. anything on the heap is just a cache
type AccountManager struct {
	sync.RWMutex                      // tier 2
	serialCacheUpdateMutex sync.Mutex // tier 3

	server *Server
	// track clients logged in to accounts
	accountToClients  map[string][]*Client
	nickToAccount     map[string]string
	skeletonToAccount map[string]string
	accountToMethod   map[string]NickEnforcementMethod
	registerThrottle  connection_limits.GenericThrottle
}

func (am *AccountManager) Initialize(server *Server) {
	am.accountToClients = make(map[string][]*Client)
	am.nickToAccount = make(map[string]string)
	am.skeletonToAccount = make(map[string]string)
	am.accountToMethod = make(map[string]NickEnforcementMethod)
	am.server = server

	config := server.Config()
	am.buildNickToAccountIndex(config)
	am.createAlwaysOnClients(config)
	am.resetRegisterThrottle(config)
}

func (am *AccountManager) resetRegisterThrottle(config *Config) {
	am.Lock()
	defer am.Unlock()

	am.registerThrottle = connection_limits.GenericThrottle{
		Duration: config.Accounts.Registration.Throttling.Duration,
		Limit:    config.Accounts.Registration.Throttling.MaxAttempts,
	}
}

func (am *AccountManager) touchRegisterThrottle() (throttled bool) {
	am.Lock()
	defer am.Unlock()
	throttled, _ = am.registerThrottle.Touch()
	return
}

func (am *AccountManager) createAlwaysOnClients(config *Config) {
	if config.Accounts.Multiclient.AlwaysOn == PersistentDisabled {
		return
	}

	verifiedPrefix := fmt.Sprintf(keyAccountVerified, "")

	am.serialCacheUpdateMutex.Lock()
	defer am.serialCacheUpdateMutex.Unlock()

	var accounts []string

	am.server.store.View(func(tx *buntdb.Tx) error {
		err := tx.AscendGreaterOrEqual("", verifiedPrefix, func(key, value string) bool {
			if !strings.HasPrefix(key, verifiedPrefix) {
				return false
			}
			account := strings.TrimPrefix(key, verifiedPrefix)
			accounts = append(accounts, account)
			return true
		})
		return err
	})

	for _, accountName := range accounts {
		account, err := am.LoadAccount(accountName)
		if err == nil && (account.Verified && account.Suspended == nil) &&
			persistenceEnabled(config.Accounts.Multiclient.AlwaysOn, account.Settings.AlwaysOn) {
			am.server.AddAlwaysOnClient(
				account,
				am.loadChannels(accountName),
				am.loadTimeMap(keyAccountLastSeen, accountName),
				am.loadTimeMap(keyAccountReadMarkers, accountName),
				am.loadModes(accountName),
				am.loadRealname(accountName),
				am.loadPushSubscriptions(accountName),
			)
		}
	}
}

func (am *AccountManager) buildNickToAccountIndex(config *Config) {
	if !config.Accounts.NickReservation.Enabled {
		return
	}

	nickToAccount := make(map[string]string)
	skeletonToAccount := make(map[string]string)
	accountToMethod := make(map[string]NickEnforcementMethod)
	existsPrefix := fmt.Sprintf(keyAccountExists, "")

	am.serialCacheUpdateMutex.Lock()
	defer am.serialCacheUpdateMutex.Unlock()

	err := am.server.store.View(func(tx *buntdb.Tx) error {
		err := tx.AscendGreaterOrEqual("", existsPrefix, func(key, value string) bool {
			if !strings.HasPrefix(key, existsPrefix) {
				return false
			}

			account := strings.TrimPrefix(key, existsPrefix)
			if _, err := tx.Get(fmt.Sprintf(keyAccountVerified, account)); err == nil {
				nickToAccount[account] = account
				accountName, err := tx.Get(fmt.Sprintf(keyAccountName, account))
				if err != nil {
					am.server.logger.Error("internal", "missing account name for", account)
				} else {
					skeleton, _ := Skeleton(accountName)
					skeletonToAccount[skeleton] = account
				}
			}
			if rawNicks, err := tx.Get(fmt.Sprintf(keyAccountAdditionalNicks, account)); err == nil {
				additionalNicks := unmarshalReservedNicks(rawNicks)
				for _, nick := range additionalNicks {
					cfnick, _ := CasefoldName(nick)
					nickToAccount[cfnick] = account
					skeleton, _ := Skeleton(nick)
					skeletonToAccount[skeleton] = account
				}
			}

			if rawPrefs, err := tx.Get(fmt.Sprintf(keyAccountSettings, account)); err == nil && rawPrefs != "" {
				var prefs AccountSettings
				err := json.Unmarshal([]byte(rawPrefs), &prefs)
				if err == nil && prefs.NickEnforcement != NickEnforcementOptional {
					accountToMethod[account] = prefs.NickEnforcement
				} else if err != nil {
					am.server.logger.Error("internal", "corrupt account settings", account, err.Error())
				}
			}

			return true
		})
		return err
	})

	if config.Accounts.NickReservation.Method == NickEnforcementStrict {
		unregisteredPrefix := fmt.Sprintf(keyAccountUnregistered, "")
		am.server.store.View(func(tx *buntdb.Tx) error {
			tx.AscendGreaterOrEqual("", unregisteredPrefix, func(key, value string) bool {
				if !strings.HasPrefix(key, unregisteredPrefix) {
					return false
				}
				account := strings.TrimPrefix(key, unregisteredPrefix)
				accountName := value
				nickToAccount[account] = account
				skeleton, _ := Skeleton(accountName)
				skeletonToAccount[skeleton] = account
				return true
			})
			return nil
		})
	}

	if err != nil {
		am.server.logger.Error("internal", "couldn't read reserved nicks", err.Error())
	} else {
		am.Lock()
		am.nickToAccount = nickToAccount
		am.skeletonToAccount = skeletonToAccount
		am.accountToMethod = accountToMethod
		am.Unlock()
	}
}

func (am *AccountManager) NickToAccount(nick string) string {
	cfnick, err := CasefoldName(nick)
	if err != nil {
		return ""
	}
	skel, err := Skeleton(nick)
	if err != nil {
		return ""
	}

	am.RLock()
	defer am.RUnlock()
	account := am.nickToAccount[cfnick]
	if account != "" {
		return account
	}
	return am.skeletonToAccount[skel]
}

// given an account, combine stored enforcement method with the config settings
// to compute the actual enforcement method
func configuredEnforcementMethod(config *Config, storedMethod NickEnforcementMethod) (result NickEnforcementMethod) {
	if !config.Accounts.NickReservation.Enabled {
		return NickEnforcementNone
	}
	result = storedMethod
	// if they don't have a custom setting, or customization is disabled, use the default
	if result == NickEnforcementOptional || !config.Accounts.NickReservation.AllowCustomEnforcement {
		result = config.Accounts.NickReservation.Method
	}
	if result == NickEnforcementOptional {
		// enforcement was explicitly enabled neither in the config or by the user
		result = NickEnforcementNone
	}
	return
}

// Given a nick, looks up the account that owns it and the method (none/timeout/strict)
// used to enforce ownership.
func (am *AccountManager) EnforcementStatus(cfnick, skeleton string) (account string, method NickEnforcementMethod) {
	config := am.server.Config()
	if !config.Accounts.NickReservation.Enabled {
		return "", NickEnforcementNone
	}

	am.RLock()
	defer am.RUnlock()

	finalEnforcementMethod := func(account_ string) (result NickEnforcementMethod) {
		storedMethod := am.accountToMethod[account_]
		return configuredEnforcementMethod(config, storedMethod)
	}

	nickAccount := am.nickToAccount[cfnick]
	skelAccount := am.skeletonToAccount[skeleton]
	if nickAccount == "" && skelAccount == "" {
		return "", NickEnforcementNone
	} else if nickAccount != "" && (skelAccount == nickAccount || skelAccount == "") {
		return nickAccount, finalEnforcementMethod(nickAccount)
	} else if skelAccount != "" && nickAccount == "" {
		return skelAccount, finalEnforcementMethod(skelAccount)
	} else {
		// nickAccount != skelAccount and both are nonempty:
		// two people have competing claims on (this casefolding of) this nick!
		nickMethod := finalEnforcementMethod(nickAccount)
		skelMethod := finalEnforcementMethod(skelAccount)
		switch {
		case skelMethod == NickEnforcementNone:
			return nickAccount, nickMethod
		case nickMethod == NickEnforcementNone:
			return skelAccount, skelMethod
		default:
			// nobody can use this nick
			return "!", NickEnforcementStrict
		}
	}
}

// Sets a custom enforcement method for an account and stores it in the database.
func (am *AccountManager) SetEnforcementStatus(account string, method NickEnforcementMethod) (finalSettings AccountSettings, err error) {
	config := am.server.Config()
	if !(config.Accounts.NickReservation.Enabled && config.Accounts.NickReservation.AllowCustomEnforcement) {
		err = errFeatureDisabled
		return
	}

	setter := func(in AccountSettings) (out AccountSettings, err error) {
		out = in
		out.NickEnforcement = method
		return out, nil
	}

	_, err = am.ModifyAccountSettings(account, setter)
	if err != nil {
		return
	}

	// this update of the data plane is racey, but it's probably fine
	am.Lock()
	defer am.Unlock()

	if method == NickEnforcementOptional {
		delete(am.accountToMethod, account)
	} else {
		am.accountToMethod[account] = method
	}

	return
}

func (am *AccountManager) AccountToClients(account string) (result []*Client) {
	cfaccount, err := CasefoldName(account)
	if err != nil {
		return
	}

	am.RLock()
	defer am.RUnlock()
	return am.accountToClients[cfaccount]
}

func (am *AccountManager) Register(client *Client, account string, callbackNamespace string, callbackValue string, passphrase string, certfp string) error {
	casefoldedAccount, err := CasefoldName(account)
	skeleton, skerr := Skeleton(account)
	if err != nil || skerr != nil || account == "" || account == "*" {
		return errAccountCreation
	}

	if restrictedCasefoldedNicks.Has(casefoldedAccount) || restrictedSkeletons.Has(skeleton) {
		return errAccountAlreadyRegistered
	}

	config := am.server.Config()

	// final "is registration allowed" check:
	if callbackNamespace != "admin" && (!config.Accounts.Registration.Enabled || am.server.Defcon() <= 4) {
		return errFeatureDisabled
	}

	if client != nil && client.Account() != "" {
		return errAccountAlreadyLoggedIn
	}

	if client != nil && am.touchRegisterThrottle() {
		am.server.logger.Warning("accounts", "global registration throttle exceeded by client", client.Nick())
		return errLimitExceeded
	}

	// if nick reservation is enabled, don't let people reserve nicknames
	// that they would not be eligible to take, e.g.,
	// 1. a nickname that someone else is currently holding
	// 2. a nickname confusable with an existing reserved nickname
	// this has a lot of weird edge cases because of force-guest-format
	// and the possibility of registering a nickname on an "unregistered connection"
	// (i.e., pre-handshake).
	if client != nil && config.Accounts.NickReservation.Enabled {
		_, nickAcquireError, _ := am.server.clients.SetNick(client, nil, account, true)
		if !(nickAcquireError == nil || nickAcquireError == errNoop) {
			return errAccountMustHoldNick
		}
	}

	// can't register a guest nickname
	if config.Accounts.NickReservation.guestRegexpFolded.MatchString(casefoldedAccount) {
		return errAccountAlreadyRegistered
	}

	accountKey := fmt.Sprintf(keyAccountExists, casefoldedAccount)
	unregisteredKey := fmt.Sprintf(keyAccountUnregistered, casefoldedAccount)
	accountNameKey := fmt.Sprintf(keyAccountName, casefoldedAccount)
	registeredTimeKey := fmt.Sprintf(keyAccountRegTime, casefoldedAccount)
	credentialsKey := fmt.Sprintf(keyAccountCredentials, casefoldedAccount)
	verificationCodeKey := fmt.Sprintf(keyAccountVerificationCode, casefoldedAccount)
	settingsKey := fmt.Sprintf(keyAccountSettings, casefoldedAccount)
	certFPKey := fmt.Sprintf(keyCertToAccount, certfp)

	var creds AccountCredentials
	creds.Version = 1
	err = creds.SetPassphrase(passphrase, am.server.Config().Accounts.Registration.BcryptCost)
	if err != nil {
		return err
	}
	creds.AddCertfp(certfp)
	credStr, err := creds.Serialize()
	if err != nil {
		return err
	}

	var settingsStr string
	if callbackNamespace == "mailto" {
		settings := AccountSettings{Email: callbackValue}
		j, err := json.Marshal(settings)
		if err == nil {
			settingsStr = string(j)
		}
	}

	registeredTimeStr := strconv.FormatInt(time.Now().UnixNano(), 10)

	var setOptions *buntdb.SetOptions
	ttl := time.Duration(config.Accounts.Registration.VerifyTimeout)
	if ttl != 0 {
		setOptions = &buntdb.SetOptions{Expires: true, TTL: ttl}
	}

	err = func() error {
		am.serialCacheUpdateMutex.Lock()
		defer am.serialCacheUpdateMutex.Unlock()

		// can't register an account with the same name as a registered nick
		if am.NickToAccount(account) != "" {
			return errNameReserved
		}

		return am.server.store.Update(func(tx *buntdb.Tx) error {
			if _, err := tx.Get(unregisteredKey); err == nil {
				return errAccountAlreadyUnregistered
			}

			_, err = am.loadRawAccount(tx, casefoldedAccount)
			if err != errAccountDoesNotExist {
				return errAccountAlreadyRegistered
			}

			if certfp != "" {
				// make sure certfp doesn't already exist because that'd be silly
				_, err := tx.Get(certFPKey)
				if err != buntdb.ErrNotFound {
					return errCertfpAlreadyExists
				}
			}

			tx.Set(accountKey, "1", setOptions)
			tx.Set(accountNameKey, account, setOptions)
			tx.Set(registeredTimeKey, registeredTimeStr, setOptions)
			tx.Set(credentialsKey, credStr, setOptions)
			tx.Set(settingsKey, settingsStr, setOptions)
			if certfp != "" {
				tx.Set(certFPKey, casefoldedAccount, setOptions)
			}
			return nil
		})
	}()

	if err != nil {
		return err
	}

	code, err := am.dispatchCallback(client, account, callbackNamespace, callbackValue)
	if err != nil {
		am.Unregister(casefoldedAccount, true)
		return &registrationCallbackError{underlying: err}
	} else {
		if client != nil && code != "" {
			am.server.logger.Info("accounts",
				fmt.Sprintf("nickname %s registered account %s, pending verification", client.Nick(), account))
		}
		return am.server.store.Update(func(tx *buntdb.Tx) error {
			_, _, err = tx.Set(verificationCodeKey, code, setOptions)
			return err
		})
	}
}

type registrationCallbackError struct {
	underlying error
}

func (r *registrationCallbackError) Error() string {
	return `Account verification could not be sent`
}

func registrationCallbackErrorText(config *Config, client *Client, err error) string {
	if callbackErr, ok := err.(*registrationCallbackError); ok {
		// only expose a user-visible error if we are doing direct sending
		if config.Accounts.Registration.EmailVerification.DirectSendingEnabled() {
			errorText := ircutils.SanitizeText(callbackErr.underlying.Error(), 350)
			return fmt.Sprintf(client.t("Could not dispatch registration e-mail: %s"), errorText)
		} else {
			return client.t("Could not dispatch registration e-mail")
		}
	} else {
		return ""
	}
}

// ValidatePassphrase checks whether a passphrase is allowed by our rules
func ValidatePassphrase(passphrase string) error {
	// sanity check the length
	if len(passphrase) == 0 || len(passphrase) > 300 {
		return errAccountBadPassphrase
	}
	// we use * as a placeholder in some places, if it's gotten this far then fail
	if passphrase == "*" {
		return errAccountBadPassphrase
	}
	// validate that the passphrase contains no spaces, and furthermore is valid as a
	// non-final IRC parameter. we already checked that it is nonempty:
	if passphrase[0] == ':' {
		return errAccountBadPassphrase
	}
	for _, r := range passphrase {
		if unicode.IsSpace(r) {
			return errAccountBadPassphrase
		}
	}
	return nil
}

// changes the password for an account
func (am *AccountManager) setPassword(accountName string, password string, hasPrivs bool) (err error) {
	cfAccount, err := CasefoldName(accountName)
	if err != nil {
		return errAccountDoesNotExist
	}

	credKey := fmt.Sprintf(keyAccountCredentials, cfAccount)
	var credStr string
	am.server.store.View(func(tx *buntdb.Tx) error {
		// no need to check verification status here or below;
		// you either need to be auth'ed to the account or be an oper to do this
		credStr, err = tx.Get(credKey)
		return nil
	})

	if err != nil {
		return errAccountDoesNotExist
	}

	var creds AccountCredentials
	err = json.Unmarshal([]byte(credStr), &creds)
	if err != nil {
		return err
	}

	if !hasPrivs && creds.Empty() {
		return errCredsExternallyManaged
	}

	err = creds.SetPassphrase(password, am.server.Config().Accounts.Registration.BcryptCost)
	if err != nil {
		return err
	}

	if creds.Empty() && !hasPrivs {
		return errEmptyCredentials
	}

	newCredStr, err := creds.Serialize()
	if err != nil {
		return err
	}

	err = am.server.store.Update(func(tx *buntdb.Tx) error {
		curCredStr, err := tx.Get(credKey)
		if credStr != curCredStr {
			return errCASFailed
		}
		_, _, err = tx.Set(credKey, newCredStr, nil)
		return err
	})

	return err
}

type alwaysOnChannelStatus struct {
	Modes    string
	JoinTime int64
}

func (am *AccountManager) saveChannels(account string, channelToModes map[string]alwaysOnChannelStatus) {
	j, err := json.Marshal(channelToModes)
	if err != nil {
		am.server.logger.Error("internal", "couldn't marshal channel-to-modes", account, err.Error())
		return
	}
	jStr := string(j)
	key := fmt.Sprintf(keyAccountChannelToModes, account)
	am.server.store.Update(func(tx *buntdb.Tx) error {
		tx.Set(key, jStr, nil)
		return nil
	})
}

func (am *AccountManager) loadChannels(account string) (channelToModes map[string]alwaysOnChannelStatus) {
	key := fmt.Sprintf(keyAccountChannelToModes, account)
	var channelsStr string
	am.server.store.View(func(tx *buntdb.Tx) error {
		channelsStr, _ = tx.Get(key)
		return nil
	})
	if channelsStr == "" {
		return nil
	}
	err := json.Unmarshal([]byte(channelsStr), &channelToModes)
	if err != nil {
		am.server.logger.Error("internal", "couldn't marshal channel-to-modes", account, err.Error())
		return nil
	}
	return
}

func (am *AccountManager) saveModes(account string, uModes modes.Modes) {
	modeStr := uModes.String()
	key := fmt.Sprintf(keyAccountModes, account)
	am.server.store.Update(func(tx *buntdb.Tx) error {
		tx.Set(key, modeStr, nil)
		return nil
	})
}

func (am *AccountManager) loadModes(account string) (uModes modes.Modes) {
	key := fmt.Sprintf(keyAccountModes, account)
	var modeStr string
	am.server.store.View(func(tx *buntdb.Tx) error {
		modeStr, _ = tx.Get(key)
		return nil
	})
	for _, m := range modeStr {
		uModes = append(uModes, modes.Mode(m))
	}
	return
}

func (am *AccountManager) saveLastSeen(account string, lastSeen map[string]time.Time) {
	key := fmt.Sprintf(keyAccountLastSeen, account)
	am.saveTimeMap(account, key, lastSeen)
}

func (am *AccountManager) saveReadMarkers(account string, readMarkers map[string]time.Time) {
	key := fmt.Sprintf(keyAccountReadMarkers, account)
	am.saveTimeMap(account, key, readMarkers)
}

func (am *AccountManager) saveTimeMap(account, key string, timeMap map[string]time.Time) {
	var val string
	if len(timeMap) != 0 {
		text, _ := json.Marshal(timeMap)
		val = string(text)
	}
	err := am.server.store.Update(func(tx *buntdb.Tx) error {
		if val != "" {
			tx.Set(key, val, nil)
		} else {
			tx.Delete(key)
		}
		return nil
	})
	if err != nil {
		am.server.logger.Error("internal", "error persisting timeMap", key, err.Error())
	}
}

func (am *AccountManager) loadTimeMap(baseKey, account string) (lastSeen map[string]time.Time) {
	key := fmt.Sprintf(baseKey, account)
	var lsText string
	am.server.store.Update(func(tx *buntdb.Tx) error {
		lsText, _ = tx.Get(key)
		return nil
	})
	if lsText == "" {
		return nil
	}
	err := json.Unmarshal([]byte(lsText), &lastSeen)
	if err != nil {
		return nil
	}
	return
}

func (am *AccountManager) saveRealname(account string, realname string) {
	key := fmt.Sprintf(keyAccountRealname, account)
	am.server.store.Update(func(tx *buntdb.Tx) error {
		if realname != "" {
			tx.Set(key, realname, nil)
		} else {
			tx.Delete(key)
		}
		return nil
	})
}

func (am *AccountManager) loadRealname(account string) (realname string) {
	key := fmt.Sprintf(keyAccountRealname, account)
	am.server.store.Update(func(tx *buntdb.Tx) error {
		realname, _ = tx.Get(key)
		return nil
	})
	return
}

func (am *AccountManager) savePushSubscriptions(account string, subs []storedPushSubscription) {
	j, err := json.Marshal(subs)
	if err != nil {
		am.server.logger.Error("internal", "error storing push subscriptions", err.Error())
		return
	}
	val := string(j)
	key := fmt.Sprintf(keyAccountPushSubscriptions, account)
	am.server.store.Update(func(tx *buntdb.Tx) error {
		tx.Set(key, val, nil)
		return nil
	})
	return
}

func (am *AccountManager) loadPushSubscriptions(account string) (result []storedPushSubscription) {
	key := fmt.Sprintf(keyAccountPushSubscriptions, account)
	var val string
	am.server.store.View(func(tx *buntdb.Tx) error {
		val, _ = tx.Get(key)
		return nil
	})

	if val == "" {
		return nil
	}
	if err := json.Unmarshal([]byte(val), &result); err == nil {
		return result
	} else {
		am.server.logger.Error("internal", "error loading push subscriptions", err.Error())
		return nil
	}
}

func (am *AccountManager) addRemoveCertfp(account, certfp string, add bool, hasPrivs bool) (err error) {
	certfp, err = utils.NormalizeCertfp(certfp)
	if err != nil {
		return err
	}

	cfAccount, err := CasefoldName(account)
	if err != nil {
		return errAccountDoesNotExist
	}

	credKey := fmt.Sprintf(keyAccountCredentials, cfAccount)
	var credStr string
	am.server.store.View(func(tx *buntdb.Tx) error {
		credStr, err = tx.Get(credKey)
		return nil
	})

	if err != nil {
		return errAccountDoesNotExist
	}

	var creds AccountCredentials
	err = json.Unmarshal([]byte(credStr), &creds)
	if err != nil {
		return err
	}

	if !hasPrivs && creds.Empty() {
		return errCredsExternallyManaged
	}

	if add {
		err = creds.AddCertfp(certfp)
	} else {
		err = creds.RemoveCertfp(certfp)
	}
	if err != nil {
		return err
	}

	if creds.Empty() && !hasPrivs {
		return errEmptyCredentials
	}

	newCredStr, err := creds.Serialize()
	if err != nil {
		return err
	}

	certfpKey := fmt.Sprintf(keyCertToAccount, certfp)
	err = am.server.store.Update(func(tx *buntdb.Tx) error {
		curCredStr, err := tx.Get(credKey)
		if credStr != curCredStr {
			return errCASFailed
		}
		if add {
			_, err = tx.Get(certfpKey)
			if err != buntdb.ErrNotFound {
				return errCertfpAlreadyExists
			}
			tx.Set(certfpKey, cfAccount, nil)
		} else {
			tx.Delete(certfpKey)
		}
		_, _, err = tx.Set(credKey, newCredStr, nil)
		return err
	})

	return err
}

func (am *AccountManager) dispatchCallback(client *Client, account string, callbackNamespace string, callbackValue string) (string, error) {
	if callbackNamespace == "*" || callbackNamespace == "none" || callbackNamespace == "admin" {
		return "", nil
	} else if callbackNamespace == "mailto" {
		return am.dispatchMailtoCallback(client, account, callbackValue)
	} else {
		return "", fmt.Errorf("Callback not implemented: %s", callbackNamespace)
	}
}

func (am *AccountManager) dispatchMailtoCallback(client *Client, account string, callbackValue string) (code string, err error) {
	config := am.server.Config().Accounts.Registration.EmailVerification
	code = utils.GenerateSecretToken()

	subject := config.VerifyMessageSubject
	if subject == "" {
		subject = fmt.Sprintf(client.t("Verify your account on %s"), am.server.name)
	}

	message := email.ComposeMail(config, callbackValue, subject)
	fmt.Fprintf(&message, client.t("Account: %s"), account)
	message.WriteString("\r\n")
	fmt.Fprintf(&message, client.t("Verification code: %s"), code)
	message.WriteString("\r\n")
	message.WriteString("\r\n")
	message.WriteString(client.t("To verify your account, issue the following command:"))
	message.WriteString("\r\n")
	fmt.Fprintf(&message, "/MSG NickServ VERIFY %s %s\r\n", account, code)

	err = email.SendMail(config, callbackValue, message.Bytes())
	if err != nil {
		am.server.logger.Error("internal", "Failed to dispatch e-mail to", callbackValue, err.Error())
	}
	return
}

func (am *AccountManager) Verify(client *Client, account string, code string, admin bool) error {
	casefoldedAccount, err := CasefoldName(account)
	var skeleton string
	if err != nil || account == "" || account == "*" {
		return errAccountVerificationFailed
	}

	if client != nil && client.Account() != "" {
		return errAccountAlreadyLoggedIn
	}

	verifiedKey := fmt.Sprintf(keyAccountVerified, casefoldedAccount)
	accountKey := fmt.Sprintf(keyAccountExists, casefoldedAccount)
	accountNameKey := fmt.Sprintf(keyAccountName, casefoldedAccount)
	registeredTimeKey := fmt.Sprintf(keyAccountRegTime, casefoldedAccount)
	verificationCodeKey := fmt.Sprintf(keyAccountVerificationCode, casefoldedAccount)
	credentialsKey := fmt.Sprintf(keyAccountCredentials, casefoldedAccount)
	settingsKey := fmt.Sprintf(keyAccountSettings, casefoldedAccount)

	var raw rawClientAccount

	func() {
		am.serialCacheUpdateMutex.Lock()
		defer am.serialCacheUpdateMutex.Unlock()

		// do a final check for confusability (in case someone already verified
		// a confusable identifier):
		var unfoldedName string
		err = am.server.store.View(func(tx *buntdb.Tx) error {
			unfoldedName, err = tx.Get(accountNameKey)
			return err
		})
		if err != nil {
			err = errAccountDoesNotExist
			return
		}
		skeleton, err = Skeleton(unfoldedName)
		if err != nil {
			err = errAccountDoesNotExist
			return
		}
		err = func() error {
			am.RLock()
			defer am.RUnlock()
			if _, ok := am.skeletonToAccount[skeleton]; ok {
				return errConfusableIdentifier
			}
			return nil
		}()
		if err != nil {
			return
		}

		err = am.server.store.Update(func(tx *buntdb.Tx) error {
			raw, err = am.loadRawAccount(tx, casefoldedAccount)
			if err == errAccountDoesNotExist {
				return errAccountDoesNotExist
			} else if err != nil {
				return errAccountVerificationFailed
			} else if raw.Verified {
				return errAccountAlreadyVerified
			}

			if !admin {
				// actually verify the code
				// a stored code of "" means a none callback / no code required
				success := false
				storedCode, err := tx.Get(verificationCodeKey)
				if err == nil {
					// this is probably unnecessary
					if storedCode == "" || utils.SecretTokensMatch(storedCode, code) {
						success = true
					}
				}
				if !success {
					return errAccountVerificationInvalidCode
				}
			}

			// verify the account
			tx.Set(verifiedKey, "1", nil)
			// don't need the code anymore
			tx.Delete(verificationCodeKey)
			// re-set all other keys, removing the TTL
			tx.Set(accountKey, "1", nil)
			tx.Set(accountNameKey, raw.Name, nil)
			tx.Set(registeredTimeKey, raw.RegisteredAt, nil)
			tx.Set(credentialsKey, raw.Credentials, nil)
			tx.Set(settingsKey, raw.Settings, nil)

			var creds AccountCredentials
			// XXX we shouldn't do (de)serialization inside the txn,
			// but this is like 2 usec on my system
			json.Unmarshal([]byte(raw.Credentials), &creds)
			for _, cert := range creds.Certfps {
				certFPKey := fmt.Sprintf(keyCertToAccount, cert)
				tx.Set(certFPKey, casefoldedAccount, nil)
			}

			return nil
		})

		if err == nil {
			am.Lock()
			am.nickToAccount[casefoldedAccount] = casefoldedAccount
			am.skeletonToAccount[skeleton] = casefoldedAccount
			am.Unlock()
		}
	}()

	if err != nil {
		return err
	}

	nick := "[server admin]"
	if client != nil {
		nick = client.Nick()
	}
	am.server.logger.Info("accounts", "client", nick, "registered account", account)
	raw.Verified = true
	clientAccount, err := am.deserializeRawAccount(raw, casefoldedAccount)
	if err != nil {
		return err
	}
	if client != nil {
		am.Login(client, clientAccount)
		if client.AlwaysOn() {
			client.markDirty(IncludeAllAttrs)
		}
	}
	// we may need to do nick enforcement here:
	_, method := am.EnforcementStatus(casefoldedAccount, skeleton)
	if method == NickEnforcementStrict {
		currentClient := am.server.clients.Get(casefoldedAccount)
		if currentClient != nil && currentClient != client && currentClient.Account() != casefoldedAccount {
			am.server.RandomlyRename(currentClient)
		}
	}
	return nil
}

// register and verify an account, for internal use
func (am *AccountManager) SARegister(account, passphrase string) (err error) {
	err = am.Register(nil, account, "admin", "", passphrase, "")
	if err == nil {
		err = am.Verify(nil, account, "", true)
	}
	return
}

type EmailChangeRecord struct {
	TimeCreated time.Time
	Code        string
	Email       string
}

func (am *AccountManager) NsSetEmail(client *Client, emailAddr string) (err error) {
	casefoldedAccount := client.Account()
	if casefoldedAccount == "" {
		return errAccountNotLoggedIn
	}

	if am.touchRegisterThrottle() {
		am.server.logger.Warning("accounts", "global registration throttle exceeded by client changing email", client.Nick())
		return errLimitExceeded
	}

	config := am.server.Config()
	if !config.Accounts.Registration.EmailVerification.Enabled {
		return errFeatureDisabled // redundant check, just in case
	}
	record := EmailChangeRecord{
		TimeCreated: time.Now().UTC(),
		Code:        utils.GenerateSecretToken(),
		Email:       emailAddr,
	}
	recordKey := fmt.Sprintf(keyAccountEmailChange, casefoldedAccount)
	recordBytes, _ := json.Marshal(record)
	recordVal := string(recordBytes)
	am.server.store.Update(func(tx *buntdb.Tx) error {
		tx.Set(recordKey, recordVal, nil)
		return nil
	})

	if err != nil {
		return err
	}

	message := email.ComposeMail(config.Accounts.Registration.EmailVerification,
		emailAddr,
		fmt.Sprintf(client.t("Verify your change of e-mail address on %s"), am.server.name))
	message.WriteString(fmt.Sprintf(client.t("To confirm your change of e-mail address on %s, issue the following command:"), am.server.name))
	message.WriteString("\r\n")
	fmt.Fprintf(&message, "/MSG NickServ VERIFYEMAIL %s\r\n", record.Code)

	err = email.SendMail(config.Accounts.Registration.EmailVerification, emailAddr, message.Bytes())
	if err == nil {
		am.server.logger.Info("services",
			fmt.Sprintf("email change verification sent for account %s", casefoldedAccount))
		return
	} else {
		am.server.logger.Error("internal", "Failed to dispatch e-mail change verification to", emailAddr, err.Error())
		return &registrationCallbackError{err}
	}
}

func (am *AccountManager) NsVerifyEmail(client *Client, code string) (err error) {
	casefoldedAccount := client.Account()
	if casefoldedAccount == "" {
		return errAccountNotLoggedIn
	}

	var record EmailChangeRecord
	success := false
	key := fmt.Sprintf(keyAccountEmailChange, casefoldedAccount)
	ttl := time.Duration(am.server.Config().Accounts.Registration.VerifyTimeout)
	am.server.store.Update(func(tx *buntdb.Tx) error {
		rawStr, err := tx.Get(key)
		if err == nil && rawStr != "" {
			err := json.Unmarshal([]byte(rawStr), &record)
			if err == nil {
				if (ttl == 0 || time.Since(record.TimeCreated) < ttl) && utils.SecretTokensMatch(record.Code, code) {
					success = true
					tx.Delete(key)
				}
			}
		}
		return nil
	})

	if !success {
		return errAccountVerificationInvalidCode
	}

	munger := func(in AccountSettings) (out AccountSettings, err error) {
		out = in
		out.Email = record.Email
		return
	}

	_, err = am.ModifyAccountSettings(casefoldedAccount, munger)
	return
}

func (am *AccountManager) NsSendpass(client *Client, accountName string) (err error) {
	config := am.server.Config()
	if !(config.Accounts.Registration.EmailVerification.Enabled && config.Accounts.Registration.EmailVerification.PasswordReset.Enabled) {
		return errFeatureDisabled
	}

	account, err := am.LoadAccount(accountName)
	if err != nil {
		return err
	}
	if !account.Verified {
		return errAccountUnverified
	}
	if account.Suspended != nil {
		return errAccountSuspended
	}
	if account.Settings.Email == "" {
		return errValidEmailRequired
	}

	record := PasswordResetRecord{
		TimeCreated: time.Now().UTC(),
		Code:        utils.GenerateSecretToken(),
	}
	recordKey := fmt.Sprintf(keyAccountPwReset, account.NameCasefolded)
	recordBytes, _ := json.Marshal(record)
	recordVal := string(recordBytes)

	am.server.store.Update(func(tx *buntdb.Tx) error {
		recStr, recErr := tx.Get(recordKey)
		if recErr == nil && recStr != "" {
			var existing PasswordResetRecord
			jErr := json.Unmarshal([]byte(recStr), &existing)
			cooldown := time.Duration(config.Accounts.Registration.EmailVerification.PasswordReset.Cooldown)
			if jErr == nil && time.Since(existing.TimeCreated) < cooldown {
				err = errLimitExceeded
				return nil
			}
		}
		tx.Set(recordKey, recordVal, &buntdb.SetOptions{
			Expires: true,
			TTL:     time.Duration(config.Accounts.Registration.EmailVerification.PasswordReset.Timeout),
		})
		return nil
	})

	if err != nil {
		return
	}

	subject := fmt.Sprintf(client.t("Reset your password on %s"), am.server.name)
	message := email.ComposeMail(config.Accounts.Registration.EmailVerification, account.Settings.Email, subject)
	fmt.Fprintf(&message, client.t("We received a request to reset your password on %[1]s for account: %[2]s"), am.server.name, account.Name)
	message.WriteString("\r\n")
	message.WriteString(client.t("If you did not initiate this request, you can safely ignore this message."))
	message.WriteString("\r\n")
	message.WriteString("\r\n")
	message.WriteString(client.t("Otherwise, to reset your password, issue the following command (replace `new_password` with your desired password):"))
	message.WriteString("\r\n")
	fmt.Fprintf(&message, "/MSG NickServ RESETPASS %s %s new_password\r\n", account.Name, record.Code)

	err = email.SendMail(config.Accounts.Registration.EmailVerification, account.Settings.Email, message.Bytes())
	if err == nil {
		am.server.logger.Info("services",
			fmt.Sprintf("client %s sent a password reset email for account %s", client.Nick(), account.Name))
	} else {
		am.server.logger.Error("internal", "Failed to dispatch e-mail to", account.Settings.Email, err.Error())
	}
	return

}

func (am *AccountManager) NsResetpass(client *Client, accountName, code, password string) (err error) {
	if ValidatePassphrase(password) != nil {
		return errAccountBadPassphrase
	}
	account, err := am.LoadAccount(accountName)
	if err != nil {
		return
	}
	if !account.Verified {
		return errAccountUnverified
	}
	if account.Suspended != nil {
		return errAccountSuspended
	}

	success := false
	key := fmt.Sprintf(keyAccountPwReset, account.NameCasefolded)
	am.server.store.Update(func(tx *buntdb.Tx) error {
		rawStr, err := tx.Get(key)
		if err == nil && rawStr != "" {
			var record PasswordResetRecord
			err := json.Unmarshal([]byte(rawStr), &record)
			if err == nil && utils.SecretTokensMatch(record.Code, code) {
				success = true
				tx.Delete(key)
			}
		}
		return nil
	})

	if success {
		return am.setPassword(accountName, password, true)
	} else {
		return errAccountInvalidCredentials
	}
}

type PasswordResetRecord struct {
	TimeCreated time.Time
	Code        string
}

func marshalReservedNicks(nicks []string) string {
	return strings.Join(nicks, ",")
}

func unmarshalReservedNicks(nicks string) (result []string) {
	if nicks == "" {
		return
	}
	return strings.Split(nicks, ",")
}

func (am *AccountManager) SetNickReserved(client *Client, nick string, saUnreserve bool, reserve bool) error {
	cfnick, err := CasefoldName(nick)
	skeleton, skerr := Skeleton(nick)
	// garbage nick, or garbage options, or disabled
	nrconfig := am.server.Config().Accounts.NickReservation
	if err != nil || skerr != nil || cfnick == "" || (reserve && saUnreserve) || !nrconfig.Enabled {
		return errAccountNickReservationFailed
	}

	// the cache is in sync with the DB while we hold serialCacheUpdateMutex
	am.serialCacheUpdateMutex.Lock()
	defer am.serialCacheUpdateMutex.Unlock()

	// find the affected account, which is usually the client's:
	account := client.Account()
	if saUnreserve {
		// unless this is a sadrop:
		account := func() string {
			am.RLock()
			defer am.RUnlock()
			return am.nickToAccount[cfnick]
		}()
		if account == "" {
			// nothing to do
			return nil
		}
	}
	if account == "" {
		return errAccountNotLoggedIn
	}

	am.Lock()
	accountForNick := am.nickToAccount[cfnick]
	var accountForSkeleton string
	if reserve {
		accountForSkeleton = am.skeletonToAccount[skeleton]
	}
	am.Unlock()

	if reserve && (accountForNick != "" || accountForSkeleton != "") {
		return errNicknameReserved
	} else if !reserve && !saUnreserve && accountForNick != account {
		return errNicknameReserved
	} else if !reserve && cfnick == account {
		return errAccountCantDropPrimaryNick
	}

	nicksKey := fmt.Sprintf(keyAccountAdditionalNicks, account)
	unverifiedAccountKey := fmt.Sprintf(keyAccountExists, cfnick)
	err = am.server.store.Update(func(tx *buntdb.Tx) error {
		if reserve {
			// unverified accounts don't show up in NickToAccount yet (which is intentional),
			// however you shouldn't be able to reserve a nick out from under them
			_, err := tx.Get(unverifiedAccountKey)
			if err == nil {
				return errNicknameReserved
			}
		}

		rawNicks, err := tx.Get(nicksKey)
		if err != nil && err != buntdb.ErrNotFound {
			return err
		}

		nicks := unmarshalReservedNicks(rawNicks)

		if reserve {
			if len(nicks) >= nrconfig.AdditionalNickLimit {
				return errAccountTooManyNicks
			}
			nicks = append(nicks, nick)
		} else {
			// compute (original reserved nicks) minus cfnick
			var newNicks []string
			for _, reservedNick := range nicks {
				cfreservednick, _ := CasefoldName(reservedNick)
				if cfreservednick != cfnick {
					newNicks = append(newNicks, reservedNick)
				} else {
					// found the original, unfolded version of the nick we're dropping;
					// recompute the true skeleton from it
					skeleton, _ = Skeleton(reservedNick)
				}
			}
			nicks = newNicks
		}

		marshaledNicks := marshalReservedNicks(nicks)
		_, _, err = tx.Set(nicksKey, string(marshaledNicks), nil)
		return err
	})

	if err == errAccountTooManyNicks || err == errNicknameReserved {
		return err
	} else if err != nil {
		return errAccountNickReservationFailed
	}

	// success
	am.Lock()
	defer am.Unlock()
	if reserve {
		am.nickToAccount[cfnick] = account
		am.skeletonToAccount[skeleton] = account
	} else {
		delete(am.nickToAccount, cfnick)
		delete(am.skeletonToAccount, skeleton)
	}
	return nil
}

func (am *AccountManager) checkPassphrase(accountName, passphrase string) (account ClientAccount, err error) {
	account, err = am.LoadAccount(accountName)
	// #1476: if grouped nicks are allowed, attempt to interpret accountName as a grouped nick
	if err == errAccountDoesNotExist && !am.server.Config().Accounts.NickReservation.ForceNickEqualsAccount {
		cfnick, cfErr := CasefoldName(accountName)
		if cfErr != nil {
			return
		}
		accountName = func() string {
			am.RLock()
			defer am.RUnlock()
			return am.nickToAccount[cfnick]
		}()
		if accountName != "" {
			account, err = am.LoadAccount(accountName)
		}
	}
	if err != nil {
		return
	}

	if !account.Verified {
		err = errAccountUnverified
		return
	} else if account.Suspended != nil {
		err = errAccountSuspended
		return
	}

	switch account.Credentials.Version {
	case 0:
		err = am.checkLegacyPassphrase(migrations.CheckOragonoPassphraseV0, accountName, account.Credentials.PassphraseHash, passphrase)
	case 1:
		if passwd.CompareHashAndPassword(account.Credentials.PassphraseHash, []byte(passphrase)) != nil {
			err = errAccountInvalidCredentials
		}
		if err == nil && account.Credentials.SCRAMCreds.Iters == 0 {
			// XXX: if the account was created prior to 2.8, it doesn't have SCRAM credentials;
			// since we temporarily have access to a valid plaintext password, create them:
			am.rehashPassword(account.Name, passphrase)
		}
	case -1:
		err = am.checkLegacyPassphrase(migrations.CheckAthemePassphrase, accountName, account.Credentials.PassphraseHash, passphrase)
	case -2:
		err = am.checkLegacyPassphrase(migrations.CheckAnopePassphrase, accountName, account.Credentials.PassphraseHash, passphrase)
	default:
		err = errAccountInvalidCredentials
	}
	return
}

func (am *AccountManager) checkLegacyPassphrase(check migrations.PassphraseCheck, account string, hash []byte, passphrase string) (err error) {
	err = check(hash, []byte(passphrase))
	if err != nil {
		if err == migrations.ErrHashInvalid {
			am.server.logger.Error("internal", "invalid legacy credentials for account", account)
		}
		return errAccountInvalidCredentials
	}
	// re-hash the passphrase with the latest algorithm
	am.rehashPassword(account, passphrase)
	return nil
}

func (am *AccountManager) rehashPassword(accountName, passphrase string) {
	err := am.setPassword(accountName, passphrase, true)
	if err != nil {
		am.server.logger.Error("internal", "could not upgrade user password", accountName, err.Error())
	}
}

func (am *AccountManager) loadWithAutocreation(accountName string, autocreate bool) (account ClientAccount, err error) {
	account, err = am.LoadAccount(accountName)
	if err == errAccountDoesNotExist && autocreate {
		err = am.SARegister(accountName, "")
		if err != nil {
			return
		}
		account, err = am.LoadAccount(accountName)
	}
	return
}

func (am *AccountManager) AuthenticateByPassphrase(client *Client, accountName string, passphrase string) (err error) {
	// XXX check this now, so we don't allow a redundant login for an always-on client
	// even for a brief period. the other potential source of nick-account conflicts
	// is from force-nick-equals-account, but those will be caught later by
	// fixupNickEqualsAccount and if there is a conflict, they will be logged out.
	if client.registered {
		if clientAlready := am.server.clients.Get(accountName); clientAlready != nil && clientAlready.AlwaysOn() {
			return errNickAccountMismatch
		}
	}

	if throttled, remainingTime := client.checkLoginThrottle(); throttled {
		return &ThrottleError{remainingTime}
	}

	var account ClientAccount

	defer func() {
		if err == nil {
			am.Login(client, account)
		}
	}()

	config := am.server.Config()
	if config.Accounts.AuthScript.Enabled {
		var output AuthScriptOutput
		output, err = CheckAuthScript(am.server.semaphores.AuthScript, config.Accounts.AuthScript.ScriptConfig,
			AuthScriptInput{AccountName: accountName, Passphrase: passphrase, IP: client.IP().String()})
		if err != nil {
			am.server.logger.Error("internal", "failed shell auth invocation", err.Error())
		} else if output.Success {
			if output.AccountName != "" {
				accountName = output.AccountName
			}
			account, err = am.loadWithAutocreation(accountName, config.Accounts.AuthScript.Autocreate)
			return
		}
	}

	account, err = am.checkPassphrase(accountName, passphrase)
	return err
}

func (am *AccountManager) AuthenticateByBearerToken(client *Client, tokenType, token string) (err error) {
	switch tokenType {
	case "oauth2":
		return am.AuthenticateByOAuthBearer(client, oauth2.OAuthBearerOptions{Token: token})
	case "jwt":
		return am.AuthenticateByJWT(client, token)
	default:
		return errInvalidBearerTokenType
	}
}

func (am *AccountManager) AuthenticateByOAuthBearer(client *Client, opts oauth2.OAuthBearerOptions) (err error) {
	config := am.server.Config()

	if !config.Accounts.OAuth2.Enabled {
		return errFeatureDisabled
	}

	if throttled, remainingTime := client.checkLoginThrottle(); throttled {
		return &ThrottleError{remainingTime}
	}

	var username string
	if config.Accounts.AuthScript.Enabled && config.Accounts.OAuth2.AuthScript {
		username, err = am.authenticateByOAuthBearerScript(client, config, opts)
	} else {
		username, err = config.Accounts.OAuth2.Introspect(context.Background(), opts.Token)
	}
	if err != nil {
		return err
	}

	account, err := am.loadWithAutocreation(username, config.Accounts.OAuth2.Autocreate)
	if err == nil {
		am.Login(client, account)
	}
	return err
}

func (am *AccountManager) AuthenticateByJWT(client *Client, token string) (err error) {
	config := am.server.Config()
	// enabled check is encapsulated here:
	accountName, err := config.Accounts.JWTAuth.Validate(token)
	if err != nil {
		am.server.logger.Debug("accounts", "invalid JWT token", err.Error())
		return errAccountInvalidCredentials
	}
	account, err := am.loadWithAutocreation(accountName, config.Accounts.JWTAuth.Autocreate)
	if err == nil {
		am.Login(client, account)
	}
	return err
}

func (am *AccountManager) authenticateByOAuthBearerScript(client *Client, config *Config, opts oauth2.OAuthBearerOptions) (username string, err error) {
	output, err := CheckAuthScript(am.server.semaphores.AuthScript, config.Accounts.AuthScript.ScriptConfig,
		AuthScriptInput{OAuthBearer: &opts, IP: client.IP().String()})

	if err != nil {
		am.server.logger.Error("internal", "failed shell auth invocation", err.Error())
		return "", oauth2.ErrInvalidToken
	} else if output.Success {
		return output.AccountName, nil
	} else {
		return "", oauth2.ErrInvalidToken
	}
}

// AllNicks returns the uncasefolded nicknames for all accounts, including additional (grouped) nicks.
func (am *AccountManager) AllNicks() (result []string) {
	accountNamePrefix := fmt.Sprintf(keyAccountName, "")
	accountAdditionalNicksPrefix := fmt.Sprintf(keyAccountAdditionalNicks, "")

	am.server.store.View(func(tx *buntdb.Tx) error {
		// Account names
		err := tx.AscendGreaterOrEqual("", accountNamePrefix, func(key, value string) bool {
			if !strings.HasPrefix(key, accountNamePrefix) {
				return false
			}
			result = append(result, value)
			return true
		})
		if err != nil {
			return err
		}

		// Additional nicks
		return tx.AscendGreaterOrEqual("", accountAdditionalNicksPrefix, func(key, value string) bool {
			if !strings.HasPrefix(key, accountAdditionalNicksPrefix) {
				return false
			}
			additionalNicks := unmarshalReservedNicks(value)
			for _, additionalNick := range additionalNicks {
				result = append(result, additionalNick)
			}
			return true
		})
	})

	sort.Strings(result)
	return
}

func (am *AccountManager) LoadAccount(accountName string) (result ClientAccount, err error) {
	casefoldedAccount, err := CasefoldName(accountName)
	if err != nil {
		err = errAccountDoesNotExist
		return
	}

	var raw rawClientAccount
	am.server.store.View(func(tx *buntdb.Tx) error {
		raw, err = am.loadRawAccount(tx, casefoldedAccount)
		return nil
	})
	if err != nil {
		return
	}

	result, err = am.deserializeRawAccount(raw, casefoldedAccount)
	return
}

func (am *AccountManager) accountWasUnregistered(accountName string) (result bool) {
	casefoldedAccount, err := CasefoldName(accountName)
	if err != nil {
		return false
	}

	unregisteredKey := fmt.Sprintf(keyAccountUnregistered, casefoldedAccount)
	am.server.store.View(func(tx *buntdb.Tx) error {
		if _, err := tx.Get(unregisteredKey); err == nil {
			result = true
		}
		return nil
	})
	return
}

// look up the unfolded version of an account name, possibly after deletion
func (am *AccountManager) AccountToAccountName(account string) (result string) {
	casefoldedAccount, err := CasefoldName(account)
	if err != nil {
		return
	}

	unregisteredKey := fmt.Sprintf(keyAccountUnregistered, casefoldedAccount)
	accountNameKey := fmt.Sprintf(keyAccountName, casefoldedAccount)

	am.server.store.View(func(tx *buntdb.Tx) error {
		if name, err := tx.Get(accountNameKey); err == nil {
			result = name
			return nil
		}
		if name, err := tx.Get(unregisteredKey); err == nil {
			result = name
		}
		return nil
	})

	return
}

func (am *AccountManager) deserializeRawAccount(raw rawClientAccount, cfName string) (result ClientAccount, err error) {
	result.Name = raw.Name
	result.NameCasefolded = cfName
	regTimeInt, _ := strconv.ParseInt(raw.RegisteredAt, 10, 64)
	result.RegisteredAt = time.Unix(0, regTimeInt).UTC()
	e := json.Unmarshal([]byte(raw.Credentials), &result.Credentials)
	if e != nil {
		am.server.logger.Error("internal", "could not unmarshal credentials", e.Error())
		err = errAccountDoesNotExist
		return
	}
	result.AdditionalNicks = unmarshalReservedNicks(raw.AdditionalNicks)
	result.Verified = raw.Verified
	if raw.VHost != "" {
		e := json.Unmarshal([]byte(raw.VHost), &result.VHost)
		if e != nil {
			am.server.logger.Warning("internal", "could not unmarshal vhost for account", result.Name, e.Error())
			// pretend they have no vhost and move on
		}
	}
	if raw.Settings != "" {
		e := json.Unmarshal([]byte(raw.Settings), &result.Settings)
		if e != nil {
			am.server.logger.Warning("internal", "could not unmarshal settings for account", result.Name, e.Error())
		}
	}
	if raw.Suspended != "" {
		sus := new(AccountSuspension)
		e := json.Unmarshal([]byte(raw.Suspended), sus)
		if e != nil {
			am.server.logger.Error("internal", "corrupt suspension data", result.Name, e.Error())
		} else {
			result.Suspended = sus
		}
	}
	return
}

func (am *AccountManager) loadRawAccount(tx *buntdb.Tx, casefoldedAccount string) (result rawClientAccount, err error) {
	accountKey := fmt.Sprintf(keyAccountExists, casefoldedAccount)
	accountNameKey := fmt.Sprintf(keyAccountName, casefoldedAccount)
	registeredTimeKey := fmt.Sprintf(keyAccountRegTime, casefoldedAccount)
	credentialsKey := fmt.Sprintf(keyAccountCredentials, casefoldedAccount)
	verifiedKey := fmt.Sprintf(keyAccountVerified, casefoldedAccount)
	nicksKey := fmt.Sprintf(keyAccountAdditionalNicks, casefoldedAccount)
	vhostKey := fmt.Sprintf(keyAccountVHost, casefoldedAccount)
	settingsKey := fmt.Sprintf(keyAccountSettings, casefoldedAccount)
	suspendedKey := fmt.Sprintf(keyAccountSuspended, casefoldedAccount)

	_, e := tx.Get(accountKey)
	if e == buntdb.ErrNotFound {
		err = errAccountDoesNotExist
		return
	}

	result.Name, _ = tx.Get(accountNameKey)
	result.RegisteredAt, _ = tx.Get(registeredTimeKey)
	result.Credentials, _ = tx.Get(credentialsKey)
	result.AdditionalNicks, _ = tx.Get(nicksKey)
	result.VHost, _ = tx.Get(vhostKey)
	result.Settings, _ = tx.Get(settingsKey)
	result.Suspended, _ = tx.Get(suspendedKey)

	if _, e = tx.Get(verifiedKey); e == nil {
		result.Verified = true
	}

	return
}

type AccountSuspension struct {
	AccountName string `json:"AccountName,omitempty"`
	TimeCreated time.Time
	Duration    time.Duration
	OperName    string
	Reason      string
}

func (am *AccountManager) Suspend(accountName string, duration time.Duration, operName, reason string) (err error) {
	account, err := CasefoldName(accountName)
	if err != nil {
		return errAccountDoesNotExist
	}

	suspension := AccountSuspension{
		TimeCreated: time.Now().UTC(),
		Duration:    duration,
		OperName:    operName,
		Reason:      reason,
	}
	suspensionStr, err := json.Marshal(suspension)
	if err != nil {
		am.server.logger.Error("internal", "suspension json unserializable", err.Error())
		return errAccountDoesNotExist
	}

	existsKey := fmt.Sprintf(keyAccountExists, account)
	suspensionKey := fmt.Sprintf(keyAccountSuspended, account)
	var setOptions *buntdb.SetOptions
	if duration != time.Duration(0) {
		setOptions = &buntdb.SetOptions{Expires: true, TTL: duration}
	}
	err = am.server.store.Update(func(tx *buntdb.Tx) error {
		_, err := tx.Get(existsKey)
		if err != nil {
			return errAccountDoesNotExist
		}
		_, _, err = tx.Set(suspensionKey, string(suspensionStr), setOptions)
		return err
	})

	if err == errAccountDoesNotExist {
		return err
	} else if err != nil {
		am.server.logger.Error("internal", "couldn't persist suspension", account, err.Error())
	} // keep going

	am.Lock()
	clients := am.accountToClients[account]
	delete(am.accountToClients, account)
	am.Unlock()

	// kill clients, sending them the reason
	suspension.AccountName = accountName
	for _, client := range clients {
		client.Logout()
		client.Quit(suspensionToString(client, suspension), nil)
		client.destroy(nil)
	}
	return nil
}

func (am *AccountManager) killClients(clients []*Client) {
	for _, client := range clients {
		client.Logout()
		client.Quit(client.t("You are no longer authorized to be on this server"), nil)
		client.destroy(nil)
	}
}

func (am *AccountManager) Unsuspend(accountName string) (err error) {
	cfaccount, err := CasefoldName(accountName)
	if err != nil {
		return errAccountDoesNotExist
	}

	existsKey := fmt.Sprintf(keyAccountExists, cfaccount)
	suspensionKey := fmt.Sprintf(keyAccountSuspended, cfaccount)
	err = am.server.store.Update(func(tx *buntdb.Tx) error {
		_, err := tx.Get(existsKey)
		if err != nil {
			return errAccountDoesNotExist
		}
		_, err = tx.Delete(suspensionKey)
		if err != nil {
			return errNoop
		}
		return nil
	})

	return err
}

func (am *AccountManager) ListSuspended() (result []AccountSuspension) {
	var names []string
	var raw []string

	prefix := fmt.Sprintf(keyAccountSuspended, "")
	am.server.store.View(func(tx *buntdb.Tx) error {
		err := tx.AscendGreaterOrEqual("", prefix, func(key, value string) bool {
			if !strings.HasPrefix(key, prefix) {
				return false
			}
			raw = append(raw, value)
			cfname := strings.TrimPrefix(key, prefix)
			name, _ := tx.Get(fmt.Sprintf(keyAccountName, cfname))
			names = append(names, name)
			return true
		})
		return err
	})

	result = make([]AccountSuspension, 0, len(raw))
	for i := 0; i < len(raw); i++ {
		var sus AccountSuspension
		err := json.Unmarshal([]byte(raw[i]), &sus)
		if err != nil {
			am.server.logger.Error("internal", "corrupt data for suspension", names[i], err.Error())
			continue
		}
		sus.AccountName = names[i]
		result = append(result, sus)
	}
	return
}

// renames an account (within very restrictive limits); see #1380
func (am *AccountManager) Rename(oldName, newName string) (err error) {
	accountData, err := am.LoadAccount(oldName)
	if err != nil {
		return
	}
	newCfName, err := CasefoldName(newName)
	if err != nil {
		return errNicknameInvalid
	}
	if newCfName != accountData.NameCasefolded {
		return errInvalidAccountRename
	}
	key := fmt.Sprintf(keyAccountName, accountData.NameCasefolded)
	err = am.server.store.Update(func(tx *buntdb.Tx) error {
		tx.Set(key, newName, nil)
		return nil
	})
	if err != nil {
		return err
	}

	am.RLock()
	defer am.RUnlock()
	for _, client := range am.accountToClients[accountData.NameCasefolded] {
		client.setAccountName(newName)
	}
	return nil
}

func (am *AccountManager) Unregister(account string, erase bool) error {
	config := am.server.Config()
	casefoldedAccount, err := CasefoldName(account)
	if err != nil {
		return errAccountDoesNotExist
	}

	accountKey := fmt.Sprintf(keyAccountExists, casefoldedAccount)
	accountNameKey := fmt.Sprintf(keyAccountName, casefoldedAccount)
	registeredTimeKey := fmt.Sprintf(keyAccountRegTime, casefoldedAccount)
	credentialsKey := fmt.Sprintf(keyAccountCredentials, casefoldedAccount)
	verificationCodeKey := fmt.Sprintf(keyAccountVerificationCode, casefoldedAccount)
	verifiedKey := fmt.Sprintf(keyAccountVerified, casefoldedAccount)
	nicksKey := fmt.Sprintf(keyAccountAdditionalNicks, casefoldedAccount)
	settingsKey := fmt.Sprintf(keyAccountSettings, casefoldedAccount)
	vhostKey := fmt.Sprintf(keyAccountVHost, casefoldedAccount)
	joinedChannelsKey := fmt.Sprintf(keyAccountChannelToModes, casefoldedAccount)
	lastSeenKey := fmt.Sprintf(keyAccountLastSeen, casefoldedAccount)
	readMarkersKey := fmt.Sprintf(keyAccountReadMarkers, casefoldedAccount)
	unregisteredKey := fmt.Sprintf(keyAccountUnregistered, casefoldedAccount)
	modesKey := fmt.Sprintf(keyAccountModes, casefoldedAccount)
	realnameKey := fmt.Sprintf(keyAccountRealname, casefoldedAccount)
	suspendedKey := fmt.Sprintf(keyAccountSuspended, casefoldedAccount)
	pwResetKey := fmt.Sprintf(keyAccountPwReset, casefoldedAccount)
	emailChangeKey := fmt.Sprintf(keyAccountEmailChange, casefoldedAccount)
	pushSubscriptionsKey := fmt.Sprintf(keyAccountPushSubscriptions, casefoldedAccount)

	var clients []*Client
	defer func() {
		am.killClients(clients)
	}()

	// on our way out, unregister all the account's channels and delete them from the db
	defer func() {
		for _, channelName := range am.server.channels.ChannelsForAccount(casefoldedAccount) {
			err := am.server.channels.SetUnregistered(channelName, casefoldedAccount)
			if err != nil {
				am.server.logger.Error("internal", "couldn't unregister channel", channelName, err.Error())
			}
		}
	}()

	var credText string
	var rawNicks string

	am.serialCacheUpdateMutex.Lock()
	defer am.serialCacheUpdateMutex.Unlock()

	var accountName string
	keepProtections := false
	am.server.store.Update(func(tx *buntdb.Tx) error {
		// get the unfolded account name; for an active account, this is
		// stored under accountNameKey, for an unregistered account under unregisteredKey
		accountName, _ = tx.Get(accountNameKey)
		if accountName == "" {
			accountName, _ = tx.Get(unregisteredKey)
		}
		if erase {
			tx.Delete(unregisteredKey)
		} else {
			if _, err := tx.Get(verifiedKey); err == nil {
				tx.Set(unregisteredKey, accountName, nil)
				keepProtections = true
			}
		}
		tx.Delete(accountKey)
		tx.Delete(accountNameKey)
		tx.Delete(verifiedKey)
		tx.Delete(registeredTimeKey)
		tx.Delete(verificationCodeKey)
		tx.Delete(settingsKey)
		rawNicks, _ = tx.Get(nicksKey)
		tx.Delete(nicksKey)
		credText, err = tx.Get(credentialsKey)
		tx.Delete(credentialsKey)
		tx.Delete(vhostKey)
		tx.Delete(joinedChannelsKey)
		tx.Delete(lastSeenKey)
		tx.Delete(readMarkersKey)
		tx.Delete(modesKey)
		tx.Delete(realnameKey)
		tx.Delete(suspendedKey)
		tx.Delete(pwResetKey)
		tx.Delete(emailChangeKey)
		tx.Delete(pushSubscriptionsKey)

		return nil
	})

	if err == nil {
		var creds AccountCredentials
		if err := json.Unmarshal([]byte(credText), &creds); err == nil {
			for _, cert := range creds.Certfps {
				certFPKey := fmt.Sprintf(keyCertToAccount, cert)
				am.server.store.Update(func(tx *buntdb.Tx) error {
					if account, err := tx.Get(certFPKey); err == nil && account == casefoldedAccount {
						tx.Delete(certFPKey)
					}
					return nil
				})
			}
		}
	}

	skeleton, _ := Skeleton(accountName)
	additionalNicks := unmarshalReservedNicks(rawNicks)

	am.Lock()
	defer am.Unlock()

	clients = am.accountToClients[casefoldedAccount]
	delete(am.accountToClients, casefoldedAccount)
	// protect the account name itself where applicable, but not any grouped nicks
	if !(keepProtections && config.Accounts.NickReservation.Method == NickEnforcementStrict) {
		delete(am.nickToAccount, casefoldedAccount)
		delete(am.skeletonToAccount, skeleton)
	}
	for _, nick := range additionalNicks {
		delete(am.nickToAccount, nick)
		additionalSkel, _ := Skeleton(nick)
		delete(am.skeletonToAccount, additionalSkel)
	}

	if err != nil && !erase {
		return errAccountDoesNotExist
	}

	return nil
}

func unmarshalRegisteredChannels(channelsStr string) (result []string) {
	if channelsStr != "" {
		result = strings.Split(channelsStr, ",")
	}
	return
}

func (am *AccountManager) AuthenticateByCertificate(client *Client, certfp string, peerCerts []*x509.Certificate, authzid string) (err error) {
	if certfp == "" {
		return errAccountInvalidCredentials
	}

	var clientAccount ClientAccount

	defer func() {
		if err != nil {
			return
		} else if !clientAccount.Verified {
			err = errAccountUnverified
			return
		} else if clientAccount.Suspended != nil {
			err = errAccountSuspended
			return
		}
		// TODO(#1109) clean this check up?
		if client.registered {
			if clientAlready := am.server.clients.Get(clientAccount.Name); clientAlready != nil && clientAlready.AlwaysOn() {
				err = errNickAccountMismatch
				return
			}
		}
		am.Login(client, clientAccount)
		return
	}()

	config := am.server.Config()
	if config.Accounts.AuthScript.Enabled {
		var output AuthScriptOutput
		output, err = CheckAuthScript(am.server.semaphores.AuthScript, config.Accounts.AuthScript.ScriptConfig,
			AuthScriptInput{Certfp: certfp, IP: client.IP().String(), peerCerts: peerCerts})
		if err != nil {
			am.server.logger.Error("internal", "failed shell auth invocation", err.Error())
		} else if output.Success && output.AccountName != "" {
			clientAccount, err = am.loadWithAutocreation(output.AccountName, config.Accounts.AuthScript.Autocreate)
			return
		}
	}

	var account string
	certFPKey := fmt.Sprintf(keyCertToAccount, certfp)

	err = am.server.store.View(func(tx *buntdb.Tx) error {
		account, _ = tx.Get(certFPKey)
		if account == "" {
			return errAccountInvalidCredentials
		}
		return nil
	})

	if err != nil {
		return err
	}

	if authzid != "" {
		if cfAuthzid, err := CasefoldName(authzid); err != nil || cfAuthzid != account {
			return errAuthzidAuthcidMismatch
		}
	}

	// ok, we found an account corresponding to their certificate
	clientAccount, err = am.LoadAccount(account)
	return err
}

type settingsMunger func(input AccountSettings) (output AccountSettings, err error)

func (am *AccountManager) ModifyAccountSettings(account string, munger settingsMunger) (newSettings AccountSettings, err error) {
	casefoldedAccount, err := CasefoldName(account)
	if err != nil {
		return newSettings, errAccountDoesNotExist
	}
	// TODO implement this in general via a compare-and-swap API
	accountData, err := am.LoadAccount(casefoldedAccount)
	if err != nil {
		return
	} else if !accountData.Verified {
		return newSettings, errAccountUnverified
	}
	newSettings, err = munger(accountData.Settings)
	if err != nil {
		return
	}
	text, err := json.Marshal(newSettings)
	if err != nil {
		return
	}
	key := fmt.Sprintf(keyAccountSettings, casefoldedAccount)
	serializedValue := string(text)
	err = am.server.store.Update(func(tx *buntdb.Tx) (err error) {
		_, _, err = tx.Set(key, serializedValue, nil)
		return
	})
	if err != nil {
		err = errAccountUpdateFailed
		return
	}
	// success, push new settings into the client objects
	am.Lock()
	defer am.Unlock()
	for _, client := range am.accountToClients[casefoldedAccount] {
		client.SetAccountSettings(newSettings)
	}
	return
}

// represents someone's status in hostserv
type VHostInfo struct {
	ApprovedVHost string
	Enabled       bool
}

// callback type implementing the actual business logic of vhost operations
type vhostMunger func(input VHostInfo) (output VHostInfo, err error)

func (am *AccountManager) VHostSet(account string, vhost string) (result VHostInfo, err error) {
	munger := func(input VHostInfo) (output VHostInfo, err error) {
		output = input
		output.Enabled = true
		output.ApprovedVHost = vhost
		return
	}

	return am.performVHostChange(account, munger)
}

func (am *AccountManager) VHostSetEnabled(client *Client, enabled bool) (result VHostInfo, err error) {
	munger := func(input VHostInfo) (output VHostInfo, err error) {
		if input.ApprovedVHost == "" {
			err = errNoVhost
			return
		}
		output = input
		output.Enabled = enabled
		return
	}

	return am.performVHostChange(client.Account(), munger)
}

func (am *AccountManager) performVHostChange(account string, munger vhostMunger) (result VHostInfo, err error) {
	account, err = CasefoldName(account)
	if err != nil || account == "" {
		err = errAccountDoesNotExist
		return
	}

	if am.server.Defcon() <= 3 {
		err = errFeatureDisabled
		return
	}

	clientAccount, err := am.LoadAccount(account)
	if err != nil {
		err = errAccountDoesNotExist
		return
	} else if !clientAccount.Verified {
		err = errAccountUnverified
		return
	}

	result, err = munger(clientAccount.VHost)
	if err != nil {
		return
	}

	vhtext, err := json.Marshal(result)
	if err != nil {
		err = errAccountUpdateFailed
		return
	}
	vhstr := string(vhtext)

	key := fmt.Sprintf(keyAccountVHost, account)
	err = am.server.store.Update(func(tx *buntdb.Tx) error {
		_, _, err := tx.Set(key, vhstr, nil)
		return err
	})

	if err != nil {
		err = errAccountUpdateFailed
		return
	}

	am.applyVhostToClients(account, result)
	return result, nil
}

func (am *AccountManager) applyVHostInfo(client *Client, info VHostInfo) {
	// if hostserv is disabled in config, then don't grant vhosts
	// that were previously approved while it was enabled
	if !am.server.Config().Accounts.VHosts.Enabled {
		return
	}

	vhost := ""
	if info.Enabled {
		vhost = info.ApprovedVHost
	}
	oldNickmask := client.NickMaskString()
	updated := client.SetVHost(vhost)
	if updated && client.Registered() {
		// TODO: doing I/O here is kind of a kludge
		client.sendChghost(oldNickmask, client.Hostname())
	}
}

func (am *AccountManager) applyVhostToClients(account string, result VHostInfo) {
	am.RLock()
	clients := am.accountToClients[account]
	am.RUnlock()

	for _, client := range clients {
		am.applyVHostInfo(client, result)
	}
}

func (am *AccountManager) Login(client *Client, account ClientAccount) {
	client.Login(account)

	am.applyVHostInfo(client, account.VHost)

	casefoldedAccount := client.Account()
	am.Lock()
	defer am.Unlock()
	am.accountToClients[casefoldedAccount] = append(am.accountToClients[casefoldedAccount], client)
}

func (am *AccountManager) Logout(client *Client) {
	am.Lock()
	defer am.Unlock()

	casefoldedAccount := client.Account()
	if casefoldedAccount == "" {
		return
	}

	client.Logout()

	clients := am.accountToClients[casefoldedAccount]
	if len(clients) <= 1 {
		delete(am.accountToClients, casefoldedAccount)
		return
	}
	remainingClients := make([]*Client, len(clients)-1)
	remainingPos := 0
	for currentPos := 0; currentPos < len(clients); currentPos++ {
		if clients[currentPos] != client {
			remainingClients[remainingPos] = clients[currentPos]
			remainingPos++
		}
	}
	am.accountToClients[casefoldedAccount] = remainingClients
}

var (
	// EnabledSaslMechanisms contains the SASL mechanisms that exist and that we support.
	// This can be moved to some other data structure/place if we need to load/unload mechs later.
	EnabledSaslMechanisms = map[string]func(*Server, *Client, *Session, []byte, *ResponseBuffer) bool{
		"PLAIN":         authPlainHandler,
		"EXTERNAL":      authExternalHandler,
		"SCRAM-SHA-256": authScramHandler,
		"OAUTHBEARER":   authOauthBearerHandler,
		"IRCV3BEARER":   authIRCv3BearerHandler,
	}
)

type CredentialsVersion int

const (
	CredentialsLegacy     CredentialsVersion = 0
	CredentialsSHA3Bcrypt CredentialsVersion = 1
	// negative numbers for migration
	CredentialsAtheme = -1
	CredentialsAnope  = -2
)

type SCRAMCreds struct {
	Salt      []byte
	Iters     int
	StoredKey []byte
	ServerKey []byte
}

// AccountCredentials stores the various methods for verifying accounts.
type AccountCredentials struct {
	Version        CredentialsVersion
	PassphraseHash []byte
	Certfps        []string
	SCRAMCreds
}

func (ac *AccountCredentials) Empty() bool {
	return len(ac.PassphraseHash) == 0 && len(ac.Certfps) == 0
}

// helper to assemble the serialized JSON for an account's credentials
func (ac *AccountCredentials) Serialize() (result string, err error) {
	ac.Version = 1
	credText, err := json.Marshal(*ac)
	if err != nil {
		return "", err
	}
	return string(credText), nil
}

func (ac *AccountCredentials) SetPassphrase(passphrase string, bcryptCost uint) (err error) {
	if passphrase == "" {
		ac.PassphraseHash = nil
		ac.SCRAMCreds = SCRAMCreds{}
		return nil
	}

	if ValidatePassphrase(passphrase) != nil {
		return errAccountBadPassphrase
	}

	ac.PassphraseHash, err = passwd.GenerateFromPassword([]byte(passphrase), int(bcryptCost))
	if err != nil {
		return errAccountBadPassphrase
	}

	// we can pass an empty account name because it won't actually be incorporated
	// into the credentials; it's just a quirk of the xdg-go/scram API that the way
	// to produce server credentials is to call NewClient* and then GetStoredCredentials
	scramClient, err := scram.SHA256.NewClientUnprepped("", passphrase, "")
	if err != nil {
		return errAccountBadPassphrase
	}
	salt := make([]byte, 16)
	rand.Read(salt)
	// xdg-go/scram says: "Clients have a default minimum PBKDF2 iteration count of 4096."
	minIters := 4096
	scramCreds := scramClient.GetStoredCredentials(scram.KeyFactors{Salt: string(salt), Iters: minIters})
	ac.SCRAMCreds = SCRAMCreds{
		Salt:      salt,
		Iters:     minIters,
		StoredKey: scramCreds.StoredKey,
		ServerKey: scramCreds.ServerKey,
	}

	return nil
}

func (am *AccountManager) NewScramConversation() *scram.ServerConversation {
	server, _ := scram.SHA256.NewServer(am.lookupSCRAMCreds)
	return server.NewConversation()
}

func (am *AccountManager) lookupSCRAMCreds(accountName string) (creds scram.StoredCredentials, err error) {
	// strip client ID if present:
	if strudelIndex := strings.IndexByte(accountName, '@'); strudelIndex != -1 {
		accountName = accountName[:strudelIndex]
	}

	acct, err := am.LoadAccount(accountName)
	if err != nil {
		return
	}
	if acct.Credentials.SCRAMCreds.Iters == 0 {
		err = errNoSCRAMCredentials
		return
	}
	creds.Salt = string(acct.Credentials.SCRAMCreds.Salt)
	creds.Iters = acct.Credentials.SCRAMCreds.Iters
	creds.StoredKey = acct.Credentials.SCRAMCreds.StoredKey
	creds.ServerKey = acct.Credentials.SCRAMCreds.ServerKey
	return
}

func (ac *AccountCredentials) AddCertfp(certfp string) (err error) {
	// XXX we require that certfp is already normalized (rather than normalize here
	// and pass back the normalized version as an additional return parameter);
	// this is just a final sanity check:
	if len(certfp) != 64 {
		return utils.ErrInvalidCertfp
	}

	for _, current := range ac.Certfps {
		if certfp == current {
			return errNoop
		}
	}

	if maxCertfpsPerAccount <= len(ac.Certfps) {
		return errLimitExceeded
	}

	ac.Certfps = append(ac.Certfps, certfp)
	return nil
}

func (ac *AccountCredentials) RemoveCertfp(certfp string) (err error) {
	found := false
	newList := make([]string, 0, len(ac.Certfps))
	for _, current := range ac.Certfps {
		if current == certfp {
			found = true
		} else {
			newList = append(newList, current)
		}
	}
	if !found {
		// this is important because it prevents you from deleting someone else's
		// fingerprint record
		return errNoop
	}
	ac.Certfps = newList
	return nil
}

type MulticlientAllowedSetting int

const (
	MulticlientAllowedServerDefault MulticlientAllowedSetting = iota
	MulticlientDisallowedByUser
	MulticlientAllowedByUser
)

// controls whether/when clients without event-playback support see fake
// PRIVMSGs for JOINs
type ReplayJoinsSetting uint

const (
	ReplayJoinsCommandsOnly = iota // replay in HISTORY or CHATHISTORY output
	ReplayJoinsAlways              // replay in HISTORY, CHATHISTORY, or autoreplay
)

func replayJoinsSettingFromString(str string) (result ReplayJoinsSetting, err error) {
	switch strings.ToLower(str) {
	case "commands-only":
		result = ReplayJoinsCommandsOnly
	case "always":
		result = ReplayJoinsAlways
	default:
		err = errInvalidParams
	}
	return
}

// XXX: AllowBouncer cannot be renamed AllowMulticlient because it is stored in
// persistent JSON blobs in the database
type AccountSettings struct {
	AutoreplayLines  *int
	NickEnforcement  NickEnforcementMethod
	AllowBouncer     MulticlientAllowedSetting
	ReplayJoins      ReplayJoinsSetting
	AlwaysOn         PersistentStatus
	AutoreplayMissed bool
	DMHistory        HistoryStatus
	AutoAway         PersistentStatus
	Email            string
}

// ClientAccount represents a user account.
type ClientAccount struct {
	// Name of the account.
	Name            string
	NameCasefolded  string
	RegisteredAt    time.Time
	Credentials     AccountCredentials
	Verified        bool
	Suspended       *AccountSuspension
	AdditionalNicks []string
	VHost           VHostInfo
	Settings        AccountSettings
}

// convenience for passing around raw serialized account data
type rawClientAccount struct {
	Name            string
	RegisteredAt    string
	Credentials     string
	Verified        bool
	AdditionalNicks string
	VHost           string
	Settings        string
	Suspended       string
}
