// Copyright (c) 2016-2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/smtp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	"github.com/unendingPattern/oragono/irc/caps"
	"github.com/unendingPattern/oragono/irc/passwd"
	"github.com/unendingPattern/oragono/irc/utils"
	"github.com/tidwall/buntdb"
)

const (
	keyAccountExists           = "account.exists %s"
	keyAccountVerified         = "account.verified %s"
	keyAccountCallback         = "account.callback %s"
	keyAccountVerificationCode = "account.verificationcode %s"
	keyAccountName             = "account.name %s" // stores the 'preferred name' of the account, not casemapped
	keyAccountRegTime          = "account.registered.time %s"
	keyAccountCredentials      = "account.credentials %s"
	keyAccountAdditionalNicks  = "account.additionalnicks %s"
	keyAccountVHost            = "account.vhost %s"
	keyCertToAccount           = "account.creds.certfp %s"

	keyVHostQueueAcctToId = "vhostQueue %s"
	vhostRequestIdx       = "vhostQueue"
)

// everything about accounts is persistent; therefore, the database is the authoritative
// source of truth for all account information. anything on the heap is just a cache
type AccountManager struct {
	// XXX these are up here so they can be aligned to a 64-bit boundary, please forgive me
	// autoincrementing ID for vhost requests:
	vhostRequestID           uint64
	vhostRequestPendingCount uint64

	sync.RWMutex                      // tier 2
	serialCacheUpdateMutex sync.Mutex // tier 3
	vHostUpdateMutex       sync.Mutex // tier 3

	server *Server
	// track clients logged in to accounts
	accountToClients map[string][]*Client
	nickToAccount    map[string]string
}

func NewAccountManager(server *Server) *AccountManager {
	am := AccountManager{
		accountToClients: make(map[string][]*Client),
		nickToAccount:    make(map[string]string),
		server:           server,
	}

	am.buildNickToAccountIndex()
	am.initVHostRequestQueue()
	return &am
}

func (am *AccountManager) buildNickToAccountIndex() {
	if !am.server.AccountConfig().NickReservation.Enabled {
		return
	}

	result := make(map[string]string)
	existsPrefix := fmt.Sprintf(keyAccountExists, "")

	am.serialCacheUpdateMutex.Lock()
	defer am.serialCacheUpdateMutex.Unlock()

	err := am.server.store.View(func(tx *buntdb.Tx) error {
		err := tx.AscendGreaterOrEqual("", existsPrefix, func(key, value string) bool {
			if !strings.HasPrefix(key, existsPrefix) {
				return false
			}
			accountName := strings.TrimPrefix(key, existsPrefix)
			if _, err := tx.Get(fmt.Sprintf(keyAccountVerified, accountName)); err == nil {
				result[accountName] = accountName
			}
			if rawNicks, err := tx.Get(fmt.Sprintf(keyAccountAdditionalNicks, accountName)); err == nil {
				additionalNicks := unmarshalReservedNicks(rawNicks)
				for _, nick := range additionalNicks {
					result[nick] = accountName
				}
			}
			return true
		})
		return err
	})

	if err != nil {
		am.server.logger.Error("internal", fmt.Sprintf("couldn't read reserved nicks: %v", err))
	} else {
		am.Lock()
		am.nickToAccount = result
		am.Unlock()
	}
}

func (am *AccountManager) initVHostRequestQueue() {
	if !am.server.AccountConfig().VHosts.Enabled {
		return
	}

	am.vHostUpdateMutex.Lock()
	defer am.vHostUpdateMutex.Unlock()

	// the db maps the account name to the autoincrementing integer ID of its request
	// create an numerically ordered index on ID, so we can list the oldest requests
	// finally, collect the integer id of the newest request and the total request count
	var total uint64
	var lastIDStr string
	err := am.server.store.Update(func(tx *buntdb.Tx) error {
		err := tx.CreateIndex(vhostRequestIdx, fmt.Sprintf(keyVHostQueueAcctToId, "*"), buntdb.IndexInt)
		if err != nil {
			return err
		}
		return tx.Descend(vhostRequestIdx, func(key, value string) bool {
			if lastIDStr == "" {
				lastIDStr = value
			}
			total++
			return true
		})
	})

	if err != nil {
		am.server.logger.Error("internal", "could not create vhost queue index", err.Error())
	}

	lastID, _ := strconv.ParseUint(lastIDStr, 10, 64)
	am.server.logger.Debug("services", fmt.Sprintf("vhost queue length is %d, autoincrementing id is %d", total, lastID))

	atomic.StoreUint64(&am.vhostRequestID, lastID)
	atomic.StoreUint64(&am.vhostRequestPendingCount, total)
}

func (am *AccountManager) NickToAccount(nick string) string {
	cfnick, err := CasefoldName(nick)
	if err != nil {
		return ""
	}

	am.RLock()
	defer am.RUnlock()
	return am.nickToAccount[cfnick]
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
	if err != nil || account == "" || account == "*" {
		return errAccountCreation
	}

	// can't register a guest nickname
	config := am.server.AccountConfig()
	renamePrefix := strings.ToLower(config.NickReservation.RenamePrefix)
	if renamePrefix != "" && strings.HasPrefix(casefoldedAccount, renamePrefix) {
		return errAccountAlreadyRegistered
	}

	accountKey := fmt.Sprintf(keyAccountExists, casefoldedAccount)
	accountNameKey := fmt.Sprintf(keyAccountName, casefoldedAccount)
	callbackKey := fmt.Sprintf(keyAccountCallback, casefoldedAccount)
	registeredTimeKey := fmt.Sprintf(keyAccountRegTime, casefoldedAccount)
	credentialsKey := fmt.Sprintf(keyAccountCredentials, casefoldedAccount)
	verificationCodeKey := fmt.Sprintf(keyAccountVerificationCode, casefoldedAccount)
	certFPKey := fmt.Sprintf(keyCertToAccount, certfp)

	credStr, err := am.serializeCredentials(passphrase, certfp)
	if err != nil {
		return err
	}

	registeredTimeStr := strconv.FormatInt(time.Now().Unix(), 10)
	callbackSpec := fmt.Sprintf("%s:%s", callbackNamespace, callbackValue)

	var setOptions *buntdb.SetOptions
	ttl := config.Registration.VerifyTimeout
	if ttl != 0 {
		setOptions = &buntdb.SetOptions{Expires: true, TTL: ttl}
	}

	err = func() error {
		am.serialCacheUpdateMutex.Lock()
		defer am.serialCacheUpdateMutex.Unlock()

		// can't register an account with the same name as a registered nick
		if am.NickToAccount(casefoldedAccount) != "" {
			return errAccountAlreadyRegistered
		}

		return am.server.store.Update(func(tx *buntdb.Tx) error {
			_, err := am.loadRawAccount(tx, casefoldedAccount)
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
			tx.Set(callbackKey, callbackSpec, setOptions)
			if certfp != "" {
				tx.Set(certFPKey, casefoldedAccount, setOptions)
			}
			return nil
		})
	}()

	if err != nil {
		return err
	}

	code, err := am.dispatchCallback(client, casefoldedAccount, callbackNamespace, callbackValue)
	if err != nil {
		am.Unregister(casefoldedAccount)
		return errCallbackFailed
	} else {
		return am.server.store.Update(func(tx *buntdb.Tx) error {
			_, _, err = tx.Set(verificationCodeKey, code, setOptions)
			return err
		})
	}
}

// validatePassphrase checks whether a passphrase is allowed by our rules
func validatePassphrase(passphrase string) error {
	// sanity check the length
	if len(passphrase) == 0 || len(passphrase) > 600 {
		return errAccountBadPassphrase
	}
	// for now, just enforce that spaces are not allowed
	for _, r := range passphrase {
		if unicode.IsSpace(r) {
			return errAccountBadPassphrase
		}
	}
	return nil
}

// helper to assemble the serialized JSON for an account's credentials
func (am *AccountManager) serializeCredentials(passphrase string, certfp string) (result string, err error) {
	var creds AccountCredentials
	creds.Version = 1
	// we need at least one of passphrase and certfp:
	if passphrase == "" && certfp == "" {
		return "", errAccountBadPassphrase
	}
	// but if we have one, it's fine if the other is missing, it just means no
	// credential of that type will be accepted.
	creds.Certificate = certfp
	if passphrase != "" {
		if validatePassphrase(passphrase) != nil {
			return "", errAccountBadPassphrase
		}
		bcryptCost := int(am.server.Config().Accounts.Registration.BcryptCost)
		creds.PassphraseHash, err = passwd.GenerateFromPassword([]byte(passphrase), bcryptCost)
		if err != nil {
			am.server.logger.Error("internal", fmt.Sprintf("could not hash password: %v", err))
			return "", errAccountCreation
		}
	}

	credText, err := json.Marshal(creds)
	if err != nil {
		am.server.logger.Error("internal", fmt.Sprintf("could not marshal credentials: %v", err))
		return "", errAccountCreation
	}
	return string(credText), nil
}

// changes the password for an account
func (am *AccountManager) setPassword(account string, password string) (err error) {
	casefoldedAccount, err := CasefoldName(account)
	if err != nil {
		return err
	}
	act, err := am.LoadAccount(casefoldedAccount)
	if err != nil {
		return err
	}

	credStr, err := am.serializeCredentials(password, act.Credentials.Certificate)
	if err != nil {
		return err
	}

	credentialsKey := fmt.Sprintf(keyAccountCredentials, casefoldedAccount)
	return am.server.store.Update(func(tx *buntdb.Tx) error {
		_, _, err := tx.Set(credentialsKey, credStr, nil)
		return err
	})
}

func (am *AccountManager) dispatchCallback(client *Client, casefoldedAccount string, callbackNamespace string, callbackValue string) (string, error) {
	if callbackNamespace == "*" || callbackNamespace == "none" {
		return "", nil
	} else if callbackNamespace == "mailto" {
		return am.dispatchMailtoCallback(client, casefoldedAccount, callbackValue)
	} else {
		return "", errors.New(fmt.Sprintf("Callback not implemented: %s", callbackNamespace))
	}
}

func (am *AccountManager) dispatchMailtoCallback(client *Client, casefoldedAccount string, callbackValue string) (code string, err error) {
	config := am.server.AccountConfig().Registration.Callbacks.Mailto
	code = utils.GenerateSecretToken()

	subject := config.VerifyMessageSubject
	if subject == "" {
		subject = fmt.Sprintf(client.t("Verify your account on %s"), am.server.name)
	}
	messageStrings := []string{
		fmt.Sprintf("From: %s\r\n", config.Sender),
		fmt.Sprintf("To: %s\r\n", callbackValue),
		fmt.Sprintf("Subject: %s\r\n", subject),
		"\r\n", // end headers, begin message body
		fmt.Sprintf(client.t("Account: %s"), casefoldedAccount) + "\r\n",
		fmt.Sprintf(client.t("Verification code: %s"), code) + "\r\n",
		"\r\n",
		client.t("To verify your account, issue one of these commands:") + "\r\n",
		fmt.Sprintf("/MSG NickServ VERIFY %s %s", casefoldedAccount, code) + "\r\n",
	}

	var message []byte
	for i := 0; i < len(messageStrings); i++ {
		message = append(message, []byte(messageStrings[i])...)
	}
	addr := fmt.Sprintf("%s:%d", config.Server, config.Port)
	var auth smtp.Auth
	if config.Username != "" && config.Password != "" {
		auth = smtp.PlainAuth("", config.Username, config.Password, config.Server)
	}

	// TODO: this will never send the password in plaintext over a nonlocal link,
	// but it might send the email in plaintext, regardless of the value of
	// config.TLS.InsecureSkipVerify
	err = smtp.SendMail(addr, auth, config.Sender, []string{callbackValue}, message)
	if err != nil {
		am.server.logger.Error("internal", fmt.Sprintf("Failed to dispatch e-mail: %v", err))
	}
	return
}

func (am *AccountManager) Verify(client *Client, account string, code string) error {
	casefoldedAccount, err := CasefoldName(account)
	if err != nil || account == "" || account == "*" {
		return errAccountVerificationFailed
	}

	verifiedKey := fmt.Sprintf(keyAccountVerified, casefoldedAccount)
	accountKey := fmt.Sprintf(keyAccountExists, casefoldedAccount)
	accountNameKey := fmt.Sprintf(keyAccountName, casefoldedAccount)
	registeredTimeKey := fmt.Sprintf(keyAccountRegTime, casefoldedAccount)
	verificationCodeKey := fmt.Sprintf(keyAccountVerificationCode, casefoldedAccount)
	callbackKey := fmt.Sprintf(keyAccountCallback, casefoldedAccount)
	credentialsKey := fmt.Sprintf(keyAccountCredentials, casefoldedAccount)

	var raw rawClientAccount

	func() {
		am.serialCacheUpdateMutex.Lock()
		defer am.serialCacheUpdateMutex.Unlock()

		err = am.server.store.Update(func(tx *buntdb.Tx) error {
			raw, err = am.loadRawAccount(tx, casefoldedAccount)
			if err == errAccountDoesNotExist {
				return errAccountDoesNotExist
			} else if err != nil {
				return errAccountVerificationFailed
			} else if raw.Verified {
				return errAccountAlreadyVerified
			}

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

			// verify the account
			tx.Set(verifiedKey, "1", nil)
			// don't need the code anymore
			tx.Delete(verificationCodeKey)
			// re-set all other keys, removing the TTL
			tx.Set(accountKey, "1", nil)
			tx.Set(accountNameKey, raw.Name, nil)
			tx.Set(registeredTimeKey, raw.RegisteredAt, nil)
			tx.Set(callbackKey, raw.Callback, nil)
			tx.Set(credentialsKey, raw.Credentials, nil)

			var creds AccountCredentials
			// XXX we shouldn't do (de)serialization inside the txn,
			// but this is like 2 usec on my system
			json.Unmarshal([]byte(raw.Credentials), &creds)
			if creds.Certificate != "" {
				certFPKey := fmt.Sprintf(keyCertToAccount, creds.Certificate)
				tx.Set(certFPKey, casefoldedAccount, nil)
			}

			return nil
		})

		if err == nil {
			am.Lock()
			am.nickToAccount[casefoldedAccount] = casefoldedAccount
			am.Unlock()
		}
	}()

	if err != nil {
		return err
	}

	raw.Verified = true
	clientAccount, err := am.deserializeRawAccount(raw)
	if err != nil {
		return err
	}
	am.Login(client, clientAccount)
	return nil
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
	// garbage nick, or garbage options, or disabled
	nrconfig := am.server.AccountConfig().NickReservation
	if err != nil || cfnick == "" || (reserve && saUnreserve) || !nrconfig.Enabled {
		return errAccountNickReservationFailed
	}

	// the cache is in sync with the DB while we hold serialCacheUpdateMutex
	am.serialCacheUpdateMutex.Lock()
	defer am.serialCacheUpdateMutex.Unlock()

	// find the affected account, which is usually the client's:
	account := client.Account()
	if saUnreserve {
		// unless this is a sadrop:
		account = am.NickToAccount(cfnick)
		if account == "" {
			// nothing to do
			return nil
		}
	}
	if account == "" {
		return errAccountNotLoggedIn
	}

	accountForNick := am.NickToAccount(cfnick)
	if reserve && accountForNick != "" {
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
			nicks = append(nicks, cfnick)
		} else {
			var newNicks []string
			for _, reservedNick := range nicks {
				if reservedNick != cfnick {
					newNicks = append(newNicks, reservedNick)
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
	} else {
		delete(am.nickToAccount, cfnick)
	}
	return nil
}

func (am *AccountManager) checkPassphrase(accountName, passphrase string) (account ClientAccount, err error) {
	account, err = am.LoadAccount(accountName)
	if err != nil {
		return
	}

	if !account.Verified {
		err = errAccountUnverified
		return
	}

	switch account.Credentials.Version {
	case 0:
		err = handleLegacyPasswordV0(am.server, accountName, account.Credentials, passphrase)
	case 1:
		err = passwd.CompareHashAndPassword(account.Credentials.PassphraseHash, []byte(passphrase))
	default:
		err = errAccountInvalidCredentials
	}
	return
}

func (am *AccountManager) AuthenticateByPassphrase(client *Client, accountName string, passphrase string) error {
	account, err := am.checkPassphrase(accountName, passphrase)
	if err != nil {
		return err
	}

	am.Login(client, account)
	return nil
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

	result, err = am.deserializeRawAccount(raw)
	return
}

func (am *AccountManager) deserializeRawAccount(raw rawClientAccount) (result ClientAccount, err error) {
	result.Name = raw.Name
	regTimeInt, _ := strconv.ParseInt(raw.RegisteredAt, 10, 64)
	result.RegisteredAt = time.Unix(regTimeInt, 0)
	e := json.Unmarshal([]byte(raw.Credentials), &result.Credentials)
	if e != nil {
		am.server.logger.Error("internal", fmt.Sprintf("could not unmarshal credentials: %v", e))
		err = errAccountDoesNotExist
		return
	}
	result.AdditionalNicks = unmarshalReservedNicks(raw.AdditionalNicks)
	result.Verified = raw.Verified
	if raw.VHost != "" {
		e := json.Unmarshal([]byte(raw.VHost), &result.VHost)
		if e != nil {
			am.server.logger.Warning("internal", fmt.Sprintf("could not unmarshal vhost for account %s: %v", result.Name, e))
			// pretend they have no vhost and move on
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
	callbackKey := fmt.Sprintf(keyAccountCallback, casefoldedAccount)
	nicksKey := fmt.Sprintf(keyAccountAdditionalNicks, casefoldedAccount)
	vhostKey := fmt.Sprintf(keyAccountVHost, casefoldedAccount)

	_, e := tx.Get(accountKey)
	if e == buntdb.ErrNotFound {
		err = errAccountDoesNotExist
		return
	}

	result.Name, _ = tx.Get(accountNameKey)
	result.RegisteredAt, _ = tx.Get(registeredTimeKey)
	result.Credentials, _ = tx.Get(credentialsKey)
	result.Callback, _ = tx.Get(callbackKey)
	result.AdditionalNicks, _ = tx.Get(nicksKey)
	result.VHost, _ = tx.Get(vhostKey)

	if _, e = tx.Get(verifiedKey); e == nil {
		result.Verified = true
	}

	return
}

func (am *AccountManager) Unregister(account string) error {
	casefoldedAccount, err := CasefoldName(account)
	if err != nil {
		return errAccountDoesNotExist
	}

	accountKey := fmt.Sprintf(keyAccountExists, casefoldedAccount)
	accountNameKey := fmt.Sprintf(keyAccountName, casefoldedAccount)
	registeredTimeKey := fmt.Sprintf(keyAccountRegTime, casefoldedAccount)
	credentialsKey := fmt.Sprintf(keyAccountCredentials, casefoldedAccount)
	callbackKey := fmt.Sprintf(keyAccountCallback, casefoldedAccount)
	verificationCodeKey := fmt.Sprintf(keyAccountVerificationCode, casefoldedAccount)
	verifiedKey := fmt.Sprintf(keyAccountVerified, casefoldedAccount)
	nicksKey := fmt.Sprintf(keyAccountAdditionalNicks, casefoldedAccount)
	vhostKey := fmt.Sprintf(keyAccountVHost, casefoldedAccount)
	vhostQueueKey := fmt.Sprintf(keyVHostQueueAcctToId, casefoldedAccount)

	var clients []*Client

	var credText string
	var rawNicks string

	am.serialCacheUpdateMutex.Lock()
	defer am.serialCacheUpdateMutex.Unlock()

	am.server.store.Update(func(tx *buntdb.Tx) error {
		tx.Delete(accountKey)
		tx.Delete(accountNameKey)
		tx.Delete(verifiedKey)
		tx.Delete(registeredTimeKey)
		tx.Delete(callbackKey)
		tx.Delete(verificationCodeKey)
		rawNicks, _ = tx.Get(nicksKey)
		tx.Delete(nicksKey)
		credText, err = tx.Get(credentialsKey)
		tx.Delete(credentialsKey)
		tx.Delete(vhostKey)
		_, err := tx.Delete(vhostQueueKey)
		am.decrementVHostQueueCount(casefoldedAccount, err)
		return nil
	})

	if err == nil {
		var creds AccountCredentials
		if err = json.Unmarshal([]byte(credText), &creds); err == nil && creds.Certificate != "" {
			certFPKey := fmt.Sprintf(keyCertToAccount, creds.Certificate)
			am.server.store.Update(func(tx *buntdb.Tx) error {
				if account, err := tx.Get(certFPKey); err == nil && account == casefoldedAccount {
					tx.Delete(certFPKey)
				}
				return nil
			})
		}
	}

	additionalNicks := unmarshalReservedNicks(rawNicks)

	am.Lock()
	defer am.Unlock()

	clients = am.accountToClients[casefoldedAccount]
	delete(am.accountToClients, casefoldedAccount)
	delete(am.nickToAccount, casefoldedAccount)
	for _, nick := range additionalNicks {
		delete(am.nickToAccount, nick)
	}
	for _, client := range clients {
		am.logoutOfAccount(client)
	}

	if err != nil {
		return errAccountDoesNotExist
	}
	return nil
}

func (am *AccountManager) AuthenticateByCertFP(client *Client) error {
	if client.certfp == "" {
		return errAccountInvalidCredentials
	}

	var account string
	var rawAccount rawClientAccount
	certFPKey := fmt.Sprintf(keyCertToAccount, client.certfp)

	err := am.server.store.Update(func(tx *buntdb.Tx) error {
		var err error
		account, _ = tx.Get(certFPKey)
		if account == "" {
			return errAccountInvalidCredentials
		}
		rawAccount, err = am.loadRawAccount(tx, account)
		if err != nil || !rawAccount.Verified {
			return errAccountUnverified
		}
		return nil
	})

	if err != nil {
		return err
	}

	// ok, we found an account corresponding to their certificate
	clientAccount, err := am.deserializeRawAccount(rawAccount)
	if err != nil {
		return err
	}
	am.Login(client, clientAccount)
	return nil
}

// represents someone's status in hostserv
type VHostInfo struct {
	ApprovedVHost   string
	Enabled         bool
	RequestedVHost  string
	RejectedVHost   string
	RejectionReason string
	LastRequestTime time.Time
}

// pair type, <VHostInfo, accountName>
type PendingVHostRequest struct {
	VHostInfo
	Account string
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

func (am *AccountManager) VHostRequest(account string, vhost string) (result VHostInfo, err error) {
	munger := func(input VHostInfo) (output VHostInfo, err error) {
		output = input
		output.RequestedVHost = vhost
		output.RejectedVHost = ""
		output.RejectionReason = ""
		output.LastRequestTime = time.Now().UTC()
		return
	}

	return am.performVHostChange(account, munger)
}

func (am *AccountManager) VHostApprove(account string) (result VHostInfo, err error) {
	munger := func(input VHostInfo) (output VHostInfo, err error) {
		output = input
		output.Enabled = true
		output.ApprovedVHost = input.RequestedVHost
		output.RequestedVHost = ""
		output.RejectionReason = ""
		return
	}

	return am.performVHostChange(account, munger)
}

func (am *AccountManager) VHostReject(account string, reason string) (result VHostInfo, err error) {
	munger := func(input VHostInfo) (output VHostInfo, err error) {
		output = input
		output.RejectedVHost = output.RequestedVHost
		output.RequestedVHost = ""
		output.RejectionReason = reason
		return
	}

	return am.performVHostChange(account, munger)
}

func (am *AccountManager) VHostSetEnabled(client *Client, enabled bool) (result VHostInfo, err error) {
	munger := func(input VHostInfo) (output VHostInfo, err error) {
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

	am.vHostUpdateMutex.Lock()
	defer am.vHostUpdateMutex.Unlock()

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
	queueKey := fmt.Sprintf(keyVHostQueueAcctToId, account)
	err = am.server.store.Update(func(tx *buntdb.Tx) error {
		if _, _, err := tx.Set(key, vhstr, nil); err != nil {
			return err
		}

		// update request queue
		if clientAccount.VHost.RequestedVHost == "" && result.RequestedVHost != "" {
			id := atomic.AddUint64(&am.vhostRequestID, 1)
			if _, _, err = tx.Set(queueKey, strconv.FormatUint(id, 10), nil); err != nil {
				return err
			}
			atomic.AddUint64(&am.vhostRequestPendingCount, 1)
		} else if clientAccount.VHost.RequestedVHost != "" && result.RequestedVHost == "" {
			_, err = tx.Delete(queueKey)
			am.decrementVHostQueueCount(account, err)
		}

		return nil
	})

	if err != nil {
		err = errAccountUpdateFailed
		return
	}

	am.applyVhostToClients(account, result)
	return result, nil
}

// XXX annoying helper method for keeping the queue count in sync with the DB
// `err` is the buntdb error returned from deleting the queue key
func (am *AccountManager) decrementVHostQueueCount(account string, err error) {
	if err == nil {
		// successfully deleted a queue entry, do a 2's complement decrement:
		atomic.AddUint64(&am.vhostRequestPendingCount, ^uint64(0))
	} else if err != buntdb.ErrNotFound {
		am.server.logger.Error("internal", "buntdb dequeue error", account, err.Error())
	}
}

func (am *AccountManager) VHostListRequests(limit int) (requests []PendingVHostRequest, total int) {
	am.vHostUpdateMutex.Lock()
	defer am.vHostUpdateMutex.Unlock()

	total = int(atomic.LoadUint64(&am.vhostRequestPendingCount))

	prefix := fmt.Sprintf(keyVHostQueueAcctToId, "")
	accounts := make([]string, 0, limit)
	err := am.server.store.View(func(tx *buntdb.Tx) error {
		return tx.Ascend(vhostRequestIdx, func(key, value string) bool {
			accounts = append(accounts, strings.TrimPrefix(key, prefix))
			return len(accounts) < limit
		})
	})

	if err != nil {
		am.server.logger.Error("internal", "couldn't traverse vhost queue", err.Error())
		return
	}

	for _, account := range accounts {
		accountInfo, err := am.LoadAccount(account)
		if err == nil {
			requests = append(requests, PendingVHostRequest{
				Account:   account,
				VHostInfo: accountInfo.VHost,
			})
		} else {
			am.server.logger.Error("internal", "corrupt account", account, err.Error())
		}
	}
	return
}

func (am *AccountManager) applyVHostInfo(client *Client, info VHostInfo) {
	// if hostserv is disabled in config, then don't grant vhosts
	// that were previously approved while it was enabled
	if !am.server.AccountConfig().VHosts.Enabled {
		return
	}

	vhost := ""
	if info.Enabled {
		vhost = info.ApprovedVHost
	}
	oldNickmask := client.NickMaskString()
	updated := client.SetVHost(vhost)
	if updated {
		// TODO: doing I/O here is kind of a kludge
		go client.sendChghost(oldNickmask, vhost)
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
	changed := client.SetAccountName(account.Name)
	if changed {
		go client.nickTimer.Touch()
	}

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

	am.logoutOfAccount(client)

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
	return
}

var (
	// EnabledSaslMechanisms contains the SASL mechanisms that exist and that we support.
	// This can be moved to some other data structure/place if we need to load/unload mechs later.
	EnabledSaslMechanisms = map[string]func(*Server, *Client, string, []byte, *ResponseBuffer) bool{
		"PLAIN":    authPlainHandler,
		"EXTERNAL": authExternalHandler,
	}
)

// AccountCredentials stores the various methods for verifying accounts.
type AccountCredentials struct {
	Version        uint
	PassphraseSalt []byte // legacy field, not used by v1 and later
	PassphraseHash []byte
	Certificate    string // fingerprint
}

// ClientAccount represents a user account.
type ClientAccount struct {
	// Name of the account.
	Name string
	// RegisteredAt represents the time that the account was registered.
	RegisteredAt    time.Time
	Credentials     AccountCredentials
	Verified        bool
	AdditionalNicks []string
	VHost           VHostInfo
}

// convenience for passing around raw serialized account data
type rawClientAccount struct {
	Name            string
	RegisteredAt    string
	Credentials     string
	Callback        string
	Verified        bool
	AdditionalNicks string
	VHost           string
}

// logoutOfAccount logs the client out of their current account.
func (am *AccountManager) logoutOfAccount(client *Client) {
	if client.Account() == "" {
		// already logged out
		return
	}

	client.SetAccountName("")
	go client.nickTimer.Touch()

	// dispatch account-notify
	// TODO: doing the I/O here is kind of a kludge, let's move this somewhere else
	go func() {
		for friend := range client.Friends(caps.AccountNotify) {
			friend.Send(nil, client.NickMaskString(), "ACCOUNT", "*")
		}
	}()
}
