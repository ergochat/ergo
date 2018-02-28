// Copyright (c) 2016-2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/smtp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/oragono/oragono/irc/caps"
	"github.com/oragono/oragono/irc/passwd"
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
	keyCertToAccount           = "account.creds.certfp %s"
)

// everything about accounts is persistent; therefore, the database is the authoritative
// source of truth for all account information. anything on the heap is just a cache
type AccountManager struct {
	sync.RWMutex                      // tier 2
	serialCacheUpdateMutex sync.Mutex // tier 3

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

	return
}

func (am *AccountManager) NickToAccount(cfnick string) string {
	am.RLock()
	defer am.RUnlock()
	return am.nickToAccount[cfnick]
}

func (am *AccountManager) Register(client *Client, account string, callbackNamespace string, callbackValue string, passphrase string, certfp string) error {
	casefoldedAccount, err := CasefoldName(account)
	if err != nil || account == "" || account == "*" {
		return errAccountCreation
	}

	// can't register a guest nickname
	renamePrefix := strings.ToLower(am.server.AccountConfig().NickReservation.RenamePrefix)
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

	var creds AccountCredentials
	// always set passphrase salt
	creds.PassphraseSalt, err = passwd.NewSalt()
	if err != nil {
		return errAccountCreation
	}
	// it's fine if this is empty, that just means no certificate is authorized
	creds.Certificate = certfp
	if passphrase != "" {
		creds.PassphraseHash, err = am.server.passwords.GenerateFromPassword(creds.PassphraseSalt, passphrase)
		if err != nil {
			am.server.logger.Error("internal", fmt.Sprintf("could not hash password: %v", err))
			return errAccountCreation
		}
	}

	credText, err := json.Marshal(creds)
	if err != nil {
		am.server.logger.Error("internal", fmt.Sprintf("could not marshal credentials: %v", err))
		return errAccountCreation
	}
	credStr := string(credText)

	registeredTimeStr := strconv.FormatInt(time.Now().Unix(), 10)
	callbackSpec := fmt.Sprintf("%s:%s", callbackNamespace, callbackValue)

	var setOptions *buntdb.SetOptions
	ttl := am.server.AccountConfig().Registration.VerifyTimeout
	if ttl != 0 {
		setOptions = &buntdb.SetOptions{Expires: true, TTL: ttl}
	}

	err = am.server.store.Update(func(tx *buntdb.Tx) error {
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
	buf := make([]byte, 16)
	rand.Read(buf)
	code = hex.EncodeToString(buf)

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
		fmt.Sprintf("/ACC VERIFY %s %s", casefoldedAccount, code) + "\r\n",
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
				if storedCode == "" || subtle.ConstantTimeCompare([]byte(code), []byte(storedCode)) == 1 {
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

	am.Login(client, raw.Name)
	return nil
}

func (am *AccountManager) AuthenticateByPassphrase(client *Client, accountName string, passphrase string) error {
	casefoldedAccount, err := CasefoldName(accountName)
	if err != nil {
		return errAccountDoesNotExist
	}

	account, err := am.LoadAccount(casefoldedAccount)
	if err != nil {
		return err
	}

	if !account.Verified {
		return errAccountUnverified
	}

	err = am.server.passwords.CompareHashAndPassword(
		account.Credentials.PassphraseHash, account.Credentials.PassphraseSalt, passphrase)
	if err != nil {
		return errAccountInvalidCredentials
	}

	am.Login(client, account.Name)
	return nil
}

func (am *AccountManager) LoadAccount(casefoldedAccount string) (result ClientAccount, err error) {
	var raw rawClientAccount
	am.server.store.View(func(tx *buntdb.Tx) error {
		raw, err = am.loadRawAccount(tx, casefoldedAccount)
		return nil
	})
	if err != nil {
		return
	}

	result.Name = raw.Name
	regTimeInt, _ := strconv.ParseInt(raw.RegisteredAt, 10, 64)
	result.RegisteredAt = time.Unix(regTimeInt, 0)
	e := json.Unmarshal([]byte(raw.Credentials), &result.Credentials)
	if e != nil {
		am.server.logger.Error("internal", fmt.Sprintf("could not unmarshal credentials: %v", e))
		err = errAccountDoesNotExist
		return
	}
	result.Verified = raw.Verified
	return
}

func (am *AccountManager) loadRawAccount(tx *buntdb.Tx, casefoldedAccount string) (result rawClientAccount, err error) {
	accountKey := fmt.Sprintf(keyAccountExists, casefoldedAccount)
	accountNameKey := fmt.Sprintf(keyAccountName, casefoldedAccount)
	registeredTimeKey := fmt.Sprintf(keyAccountRegTime, casefoldedAccount)
	credentialsKey := fmt.Sprintf(keyAccountCredentials, casefoldedAccount)
	verifiedKey := fmt.Sprintf(keyAccountVerified, casefoldedAccount)
	callbackKey := fmt.Sprintf(keyAccountCallback, casefoldedAccount)

	_, e := tx.Get(accountKey)
	if e == buntdb.ErrNotFound {
		err = errAccountDoesNotExist
		return
	}

	result.Name, _ = tx.Get(accountNameKey)
	result.RegisteredAt, _ = tx.Get(registeredTimeKey)
	result.Credentials, _ = tx.Get(credentialsKey)
	result.Callback, _ = tx.Get(callbackKey)

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

	var clients []*Client

	func() {
		var credText string

		am.serialCacheUpdateMutex.Lock()
		defer am.serialCacheUpdateMutex.Unlock()

		am.server.store.Update(func(tx *buntdb.Tx) error {
			tx.Delete(accountKey)
			tx.Delete(accountNameKey)
			tx.Delete(verifiedKey)
			tx.Delete(registeredTimeKey)
			tx.Delete(callbackKey)
			tx.Delete(verificationCodeKey)
			credText, err = tx.Get(credentialsKey)
			tx.Delete(credentialsKey)
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

		am.Lock()
		defer am.Unlock()
		clients = am.accountToClients[casefoldedAccount]
		delete(am.accountToClients, casefoldedAccount)
		// TODO when registration of multiple nicks is fully implemented,
		// save the nicks that were deleted from the store and delete them here:
		delete(am.nickToAccount, casefoldedAccount)
	}()

	for _, client := range clients {
		client.LogoutOfAccount()
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

	am.Login(client, rawAccount.Name)
	return nil
}

func (am *AccountManager) Login(client *Client, account string) {
	client.LoginToAccount(account)

	casefoldedAccount, _ := CasefoldName(account)
	am.Lock()
	defer am.Unlock()
	am.accountToClients[casefoldedAccount] = append(am.accountToClients[casefoldedAccount], client)
}

func (am *AccountManager) Logout(client *Client) {
	casefoldedAccount := client.Account()
	if casefoldedAccount == "" || casefoldedAccount == "*" {
		return
	}

	client.LogoutOfAccount()

	am.Lock()
	defer am.Unlock()

	if client.LoggedIntoAccount() {
		return
	}

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
	PassphraseSalt []byte
	PassphraseHash []byte
	Certificate    string // fingerprint
}

// ClientAccount represents a user account.
type ClientAccount struct {
	// Name of the account.
	Name string
	// RegisteredAt represents the time that the account was registered.
	RegisteredAt time.Time
	Credentials  AccountCredentials
	Verified     bool
}

// convenience for passing around raw serialized account data
type rawClientAccount struct {
	Name         string
	RegisteredAt string
	Credentials  string
	Callback     string
	Verified     bool
}

// LoginToAccount logs the client into the given account.
func (client *Client) LoginToAccount(account string) {
	changed := client.SetAccountName(account)
	if changed {
		client.nickTimer.Touch()
	}
}

// LogoutOfAccount logs the client out of their current account.
func (client *Client) LogoutOfAccount() {
	if client.Account() == "" {
		// already logged out
		return
	}

	client.SetAccountName("")
	client.nickTimer.Touch()

	// dispatch account-notify
	// TODO: doing the I/O here is kind of a kludge, let's move this somewhere else
	for friend := range client.Friends(caps.AccountNotify) {
		friend.Send(nil, client.nickMaskString, "ACCOUNT", "*")
	}
}

