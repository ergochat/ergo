// Copyright (c) 2012-2014 Jeremy Latt
// Copyright (c) 2014-2015 Edmund Huber
// Copyright (c) 2016-2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import (
	"errors"
	"fmt"
	"time"

	"github.com/oragono/oragono/irc/utils"
)

// Runtime Errors
var (
	errAccountAlreadyRegistered       = errors.New(`Account already exists`)
	errAccountAlreadyUnregistered     = errors.New(`That account name was registered previously and can't be reused`)
	errAccountAlreadyVerified         = errors.New(`Account is already verified`)
	errAccountCantDropPrimaryNick     = errors.New("Can't unreserve primary nickname")
	errAccountCreation                = errors.New("Account could not be created")
	errAccountDoesNotExist            = errors.New("Account does not exist")
	errAccountInvalidCredentials      = errors.New("Invalid account credentials")
	errAccountBadPassphrase           = errors.New(`Passphrase contains forbidden characters or is otherwise invalid`)
	errAccountNickReservationFailed   = errors.New("Could not (un)reserve nick")
	errAccountNotLoggedIn             = errors.New("You're not logged into an account")
	errAccountAlreadyLoggedIn         = errors.New("You're already logged into an account")
	errAccountTooManyNicks            = errors.New("Account has too many reserved nicks")
	errAccountUnverified              = errors.New(`Account is not yet verified`)
	errAccountVerificationFailed      = errors.New("Account verification failed")
	errAccountVerificationInvalidCode = errors.New("Invalid account verification code")
	errAccountUpdateFailed            = errors.New(`Error while updating your account information`)
	errAccountMustHoldNick            = errors.New(`You must hold that nickname in order to register it`)
	errAuthzidAuthcidMismatch         = errors.New(`authcid and authzid must be the same`)
	errCallbackFailed                 = errors.New("Account verification could not be sent")
	errCertfpAlreadyExists            = errors.New(`An account already exists for your certificate fingerprint`)
	errChannelNotOwnedByAccount       = errors.New("Channel not owned by the specified account")
	errChannelTransferNotOffered      = errors.New(`You weren't offered ownership of that channel`)
	errChannelAlreadyRegistered       = errors.New("Channel is already registered")
	errChannelNotRegistered           = errors.New("Channel is not registered")
	errChannelNameInUse               = errors.New(`Channel name in use`)
	errInvalidChannelName             = errors.New(`Invalid channel name`)
	errMonitorLimitExceeded           = errors.New("Monitor limit exceeded")
	errNickMissing                    = errors.New("nick missing")
	errNicknameInvalid                = errors.New("invalid nickname")
	errNicknameInUse                  = errors.New("nickname in use")
	errInsecureReattach               = errors.New("insecure reattach")
	errNicknameReserved               = errors.New("nickname is reserved")
	errNickAccountMismatch            = errors.New(`Your nickname must match your account name; try logging out and logging back in with SASL`)
	errNoExistingBan                  = errors.New("Ban does not exist")
	errNoSuchChannel                  = errors.New(`No such channel`)
	errChannelPurged                  = errors.New(`This channel was purged by the server operators and cannot be used`)
	errConfusableIdentifier           = errors.New("This identifier is confusable with one already in use")
	errInsufficientPrivs              = errors.New("Insufficient privileges")
	errInvalidUsername                = errors.New("Invalid username")
	errFeatureDisabled                = errors.New(`That feature is disabled`)
	errBanned                         = errors.New("IP or nickmask banned")
	errInvalidParams                  = utils.ErrInvalidParams
	errNoVhost                        = errors.New(`You do not have an approved vhost`)
	errVhostsForbidden                = errors.New(`An administrator has denied you the ability to use vhosts`)
	errLimitExceeded                  = errors.New("Limit exceeded")
	errNoop                           = errors.New("Action was a no-op")
	errCASFailed                      = errors.New("Compare-and-swap update of database value failed")
	errEmptyCredentials               = errors.New("No more credentials are approved")
	errCredsExternallyManaged         = errors.New("Credentials are externally managed and cannot be changed here")
	errInvalidMultilineBatch          = errors.New("Invalid multiline batch")
	errTimedOut                       = errors.New("Operation timed out")
	errInvalidUtf8                    = errors.New("Message rejected for invalid utf8")
	errClientDestroyed                = errors.New("Client was already destroyed")
	errTooManyChannels                = errors.New("You have joined too many channels")
	errWrongChannelKey                = errors.New("Cannot join password-protected channel without the password")
	errInviteOnly                     = errors.New("Cannot join invite-only channel without an invite")
	errRegisteredOnly                 = errors.New("Cannot join registered-only channel without an account")
)

// Socket Errors
var (
	errNoPeerCerts = errors.New("Client did not provide a certificate")
	errNotTLS      = errors.New("Not a TLS connection")
	errReadQ       = errors.New("ReadQ Exceeded")
)

// String Errors
var (
	errCouldNotStabilize = errors.New("Could not stabilize string while casefolding")
	errStringIsEmpty     = errors.New("String is empty")
	errInvalidCharacter  = errors.New("Invalid character")
)

type CertKeyError struct {
	Err error
}

func (ck *CertKeyError) Error() string {
	return fmt.Sprintf("Invalid TLS cert/key pair: %v", ck.Err)
}

type ThrottleError struct {
	time.Duration
}

func (te *ThrottleError) Error() string {
	return fmt.Sprintf(`Please wait at least %v and try again`, te.Duration)
}

// Config Errors
var (
	ErrDatastorePathMissing    = errors.New("Datastore path missing")
	ErrLimitsAreInsane         = errors.New("Limits aren't setup properly, check them and make them sane")
	ErrLineLengthsTooSmall     = errors.New("Line lengths must be 512 or greater (check the linelen section under server->limits)")
	ErrLoggerExcludeEmpty      = errors.New("Encountered logging type '-' with no type to exclude")
	ErrLoggerFilenameMissing   = errors.New("Logging configuration specifies 'file' method but 'filename' is empty")
	ErrLoggerHasNoTypes        = errors.New("Logger has no types to log")
	ErrNetworkNameMissing      = errors.New("Network name missing")
	ErrNoFingerprintOrPassword = errors.New("Fingerprint or password needs to be specified")
	ErrNoListenersDefined      = errors.New("Server listening addresses missing")
	ErrOperClassDependencies   = errors.New("OperClasses contains a looping dependency, or a class extends from a class that doesn't exist")
	ErrServerNameMissing       = errors.New("Server name missing")
	ErrServerNameNotHostname   = errors.New("Server name must match the format of a hostname")
)
