// Copyright (c) 2012-2014 Jeremy Latt
// Copyright (c) 2014-2015 Edmund Huber
// Copyright (c) 2016-2017 Daniel Oaks <daniel@danieloaks.net>
// released under the MIT license

package irc

import "errors"

// Runtime Errors
var (
	errAccountAlreadyRegistered       = errors.New("Account already exists")
	errAccountAlreadyVerified         = errors.New("Account is already verified")
	errAccountCantDropPrimaryNick     = errors.New("Can't unreserve primary nickname")
	errAccountCreation                = errors.New("Account could not be created")
	errAccountCredUpdate              = errors.New("Could not update password hash to new method")
	errAccountDoesNotExist            = errors.New("Account does not exist")
	errAccountInvalidCredentials      = errors.New("Invalid account credentials")
	errAccountBadPassphrase           = errors.New("Passphrase contains forbidden characters or is otherwise invalid")
	errAccountNickReservationFailed   = errors.New("Could not (un)reserve nick")
	errAccountNotLoggedIn             = errors.New("You're not logged into an account")
	errAccountTooManyNicks            = errors.New("Account has too many reserved nicks")
	errAccountUnverified              = errors.New("Account is not yet verified")
	errAccountVerificationFailed      = errors.New("Account verification failed")
	errAccountVerificationInvalidCode = errors.New("Invalid account verification code")
	errAccountUpdateFailed            = errors.New("Error while updating your account information")
	errCallbackFailed                 = errors.New("Account verification could not be sent")
	errCertfpAlreadyExists            = errors.New("An account already exists with your certificate")
	errChannelAlreadyRegistered       = errors.New("Channel is already registered")
	errChannelNameInUse               = errors.New("Channel name in use")
	errInvalidChannelName             = errors.New("Invalid channel name")
	errMonitorLimitExceeded           = errors.New("Monitor limit exceeded")
	errNickMissing                    = errors.New("nick missing")
	errNicknameInUse                  = errors.New("nickname in use")
	errNicknameReserved               = errors.New("nickname is reserved")
	errNoExistingBan                  = errors.New("Ban does not exist")
	errNoSuchChannel                  = errors.New("No such channel")
	errRenamePrivsNeeded              = errors.New("Only chanops can rename channels")
	errInsufficientPrivs              = errors.New("Insufficient privileges")
	errSaslFail                       = errors.New("SASL failed")
	errResumeTokenAlreadySet          = errors.New("Client was already assigned a resume token")
	errInvalidUsername                = errors.New("Invalid username")
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

// Config Errors
var (
	ErrDatastorePathMissing    = errors.New("Datastore path missing")
	ErrInvalidCertKeyPair      = errors.New("tls cert+key: invalid pair")
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
