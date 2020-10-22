// Copyright (c) 2018 Shivaram Lingamneni <slingamn@cs.stanford.edu>
// released under the MIT license

package irc

import (
	"errors"
	"fmt"
	"regexp"

	"github.com/goshuirc/irc-go/ircfmt"

	"github.com/oragono/oragono/irc/utils"
)

const (
	hostservHelp = `HostServ lets you manage your vhost (i.e., the string displayed
in place of your client's hostname/IP).`
	hsNickMask = "HostServ!HostServ@localhost"
)

var (
	errVHostBadCharacters = errors.New("Vhost contains prohibited characters")
	errVHostTooLong       = errors.New("Vhost is too long")
	// ascii only for now
	defaultValidVhostRegex = regexp.MustCompile(`^[0-9A-Za-z.\-_/]+$`)
)

func hostservEnabled(config *Config) bool {
	return config.Accounts.VHosts.Enabled
}

var (
	hostservCommands = map[string]*serviceCommand{
		"on": {
			handler: hsOnOffHandler,
			help: `Syntax: $bON$b

ON enables your vhost, if you have one approved.`,
			helpShort:    `$bON$b enables your vhost, if you have one approved.`,
			authRequired: true,
			enabled:      hostservEnabled,
		},
		"off": {
			handler: hsOnOffHandler,
			help: `Syntax: $bOFF$b

OFF disables your vhost, if you have one approved.`,
			helpShort:    `$bOFF$b disables your vhost, if you have one approved.`,
			authRequired: true,
			enabled:      hostservEnabled,
		},
		"status": {
			handler: hsStatusHandler,
			help: `Syntax: $bSTATUS [user]$b

STATUS displays your current vhost, if any, and the status of your most recent
request for a new one. A server operator can view someone else's status.`,
			helpShort: `$bSTATUS$b shows your vhost and request status.`,
			enabled:   hostservEnabled,
		},
		"set": {
			handler: hsSetHandler,
			help: `Syntax: $bSET <user> <vhost>$b

SET sets a user's vhost, bypassing the request system.`,
			helpShort: `$bSET$b sets a user's vhost.`,
			capabs:    []string{"vhosts"},
			enabled:   hostservEnabled,
			minParams: 2,
		},
		"del": {
			handler: hsSetHandler,
			help: `Syntax: $bDEL <user>$b

DEL deletes a user's vhost.`,
			helpShort: `$bDEL$b deletes a user's vhost.`,
			capabs:    []string{"vhosts"},
			enabled:   hostservEnabled,
			minParams: 1,
		},
		"setcloaksecret": {
			handler: hsSetCloakSecretHandler,
			help: `Syntax: $bSETCLOAKSECRET$b <secret> [code]

SETCLOAKSECRET can be used to set or rotate the cloak secret. You should use
a cryptographically strong secret. To prevent accidental modification, a
verification code is required; invoking the command without a code will
display the necessary code.`,
			helpShort: `$bSETCLOAKSECRET$b modifies the IP cloaking secret.`,
			capabs:    []string{"vhosts", "rehash"},
			minParams: 1,
			maxParams: 2,
		},
	}
)

// hsNotice sends the client a notice from HostServ
func hsNotice(rb *ResponseBuffer, text string) {
	rb.Add(nil, hsNickMask, "NOTICE", rb.target.Nick(), text)
}

func hsOnOffHandler(server *Server, client *Client, command string, params []string, rb *ResponseBuffer) {
	enable := false
	if command == "on" {
		enable = true
	}

	_, err := server.accounts.VHostSetEnabled(client, enable)
	if err == errNoVhost {
		hsNotice(rb, client.t(err.Error()))
	} else if err != nil {
		hsNotice(rb, client.t("An error occurred"))
	} else if enable {
		hsNotice(rb, client.t("Successfully enabled your vhost"))
	} else {
		hsNotice(rb, client.t("Successfully disabled your vhost"))
	}
}

func hsStatusHandler(server *Server, client *Client, command string, params []string, rb *ResponseBuffer) {
	var accountName string
	if len(params) > 0 {
		if !client.HasRoleCapabs("vhosts") {
			hsNotice(rb, client.t("Command restricted"))
			return
		}
		accountName = params[0]
	} else {
		accountName = client.Account()
		if accountName == "" {
			hsNotice(rb, client.t("You're not logged into an account"))
			return
		}
	}

	account, err := server.accounts.LoadAccount(accountName)
	if err != nil {
		if err != errAccountDoesNotExist {
			server.logger.Warning("internal", "error loading account info", accountName, err.Error())
		}
		hsNotice(rb, client.t("No such account"))
		return
	}

	if account.VHost.ApprovedVHost != "" {
		hsNotice(rb, fmt.Sprintf(client.t("Account %[1]s has vhost: %[2]s"), accountName, account.VHost.ApprovedVHost))
		if !account.VHost.Enabled {
			hsNotice(rb, client.t("This vhost is currently disabled, but can be enabled with /HS ON"))
		}
	} else {
		hsNotice(rb, fmt.Sprintf(client.t("Account %s has no vhost"), accountName))
	}
}

func validateVhost(server *Server, vhost string, oper bool) error {
	config := server.Config()
	if len(vhost) > config.Accounts.VHosts.MaxLength {
		return errVHostTooLong
	}
	if !config.Accounts.VHosts.validRegexp.MatchString(vhost) {
		return errVHostBadCharacters
	}
	return nil
}

func hsSetHandler(server *Server, client *Client, command string, params []string, rb *ResponseBuffer) {
	user := params[0]
	var vhost string

	if command == "set" {
		vhost = params[1]
		if validateVhost(server, vhost, true) != nil {
			hsNotice(rb, client.t("Invalid vhost"))
			return
		}
	}
	// else: command == "del", vhost == ""

	_, err := server.accounts.VHostSet(user, vhost)
	if err != nil {
		hsNotice(rb, client.t("An error occurred"))
	} else if vhost != "" {
		hsNotice(rb, client.t("Successfully set vhost"))
	} else {
		hsNotice(rb, client.t("Successfully cleared vhost"))
	}
}

func hsSetCloakSecretHandler(server *Server, client *Client, command string, params []string, rb *ResponseBuffer) {
	secret := params[0]
	expectedCode := utils.ConfirmationCode(secret, server.ctime)
	if len(params) == 1 || params[1] != expectedCode {
		hsNotice(rb, ircfmt.Unescape(client.t("$bWarning: changing the cloak secret will invalidate stored ban/invite/exception lists.$b")))
		hsNotice(rb, fmt.Sprintf(client.t("To confirm, run this command: %s"), fmt.Sprintf("/HS SETCLOAKSECRET %s %s", secret, expectedCode)))
		return
	}
	StoreCloakSecret(server.store, secret)
	hsNotice(rb, client.t("Rotated the cloak secret; you must rehash or restart the server for it to take effect"))
}
