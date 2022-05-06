// Copyright (c) 2018 Shivaram Lingamneni <slingamn@cs.stanford.edu>
// released under the MIT license

package irc

import (
	"errors"
	"fmt"
	"regexp"

	"github.com/ergochat/irc-go/ircfmt"

	"github.com/ergochat/ergo/irc/sno"
	"github.com/ergochat/ergo/irc/utils"
)

const (
	hostservHelp = `HostServ lets you manage your vhost (i.e., the string displayed
in place of your client's hostname/IP).`
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

STATUS displays your current vhost, if any, and whether it is enabled or
disabled. A server operator can view someone else's status.`,
			helpShort: `$bSTATUS$b shows your vhost status.`,
			enabled:   hostservEnabled,
		},
		"set": {
			handler: hsSetHandler,
			help: `Syntax: $bSET <user> <vhost>$b

SET sets a user's vhost.`,
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

func hsOnOffHandler(service *ircService, server *Server, client *Client, command string, params []string, rb *ResponseBuffer) {
	enable := false
	if command == "on" {
		enable = true
	}

	_, err := server.accounts.VHostSetEnabled(client, enable)
	if err == errNoVhost {
		service.Notice(rb, client.t(err.Error()))
	} else if err != nil {
		service.Notice(rb, client.t("An error occurred"))
	} else if enable {
		service.Notice(rb, client.t("Successfully enabled your vhost"))
	} else {
		service.Notice(rb, client.t("Successfully disabled your vhost"))
	}
}

func hsStatusHandler(service *ircService, server *Server, client *Client, command string, params []string, rb *ResponseBuffer) {
	var accountName string
	if len(params) > 0 {
		if !client.HasRoleCapabs("vhosts") {
			service.Notice(rb, client.t("Command restricted"))
			return
		}
		accountName = params[0]
	} else {
		accountName = client.Account()
		if accountName == "" {
			service.Notice(rb, client.t("You're not logged into an account"))
			return
		}
	}

	account, err := server.accounts.LoadAccount(accountName)
	if err != nil {
		if err != errAccountDoesNotExist {
			server.logger.Warning("internal", "error loading account info", accountName, err.Error())
		}
		service.Notice(rb, client.t("No such account"))
		return
	}

	if account.VHost.ApprovedVHost != "" {
		service.Notice(rb, fmt.Sprintf(client.t("Account %[1]s has vhost: %[2]s"), accountName, account.VHost.ApprovedVHost))
		if !account.VHost.Enabled {
			service.Notice(rb, client.t("This vhost is currently disabled, but can be enabled with /HS ON"))
		}
	} else {
		service.Notice(rb, fmt.Sprintf(client.t("Account %s has no vhost"), accountName))
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

func hsSetHandler(service *ircService, server *Server, client *Client, command string, params []string, rb *ResponseBuffer) {
	oper := client.Oper()
	user := params[0]
	var vhost string

	if command == "set" {
		vhost = params[1]
		if validateVhost(server, vhost, true) != nil {
			service.Notice(rb, client.t("Invalid vhost"))
			return
		}
	}
	// else: command == "del", vhost == ""

	_, err := server.accounts.VHostSet(user, vhost)
	if err != nil {
		service.Notice(rb, client.t("An error occurred"))
	} else if vhost != "" {
		service.Notice(rb, client.t("Successfully set vhost"))
		server.snomasks.Send(sno.LocalVhosts, fmt.Sprintf("Operator %[1]s set vhost %[2]s on account %[3]s", oper.Name, vhost, user))
	} else {
		service.Notice(rb, client.t("Successfully cleared vhost"))
		server.snomasks.Send(sno.LocalVhosts, fmt.Sprintf("Operator %[1]s cleared vhost on account %[2]s", oper.Name, user))
	}
}

func hsSetCloakSecretHandler(service *ircService, server *Server, client *Client, command string, params []string, rb *ResponseBuffer) {
	secret := params[0]
	expectedCode := utils.ConfirmationCode(secret, server.ctime)
	if len(params) == 1 || params[1] != expectedCode {
		service.Notice(rb, ircfmt.Unescape(client.t("$bWarning: changing the cloak secret will invalidate stored ban/invite/exception lists.$b")))
		service.Notice(rb, fmt.Sprintf(client.t("To confirm, run this command: %s"), fmt.Sprintf("/HS SETCLOAKSECRET %s %s", secret, expectedCode)))
		return
	}
	StoreCloakSecret(server.store, secret)
	service.Notice(rb, client.t("Rotated the cloak secret; you must rehash or restart the server for it to take effect"))
}
