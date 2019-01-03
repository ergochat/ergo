// Copyright (c) 2018 Shivaram Lingamneni <slingamn@cs.stanford.edu>
// released under the MIT license

package irc

import (
	"fmt"
	"log"
	"sort"
	"strings"

	"github.com/goshuirc/irc-go/ircfmt"
	"github.com/goshuirc/irc-go/ircmsg"

	"github.com/unendingPattern/oragono-laced/irc/utils"
)

// defines an IRC service, e.g., NICKSERV
type ircService struct {
	Name           string
	ShortName      string
	CommandAliases []string
	Commands       map[string]*serviceCommand
	HelpBanner     string
}

// defines a command associated with a service, e.g., NICKSERV IDENTIFY
type serviceCommand struct {
	aliasOf      string   // marks this command as an alias of another
	capabs       []string // oper capabs the given user has to have to access this command
	handler      func(server *Server, client *Client, command, params string, rb *ResponseBuffer)
	help         string
	helpShort    string
	authRequired bool
	enabled      func(*Server) bool // is this command enabled in the server config?
}

// looks up a command in the table of command definitions for a service, resolving aliases
func lookupServiceCommand(commands map[string]*serviceCommand, command string) *serviceCommand {
	maxDepth := 1
	depth := 0
	for depth <= maxDepth {
		result, ok := commands[command]
		if !ok {
			return nil
		} else if result.aliasOf == "" {
			return result
		} else {
			command = result.aliasOf
			depth += 1
		}
	}
	return nil
}

// all services, by lowercase name
var OragonoServices = map[string]*ircService{
	"nickserv": {
		Name:           "NickServ",
		ShortName:      "NS",
		CommandAliases: []string{"NICKSERV", "NS"},
		Commands:       nickservCommands,
		HelpBanner:     nickservHelp,
	},
	"chanserv": {
		Name:           "ChanServ",
		ShortName:      "CS",
		CommandAliases: []string{"CHANSERV", "CS"},
		Commands:       chanservCommands,
		HelpBanner:     chanservHelp,
	},
	"hostserv": {
		Name:           "HostServ",
		ShortName:      "HS",
		CommandAliases: []string{"HOSTSERV", "HS"},
		Commands:       hostservCommands,
		HelpBanner:     hostservHelp,
	},
}

// all service commands at the protocol level, by uppercase command name
// e.g., NICKSERV, NS
var oragonoServicesByCommandAlias map[string]*ircService

// special-cased command shared by all services
var servHelpCmd serviceCommand = serviceCommand{
	help: `Syntax: $bHELP [command]$b

HELP returns information on the given command.`,
	helpShort: `$bHELP$b shows in-depth information about commands.`,
}

// this handles IRC commands like `/NICKSERV INFO`, translating into `/MSG NICKSERV INFO`
func serviceCmdHandler(server *Server, client *Client, msg ircmsg.IrcMessage, rb *ResponseBuffer) bool {
	service, ok := oragonoServicesByCommandAlias[msg.Command]
	if !ok {
		server.logger.Warning("internal", "can't handle unrecognized service", msg.Command)
		return false
	}

	fakePrivmsg := strings.Join(msg.Params, " ")
	servicePrivmsgHandler(service, server, client, fakePrivmsg, rb)
	return false
}

// generic handler for service PRIVMSG
func servicePrivmsgHandler(service *ircService, server *Server, client *Client, message string, rb *ResponseBuffer) {
	commandName, params := utils.ExtractParam(message)
	commandName = strings.ToLower(commandName)

	nick := rb.target.Nick()
	sendNotice := func(notice string) {
		rb.Add(nil, service.Name, "NOTICE", nick, notice)
	}

	cmd := lookupServiceCommand(service.Commands, commandName)
	if cmd == nil {
		sendNotice(fmt.Sprintf("%s /%s HELP", client.t("Unknown command. To see available commands, run"), service.ShortName))
		return
	}

	if cmd.enabled != nil && !cmd.enabled(server) {
		sendNotice(client.t("This command has been disabled by the server administrators"))
		return
	}

	if 0 < len(cmd.capabs) && !client.HasRoleCapabs(cmd.capabs...) {
		sendNotice(client.t("Command restricted"))
		return
	}

	if cmd.authRequired && client.Account() == "" {
		sendNotice(client.t("You're not logged into an account"))
		return
	}

	server.logger.Debug("services", fmt.Sprintf("Client %s ran %s command %s", client.Nick(), service.Name, commandName))
	if commandName == "help" {
		serviceHelpHandler(service, server, client, params, rb)
	} else {
		cmd.handler(server, client, commandName, params, rb)
	}
}

// generic handler that displays help for service commands
func serviceHelpHandler(service *ircService, server *Server, client *Client, params string, rb *ResponseBuffer) {
	nick := rb.target.Nick()
	sendNotice := func(notice string) {
		rb.Add(nil, service.Name, "NOTICE", nick, notice)
	}

	sendNotice(ircfmt.Unescape(fmt.Sprintf("*** $b%s HELP$b ***", service.Name)))

	if params == "" {
		// show general help
		var shownHelpLines sort.StringSlice
		var disabledCommands bool
		for _, commandInfo := range service.Commands {
			// skip commands user can't access
			if 0 < len(commandInfo.capabs) && !client.HasRoleCapabs(commandInfo.capabs...) {
				continue
			}
			if commandInfo.aliasOf != "" {
				continue // don't show help lines for aliases
			}
			if commandInfo.enabled != nil && !commandInfo.enabled(server) {
				disabledCommands = true
				continue
			}

			shownHelpLines = append(shownHelpLines, "    "+client.t(commandInfo.helpShort))
		}

		if disabledCommands {
			shownHelpLines = append(shownHelpLines, "    "+client.t("... and other commands which have been disabled"))
		}

		// sort help lines
		sort.Sort(shownHelpLines)

		// assemble help text
		assembledHelpLines := strings.Join(shownHelpLines, "\n")
		fullHelp := ircfmt.Unescape(fmt.Sprintf(client.t(service.HelpBanner), assembledHelpLines))

		// push out help text
		for _, line := range strings.Split(fullHelp, "\n") {
			sendNotice(line)
		}
	} else {
		commandName := strings.ToLower(strings.TrimSpace(params))
		commandInfo := lookupServiceCommand(service.Commands, commandName)
		if commandInfo == nil {
			sendNotice(client.t(fmt.Sprintf("Unknown command. To see available commands, run /%s HELP", service.ShortName)))
		} else {
			for _, line := range strings.Split(ircfmt.Unescape(client.t(commandInfo.help)), "\n") {
				sendNotice(line)
			}
		}
	}

	sendNotice(ircfmt.Unescape(fmt.Sprintf(client.t("*** $bEnd of %s HELP$b ***"), service.Name)))
}

func initializeServices() {
	// this modifies the global Commands map,
	// so it must be called from irc/commands.go's init()
	oragonoServicesByCommandAlias = make(map[string]*ircService)

	for serviceName, service := range OragonoServices {
		// make `/MSG ServiceName HELP` work correctly
		service.Commands["help"] = &servHelpCmd

		// reserve the nickname
		restrictedNicknames[serviceName] = true

		// register the protocol-level commands (NICKSERV, NS) that talk to the service
		var ircCmdDef Command
		ircCmdDef.handler = serviceCmdHandler
		for _, ircCmd := range service.CommandAliases {
			Commands[ircCmd] = ircCmdDef
			oragonoServicesByCommandAlias[ircCmd] = service
		}

		// force devs to write a help entry for every command
		for commandName, commandInfo := range service.Commands {
			if commandInfo.aliasOf == "" && (commandInfo.help == "" || commandInfo.helpShort == "") {
				log.Fatal(fmt.Sprintf("help entry missing for %s command %s", serviceName, commandName))
			}
		}
	}
}
