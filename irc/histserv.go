// Copyright (c) 2020 Shivaram Lingamneni <slingamn@cs.stanford.edu>
// released under the MIT license

package irc

import (
	"bufio"
	"fmt"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/oragono/oragono/irc/history"
	"github.com/oragono/oragono/irc/utils"
)

const (
	histservHelp = `HistServ provides commands related to history.`
	histServMask = "HistServ!HistServ@localhost"
)

func histservEnabled(config *Config) bool {
	return config.History.Enabled
}

func historyComplianceEnabled(config *Config) bool {
	return config.History.Enabled && config.History.Persistent.Enabled && config.History.Retention.EnableAccountIndexing
}

var (
	histservCommands = map[string]*serviceCommand{
		"forget": {
			handler: histservForgetHandler,
			help: `Syntax: $bFORGET <account>$b

FORGET deletes all history messages sent by an account.`,
			helpShort: `$bFORGET$b deletes all history messages sent by an account.`,
			capabs:    []string{"history"},
			enabled:   histservEnabled,
			minParams: 1,
			maxParams: 1,
		},
		"delete": {
			handler: histservDeleteHandler,
			help: `Syntax: $bDELETE [target] <msgid>$b

DELETE deletes an individual message by its msgid. The target is a channel
name or nickname; depending on the history implementation, this may or may not
be necessary to locate the message.`,
			helpShort: `$bDELETE$b deletes an individual message by its msgid.`,
			enabled:   histservEnabled,
			minParams: 1,
			maxParams: 2,
		},
		"export": {
			handler: histservExportHandler,
			help: `Syntax: $bEXPORT <account>$b

EXPORT exports all messages sent by an account as JSON. This can be used at
the request of the account holder.`,
			helpShort: `$bEXPORT$b exports all messages sent by an account as JSON.`,
			enabled:   historyComplianceEnabled,
			capabs:    []string{"history"},
			minParams: 1,
			maxParams: 1,
		},
		"play": {
			handler: histservPlayHandler,
			help: `Syntax: $bPLAY <target> [limit]$b

PLAY plays back history messages, rendering them into direct messages from
HistServ. 'target' is a channel name (or 'me' for direct messages), and 'limit'
is a message count or a time duration. Note that message playback may be
incomplete or degraded, relative to direct playback from /HISTORY or
CHATHISTORY.`,
			helpShort: `$bPLAY$b plays back history messages.`,
			enabled:   histservEnabled,
			minParams: 1,
			maxParams: 2,
		},
	}
)

// histNotice sends the client a notice from HistServ
func histNotice(rb *ResponseBuffer, text string) {
	rb.Add(nil, histServMask, "NOTICE", rb.target.Nick(), text)
}

func histservForgetHandler(server *Server, client *Client, command string, params []string, rb *ResponseBuffer) {
	accountName := server.accounts.AccountToAccountName(params[0])
	if accountName == "" {
		histNotice(rb, client.t("Could not look up account name, proceeding anyway"))
		accountName = params[0]
	}

	server.ForgetHistory(accountName)

	histNotice(rb, fmt.Sprintf(client.t("Enqueued account %s for message deletion"), accountName))
}

func histservDeleteHandler(server *Server, client *Client, command string, params []string, rb *ResponseBuffer) {
	var target, msgid string
	if len(params) == 1 {
		msgid = params[0]
	} else {
		target, msgid = params[0], params[1]
	}

	accountName := "*"
	hasPrivs := client.HasRoleCapabs("history")
	if !hasPrivs {
		accountName = client.AccountName()
		if !(server.Config().History.Retention.AllowIndividualDelete && accountName != "*") {
			hsNotice(rb, client.t("Insufficient privileges"))
			return
		}
	}

	err := server.DeleteMessage(target, msgid, accountName)
	if err == nil {
		hsNotice(rb, client.t("Successfully deleted message"))
	} else {
		if hasPrivs {
			hsNotice(rb, fmt.Sprintf(client.t("Error deleting message: %v"), err))
		} else {
			hsNotice(rb, client.t("Could not delete message"))
		}
	}
}

func histservExportHandler(server *Server, client *Client, command string, params []string, rb *ResponseBuffer) {
	cfAccount, err := CasefoldName(params[0])
	if err != nil {
		histNotice(rb, client.t("Invalid account name"))
		return
	}

	config := server.Config()
	// don't include the account name in the filename because of escaping concerns
	filename := fmt.Sprintf("%s-%s.json", utils.GenerateSecretToken(), time.Now().UTC().Format(IRCv3TimestampFormat))
	pathname := config.getOutputPath(filename)
	outfile, err := os.Create(pathname)
	if err != nil {
		hsNotice(rb, fmt.Sprintf(client.t("Error opening export file: %v"), err))
	} else {
		hsNotice(rb, fmt.Sprintf(client.t("Started exporting data for account %[1]s to file %[2]s"), cfAccount, filename))
	}

	go histservExportAndNotify(server, cfAccount, outfile, filename, client.Nick())
}

func histservExportAndNotify(server *Server, cfAccount string, outfile *os.File, filename, alertNick string) {
	defer func() {
		if r := recover(); r != nil {
			server.logger.Error("history",
				fmt.Sprintf("Panic in history export routine: %v\n%s", r, debug.Stack()))
		}
	}()

	defer outfile.Close()
	writer := bufio.NewWriter(outfile)
	defer writer.Flush()

	server.historyDB.Export(cfAccount, writer)

	client := server.clients.Get(alertNick)
	if client != nil && client.HasRoleCapabs("history") {
		client.Send(nil, histServMask, "NOTICE", client.Nick(), fmt.Sprintf(client.t("Data export for %[1]s completed and written to %[2]s"), cfAccount, filename))
	}
}

func histservPlayHandler(server *Server, client *Client, command string, params []string, rb *ResponseBuffer) {
	items, _, err := easySelectHistory(server, client, params)
	if err != nil {
		hsNotice(rb, client.t("Could not retrieve history"))
		return
	}

	playMessage := func(timestamp time.Time, nick, message string) {
		hsNotice(rb, fmt.Sprintf("%s <%s> %s", timestamp.Format("15:04:05"), stripMaskFromNick(nick), message))
	}

	for _, item := range items {
		// TODO: support a few more of these, maybe JOIN/PART/QUIT
		if item.Type != history.Privmsg && item.Type != history.Notice {
			continue
		}
		if len(item.Message.Split) == 0 {
			playMessage(item.Message.Time, item.Nick, item.Message.Message)
		} else {
			for _, pair := range item.Message.Split {
				playMessage(item.Message.Time, item.Nick, pair.Message)
			}
		}
	}

	hsNotice(rb, client.t("End of history playback"))
}

// handles parameter parsing and history queries for /HISTORY and /HISTSERV PLAY
func easySelectHistory(server *Server, client *Client, params []string) (items []history.Item, channel *Channel, err error) {
	target := params[0]
	if strings.ToLower(target) == "me" {
		target = "*"
	}
	channel, sequence, err := server.GetHistorySequence(nil, client, target)

	if sequence == nil || err != nil {
		return nil, nil, errNoSuchChannel
	}

	var duration time.Duration
	maxChathistoryLimit := server.Config().History.ChathistoryMax
	limit := 100
	if maxChathistoryLimit < limit {
		limit = maxChathistoryLimit
	}
	if len(params) > 1 {
		providedLimit, err := strconv.Atoi(params[1])
		if err == nil && providedLimit != 0 {
			limit = providedLimit
			if maxChathistoryLimit < limit {
				limit = maxChathistoryLimit
			}
		} else if err != nil {
			duration, err = time.ParseDuration(params[1])
			if err == nil {
				limit = maxChathistoryLimit
			}
		}
	}

	if duration == 0 {
		items, _, err = sequence.Between(history.Selector{}, history.Selector{}, limit)
	} else {
		now := time.Now().UTC()
		start := history.Selector{Time: now}
		end := history.Selector{Time: now.Add(-duration)}
		items, _, err = sequence.Between(start, end, limit)
	}
	return
}
