// Copyright (c) 2019 Shivaram Lingamneni <slingamn@cs.stanford.edu>
// released under the MIT license

package irc

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

type zncCommandHandler func(client *Client, command string, params []string, rb *ResponseBuffer)

var zncHandlers = map[string]zncCommandHandler{
	"*playback": zncPlaybackHandler,
}

func zncPrivmsgHandler(client *Client, command string, privmsg string, rb *ResponseBuffer) {
	zncModuleHandler(client, command, strings.Fields(privmsg), rb)
}

func zncModuleHandler(client *Client, command string, params []string, rb *ResponseBuffer) {
	command = strings.ToLower(command)
	if subHandler, ok := zncHandlers[command]; ok {
		subHandler(client, command, params, rb)
	} else {
		rb.Add(nil, "*status!znc@znc.in", "NOTICE", rb.target.Nick(), fmt.Sprintf(client.t("No such module [%s]"), command))
	}
}

// "number of seconds (floating point for millisecond precision) elapsed since January 1, 1970"
func zncWireTimeToTime(str string) (result time.Time) {
	var secondsPortion, fracPortion string
	dot := strings.IndexByte(str, '.')
	if dot == -1 {
		secondsPortion = str
	} else {
		secondsPortion = str[:dot]
		fracPortion = str[dot:]
	}
	seconds, _ := strconv.ParseInt(secondsPortion, 10, 64)
	fraction, _ := strconv.ParseFloat(fracPortion, 64)
	return time.Unix(seconds, int64(fraction*1000000000))
}

type zncPlaybackTimes struct {
	after   time.Time
	before  time.Time
	targets map[string]bool // nil for "*" (everything), otherwise the channel names
}

// https://wiki.znc.in/Playback
// PRIVMSG *playback :play <target> [lower_bound] [upper_bound]
// e.g., PRIVMSG *playback :play * 1558374442
func zncPlaybackHandler(client *Client, command string, params []string, rb *ResponseBuffer) {
	if len(params) < 2 {
		return
	} else if strings.ToLower(params[0]) != "play" {
		return
	}
	targetString := params[1]

	var after, before time.Time
	if 2 < len(params) {
		after = zncWireTimeToTime(params[2])
	}
	if 3 < len(params) {
		before = zncWireTimeToTime(params[3])
	}

	var targets map[string]bool

	// OK: the user's PMs get played back immediately on receiving this,
	// then we save the timestamps in the session to handle replay on future channel joins
	config := client.server.Config()
	if params[1] == "*" {
		items, _ := client.history.Between(after, before, false, config.History.ChathistoryMax)
		client.replayPrivmsgHistory(rb, items, true)
	} else {
		for _, targetName := range strings.Split(targetString, ",") {
			if cfTarget, err := CasefoldChannel(targetName); err == nil {
				if targets == nil {
					targets = make(map[string]bool)
				}
				targets[cfTarget] = true
			}
		}
	}

	rb.session.zncPlaybackTimes = &zncPlaybackTimes{
		after:   after,
		before:  before,
		targets: targets,
	}
}
