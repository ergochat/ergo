package irc

type Channel struct {
	server    *Server
	name      string
	key       string
	topic     string
	members   ClientSet
	noOutside bool
	password  string
}

type ChannelSet map[*Channel]bool

// NewChannel creates a new channel from a `Server` and a `name` string, which
// must be unique on the server.
func NewChannel(s *Server, name string) *Channel {
	return &Channel{
		name:    name,
		members: make(ClientSet),
		server:  s,
	}
}

// Send a `Reply` to all `Client`s of the `Channel`. Skip `fromClient`, if it is
// provided.
func (ch *Channel) Send(reply Reply, fromClient *Client) {
	for client := range ch.members {
		if client != fromClient {
			client.send <- reply
		}
	}
}

func (ch *Channel) Nicks() []string {
	nicks := make([]string, len(ch.members))
	i := 0
	for member := range ch.members {
		nicks[i] = member.Nick()
		i++
	}
	return nicks
}

func (ch *Channel) IsEmpty() bool {
	return len(ch.members) == 0
}

//
// channel functionality
//

func (ch *Channel) Join(cl *Client, key string) {
	if ch.key != key {
		cl.send <- ErrBadChannelKey(ch)
		return
	}

	ch.members[cl] = true
	cl.channels[ch] = true

	ch.Send(RplJoin(ch, cl), nil)
	ch.GetTopic(cl)
	cl.send <- RplNamReply(ch)
	cl.send <- RplEndOfNames(ch.server)
}

func (ch *Channel) Part(cl *Client, message string) {
	if !ch.members[cl] {
		cl.send <- ErrNotOnChannel(ch)
		return
	}

	if message == "" {
		message = cl.Nick()
	}

	ch.Send(RplPart(ch, cl, message), nil)

	delete(ch.members, cl)
	delete(cl.channels, ch)
}

func (ch *Channel) PrivMsg(cl *Client, message string) {
	ch.Send(RplPrivMsgChannel(ch, cl, message), cl)
}

func (ch *Channel) GetTopic(cl *Client) {
	if !ch.members[cl] {
		cl.send <- ErrNotOnChannel(ch)
		return
	}

	if ch.topic != "" {
		cl.send <- RplTopic(ch)
	} else {
		cl.send <- RplNoTopic(ch)
	}
}

func (ch *Channel) ChangeTopic(cl *Client, newTopic string) {
	if !ch.members[cl] {
		cl.send <- ErrNotOnChannel(ch)
		return
	}

	ch.topic = newTopic

	if ch.topic != "" {
		ch.Send(RplTopic(ch), nil)
	} else {
		ch.Send(RplNoTopic(ch), nil)
	}
}
