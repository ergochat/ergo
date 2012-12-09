package irc

type Channel struct {
	name       string
	key        string
	topic      string
	members    ClientSet
	inviteOnly bool
	invites    map[string]bool
	server     *Server
}

type ChannelSet map[*Channel]bool

func NewChannel(s *Server, name string) *Channel {
	return &Channel{name: name, members: make(ClientSet), invites: make(map[string]bool), server: s}
}

func (ch *Channel) Send(reply Reply, fromClient *Client) {
	for client := range ch.members {
		if client != fromClient {
			client.send <- reply
		}
	}
}

// channel functionality

func (ch *Channel) Join(cl *Client, key string) {
	if ch.key != key {
		cl.send <- ErrInviteOnlyChannel(ch)
		return
	}

	if ch.inviteOnly && !ch.invites[cl.nick] {
		cl.send <- ErrBadChannelKey(ch)
		return
	}

	ch.members[cl] = true
	cl.channels[ch] = true

	ch.Send(RplJoin(ch, cl), nil)
	ch.GetTopic(cl)

	for member := range ch.members {
		cl.send <- RplNamReply(ch, member)
	}
	cl.send <- RplEndOfNames(ch.server)
}

func (ch *Channel) Part(cl *Client, message string) {
	if !ch.members[cl] {
		cl.send <- ErrNotOnChannel(ch)
		return
	}

	delete(ch.members, cl)
	delete(cl.channels, ch)

	ch.Send(RplPart(ch, cl, message), nil)
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
