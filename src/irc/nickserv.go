package irc

import (
	"log"
)

type NickServCommand interface {
	HandleNickServ(*NickServ)
	Client() *Client
	SetClient(*Client)
}

type NickServ struct {
	*Service
}

func NewNickServ(s *Server) *NickServ {
	return &NickServ{
		Service: NewService(s, "NickServ"),
	}
}

var (
	parseNickServCommandFuncs = map[string]func([]string) (NickServCommand, error){
		"REGISTER": NewRegisterCommand,
		"IDENTIFY": NewIdentifyCommand,
	}
)

//
// commands
//

func (ns *NickServ) HandleMsg(m *PrivMsgCommand) {
	command, args := parseLine(m.message)
	constructor := parseNickServCommandFuncs[command]
	if constructor == nil {
		ns.Reply(m.Client(), "Unknown command.")
		return
	}

	cmd, err := constructor(args)
	if err != nil {
		ns.Reply(m.Client(), "Not enough parameters.")
		return
	}

	cmd.SetClient(m.Client())
	log.Printf("%s %T %+v", ns.Id(), cmd, cmd)

	cmd.HandleNickServ(ns)
}

//
// sub-commands
//

type RegisterCommand struct {
	BaseCommand
	password string
	email    string
}

func NewRegisterCommand(args []string) (NickServCommand, error) {
	if len(args) == 0 {
		return nil, NotEnoughArgsError
	}

	cmd := &RegisterCommand{
		BaseCommand: BaseCommand{},
		password:    args[0],
	}
	if len(args) > 1 {
		cmd.email = args[1]
	}
	return cmd, nil
}

func (m *RegisterCommand) HandleNickServ(ns *NickServ) {
	client := m.Client()

	if client.user != nil {
		ns.Reply(client, "You are already registered.")
		return
	}

	if ns.server.users[client.nick] != nil {
		ns.Reply(client, "That nick is already registered.")
		return
	}

	user := NewUser(client.nick, m.password, ns.server)
	ns.server.users[client.nick] = user
	ns.Reply(client, "You have registered.")

	if !user.Login(client, client.nick, m.password) {
		ns.Reply(client, "Login failed.")
	}
	ns.Reply(client, "Logged in.")
}

type IdentifyCommand struct {
	BaseCommand
	password string
}

func NewIdentifyCommand(args []string) (NickServCommand, error) {
	if len(args) == 0 {
		return nil, NotEnoughArgsError
	}

	return &IdentifyCommand{
		BaseCommand: BaseCommand{},
		password:    args[0],
	}, nil
}

func (m *IdentifyCommand) HandleNickServ(ns *NickServ) {
	client := m.Client()
	if client.user != nil {
		ns.Reply(client, "That nick is already registered.")
		return
	}

	user := ns.server.users[client.nick]
	if user == nil {
		ns.Reply(client, "No such nick.")
		return
	}

	if !user.Login(client, client.nick, m.password) {
		ns.Reply(client, "Login failed.")
	}
	ns.Reply(client, "Logged in.")
}
