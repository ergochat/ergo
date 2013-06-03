package irc

import (
	"fmt"
	"log"
)

const (
	DEBUG_NICKSERV = true
)

type NickServCommand interface {
	HandleNickServ(*NickServ)
	Client() *Client
	SetBase(*Client)
}

type NickServ struct {
	BaseService
}

func NewNickServ(s *Server) Service {
	return NewService(new(NickServ), s, "NickServ")
}

func (ns *NickServ) SetBase(base *BaseService) {
	ns.BaseService = *base
}

func (ns *NickServ) Debug() bool {
	return DEBUG_NICKSERV
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

func (ns *NickServ) HandlePrivMsg(m *PrivMsgCommand) {
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

	cmd.SetBase(m.Client())
	if ns.Debug() {
		log.Printf("%s ← %s %s", ns, cmd.Client(), cmd)
	}

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

func (m *RegisterCommand) String() string {
	return fmt.Sprintf("REGISTER(email=%s, password=%s)", m.email, m.password)
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

	user := NewUser(client.nick, ns.server)
	user.SetPassword(m.password)
	Save(ns.server.db, user)
	ns.Reply(client, "You have registered.")

	if !user.Login(client, client.nick, m.password) {
		ns.Reply(client, "Login failed.")
		return
	}
	ns.Reply(client, "Logged in.")
}

type IdentifyCommand struct {
	BaseCommand
	password string
}

func (m *IdentifyCommand) String() string {
	return fmt.Sprintf("IDENTIFY(password=%s)", m.password)
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
