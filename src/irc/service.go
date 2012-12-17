package irc

import (
	"fmt"
	"log"
)

type ServiceCommand interface {
	Command
	HandleService(*Service)
}

type PrivMsgCommandFunc func(*PrivMsgCommand)

type Service struct {
	server   *Server
	name     string
	commands chan<- ServiceCommand
	Handle   PrivMsgCommandFunc
}

func NewService(s *Server, name string, Handle PrivMsgCommandFunc) *Service {
	commands := make(chan ServiceCommand)
	service := &Service{
		server:   s,
		name:     name,
		commands: commands,
		Handle:   Handle,
	}
	go service.receiveCommands(commands)
	s.services[name] = service
	return service
}

func (service *Service) receiveCommands(commands <-chan ServiceCommand) {
	for command := range commands {
		log.Printf("%s %T %+V", service.Id(), command, command)
		command.HandleService(service)
	}
}

func (service *Service) Id() string {
	return fmt.Sprintf("%s!%s@%s", service.name, service.name, service.server.name)
}

func (service *Service) PublicId() string {
	return service.Id()
}

func (service *Service) Nick() string {
	return service.name
}

func (service *Service) Reply(client *Client, message string) {
	client.replies <- RplPrivMsg(service, client, message)
}

//
// commands
//

func (m *PrivMsgCommand) HandleService(s *Service) {
	s.Handle(m)
}
