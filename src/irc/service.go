package irc

import (
	"fmt"
	"log"
)

type ServiceCommand interface {
	Command
	HandleService(*Service)
}

type Service struct {
	server   *Server
	name     string
	commands chan<- ServiceCommand
}

func NewService(s *Server, name string) *Service {
	commands := make(chan ServiceCommand)
	service := &Service{
		server:   s,
		name:     name,
		commands: commands,
	}
	go service.receiveCommands(commands)
	s.services[name] = service
	return service
}

func (service *Service) HandleMsg(m *PrivMsgCommand) {}

func (service *Service) receiveCommands(commands <-chan ServiceCommand) {
	for command := range commands {
		log.Printf("%s %T %+V", service.Id(), command, command)
		command.HandleService(service)
	}
}

func (service Service) Id() string {
	return fmt.Sprintf("%s!%s@%s", service.name, service.name, service.server.name)
}

func (service Service) PublicId() string {
	return service.Id()
}

func (service Service) Nick() string {
	return service.name
}

func (service *Service) Reply(client *Client, message string) {
	client.Replies() <- RplPrivMsg(service, client, message)
}

func (service Service) Commands() chan<- ServiceCommand {
	return service.commands
}

//
// commands
//

func (m *PrivMsgCommand) HandleService(s *Service) {
	s.HandleMsg(m)
}
