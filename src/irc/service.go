package irc

import (
	"fmt"
	"log"
)

type ServiceCommand interface {
	Command
	HandleService(Service)
}

type Service interface {
	Identifier
	Commands() chan<- ServiceCommand
	HandlePrivMsg(*PrivMsgCommand)
	Debug() bool
}

type EditableService interface {
	Service
	SetBase(*BaseService)
}

type BaseService struct {
	server   *Server
	name     string
	commands chan<- ServiceCommand
}

func NewService(service EditableService, s *Server, name string) Service {
	commands := make(chan ServiceCommand, 1)
	base := &BaseService{
		server:   s,
		name:     name,
		commands: commands,
	}
	go receiveCommands(service, commands)
	service.SetBase(base)
	s.services[service.Nick()] = service
	return service
}

func receiveCommands(service Service, commands <-chan ServiceCommand) {
	for command := range commands {
		if service.Debug() {
			log.Printf("%s ← %s %s", service.Id(), command.Client(), command)
		}
		command.HandleService(service)
	}
}

func (service *BaseService) Id() string {
	return fmt.Sprintf("%s!%s@%s", service.name, service.name, service.server.name)
}

func (service *BaseService) String() string {
	return service.Id()
}

func (service *BaseService) PublicId() string {
	return service.Id()
}

func (service *BaseService) Nick() string {
	return service.name
}

func (service *BaseService) Reply(client *Client, message string) {
	client.Replies() <- RplPrivMsg(service, client, message)
}

func (service *BaseService) Commands() chan<- ServiceCommand {
	return service.commands
}

//
// commands
//

func (m *PrivMsgCommand) HandleService(service Service) {
	service.HandlePrivMsg(m)
}
