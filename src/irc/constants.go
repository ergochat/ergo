package irc

const (
	VERSION = "ergonomadic-1"
)

const (
	// # numeric codes
	// ## reply codes
	RPL_WELCOME    = "001"
	RPL_YOURHOST   = "002"
	RPL_CREATED    = "003"
	RPL_MYINFO     = "004"
	RPL_UMODEIS    = "221"
	RPL_NOTOPIC    = "331"
	RPL_TOPIC      = "332"
	RPL_NAMREPLY   = "353"
	RPL_ENDOFNAMES = "366"
	RPL_INFO       = "371"
	// ## error codes
	ERR_NOSUCHNICK        = "401"
	ERR_NOSUCHSERVER      = "402"
	ERR_NOSUCHCHANNEL     = "403"
	ERR_UNKNOWNCOMMAND    = "421"
	ERR_NICKNAMEINUSE     = "433"
	ERR_NOTONCHANNEL      = "442"
	ERR_NEEDMOREPARAMS    = "461"
	ERR_ALREADYREGISTRED  = "462"
	ERR_INVITEONLYCHANNEL = "473"
	ERR_BADCHANNELKEY     = "475"
	ERR_USERSDONTMATCH    = "502"
	// # message codes
	RPL_JOIN    = "JOIN"
	RPL_NICK    = "NICK"
	RPL_PART    = "PART"
	RPL_PONG    = "PONG"
	RPL_PRIVMSG = "PRIVMSG"
)
