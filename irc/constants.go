package irc

import (
	"errors"
	"time"
)

var (
	DEBUG_NET     = false
	DEBUG_CLIENT  = false
	DEBUG_CHANNEL = false
	DEBUG_SERVER  = false

	ErrAlreadyDestroyed = errors.New("already destroyed")
)

const (
	VERSION       = "1.0.0"
	CRLF          = "\r\n"
	MAX_REPLY_LEN = 512 - len(CRLF)

	LOGIN_TIMEOUT = time.Minute / 2 // how long the client has to login
	IDLE_TIMEOUT  = time.Minute     // how long before a client is considered idle
	QUIT_TIMEOUT  = time.Minute     // how long after idle before a client is kicked

	// numeric codes
	RPL_WELCOME           Numeric = 1
	RPL_YOURHOST          Numeric = 2
	RPL_CREATED           Numeric = 3
	RPL_MYINFO            Numeric = 4
	RPL_BOUNCE            Numeric = 5
	RPL_TRACELINK         Numeric = 200
	RPL_TRACECONNECTING   Numeric = 201
	RPL_TRACEHANDSHAKE    Numeric = 202
	RPL_TRACEUNKNOWN      Numeric = 203
	RPL_TRACEOPERATOR     Numeric = 204
	RPL_TRACEUSER         Numeric = 205
	RPL_TRACESERVER       Numeric = 206
	RPL_TRACESERVICE      Numeric = 207
	RPL_TRACENEWTYPE      Numeric = 208
	RPL_TRACECLASS        Numeric = 209
	RPL_TRACERECONNECT    Numeric = 210
	RPL_STATSLINKINFO     Numeric = 211
	RPL_STATSCOMMANDS     Numeric = 212
	RPL_ENDOFSTATS        Numeric = 219
	RPL_UMODEIS           Numeric = 221
	RPL_SERVLIST          Numeric = 234
	RPL_SERVLISTEND       Numeric = 235
	RPL_STATSUPTIME       Numeric = 242
	RPL_STATSOLINE        Numeric = 243
	RPL_LUSERCLIENT       Numeric = 251
	RPL_LUSEROP           Numeric = 252
	RPL_LUSERUNKNOWN      Numeric = 253
	RPL_LUSERCHANNELS     Numeric = 254
	RPL_LUSERME           Numeric = 255
	RPL_ADMINME           Numeric = 256
	RPL_ADMINLOC1         Numeric = 257
	RPL_ADMINLOC2         Numeric = 258
	RPL_ADMINEMAIL        Numeric = 259
	RPL_TRACELOG          Numeric = 261
	RPL_TRACEEND          Numeric = 262
	RPL_TRYAGAIN          Numeric = 263
	RPL_AWAY              Numeric = 301
	RPL_USERHOST          Numeric = 302
	RPL_ISON              Numeric = 303
	RPL_UNAWAY            Numeric = 305
	RPL_NOWAWAY           Numeric = 306
	RPL_WHOISUSER         Numeric = 311
	RPL_WHOISSERVER       Numeric = 312
	RPL_WHOISOPERATOR     Numeric = 313
	RPL_WHOWASUSER        Numeric = 314
	RPL_ENDOFWHO          Numeric = 315
	RPL_WHOISIDLE         Numeric = 317
	RPL_ENDOFWHOIS        Numeric = 318
	RPL_WHOISCHANNELS     Numeric = 319
	RPL_LIST              Numeric = 322
	RPL_LISTEND           Numeric = 323
	RPL_CHANNELMODEIS     Numeric = 324
	RPL_UNIQOPIS          Numeric = 325
	RPL_NOTOPIC           Numeric = 331
	RPL_TOPIC             Numeric = 332
	RPL_INVITING          Numeric = 341
	RPL_SUMMONING         Numeric = 342
	RPL_INVITELIST        Numeric = 346
	RPL_ENDOFINVITELIST   Numeric = 347
	RPL_EXCEPTLIST        Numeric = 348
	RPL_ENDOFEXCEPTLIST   Numeric = 349
	RPL_VERSION           Numeric = 351
	RPL_WHOREPLY          Numeric = 352
	RPL_NAMREPLY          Numeric = 353
	RPL_LINKS             Numeric = 364
	RPL_ENDOFLINKS        Numeric = 365
	RPL_ENDOFNAMES        Numeric = 366
	RPL_BANLIST           Numeric = 367
	RPL_ENDOFBANLIST      Numeric = 368
	RPL_ENDOFWHOWAS       Numeric = 369
	RPL_INFO              Numeric = 371
	RPL_MOTD              Numeric = 372
	RPL_ENDOFINFO         Numeric = 374
	RPL_MOTDSTART         Numeric = 375
	RPL_ENDOFMOTD         Numeric = 376
	RPL_YOUREOPER         Numeric = 381
	RPL_REHASHING         Numeric = 382
	RPL_YOURESERVICE      Numeric = 383
	RPL_TIME              Numeric = 391
	RPL_USERSSTART        Numeric = 392
	RPL_USERS             Numeric = 393
	RPL_ENDOFUSERS        Numeric = 394
	RPL_NOUSERS           Numeric = 395
	ERR_NOSUCHNICK        Numeric = 401
	ERR_NOSUCHSERVER      Numeric = 402
	ERR_NOSUCHCHANNEL     Numeric = 403
	ERR_CANNOTSENDTOCHAN  Numeric = 404
	ERR_TOOMANYCHANNELS   Numeric = 405
	ERR_WASNOSUCHNICK     Numeric = 406
	ERR_TOOMANYTARGETS    Numeric = 407
	ERR_NOSUCHSERVICE     Numeric = 408
	ERR_NOORIGIN          Numeric = 409
	ERR_NORECIPIENT       Numeric = 411
	ERR_NOTEXTTOSEND      Numeric = 412
	ERR_NOTOPLEVEL        Numeric = 413
	ERR_WILDTOPLEVEL      Numeric = 414
	ERR_BADMASK           Numeric = 415
	ERR_UNKNOWNCOMMAND    Numeric = 421
	ERR_NOMOTD            Numeric = 422
	ERR_NOADMININFO       Numeric = 423
	ERR_FILEERROR         Numeric = 424
	ERR_NONICKNAMEGIVEN   Numeric = 431
	ERR_ERRONEUSNICKNAME  Numeric = 432
	ERR_NICKNAMEINUSE     Numeric = 433
	ERR_NICKCOLLISION     Numeric = 436
	ERR_UNAVAILRESOURCE   Numeric = 437
	ERR_USERNOTINCHANNEL  Numeric = 441
	ERR_NOTONCHANNEL      Numeric = 442
	ERR_USERONCHANNEL     Numeric = 443
	ERR_NOLOGIN           Numeric = 444
	ERR_SUMMONDISABLED    Numeric = 445
	ERR_USERSDISABLED     Numeric = 446
	ERR_NOTREGISTERED     Numeric = 451
	ERR_NEEDMOREPARAMS    Numeric = 461
	ERR_ALREADYREGISTRED  Numeric = 462
	ERR_NOPERMFORHOST     Numeric = 463
	ERR_PASSWDMISMATCH    Numeric = 464
	ERR_YOUREBANNEDCREEP  Numeric = 465
	ERR_YOUWILLBEBANNED   Numeric = 466
	ERR_KEYSET            Numeric = 467
	ERR_CHANNELISFULL     Numeric = 471
	ERR_UNKNOWNMODE       Numeric = 472
	ERR_INVITEONLYCHAN    Numeric = 473
	ERR_BANNEDFROMCHAN    Numeric = 474
	ERR_BADCHANNELKEY     Numeric = 475
	ERR_BADCHANMASK       Numeric = 476
	ERR_NOCHANMODES       Numeric = 477
	ERR_BANLISTFULL       Numeric = 478
	ERR_NOPRIVILEGES      Numeric = 481
	ERR_CHANOPRIVSNEEDED  Numeric = 482
	ERR_CANTKILLSERVER    Numeric = 483
	ERR_RESTRICTED        Numeric = 484
	ERR_UNIQOPPRIVSNEEDED Numeric = 485
	ERR_NOOPERHOST        Numeric = 491
	ERR_UMODEUNKNOWNFLAG  Numeric = 501
	ERR_USERSDONTMATCH    Numeric = 502

	Add    ModeOp = '+'
	List   ModeOp = '='
	Remove ModeOp = '-'

	Away          UserMode = 'a'
	Invisible     UserMode = 'i'
	LocalOperator UserMode = 'O'
	Operator      UserMode = 'o'
	Restricted    UserMode = 'r'
	ServerNotice  UserMode = 's'
	WallOps       UserMode = 'w'

	Anonymous     ChannelMode = 'a' // flag
	BanMask       ChannelMode = 'b' // arg
	ExceptionMask ChannelMode = 'e' // arg
	InviteMask    ChannelMode = 'I' // arg
	InviteOnly    ChannelMode = 'i' // flag
	Key           ChannelMode = 'k' // flag arg
	Moderated     ChannelMode = 'm' // flag
	NoOutside     ChannelMode = 'n' // flag
	OpOnlyTopic   ChannelMode = 't' // flag
	Private       ChannelMode = 'p' // flag
	Quiet         ChannelMode = 'q' // flag
	ReOp          ChannelMode = 'r' // flag
	Secret        ChannelMode = 's' // flag
	UserLimit     ChannelMode = 'l' // flag arg

	ChannelCreator  UserChannelMode = 'O'
	ChannelOperator UserChannelMode = 'o'
	Voice           UserChannelMode = 'v'
)

const (
	Authorization Phase = iota
	Registration  Phase = iota
	Normal        Phase = iota
)
