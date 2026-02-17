create table history (
	id integer primary key,
	data blob not null,
	msgid blob not null
) strict;
create index history_msgid
on history (msgid);

create table sequence (
	history_id integer primary key,
	target text not null,
	nanotime integer not null
) strict;
create index sequence_target_nanotime
on sequence (target, nanotime);

create table conversations (
	id integer primary key,
	target text not null,
	correspondent text not null,
	nanotime integer not null,
	history_id integer not null
) strict;
create index conversations_target_correspondent_nanotime
on conversations (target, correspondent, nanotime);
create index conversations_history
on conversations (history_id);

create table correspondents (
	id integer primary key,
	target text not null,
	correspondent text not null,
	nanotime integer not null
) strict;
create unique index correspondents_target_correspondent
on correspondents (target, correspondent);
create index correspondents_target_nanotime
on correspondents (target, nanotime);
create index correspondents_nanotime
on correspondents (nanotime);

create table account_messages (
	history_id integer primary key,
	account text not null
) strict;
create index account_messages_account_history
on account_messages (account, history_id);

create table forget (
	id integer primary key,
	account text not null
) strict;
