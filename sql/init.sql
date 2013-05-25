CREATE TABLE user (id integer not null primary key autoincrement, nick text not null, hash blob not null)
CREATE UNIQUE INDEX user_id ON user (id)
CREATE UNIQUE INDEX user_nick ON user (nick)

CREATE TABLE channel (id integer not null primary key autoincrement, name text not  null)
CREATE UNIQUE INDEX channel_id ON channel (id)
CREATE UNIQUE INDEX channel_name ON channel (name)

CREATE_TABLE user_channel (id integer not null primary key autoincrement, user_id integer not null, channel_id integer not null)
CREATE UNIQUE INDEX user_id_channel_id ON user_channel (user_id, channel_id)
