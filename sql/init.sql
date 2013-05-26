CREATE TABLE user (
  id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
  nick TEXT NOT NULL UNIQUE,
  hash BLOB NOT NULL
);
CREATE INDEX index_user_id ON user(id);
CREATE INDEX index_user_nick ON user(nick);

CREATE TABLE channel (
  id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
  name TEXT NOT NULL UNIQUE
);
CREATE INDEX index_channel_id ON channel(id);

CREATE TABLE user_channel (
  id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
  user_id INTEGER NOT NULL,
  channel_id INTEGER NOT NULL
);
CREATE UNIQUE INDEX index_user_id_channel_id ON user_channel (user_id, channel_id);
