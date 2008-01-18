CREATE TABLE item (
  id integer primary key not null,
  user_id integer not null,
  externalkey varchar(40),
  description text
);
CREATE TABLE user (
  id integer primary key not null,
  name varchar(40) not null,
  password char(32) not null,
  email varchar(60) not null
);

INSERT INTO user VALUES (
  0,
  "foo",
  "123",
  "foo@test"
);

CREATE INDEX item_user on item (user_id);
