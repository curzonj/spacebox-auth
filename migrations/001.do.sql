CREATE EXTENSION "uuid-ossp";

CREATE TABLE accounts (
  id uuid PRIMARY KEY,
  google_account varchar(255),
  secret varchar(255) NOT NULL,
  privileged boolean NOT NULL DEFAULT false,
  expires timestamp
);

INSERT INTO accounts (id, secret, privileged) VALUES (
    '08b9cfde-5612-486e-bb34-78605e5f0375',
    '40a58204-1c50-41fc-bb66-89a357b08e1c',
    true);

CREATE TABLE tokens (
  id uuid PRIMARY KEY,
  account_id uuid NOT NULL references accounts (id),
  privileged boolean NOT NULL DEFAULT false,
  expires timestamp
);
