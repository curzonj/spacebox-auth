CREATE TABLE accounts (
  id uuid PRIMARY KEY,
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
  account_id uuid NOT NULL,
  privileged boolean NOT NULL DEFAULT false,
  expires timestamp
);
