-- +migrate Up
CREATE OR REPLACE FUNCTION trigger_set_updated_at() RETURNS trigger
    LANGUAGE plpgsql
AS $$ BEGIN NEW.updated_at = (NOW() AT TIME ZONE 'utc'); RETURN NEW; END; $$;

CREATE TABLE IF NOT EXISTS users
(
    nullifier          TEXT PRIMARY KEY,
    anonymous_id       TEXT UNIQUE,
    is_proven        BOOLEAN NOT NULL default FALSE,
    created_at         TIMESTAMP NOT NULL DEFAULT (NOW() AT TIME ZONE 'utc'),
    updated_at         TIMESTAMP NOT NULL DEFAULT (NOW() AT TIME ZONE 'utc')
);

DROP TRIGGER IF EXISTS set_updated_at ON users;
CREATE TRIGGER set_updated_at
    BEFORE UPDATE
    ON users
    FOR EACH ROW
EXECUTE FUNCTION trigger_set_updated_at();

-- +migrate Down
DROP TABLE IF EXISTS users;
