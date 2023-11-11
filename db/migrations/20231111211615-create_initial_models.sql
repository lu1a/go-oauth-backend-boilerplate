
-- +migrate Up
CREATE TABLE IF NOT EXISTS account (
    account_id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT UNIQUE,
    country TEXT,
    password_hash TEXT,
    password_salt TEXT
    -- TODO: Add other fields
);
CREATE TABLE IF NOT EXISTS github_account_profile (
    profile_id SERIAL PRIMARY KEY,
    account_id INTEGER REFERENCES account(account_id) ON DELETE CASCADE,
    is_primary_profile BOOLEAN DEFAULT false,
    avatar_url TEXT,
    bio TEXT,
    blog TEXT,
    company TEXT,
    created_at TIMESTAMPTZ,
    email TEXT,
    events_url TEXT,
    followers INTEGER,
    followers_url TEXT,
    following INTEGER,
    following_url TEXT,
    gists_url TEXT,
    gravatar_id TEXT,
    hireable BOOLEAN,
    html_url TEXT,
    user_profile_id BIGINT,
    location TEXT,
    login TEXT,
    name TEXT,
    node_id TEXT,
    organizations_url TEXT,
    public_gists INTEGER,
    public_repos INTEGER,
    received_events_url TEXT,
    repos_url TEXT,
    site_admin BOOLEAN,
    starred_url TEXT,
    subscriptions_url TEXT,
    twitter_username TEXT,
    user_type TEXT,
    updated_at TIMESTAMPTZ,
    url TEXT
);
CREATE TABLE IF NOT EXISTS session (
    session_id SERIAL PRIMARY KEY,
    session_token TEXT UNIQUE NOT NULL,
    account_id INTEGER REFERENCES account(account_id) ON DELETE CASCADE,
    github_account_profile_id INTEGER REFERENCES github_account_profile(profile_id) ON DELETE CASCADE
);

-- TODO: add other oauth provider profile tables

-- +migrate Down
DROP TABLE IF EXISTS account;
DROP TABLE IF EXISTS github_account_profile;
DROP TABLE IF EXISTS session;
