CREATE TABLE IF NOT EXISTS user_crypto_keys (
 user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
 public_key TEXT NOT NULL,
 updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS avatar_key_shares (
 owner_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 friend_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 avatar_key TEXT NOT NULL,
 wrap_iv TEXT NOT NULL,
 wrapped_key TEXT NOT NULL,
 created_at TEXT NOT NULL,
 PRIMARY KEY(owner_id,friend_id)
);
CREATE INDEX IF NOT EXISTS idx_avatar_key_shares_friend ON avatar_key_shares(friend_id);