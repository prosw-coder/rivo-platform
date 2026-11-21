ALTER TABLE users ADD COLUMN password_iterations INTEGER NOT NULL DEFAULT 100000;
ALTER TABLE videos ADD COLUMN recipient_read_at TEXT;
CREATE TABLE IF NOT EXISTS auth_rate_limits (
  key_hash TEXT PRIMARY KEY,
  window_start INTEGER NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  blocked_until INTEGER
);
CREATE TABLE IF NOT EXISTS conversation_hides (
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  friend_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  hidden_at TEXT NOT NULL,
  PRIMARY KEY(user_id,friend_id),
  CHECK(user_id <> friend_id)
);
CREATE INDEX IF NOT EXISTS idx_videos_unread ON videos(recipient_id, recipient_read_at, created_at);
