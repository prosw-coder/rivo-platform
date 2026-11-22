CREATE TABLE IF NOT EXISTS blocked_users (
  blocker_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  blocked_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at TEXT NOT NULL,
  PRIMARY KEY(blocker_id, blocked_id),
  CHECK(blocker_id <> blocked_id)
);
CREATE INDEX IF NOT EXISTS idx_blocked_users_target ON blocked_users(blocked_id, blocker_id);
CREATE TABLE IF NOT EXISTS privacy_settings (
  user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  allow_friend_requests INTEGER NOT NULL DEFAULT 1 CHECK(allow_friend_requests IN (0,1))
);