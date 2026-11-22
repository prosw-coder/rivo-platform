CREATE TABLE IF NOT EXISTS subscriptions (
  user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  plan TEXT NOT NULL CHECK(plan IN ('plus','team')),
  status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','canceled','expired')),
  started_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_subscriptions_expiry ON subscriptions(status,expires_at);

CREATE TABLE IF NOT EXISTS team_memberships (
  id TEXT PRIMARY KEY,
  owner_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  member_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  status TEXT NOT NULL CHECK(status IN ('pending','active','expired','revoked')),
  expires_at INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(owner_id,member_id),
  CHECK(owner_id <> member_id)
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_team_membership_one_live_per_member
ON team_memberships(member_id) WHERE status IN ('pending','active');
CREATE INDEX IF NOT EXISTS idx_team_memberships_owner ON team_memberships(owner_id,status,expires_at);
