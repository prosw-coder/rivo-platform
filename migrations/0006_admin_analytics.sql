CREATE TABLE IF NOT EXISTS admin_accounts (
  singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
  user_id TEXT NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS visitor_daily (
  visitor_hash TEXT NOT NULL,
  visit_day TEXT NOT NULL,
  first_seen_at TEXT NOT NULL,
  PRIMARY KEY(visitor_hash, visit_day)
);
CREATE INDEX IF NOT EXISTS idx_visitor_daily_day ON visitor_daily(visit_day);
CREATE TABLE IF NOT EXISTS admin_announcements (
  id TEXT PRIMARY KEY,
  admin_user_id TEXT NOT NULL REFERENCES users(id),
  message TEXT NOT NULL CHECK(length(message) BETWEEN 1 AND 1000),
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_admin_announcements_created ON admin_announcements(created_at);
CREATE TABLE IF NOT EXISTS payment_records (
  id TEXT PRIMARY KEY,
  provider_ref TEXT UNIQUE,
  user_id TEXT REFERENCES users(id),
  amount_minor INTEGER NOT NULL CHECK(amount_minor >= 0),
  currency TEXT NOT NULL DEFAULT 'JOD',
  status TEXT NOT NULL CHECK(status IN ('pending','paid','refunded','failed')),
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_payment_records_paid ON payment_records(status,created_at);
