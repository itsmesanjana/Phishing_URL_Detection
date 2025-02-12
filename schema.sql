CREATE TABLE feedback (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  url TEXT NOT NULL,
  safe_votes INTEGER DEFAULT 0,
  suspicious_votes INTEGER DEFAULT 0,
  reason TEXT
);
