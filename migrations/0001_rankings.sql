CREATE TABLE ranking_settings (
  name TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
INSERT INTO ranking_settings (name, value) VALUES ('hash_key', lower(hex(randomblob(32))));

CREATE TABLE ranked_ips (
  ip_hash TEXT PRIMARY KEY,
  asn INTEGER,
  score INTEGER NOT NULL CHECK (score BETWEEN 0 AND 100),
  scoring_version TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE INDEX ranked_ips_updated ON ranked_ips(updated_at);

-- scope 0 is the whole site; other scopes are ASN numbers.
CREATE TABLE ranking_counts (
  scope INTEGER NOT NULL,
  scoring_version TEXT NOT NULL,
  score INTEGER NOT NULL,
  count INTEGER NOT NULL,
  PRIMARY KEY (scope, scoring_version, score)
);

CREATE TRIGGER ranked_ips_insert AFTER INSERT ON ranked_ips BEGIN
  INSERT INTO ranking_counts (scope, scoring_version, score, count)
    SELECT 0, NEW.scoring_version, NEW.score, 1
    UNION ALL SELECT NEW.asn, NEW.scoring_version, NEW.score, 1 WHERE NEW.asn IS NOT NULL
    ON CONFLICT (scope, scoring_version, score) DO UPDATE SET count = count + 1;
END;

CREATE TRIGGER ranked_ips_delete AFTER DELETE ON ranked_ips BEGIN
  UPDATE ranking_counts SET count = count - 1
    WHERE scope IN (0, OLD.asn) AND scoring_version = OLD.scoring_version AND score = OLD.score;
  DELETE FROM ranking_counts WHERE count = 0;
END;

CREATE TRIGGER ranked_ips_update AFTER UPDATE ON ranked_ips
WHEN OLD.asn IS NOT NEW.asn OR OLD.score != NEW.score OR OLD.scoring_version != NEW.scoring_version
BEGIN
  UPDATE ranking_counts SET count = count - 1
    WHERE scope IN (0, OLD.asn) AND scoring_version = OLD.scoring_version AND score = OLD.score;
  DELETE FROM ranking_counts WHERE count = 0;
  INSERT INTO ranking_counts (scope, scoring_version, score, count)
    SELECT 0, NEW.scoring_version, NEW.score, 1
    UNION ALL SELECT NEW.asn, NEW.scoring_version, NEW.score, 1 WHERE NEW.asn IS NOT NULL
    ON CONFLICT (scope, scoring_version, score) DO UPDATE SET count = count + 1;
END;
