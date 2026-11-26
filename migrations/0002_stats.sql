-- 站点统计：只存计数器，不存任何 IP、访客身份或查询内容。
-- total 为累计成功出分查询次数；stats_daily 按 UTC 日期存每日次数。
CREATE TABLE stats_counters (
  name TEXT PRIMARY KEY,
  value INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE stats_daily (
  day TEXT PRIMARY KEY,
  value INTEGER NOT NULL DEFAULT 0
);
