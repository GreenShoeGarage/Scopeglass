-- Synthetic loopback fixture generated with the shipped Scopeglass v0.8.0 server.
BEGIN TRANSACTION;
CREATE TABLE app_meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);
INSERT INTO "app_meta" VALUES('epoch','d4444feffac0d437b340bd37312fcabf');
CREATE TABLE assets(host TEXT PRIMARY KEY,name TEXT NOT NULL,tags TEXT NOT NULL,notes TEXT NOT NULL,expected_ports TEXT NOT NULL,revision INTEGER NOT NULL,updated TEXT NOT NULL);
INSERT INTO "assets" VALUES('127.0.0.1','Workshop','["lab"]','Retain this note','[2323]',1,'2026-09-27T13:08:26.543267+00:00');
CREATE TABLE baselines(id INTEGER PRIMARY KEY, created TEXT NOT NULL,
          note TEXT NOT NULL, scan_id INTEGER NOT NULL);
INSERT INTO "baselines" VALUES(1,'2026-09-27T13:08:26.543267+00:00','Before upgrade',1);
CREATE TABLE changes(
      id INTEGER PRIMARY KEY, schedule_id INTEGER NOT NULL, schedule_name TEXT NOT NULL,
      scan_id INTEGER NOT NULL, previous_scan INTEGER NOT NULL, created TEXT NOT NULL,
      host TEXT NOT NULL, port INTEGER NOT NULL, kind TEXT NOT NULL, evidence TEXT NOT NULL,
      reviewed TEXT, UNIQUE(scan_id,host,port,kind));
INSERT INTO "changes" VALUES(1,1,'Daily',2,1,'2026-09-27T13:08:26.544857+00:00','127.0.0.1',2323,'not_observed','{"before": {"observed": "2026-09-27T13:08:26.543267+00:00", "service": "telnet", "banner": "fixture", "metadata": {"protocol": "telnet", "identification": "verified"}}, "after": null, "outcome": "refused"}','2026-09-27T13:08:26.543267+00:00');
CREATE TABLE checks(scan_id INTEGER NOT NULL, host TEXT NOT NULL, port INTEGER NOT NULL,
          outcome TEXT NOT NULL, PRIMARY KEY(scan_id,host,port));
INSERT INTO "checks" VALUES(1,'127.0.0.1',2323,'open');
INSERT INTO "checks" VALUES(2,'127.0.0.1',2323,'refused');
CREATE TABLE observations(id INTEGER PRIMARY KEY, scan_id INTEGER NOT NULL,
          host TEXT NOT NULL, port INTEGER NOT NULL, service TEXT NOT NULL, banner TEXT NOT NULL,
          observed TEXT NOT NULL, metadata TEXT NOT NULL DEFAULT '{}', FOREIGN KEY(scan_id) REFERENCES scans(id));
INSERT INTO "observations" VALUES(1,1,'127.0.0.1',2323,'telnet','fixture','2026-09-27T13:08:26.543267+00:00','{"protocol": "telnet", "identification": "verified"}');
CREATE TABLE saved_views(id INTEGER PRIMARY KEY,name TEXT NOT NULL UNIQUE,settings TEXT NOT NULL,revision INTEGER NOT NULL,updated TEXT NOT NULL);
INSERT INTO "saved_views" VALUES(1,'Pinned','{"q": "port:2323", "scan": "1", "category": "all", "sort": "ip", "view": "devices"}',1,'2026-09-27T13:08:26.543267+00:00');
CREATE TABLE scans(id INTEGER PRIMARY KEY, started TEXT NOT NULL,
          finished TEXT, status TEXT NOT NULL, targets TEXT NOT NULL, ports TEXT NOT NULL, error TEXT DEFAULT '', checked INTEGER NOT NULL DEFAULT 0, total INTEGER NOT NULL DEFAULT 0, preset TEXT NOT NULL DEFAULT 'custom', parent_scan INTEGER, schedule_id INTEGER, comparison_scan INTEGER, comparison_status TEXT NOT NULL DEFAULT '');
INSERT INTO "scans" VALUES(1,'2026-09-27T13:08:26.543267+00:00','2026-09-27T13:08:26.543267+00:00','complete','["127.0.0.1"]','[2323]','',1,1,'custom',NULL,NULL,NULL,'');
INSERT INTO "scans" VALUES(2,'2026-09-27T13:08:26.543267+00:00','2026-09-27T13:08:26.543267+00:00','complete','["127.0.0.1"]','[2323]','',1,1,'custom',NULL,1,1,'compared: 1 changes');
CREATE TABLE schedules(
      id INTEGER PRIMARY KEY, name TEXT NOT NULL, source_scan INTEGER NOT NULL,
      targets TEXT NOT NULL, ports TEXT NOT NULL, preset TEXT NOT NULL,
      interval_minutes INTEGER NOT NULL, enabled INTEGER NOT NULL, next_run TEXT NOT NULL,
      last_scan INTEGER, last_error TEXT NOT NULL DEFAULT '', deleted INTEGER NOT NULL DEFAULT 0,
      revision INTEGER NOT NULL DEFAULT 1, updated TEXT NOT NULL);
INSERT INTO "schedules" VALUES(1,'Daily',1,'["127.0.0.1"]','[2323]','custom',1440,0,'2026-09-27T13:08:26.543267+00:00',2,'',0,1,'2026-09-27T13:08:26.543267+00:00');
CREATE INDEX observations_host ON observations(host,port,scan_id);
CREATE INDEX changes_review ON changes(reviewed,id);
COMMIT;
PRAGMA user_version=8;
