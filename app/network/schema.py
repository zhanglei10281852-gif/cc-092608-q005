from __future__ import annotations

import sqlite3

NETWORK_SCHEMA = r'''
CREATE TABLE IF NOT EXISTS network_scenarios (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    scene_type TEXT NOT NULL CHECK(scene_type IN ('railway','metro','concert','venue')),
    timezone TEXT NOT NULL DEFAULT 'Asia/Shanghai',
    status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','paused','retired')),
    max_concurrent_sessions INTEGER NOT NULL CHECK(max_concurrent_sessions > 0),
    capacity_mbps INTEGER NOT NULL CHECK(capacity_mbps > 0),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS network_segments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scenario_id INTEGER NOT NULL REFERENCES network_scenarios(id) ON DELETE CASCADE,
    code TEXT NOT NULL,
    name TEXT NOT NULL,
    sequence_no INTEGER NOT NULL CHECK(sequence_no >= 0),
    expected_dwell_seconds INTEGER NOT NULL CHECK(expected_dwell_seconds > 0),
    capacity_mbps INTEGER NOT NULL CHECK(capacity_mbps > 0),
    status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','maintenance','disabled')),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(scenario_id, code),
    UNIQUE(scenario_id, sequence_no)
);
CREATE TABLE IF NOT EXISTS application_profiles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    app_code TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    category TEXT NOT NULL CHECK(category IN ('game','live','video_call','video','office')),
    latency_target_ms INTEGER NOT NULL CHECK(latency_target_ms > 0),
    packet_loss_target REAL NOT NULL CHECK(packet_loss_target >= 0 AND packet_loss_target <= 1),
    min_downlink_mbps REAL NOT NULL CHECK(min_downlink_mbps >= 0),
    min_uplink_mbps REAL NOT NULL CHECK(min_uplink_mbps >= 0),
    default_priority INTEGER NOT NULL CHECK(default_priority BETWEEN 0 AND 100),
    status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','paused','retired')),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS policy_versions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scenario_id INTEGER NOT NULL REFERENCES network_scenarios(id) ON DELETE CASCADE,
    version_no INTEGER NOT NULL,
    state TEXT NOT NULL DEFAULT 'draft' CHECK(state IN ('draft','published','retired')),
    rules_json TEXT NOT NULL,
    rules_digest TEXT NOT NULL,
    created_by TEXT NOT NULL,
    published_by TEXT,
    effective_from TEXT,
    retired_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(scenario_id, version_no),
    UNIQUE(scenario_id, rules_digest)
);
CREATE INDEX IF NOT EXISTS idx_policy_effective ON policy_versions(scenario_id,state,effective_from);
CREATE TABLE IF NOT EXISTS experience_samples (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sample_key TEXT NOT NULL UNIQUE,
    scenario_id INTEGER NOT NULL REFERENCES network_scenarios(id),
    segment_id INTEGER REFERENCES network_segments(id),
    app_id INTEGER NOT NULL REFERENCES application_profiles(id),
    subscriber_hash TEXT NOT NULL,
    device_class TEXT NOT NULL,
    train_speed_kmh REAL NOT NULL CHECK(train_speed_kmh >= 0),
    latency_ms REAL NOT NULL CHECK(latency_ms >= 0),
    packet_loss REAL NOT NULL CHECK(packet_loss >= 0 AND packet_loss <= 1),
    downlink_mbps REAL NOT NULL CHECK(downlink_mbps >= 0),
    uplink_mbps REAL NOT NULL CHECK(uplink_mbps >= 0),
    observed_at TEXT NOT NULL,
    received_at TEXT NOT NULL,
    payload_digest TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_samples_scene_time ON experience_samples(scenario_id,observed_at);
CREATE TABLE IF NOT EXISTS quality_incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sample_id INTEGER NOT NULL REFERENCES experience_samples(id) ON DELETE CASCADE,
    scenario_id INTEGER NOT NULL REFERENCES network_scenarios(id),
    segment_id INTEGER REFERENCES network_segments(id),
    app_id INTEGER NOT NULL REFERENCES application_profiles(id),
    subscriber_hash TEXT NOT NULL DEFAULT '',
    severity TEXT NOT NULL CHECK(severity IN ('minor','major','critical')),
    reasons_json TEXT NOT NULL DEFAULT '[]',
    state TEXT NOT NULL DEFAULT 'open' CHECK(state IN ('open','accelerating','cooling','resolved','expired')),
    policy_version_id INTEGER REFERENCES policy_versions(id),
    policy_version_no INTEGER,
    rules_digest TEXT NOT NULL DEFAULT '',
    hysteresis_json TEXT NOT NULL DEFAULT '{}',
    sample_count INTEGER NOT NULL DEFAULT 1 CHECK(sample_count >= 1),
    worst_score REAL NOT NULL DEFAULT 0,
    worst_sample_id INTEGER REFERENCES experience_samples(id),
    opened_at TEXT NOT NULL,
    first_observed_at TEXT NOT NULL,
    last_observed_at TEXT NOT NULL,
    recovered_at TEXT,
    closed_at TEXT,
    resolved_at TEXT,
    version INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_incidents_open ON quality_incidents(state,severity,opened_at);
-- idx_incidents_lifecycle 依赖迁移后的新列，在 ensure_network_schema 末尾创建。
CREATE TABLE IF NOT EXISTS incident_samples (
    incident_id INTEGER NOT NULL REFERENCES quality_incidents(id) ON DELETE CASCADE,
    sample_id INTEGER NOT NULL UNIQUE REFERENCES experience_samples(id) ON DELETE CASCADE,
    link_role TEXT NOT NULL DEFAULT 'attached' CHECK(link_role IN ('trigger','attached')),
    degraded INTEGER NOT NULL DEFAULT 1 CHECK(degraded IN (0,1)),
    score REAL NOT NULL DEFAULT 0,
    observed_at TEXT NOT NULL,
    PRIMARY KEY(incident_id, sample_id)
);
CREATE INDEX IF NOT EXISTS idx_incident_samples_sample ON incident_samples(sample_id);
CREATE TABLE IF NOT EXISTS quality_tracks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    track_key TEXT NOT NULL UNIQUE,
    scenario_id INTEGER NOT NULL REFERENCES network_scenarios(id),
    segment_id INTEGER REFERENCES network_segments(id),
    app_id INTEGER NOT NULL REFERENCES application_profiles(id),
    subscriber_hash TEXT NOT NULL,
    incident_id INTEGER REFERENCES quality_incidents(id) ON DELETE SET NULL,
    phase TEXT NOT NULL CHECK(phase IN ('pending','open','cooling')),
    degrade_streak INTEGER NOT NULL DEFAULT 0 CHECK(degrade_streak >= 0),
    healthy_streak INTEGER NOT NULL DEFAULT 0 CHECK(healthy_streak >= 0),
    peak_severity TEXT CHECK(peak_severity IN ('minor','major','critical')),
    worst_score REAL NOT NULL DEFAULT 0,
    sample_count INTEGER NOT NULL DEFAULT 0 CHECK(sample_count >= 0),
    cooldown_until TEXT,
    staging_json TEXT NOT NULL DEFAULT '[]',
    first_observed_at TEXT NOT NULL,
    last_observed_at TEXT NOT NULL,
    policy_version_id INTEGER REFERENCES policy_versions(id),
    policy_version_no INTEGER,
    rules_digest TEXT NOT NULL DEFAULT '',
    hysteresis_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tracks_active ON quality_tracks(phase,cooldown_until);
CREATE INDEX IF NOT EXISTS idx_tracks_incident ON quality_tracks(incident_id);
CREATE TABLE IF NOT EXISTS acceleration_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER NOT NULL REFERENCES quality_incidents(id),
    subscriber_hash TEXT NOT NULL,
    app_id INTEGER NOT NULL REFERENCES application_profiles(id),
    scenario_id INTEGER NOT NULL REFERENCES network_scenarios(id),
    segment_id INTEGER REFERENCES network_segments(id),
    policy_version_id INTEGER NOT NULL REFERENCES policy_versions(id),
    status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','completed','cancelled','expired')),
    allocated_downlink_mbps REAL NOT NULL CHECK(allocated_downlink_mbps >= 0),
    allocated_uplink_mbps REAL NOT NULL CHECK(allocated_uplink_mbps >= 0),
    priority INTEGER NOT NULL CHECK(priority BETWEEN 0 AND 100),
    started_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    ended_at TEXT,
    end_reason TEXT NOT NULL DEFAULT '',
    version INTEGER NOT NULL DEFAULT 1,
    UNIQUE(incident_id)
);
CREATE INDEX IF NOT EXISTS idx_sessions_capacity ON acceleration_sessions(scenario_id,segment_id,status,expires_at);
CREATE TABLE IF NOT EXISTS capacity_reservations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL REFERENCES acceleration_sessions(id) ON DELETE CASCADE,
    scenario_id INTEGER NOT NULL REFERENCES network_scenarios(id),
    segment_id INTEGER REFERENCES network_segments(id),
    downlink_mbps REAL NOT NULL,
    uplink_mbps REAL NOT NULL,
    state TEXT NOT NULL DEFAULT 'held' CHECK(state IN ('held','released')),
    held_at TEXT NOT NULL,
    released_at TEXT,
    UNIQUE(session_id)
);
CREATE TABLE IF NOT EXISTS session_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL REFERENCES acceleration_sessions(id) ON DELETE CASCADE,
    event_type TEXT NOT NULL,
    actor TEXT NOT NULL,
    detail_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_session_events ON session_events(session_id,id);
CREATE TABLE IF NOT EXISTS subscriber_entitlements (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    subscriber_hash TEXT NOT NULL,
    scenario_id INTEGER NOT NULL REFERENCES network_scenarios(id),
    product_code TEXT NOT NULL,
    valid_from TEXT NOT NULL,
    valid_until TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'active' CHECK(state IN ('active','suspended','expired','cancelled')),
    source_order_id TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_entitlements_lookup ON subscriber_entitlements(subscriber_hash,scenario_id,state,valid_from,valid_until);
CREATE TABLE IF NOT EXISTS rollout_campaigns (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scenario_id INTEGER NOT NULL REFERENCES network_scenarios(id),
    code TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    strategy TEXT NOT NULL CHECK(strategy IN ('percentage','segments','scheduled')),
    state TEXT NOT NULL DEFAULT 'draft' CHECK(state IN ('draft','scheduled','running','paused','completed','cancelled')),
    target_percentage INTEGER NOT NULL DEFAULT 100 CHECK(target_percentage BETWEEN 1 AND 100),
    policy_version_id INTEGER NOT NULL REFERENCES policy_versions(id),
    starts_at TEXT,
    ends_at TEXT,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS rollout_targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign_id INTEGER NOT NULL REFERENCES rollout_campaigns(id) ON DELETE CASCADE,
    segment_id INTEGER REFERENCES network_segments(id),
    cohort_key TEXT NOT NULL DEFAULT '',
    state TEXT NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','active','paused','completed','failed')),
    activated_at TEXT,
    completed_at TEXT,
    last_error TEXT NOT NULL DEFAULT '',
    version INTEGER NOT NULL DEFAULT 1,
    UNIQUE(campaign_id,segment_id,cohort_key)
);
CREATE INDEX IF NOT EXISTS idx_rollout_targets_state ON rollout_targets(campaign_id,state,id);
CREATE TABLE IF NOT EXISTS maintenance_windows (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scenario_id INTEGER NOT NULL REFERENCES network_scenarios(id),
    segment_id INTEGER REFERENCES network_segments(id),
    code TEXT NOT NULL UNIQUE,
    reason TEXT NOT NULL,
    starts_at TEXT NOT NULL,
    ends_at TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'scheduled' CHECK(state IN ('scheduled','active','completed','cancelled')),
    drain_mode TEXT NOT NULL DEFAULT 'finish_active' CHECK(drain_mode IN ('finish_active','cancel_active','block_new')),
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_maintenance_active ON maintenance_windows(scenario_id,segment_id,state,starts_at,ends_at);
CREATE TABLE IF NOT EXISTS operation_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    resource_type TEXT NOT NULL,
    resource_id INTEGER NOT NULL,
    event_type TEXT NOT NULL,
    actor TEXT NOT NULL,
    detail_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_operation_events_resource ON operation_events(resource_type,resource_id,id);
'''


def ensure_network_schema(connection: sqlite3.Connection) -> None:
    # 先建全部新表；旧库中已存在的 quality_incidents（旧形态）会被 IF NOT EXISTS 跳过。
    connection.executescript(NETWORK_SCHEMA)
    _migrate_quality_incidents(connection)
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_incidents_lifecycle "
        "ON quality_incidents(scenario_id,app_id,subscriber_hash,state,last_observed_at)"
    )


def _migrate_quality_incidents(connection: sqlite3.Connection) -> None:
    """旧库中 quality_incidents.sample_id 带有 UNIQUE 约束，无法承载事件聚合，检测到旧形态则重建。"""
    existing = connection.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='quality_incidents'"
    ).fetchone()
    if existing is None:
        return
    columns = {row[1] for row in connection.execute("PRAGMA table_info(quality_incidents)")}
    if "sample_count" in columns:
        return
    # 重建父表期间关闭外键（必须在事务外执行），完成后立即恢复。
    foreign_keys = connection.execute("PRAGMA foreign_keys").fetchone()[0]
    connection.execute("PRAGMA foreign_keys=OFF")
    try:
        connection.executescript(
            """
            CREATE TABLE quality_incidents_new (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sample_id INTEGER NOT NULL REFERENCES experience_samples(id) ON DELETE CASCADE,
                scenario_id INTEGER NOT NULL REFERENCES network_scenarios(id),
                segment_id INTEGER REFERENCES network_segments(id),
                app_id INTEGER NOT NULL REFERENCES application_profiles(id),
                subscriber_hash TEXT NOT NULL DEFAULT '',
                severity TEXT NOT NULL CHECK(severity IN ('minor','major','critical')),
                reasons_json TEXT NOT NULL DEFAULT '[]',
                state TEXT NOT NULL DEFAULT 'open' CHECK(state IN ('open','accelerating','cooling','resolved','expired')),
                policy_version_id INTEGER REFERENCES policy_versions(id),
                policy_version_no INTEGER,
                rules_digest TEXT NOT NULL DEFAULT '',
                hysteresis_json TEXT NOT NULL DEFAULT '{}',
                sample_count INTEGER NOT NULL DEFAULT 1 CHECK(sample_count >= 1),
                worst_score REAL NOT NULL DEFAULT 0,
                worst_sample_id INTEGER REFERENCES experience_samples(id),
                opened_at TEXT NOT NULL,
                first_observed_at TEXT NOT NULL,
                last_observed_at TEXT NOT NULL,
                recovered_at TEXT,
                closed_at TEXT,
                resolved_at TEXT,
                version INTEGER NOT NULL DEFAULT 1
            );
            INSERT INTO quality_incidents_new
                (id,sample_id,scenario_id,segment_id,app_id,subscriber_hash,severity,reasons_json,state,
                 opened_at,first_observed_at,last_observed_at,resolved_at,version,worst_sample_id)
            SELECT i.id,i.sample_id,i.scenario_id,i.segment_id,i.app_id,x.subscriber_hash,i.severity,i.reasons_json,i.state,
                   i.opened_at,x.observed_at,x.observed_at,i.resolved_at,i.version,i.sample_id
            FROM quality_incidents i JOIN experience_samples x ON x.id=i.sample_id;
            DROP TABLE quality_incidents;
            ALTER TABLE quality_incidents_new RENAME TO quality_incidents;
            """
        )
        # incident_samples 已由 NETWORK_SCHEMA 建立，回填旧事件的触发样本关联。
        connection.execute(
            "INSERT OR IGNORE INTO incident_samples(incident_id,sample_id,link_role,score,observed_at) "
            "SELECT i.id,i.sample_id,'trigger',0,x.observed_at "
            "FROM quality_incidents i JOIN experience_samples x ON x.id=i.sample_id"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_incidents_open ON quality_incidents(state,severity,opened_at)"
        )
        if foreign_keys:
            violation = connection.execute("PRAGMA foreign_key_check").fetchall()
            if violation:
                raise RuntimeError(f"迁移后存在外键违例: {violation[:5]}")
    finally:
        connection.execute(f"PRAGMA foreign_keys={'ON' if foreign_keys else 'OFF'}")

