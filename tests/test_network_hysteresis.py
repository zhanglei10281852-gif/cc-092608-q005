"""迟滞、稳定窗口与冷却期的判定链路测试。

所有时间均以样本 observed_at 推进，配合 FrozenClock，保证事件数量与状态变化确定。
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.core.clock import FrozenClock, to_storage
from app.database import close_connection, get_connection
from app.network.hysteresis import HysteresisConfig, HysteresisEngine, IncidentState, PHASE_IDLE, PHASE_PENDING
from app.network.rules import DEFAULT_RULES
from app.network.service import NetworkAccelerationService
from app.network.types import QualityDecision

BASE = datetime(2026, 9, 26, 10, 0, tzinfo=UTC)

DEGRADED = QualityDecision(True, "minor", ("latency",), 0.3)
CRITICAL = QualityDecision(True, "critical", ("latency",), 9.0)
HEALTHY = QualityDecision(False, None, (), 0.0)


def engine(**overrides):
    config = HysteresisConfig(
        trigger_samples=overrides.get("trigger_samples", 2),
        recovery_samples=overrides.get("recovery_samples", 2),
        cooldown_seconds=overrides.get("cooldown_seconds", 60),
        escalate_immediately=overrides.get("escalate_immediately", True),
    )
    return HysteresisEngine(config)


def advance(eng, sequence, start=BASE):
    state = IncidentState()
    effects: list[str] = []
    incident_ids: list[int | None] = []
    next_id = 1
    for index, decision in enumerate(sequence):
        result = eng.advance(state, decision, start + timedelta(seconds=index * 10))
        state = result.state
        for effect in result.effects:
            if effect.kind == "opened":
                state.incident_id = next_id
                next_id += 1
            effects.append(effect.kind)
        incident_ids.append(state.incident_id)
    return state, effects, incident_ids


def test_engine_requires_consecutive_degradation():
    # 差-好-差-好 的摆动不产生任何事件。
    state, effects, ids = advance(engine(), [DEGRADED, HEALTHY, DEGRADED, HEALTHY])
    assert state.phase == PHASE_IDLE
    assert "opened" not in effects
    assert ids == [None, None, None, None]


def test_engine_opens_after_consecutive_samples():
    state, effects, _ = advance(engine(), [HEALTHY, DEGRADED, DEGRADED])
    assert state.phase == "open" and state.incident_id == 1
    assert effects == ["pending", "opened"]


def test_engine_recovery_window_then_cooling_reopen_and_close():
    eng = engine(cooldown_seconds=60)
    state = IncidentState()
    timeline = [
        (0, DEGRADED),    # pending
        (10, DEGRADED),   # opened，冷却锚到 70s
        (20, HEALTHY),    # 稳定窗口 1/2
        (30, HEALTHY),    # recovered -> cooling
        (40, DEGRADED),   # 冷却内重开同一事件，冷却锚到 100s
        (50, HEALTHY),    # 稳定窗口 1/2
        (60, HEALTHY),    # recovered -> cooling
        (70, HEALTHY),    # 仍在冷却（<100s）
        (110, HEALTHY),   # 越过冷却点 -> closed
    ]
    kinds = []
    incident_id = None
    for at, decision in timeline:
        result = eng.advance(state, decision, BASE + timedelta(seconds=at))
        state = result.state
        for effect in result.effects:
            kinds.append(effect.kind)
            if effect.kind == "opened":
                incident_id = 1
                state.incident_id = 1
    assert kinds == [
        "pending", "opened", "attached", "recovered", "reopened",
        "attached", "recovered", "attached", "closed",
    ]
    assert incident_id == 1
    assert state.phase == PHASE_IDLE and state.incident_id is None


def test_engine_starts_new_sequence_after_cooldown():
    # 恢复于 30s、冷却 60s；40s 的恶化在冷却内重开同一事件；200s 的样本越过冷却点定稿旧事件。
    eng = engine(cooldown_seconds=60)
    state = IncidentState()
    timeline = [
        (0, DEGRADED), (10, DEGRADED), (20, HEALTHY), (30, HEALTHY),
        (200, DEGRADED), (210, DEGRADED),
    ]
    kinds = []
    next_id = 0
    for at, decision in timeline:
        result = eng.advance(state, decision, BASE + timedelta(seconds=at))
        state = result.state
        for effect in result.effects:
            kinds.append(effect.kind)
            if effect.kind == "opened":
                next_id += 1
                state.incident_id = next_id
    assert kinds == ["pending", "opened", "attached", "recovered", "closed", "pending", "opened"]
    assert state.incident_id == 2


def test_engine_escalates_immediately_but_never_downgrades():
    sequence = [CRITICAL, CRITICAL, DEGRADED, HEALTHY, HEALTHY]
    state, effects, _ = advance(engine(), sequence)
    assert "escalated" not in effects  # 打开时即按最差严重度
    # 打开后严重样本不会造成降级：用 minor 打开，再 critical 立即升级
    state, effects, _ = advance(engine(), [DEGRADED, DEGRADED, CRITICAL, DEGRADED])
    assert "escalated" in effects
    assert state.peak_severity == "critical"


def test_engine_is_deterministic_under_fixed_clock():
    sequence = [DEGRADED, HEALTHY, DEGRADED, DEGRADED, CRITICAL, HEALTHY, HEALTHY, DEGRADED]
    _, first, ids_first = advance(engine(cooldown_seconds=120), sequence)
    _, second, ids_second = advance(engine(cooldown_seconds=120), sequence)
    assert first == second and ids_first == ids_second


def _scenario(service: NetworkAccelerationService) -> dict:
    service.create_scenario({
        "code": "concert", "name": "散场演唱会", "scene_type": "concert",
        "timezone": "Asia/Shanghai", "max_concurrent_sessions": 100, "capacity_mbps": 1000,
    })
    service.add_segment("concert", {
        "code": "gate", "name": "散场口", "sequence_no": 1,
        "expected_dwell_seconds": 600, "capacity_mbps": 500,
    })
    service.create_application({
        "app_code": "video", "name": "短视频", "category": "video",
        "latency_target_ms": 100, "packet_loss_target": 0.01,
        "min_downlink_mbps": 8, "min_uplink_mbps": 4, "default_priority": 70,
    })
    policy = service.create_policy("concert", RULES, "tests")
    return service.publish_policy(policy["id"], "tests", "2026-01-01T00:00:00Z")


RULES = {
    **DEFAULT_RULES,
    "hysteresis": {
        "trigger_samples": 2,
        "recovery_samples": 2,
        "cooldown_seconds": 120,
        "escalate_immediately": True,
    },
}

SUBSCRIBER = "subscriber-hysteresis-0001"


def _service(tmp_path) -> NetworkAccelerationService:
    close_connection()
    import os
    os.environ["NETWORK_DATABASE_PATH"] = str(tmp_path / "hys.db")
    service = NetworkAccelerationService(get_connection(), FrozenClock(BASE))
    _scenario(service)
    return service


def _sample(key, at, level="mild", subscriber=SUBSCRIBER, segment="gate"):
    profiles = {
        "good": dict(latency_ms=80, packet_loss=0.002, downlink_mbps=20, uplink_mbps=8),
        "mild": dict(latency_ms=150, packet_loss=0.005, downlink_mbps=6, uplink_mbps=3),
        "bad": dict(latency_ms=300, packet_loss=0.1, downlink_mbps=1, uplink_mbps=0.5),
    }
    return {
        "sample_key": key, "scenario_code": "concert", "segment_code": segment, "app_code": "video",
        "subscriber_hash": subscriber, "device_class": "phone", "train_speed_kmh": 0,
        **profiles[level], "observed_at": to_storage(at),
    }


def test_service_lifecycle_aggregates_single_incident(tmp_path):
    service = _service(tmp_path)
    t = BASE
    plan = [
        ("hys-0001", 0, "mild"), ("hys-0002", 5, "good"), ("hys-0003", 10, "mild"),
        ("hys-0004", 15, "mild"), ("hys-0005", 20, "bad"), ("hys-0006", 25, "good"),
        ("hys-0007", 30, "good"), ("hys-0008", 40, "mild"), ("hys-0009", 45, "good"),
        ("hys-0010", 50, "good"), ("hys-0011", 300, "good"),
        ("hys-0012", 310, "mild"), ("hys-0013", 315, "mild"),
    ]
    effects = [service.ingest_sample(_sample(k, t + timedelta(seconds=sec), lvl))["effect"]
               for k, sec, lvl in plan]
    assert effects == [
        "pending", "none", "pending", "opened", "escalated", "attached", "recovered",
        "reopened", "attached", "recovered", "closed", "pending", "opened",
    ]
    connection = get_connection()
    first = connection.execute("SELECT id FROM quality_incidents ORDER BY id LIMIT 1").fetchone()[0]
    second = connection.execute("SELECT id FROM quality_incidents ORDER BY id DESC LIMIT 1").fetchone()[0]
    assert first != second
    detail = service.get_incident(first)
    # 触发序列（hys-0003 起）到定稿确认样本全部归入同一事件。
    assert detail["sample_count"] == 9
    assert detail["state"] == "resolved" and detail["severity"] == "critical"
    assert detail["first_observed_at"] == to_storage(t + timedelta(seconds=10))
    assert detail["last_observed_at"] == to_storage(t + timedelta(seconds=300))
    assert detail["policy_version_no"] == 1 and detail["rules_digest"]
    assert detail["hysteresis"]["cooldown_seconds"] == 120
    assert {row["link_role"] for row in detail["links"]} == {"trigger", "attached"}
    # 活跃跟踪只剩第二个事件。
    tracks = service.list_hysteresis_tracks("concert")
    assert len(tracks) == 1 and tracks[0]["incident_id"] == second


def test_separate_subscribers_keep_independent_tracks(tmp_path):
    service = _service(tmp_path)
    t = BASE
    r1 = service.ingest_sample(_sample("hys-sub-a1", t, "mild", "subscriber-hys-a-00000001"))
    r2 = service.ingest_sample(_sample("hys-sub-b1", t, "mild", "subscriber-hys-b-00000001"))
    r3 = service.ingest_sample(_sample("hys-sub-a2", t + timedelta(seconds=5), "mild", "subscriber-hys-a-00000001"))
    assert r1["incident_id"] is None and r2["incident_id"] is None
    assert r3["incident_id"] is not None
    tracks = service.list_hysteresis_tracks("concert", subscriber_hash="subscriber-hys-a-00000001")
    assert len(tracks) == 1 and tracks[0]["incident_id"] == r3["incident_id"]


def test_per_app_hysteresis_override(tmp_path):
    close_connection()
    import os
    os.environ["NETWORK_DATABASE_PATH"] = str(tmp_path / "override.db")
    service = NetworkAccelerationService(get_connection(), FrozenClock(BASE))
    rules = {
        **DEFAULT_RULES,
        "hysteresis": {
            "trigger_samples": 3, "recovery_samples": 2, "cooldown_seconds": 60,
            "overrides": {"video": {"trigger_samples": 1, "recovery_samples": 3, "cooldown_seconds": 60}},
        },
    }
    service.create_scenario({
        "code": "concert", "name": "散场演唱会", "scene_type": "concert", "timezone": "Asia/Shanghai",
        "max_concurrent_sessions": 100, "capacity_mbps": 1000,
    })
    service.create_application({
        "app_code": "video", "name": "短视频", "category": "video",
        "latency_target_ms": 100, "packet_loss_target": 0.01,
        "min_downlink_mbps": 8, "min_uplink_mbps": 4, "default_priority": 70,
    })
    policy = service.create_policy("concert", rules, "tests")
    service.publish_policy(policy["id"], "tests", "2026-01-01T00:00:00Z")
    opened = service.ingest_sample(_sample("hys-ov-01", BASE, "mild", segment=None))
    assert opened["effect"] == "opened"
    detail = service.get_incident(opened["incident_id"])
    assert detail["hysteresis"]["trigger_samples"] == 1
    assert detail["hysteresis"]["recovery_samples"] == 3


def test_invalid_hysteresis_rejected(tmp_path):
    close_connection()
    import os
    os.environ["NETWORK_DATABASE_PATH"] = str(tmp_path / "invalid.db")
    service = NetworkAccelerationService(get_connection(), FrozenClock(BASE))
    service.create_scenario({
        "code": "concert", "name": "散场演唱会", "scene_type": "concert", "timezone": "Asia/Shanghai",
        "max_concurrent_sessions": 100, "capacity_mbps": 1000,
    })
    bad = {**DEFAULT_RULES, "hysteresis": {"trigger_samples": 2, "recovery_samples": 2, "cooldown_seconds": 99999}}
    try:
        service.create_policy("concert", bad, "tests")
    except Exception as exc:
        assert "冷却时长" in str(exc)
    else:
        raise AssertionError("非法冷却时长应被拒绝")


def test_incident_query_endpoint(client):
    # 场景级默认 trigger_samples=1（DEFAULT_RULES 未显式配置时），单条恶化即开事件。
    client.post("/api/network/scenarios", json={
        "code": "concert", "name": "散场演唱会", "scene_type": "concert",
        "max_concurrent_sessions": 100, "capacity_mbps": 1000,
    })
    client.post("/api/network/applications", json={
        "app_code": "video", "name": "短视频", "category": "video",
        "latency_target_ms": 100, "packet_loss_target": 0.01,
        "min_downlink_mbps": 8, "min_uplink_mbps": 4, "default_priority": 70,
    })
    policy = client.post("/api/network/scenarios/concert/policies", json={"rules": DEFAULT_RULES, "actor": "tests"}).json()
    client.post(f"/api/network/policies/{policy['id']}/publish", json={"actor": "tests", "effective_from": "2026-01-01T00:00:00Z"})
    response = client.post("/api/network/samples", json={
        "sample_key": "hys-api-0001", "scenario_code": "concert", "app_code": "video",
        "subscriber_hash": "subscriber-hys-api-0001", "device_class": "phone", "train_speed_kmh": 0,
        "latency_ms": 300, "packet_loss": 0.1, "downlink_mbps": 1, "uplink_mbps": 0.5,
        "observed_at": "2026-09-26T10:00:00Z",
    })
    incident_id = response.json()["incident_id"]
    assert incident_id is not None
    detail = client.get(f"/api/network/incidents/{incident_id}")
    assert detail.status_code == 200
    body = detail.json()
    assert body["sample_count"] == 1
    assert body["first_observed_at"] and body["last_observed_at"]
    assert body["policy_version_no"] == policy["version_no"]
    assert client.get("/api/network/incidents/999999").status_code == 404
    tracks = client.get("/api/network/hysteresis/tracks", params={"scenario_code": "concert"})
    assert tracks.status_code == 200 and tracks.json()["items"][0]["incident_id"] == incident_id
