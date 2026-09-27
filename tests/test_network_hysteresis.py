from __future__ import annotations

from datetime import UTC, datetime

from app.core.clock import FrozenClock, to_storage
from app.database import get_connection
from app.network.rules import DEFAULT_RULES
from app.network.service import NetworkAccelerationService

T0 = datetime(2026, 9, 27, 21, 0, 0, tzinfo=UTC)

CONCERT_RULES = {
    "score": dict(DEFAULT_RULES["score"]),
    "allocation": dict(DEFAULT_RULES["allocation"]),
    "hysteresis": {
        "open_after": 3,
        "recover_after": 2,
        "cooldown_seconds": 120,
        "app_overrides": {
            "concert-video": {"open_after": 1},
        },
    },
}


def prepare_concert(client, rules=None):
    scenario = client.post(
        "/api/network/scenarios",
        json={"code": "concert-01", "name": "奥体演唱会", "scene_type": "concert", "timezone": "Asia/Shanghai", "max_concurrent_sessions": 50, "capacity_mbps": 2000},
    )
    assert scenario.status_code == 201, scenario.text
    segment = client.post(
        "/api/network/scenarios/concert-01/segments",
        json={"code": "east-gate", "name": "东门散场区", "sequence_no": 1, "expected_dwell_seconds": 600, "capacity_mbps": 800},
    )
    assert segment.status_code == 201, segment.text
    for app_code, category in (("concert-live", "live"), ("concert-video", "video")):
        app = client.post(
            "/api/network/applications",
            json={"app_code": app_code, "name": app_code, "category": category, "latency_target_ms": 100, "packet_loss_target": 0.01, "min_downlink_mbps": 8, "min_uplink_mbps": 4, "default_priority": 60},
        )
        assert app.status_code == 201, app.text
    policy = client.post("/api/network/scenarios/concert-01/policies", json={"rules": rules or CONCERT_RULES, "actor": "tests"})
    assert policy.status_code == 201, policy.text
    published = client.post(
        f"/api/network/policies/{policy.json()['id']}/publish",
        json={"actor": "tests", "effective_from": "2026-09-27T00:00:00Z"},
    )
    assert published.status_code == 200, published.text
    return published.json()


def sample_payload(sample_key, subscriber, *, degraded=True, latency=None, app_code="concert-live", observed_at="2026-09-27T21:00:00Z"):
    return {
        "sample_key": sample_key,
        "scenario_code": "concert-01",
        "segment_code": "east-gate",
        "app_code": app_code,
        "subscriber_hash": subscriber,
        "device_class": "phone",
        "train_speed_kmh": 0,
        "latency_ms": latency if latency is not None else (250 if degraded else 90),
        "packet_loss": 0.005,
        "downlink_mbps": 20,
        "uplink_mbps": 8,
        "observed_at": observed_at,
    }


def flap_sequence(service, subscriber, prefix):
    """围绕阈值波动的固定样本序列：三波恶化-恢复，中间穿插冷却期。"""
    actions = []
    incident_ids = []

    def feed(index, degraded, latency=None, advance=5):
        service.clock.advance(seconds=advance) if index else None
        observed = to_storage(service.clock.now())
        result = service.ingest_sample(
            sample_payload(f"{prefix}-{index:03d}", subscriber, degraded=degraded, latency=latency, observed_at=observed)
        )
        actions.append(result["detection"]["action"])
        incident_ids.append(result["incident_id"])
        return result

    feed(0, True)                      # tracking：连续恶化 1/3
    feed(1, True)                      # tracking：连续恶化 2/3
    feed(2, True)                      # opened：达到 open_after=3
    feed(3, False)                     # recovering：稳定窗口 1/2
    feed(4, True)                      # merged：恢复被打断，归入原事件
    feed(5, False)                     # recovering：重新累计 1/2
    feed(6, False)                     # recovered：稳定窗口达成，进入冷却
    feed(7, True, latency=400)         # reopened：冷却期内归入原事件并更新最差指标
    feed(8, False)                     # recovering
    feed(9, False)                     # recovered：再次进入冷却
    service.clock.advance(seconds=125) # 越过冷却期
    feed(10, True, advance=0)          # tracking：冷却结束，重新累计 1/3
    feed(11, True)                     # tracking：2/3
    feed(12, True)                     # opened：新事件
    return actions, incident_ids


def test_hysteresis_dampens_flapping_with_fixed_clock(client):
    policy = prepare_concert(client)
    service = NetworkAccelerationService(get_connection(), FrozenClock(T0))
    subscriber = "subscriber-flap-0000000001"
    actions, incident_ids = flap_sequence(service, subscriber, "flap-a")
    assert actions == [
        "tracking", "tracking", "opened",
        "recovering", "merged", "recovering", "recovered",
        "reopened", "recovering", "recovered",
        "tracking", "tracking", "opened",
    ]
    first = service.get_incident(incident_ids[2])
    assert incident_ids[7] == first["id"]
    assert incident_ids[12] != first["id"]
    assert first["state"] == "resolved"
    assert first["sample_count"] == 10
    assert first["rule_version"] == policy["version_no"]
    assert first["policy_version_id"] == policy["id"]
    assert first["first_observed_at"] == "2026-09-27T21:00:00+00:00"
    assert first["last_observed_at"] == "2026-09-27T21:00:45+00:00"
    assert first["worst_latency_ms"] == 400
    assert first["worst_score"] == 1.05
    second = service.get_incident(incident_ids[12])
    assert second["state"] == "open"
    assert second["sample_count"] == 3
    assert second["first_observed_at"] == "2026-09-27T21:02:50+00:00"
    connection = get_connection()
    total = connection.execute("SELECT COUNT(*) FROM quality_incidents").fetchone()[0]
    assert total == 2
    detector = connection.execute(
        "SELECT * FROM incident_detectors WHERE subscriber_hash=?", (subscriber,)
    ).fetchone()
    assert detector["sample_count"] == 13
    assert detector["active_incident_id"] == second["id"]
    assert detector["rule_version"] == policy["version_no"]
    open_items = service.open_incidents("concert-01")
    assert [item["id"] for item in open_items] == [second["id"]]


def test_flapping_sequence_is_deterministic_across_subscribers(client):
    prepare_concert(client)
    service = NetworkAccelerationService(get_connection(), FrozenClock(T0))
    first_actions, _ = flap_sequence(service, "subscriber-flap-0000000002", "flap-b")
    service2 = NetworkAccelerationService(get_connection(), FrozenClock(T0))
    second_actions, _ = flap_sequence(service2, "subscriber-flap-0000000003", "flap-c")
    assert first_actions == second_actions
    total = get_connection().execute("SELECT COUNT(*) FROM quality_incidents").fetchone()[0]
    assert total == 4


def test_severity_upgrade_applies_immediately(client):
    rules = {
        "score": dict(DEFAULT_RULES["score"]),
        "allocation": dict(DEFAULT_RULES["allocation"]),
        "hysteresis": {"open_after": 2, "recover_after": 1, "cooldown_seconds": 300},
    }
    prepare_concert(client, rules)
    service = NetworkAccelerationService(get_connection(), FrozenClock(T0))
    subscriber = "subscriber-upgrade-00000001"

    def feed(index, degraded, latency=None):
        service.clock.advance(seconds=5)
        return service.ingest_sample(
            sample_payload(f"upgrade-{index:03d}", subscriber, degraded=degraded, latency=latency, observed_at=to_storage(service.clock.now()))
        )

    assert feed(0, True)["detection"]["action"] == "tracking"
    opened = feed(1, True)
    assert opened["detection"]["action"] == "opened"
    incident_id = opened["incident_id"]
    assert service.get_incident(incident_id)["severity"] == "minor"
    merged = feed(2, True, latency=900)
    assert merged["detection"]["action"] == "merged"
    upgraded = service.get_incident(incident_id)
    assert upgraded["severity"] == "critical"
    assert upgraded["worst_score"] == 2.8
    assert upgraded["worst_latency_ms"] == 900
    assert feed(3, False)["detection"]["action"] == "recovered"
    reopened = feed(4, True)
    assert reopened["detection"]["action"] == "reopened"
    assert reopened["incident_id"] == incident_id
    kept = service.get_incident(incident_id)
    assert kept["severity"] == "critical"
    assert kept["state"] == "open"
    assert kept["sample_count"] == 5


def test_per_app_hysteresis_override(client):
    prepare_concert(client)
    service = NetworkAccelerationService(get_connection(), FrozenClock(T0))
    observed = to_storage(service.clock.now())
    video = service.ingest_sample(sample_payload("override-video", "subscriber-override-000001", app_code="concert-video", observed_at=observed))
    assert video["detection"]["action"] == "opened"
    assert video["incident_id"] is not None
    live = service.ingest_sample(sample_payload("override-live", "subscriber-override-000002", app_code="concert-live", observed_at=observed))
    assert live["detection"]["action"] == "tracking"
    assert live["incident_id"] is None


def test_session_completion_arms_cooldown_for_same_subscriber(client):
    prepare_concert(client)
    clock = FrozenClock(T0)
    service = NetworkAccelerationService(get_connection(), clock)
    subscriber = "subscriber-session-00000001"
    client.post(
        "/api/network/entitlements",
        json={
            "subscriber_hash": subscriber,
            "scenario_code": "concert-01",
            "product_code": "concert-boost",
            "valid_from": "2026-09-27T00:00:00Z",
            "valid_until": "2026-09-28T00:00:00Z",
            "source_order_id": "order-hysteresis-001",
        },
    )
    opened = service.ingest_sample(
        sample_payload("session-flap-000", subscriber, app_code="concert-video", observed_at=to_storage(clock.now()))
    )
    incident_id = opened["incident_id"]
    assert opened["detection"]["action"] == "opened"
    started = service.start_acceleration(incident_id, "tests")
    assert started["status"] == "active"
    clock.advance(seconds=10)
    finished = service.finish_session(started["id"], "tests", "体验恢复", "completed")
    assert finished["status"] == "completed"
    clock.advance(seconds=30)
    degraded = service.ingest_sample(
        sample_payload("session-flap-001", subscriber, app_code="concert-video", observed_at=to_storage(clock.now()))
    )
    assert degraded["detection"]["action"] == "reopened"
    assert degraded["incident_id"] == incident_id
    incident = service.get_incident(incident_id)
    assert incident["state"] == "open"
    assert incident["sample_count"] == 2
    total = get_connection().execute("SELECT COUNT(*) FROM quality_incidents").fetchone()[0]
    assert total == 1


def test_hysteresis_rules_validation(client):
    prepare_concert(client)
    base = {"score": dict(DEFAULT_RULES["score"]), "allocation": dict(DEFAULT_RULES["allocation"])}
    for hysteresis in (
        {"open_after": 0},
        {"recover_after": 101},
        {"cooldown_seconds": -1},
        {"app_overrides": {"concert-live": {"open_after": 0}}},
    ):
        response = client.post("/api/network/scenarios/concert-01/policies", json={"rules": {**base, "hysteresis": hysteresis}, "actor": "tests"})
        assert response.status_code == 422, response.text


def test_incident_detail_and_detectors_endpoints(client):
    prepare_concert(client)
    observed = "2026-09-27T21:00:00Z"
    sample = client.post(
        "/api/network/samples",
        json=sample_payload("endpoint-000", "subscriber-endpoint-000001", app_code="concert-video", observed_at=observed),
    )
    assert sample.status_code == 202, sample.text
    assert sample.json()["detection"]["action"] == "opened"
    incident_id = sample.json()["incident_id"]
    detail = client.get(f"/api/network/incidents/{incident_id}")
    assert detail.status_code == 200
    body = detail.json()
    assert body["rule_version"] == 1
    assert body["sample_count"] == 1
    assert body["first_observed_at"] is not None
    assert body["last_observed_at"] is not None
    assert body["worst_latency_ms"] == 250
    detectors = client.get("/api/network/detectors", params={"scenario_code": "concert-01"})
    assert detectors.status_code == 200
    items = detectors.json()["items"]
    assert len(items) == 1
    assert items[0]["subscriber_hash"] == "subscriber-endpoint-000001"
    assert items[0]["sample_count"] == 1
    assert items[0]["active_incident_id"] == incident_id
    assert items[0]["rule_version"] == 1
    missing = client.get("/api/network/incidents/999999")
    assert missing.status_code == 404
