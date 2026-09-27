from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta
from typing import Any

from app.core.clock import Clock, SystemClock, from_storage, to_storage
from app.core.errors import ConflictError, NotFoundError, ValidationError
from app.core.security import request_fingerprint
from app.database import get_connection, transaction
from app.network.hysteresis import (
    PHASE_COOLING,
    PHASE_IDLE,
    PHASE_OPEN,
    PHASE_PENDING,
    EngineResult,
    HysteresisEngine,
    IncidentState,
    resolve_hysteresis,
)
from app.network.repository import NetworkRepository
from app.network.rules import DEFAULT_RULES, allocation_for, canonical_rules, judge_quality
from app.network.schema import ensure_network_schema


class NetworkAccelerationService:
    def __init__(self, connection: sqlite3.Connection | None = None, clock: Clock | None = None) -> None:
        self.connection = connection or get_connection()
        ensure_network_schema(self.connection)
        self.clock = clock or SystemClock()
        self.repository = NetworkRepository(self.connection)

    def create_scenario(self, payload: dict[str, Any]) -> dict[str, Any]:
        now = to_storage(self.clock.now())
        with transaction(immediate=True) as connection:
            try:
                cursor = connection.execute(
                    "INSERT INTO network_scenarios(code,name,scene_type,timezone,max_concurrent_sessions,capacity_mbps,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
                    (payload["code"], payload["name"], payload["scene_type"], payload["timezone"], payload["max_concurrent_sessions"], payload["capacity_mbps"], now, now),
                )
            except sqlite3.IntegrityError as exc:
                raise ConflictError("场景编码已存在") from exc
            return dict(NetworkRepository(connection).scenario_by_id(cursor.lastrowid))

    def list_scenarios(self, status: str | None = None) -> list[dict[str, Any]]:
        return self.repository.list_scenarios(status=status)

    def add_segment(self, scenario_code: str, payload: dict[str, Any]) -> dict[str, Any]:
        scenario = self._scenario(scenario_code)
        now = to_storage(self.clock.now())
        with transaction(immediate=True) as connection:
            try:
                cursor = connection.execute(
                    "INSERT INTO network_segments(scenario_id,code,name,sequence_no,expected_dwell_seconds,capacity_mbps,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
                    (scenario["id"], payload["code"], payload["name"], payload["sequence_no"], payload["expected_dwell_seconds"], payload["capacity_mbps"], now, now),
                )
            except sqlite3.IntegrityError as exc:
                raise ConflictError("区段编码或顺序已存在") from exc
            return dict(NetworkRepository(connection).segment_by_id(cursor.lastrowid))

    def create_application(self, payload: dict[str, Any]) -> dict[str, Any]:
        now = to_storage(self.clock.now())
        with transaction(immediate=True) as connection:
            try:
                cursor = connection.execute(
                    "INSERT INTO application_profiles(app_code,name,category,latency_target_ms,packet_loss_target,min_downlink_mbps,min_uplink_mbps,default_priority,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (payload["app_code"], payload["name"], payload["category"], payload["latency_target_ms"], payload["packet_loss_target"], payload["min_downlink_mbps"], payload["min_uplink_mbps"], payload["default_priority"], now, now),
                )
            except sqlite3.IntegrityError as exc:
                raise ConflictError("应用编码已存在") from exc
            return dict(NetworkRepository(connection).application_by_id(cursor.lastrowid))

    def list_applications(self, category: str | None = None) -> list[dict[str, Any]]:
        return self.repository.list_applications(category=category)

    def create_policy(self, scenario_code: str, rules: dict[str, Any], actor: str) -> dict[str, Any]:
        scenario = self._scenario(scenario_code)
        text, digest = canonical_rules(rules)
        existing = self.repository.policy_by_digest(scenario["id"], digest)
        if existing is not None:
            return NetworkRepository._policy(existing)
        now = to_storage(self.clock.now())
        with transaction(immediate=True) as connection:
            repository = NetworkRepository(connection)
            version = repository.next_policy_version(scenario["id"])
            cursor = connection.execute(
                "INSERT INTO policy_versions(scenario_id,version_no,rules_json,rules_digest,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
                (scenario["id"], version, text, digest, actor, now, now),
            )
            return NetworkRepository._policy(repository.policy_by_id(cursor.lastrowid))

    def publish_policy(self, policy_id: int, actor: str, effective_from: str) -> dict[str, Any]:
        policy = self.repository.policy_by_id(policy_id)
        if policy is None:
            raise NotFoundError("策略版本不存在")
        if policy["state"] == "retired":
            raise ConflictError("已退役策略不能发布")
        try:
            effective = to_storage(from_storage(effective_from))
        except ValueError as exc:
            raise ValidationError("生效时间格式不正确") from exc
        now = to_storage(self.clock.now())
        with transaction(immediate=True) as connection:
            connection.execute(
                "UPDATE policy_versions SET state='retired',retired_at=?,updated_at=? WHERE scenario_id=? AND state='published' AND id<>?",
                (now, now, policy["scenario_id"], policy_id),
            )
            connection.execute(
                "UPDATE policy_versions SET state='published',published_by=?,effective_from=?,retired_at=NULL,updated_at=? WHERE id=?",
                (actor, effective, now, policy_id),
            )
            return NetworkRepository._policy(NetworkRepository(connection).policy_by_id(policy_id))

    def add_entitlement(self, payload: dict[str, Any]) -> dict[str, Any]:
        scenario = self._scenario(payload["scenario_code"])
        try:
            start = to_storage(from_storage(payload["valid_from"]))
            end = to_storage(from_storage(payload["valid_until"]))
        except ValueError as exc:
            raise ValidationError("权益有效期格式不正确") from exc
        if end <= start:
            raise ValidationError("权益结束时间必须晚于开始时间")
        now = to_storage(self.clock.now())
        with transaction(immediate=True) as connection:
            existing = connection.execute("SELECT * FROM subscriber_entitlements WHERE source_order_id=?", (payload["source_order_id"],)).fetchone()
            if existing is not None:
                return dict(existing)
            cursor = connection.execute(
                "INSERT INTO subscriber_entitlements(subscriber_hash,scenario_id,product_code,valid_from,valid_until,source_order_id,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
                (payload["subscriber_hash"], scenario["id"], payload["product_code"], start, end, payload["source_order_id"], now, now),
            )
            return dict(connection.execute("SELECT * FROM subscriber_entitlements WHERE id=?", (cursor.lastrowid,)).fetchone())

    def ingest_sample(self, payload: dict[str, Any]) -> dict[str, Any]:
        scenario = self._scenario(payload["scenario_code"])
        app = self._application(payload["app_code"])
        segment = None
        if payload.get("segment_code"):
            segment = self.repository.segment_by_code(scenario["id"], payload["segment_code"])
            if segment is None:
                raise NotFoundError("场景区段不存在")
        try:
            observed_dt = from_storage(payload["observed_at"])
        except ValueError as exc:
            raise ValidationError("观测时间格式不正确") from exc
        observed = to_storage(observed_dt)
        digest = request_fingerprint(payload)
        existing = self.repository.sample_by_key(payload["sample_key"])
        if existing is not None:
            if existing["payload_digest"] != digest:
                raise ConflictError("相同 sample_key 对应了不同观测内容")
            return self._sample_result(existing["id"])
        now = to_storage(self.clock.now())
        policy = self.repository.effective_policy(scenario["id"], now)
        rules = json.loads(policy["rules_json"]) if policy else DEFAULT_RULES
        decision = judge_quality(payload, dict(app), rules)
        hysteresis = resolve_hysteresis(rules.get("hysteresis"), app["app_code"])
        segment_id = segment["id"] if segment else None
        with transaction(immediate=True) as connection:
            repository = NetworkRepository(connection)
            cursor = connection.execute(
                "INSERT INTO experience_samples(sample_key,scenario_id,segment_id,app_id,subscriber_hash,device_class,train_speed_kmh,latency_ms,packet_loss,downlink_mbps,uplink_mbps,observed_at,received_at,payload_digest) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (payload["sample_key"], scenario["id"], segment_id, app["id"], payload["subscriber_hash"], payload["device_class"], payload["train_speed_kmh"], payload["latency_ms"], payload["packet_loss"], payload["downlink_mbps"], payload["uplink_mbps"], observed, now, digest),
            )
            sample_id = cursor.lastrowid
            outcome = self._advance_track(
                connection,
                repository,
                scenario_id=scenario["id"],
                segment_id=segment_id,
                app=app,
                subscriber_hash=payload["subscriber_hash"],
                sample_id=sample_id,
                observed_dt=observed_dt,
                observed=observed,
                now=now,
                decision=decision,
                hysteresis=hysteresis,
                policy=policy,
            )
            return {
                "sample_id": sample_id,
                "incident_id": outcome["incident_id"],
                "track_phase": outcome["phase"],
                "effect": outcome["effect"],
                "sample_count": outcome["sample_count"],
                "quality": decision.as_dict(),
            }

    def ingest_batch(self, items: list[dict[str, Any]]) -> dict[str, Any]:
        results = []
        for item in items:
            results.append(self.ingest_sample(item))
        return {"items": results, "accepted": len(results)}

    def start_acceleration(self, incident_id: int, actor: str) -> dict[str, Any]:
        incident = self.repository.incident_by_id(incident_id)
        if incident is None:
            raise NotFoundError("质差事件不存在")
        existing = self.repository.session_by_incident(incident_id)
        if existing is not None:
            return self.repository.session_detail(existing["id"])
        if incident["state"] != "open":
            raise ConflictError("只有待处理事件可以启动加速")
        sample = self.repository.sample_by_id(incident["sample_id"])
        app = self.repository.application_by_id(incident["app_id"])
        now_value = self.clock.now()
        now = to_storage(now_value)
        entitlement = self.repository.active_entitlement(sample["subscriber_hash"], incident["scenario_id"], now)
        if entitlement is None:
            raise ConflictError("用户没有当前场景的有效加速权益")
        policy = self.repository.effective_policy(incident["scenario_id"], now)
        if policy is None:
            raise ConflictError("场景没有已生效的加速策略")
        # 事件记录了建立时的策略快照，加速规格以快照为准，避免事件生命周期内换版导致配置漂移。
        if incident["policy_version_id"]:
            snapshotted = self.repository.policy_by_id(incident["policy_version_id"])
            if snapshotted is not None and snapshotted["state"] != "draft":
                policy = snapshotted
        rules = json.loads(policy["rules_json"])
        allocation = allocation_for(dict(app), incident["severity"], rules)
        scenario = self.repository.scenario_by_id(incident["scenario_id"])
        segment = self.repository.segment_by_id(incident["segment_id"]) if incident["segment_id"] else None
        from app.network.operations import NetworkOperationsService
        maintenance = NetworkOperationsService(self.connection, self.clock).blocks_new_session(incident["scenario_id"], incident["segment_id"], now)
        if maintenance is not None:
            raise ConflictError("当前场景处于维护窗口，不能启动新的加速会话", context={"maintenance_code": maintenance["code"]})
        limit = int(segment["capacity_mbps"] if segment else scenario["capacity_mbps"])
        used = self.repository.active_capacity(incident["scenario_id"], incident["segment_id"])
        if used["sessions"] >= int(scenario["max_concurrent_sessions"]):
            raise ConflictError("场景并发加速会话已达到上限")
        if used["downlink_mbps"] + allocation.downlink_mbps > limit:
            raise ConflictError("区段下行加速容量不足")
        expires = to_storage(now_value + timedelta(seconds=allocation.duration_seconds))
        with transaction(immediate=True) as connection:
            cursor = connection.execute(
                "INSERT INTO acceleration_sessions(incident_id,subscriber_hash,app_id,scenario_id,segment_id,policy_version_id,allocated_downlink_mbps,allocated_uplink_mbps,priority,started_at,expires_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (incident_id, sample["subscriber_hash"], incident["app_id"], incident["scenario_id"], incident["segment_id"], policy["id"], allocation.downlink_mbps, allocation.uplink_mbps, allocation.priority, now, expires),
            )
            connection.execute(
                "INSERT INTO capacity_reservations(session_id,scenario_id,segment_id,downlink_mbps,uplink_mbps,held_at) VALUES(?,?,?,?,?,?)",
                (cursor.lastrowid, incident["scenario_id"], incident["segment_id"], allocation.downlink_mbps, allocation.uplink_mbps, now),
            )
            connection.execute("UPDATE quality_incidents SET state='accelerating',version=version+1 WHERE id=?", (incident_id,))
            self._event(connection, cursor.lastrowid, "started", actor, {"policy_version": policy["version_no"]}, now)
            return NetworkRepository(connection).session_detail(cursor.lastrowid)

    def finish_session(self, session_id: int, actor: str, reason: str, result: str) -> dict[str, Any]:
        session = self.repository.session_by_id(session_id)
        if session is None:
            raise NotFoundError("加速会话不存在")
        if session["status"] != "active":
            return self.repository.session_detail(session_id)
        now = to_storage(self.clock.now())
        with transaction(immediate=True) as connection:
            connection.execute(
                "UPDATE acceleration_sessions SET status=?,ended_at=?,end_reason=?,version=version+1 WHERE id=? AND status='active'",
                (result, now, reason, session_id),
            )
            connection.execute("UPDATE capacity_reservations SET state='released',released_at=? WHERE session_id=? AND state='held'", (now, session_id))
            incident_state = "resolved" if result == "completed" else "open"
            connection.execute(
                "UPDATE quality_incidents SET state=?,resolved_at=?,closed_at=CASE WHEN ?='resolved' THEN ? ELSE closed_at END,version=version+1 WHERE id=?",
                (incident_state, now if result == "completed" else None, incident_state, now, session["incident_id"]),
            )
            if result == "completed":
                # 事件随会话正常结束而定稿，迟滞跟踪重新开始。
                connection.execute("DELETE FROM quality_tracks WHERE incident_id=?", (session["incident_id"],))
            self._event(connection, session_id, result, actor, {"reason": reason}, now)
            return NetworkRepository(connection).session_detail(session_id)

    def expire_sessions(self, actor: str = "session-reaper") -> dict[str, Any]:
        now = to_storage(self.clock.now())
        rows = self.connection.execute("SELECT id FROM acceleration_sessions WHERE status='active' AND expires_at<=? ORDER BY id", (now,)).fetchall()
        expired = []
        for row in rows:
            with transaction(immediate=True) as connection:
                session = NetworkRepository(connection).session_by_id(row["id"])
                if session is None or session["status"] != "active":
                    continue
                connection.execute("UPDATE acceleration_sessions SET status='expired',ended_at=?,end_reason='duration_elapsed',version=version+1 WHERE id=?", (now, row["id"]))
                connection.execute("UPDATE capacity_reservations SET state='released',released_at=? WHERE session_id=? AND state='held'", (now, row["id"]))
                connection.execute("UPDATE quality_incidents SET state='open',version=version+1 WHERE id=?", (session["incident_id"],))
                self._event(connection, row["id"], "expired", actor, {}, now)
                expired.append(row["id"])
        return {"expired": expired}

    def open_incidents(self, scenario_code: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        scenario_id = self._scenario(scenario_code)["id"] if scenario_code else None
        return self.repository.open_incidents(scenario_id, limit=limit)

    def get_incident(self, incident_id: int) -> dict[str, Any]:
        result = self.repository.incident_detail(incident_id)
        if result is None:
            raise NotFoundError("质差事件不存在")
        return result

    def list_hysteresis_tracks(
        self,
        scenario_code: str | None = None,
        app_code: str | None = None,
        subscriber_hash: str | None = None,
        include_closed: bool = False,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        scenario_id = self._scenario(scenario_code)["id"] if scenario_code else None
        app_id = self._application(app_code)["id"] if app_code else None
        return self.repository.list_tracks(
            scenario_id=scenario_id,
            app_id=app_id,
            subscriber_hash=subscriber_hash,
            active_only=not include_closed,
            limit=limit,
        )

    def get_session(self, session_id: int) -> dict[str, Any]:
        result = self.repository.session_detail(session_id)
        if result is None:
            raise NotFoundError("加速会话不存在")
        return result

    def summary(self) -> dict[str, Any]:
        return self.repository.summary()

    def seed_demo(self) -> dict[str, Any]:
        scenario = self.repository.scenario_by_code("gdh-rail")
        if scenario is None:
            scenario = self.create_scenario({"code": "gdh-rail", "name": "广深高铁", "scene_type": "railway", "timezone": "Asia/Shanghai", "max_concurrent_sessions": 5000, "capacity_mbps": 3000})
            self.add_segment("gdh-rail", {"code": "gz-sz-01", "name": "广州南至虎门", "sequence_no": 1, "expected_dwell_seconds": 900, "capacity_mbps": 1200})
        app = self.repository.application_by_code("video-call")
        if app is None:
            app = self.create_application({"app_code": "video-call", "name": "视频通话", "category": "video_call", "latency_target_ms": 100, "packet_loss_target": 0.01, "min_downlink_mbps": 8, "min_uplink_mbps": 4, "default_priority": 70})
        policy = self.create_policy("gdh-rail", DEFAULT_RULES, "demo")
        if policy["state"] != "published":
            policy = self.publish_policy(policy["id"], "demo", to_storage(self.clock.now()))
        return {"scenario": scenario, "application": app, "policy": policy}

    def _sample_result(self, sample_id: int) -> dict[str, Any]:
        sample = self.repository.sample_by_id(sample_id)
        link = self.connection.execute(
            "SELECT incident_id FROM incident_samples WHERE sample_id=?", (sample_id,)
        ).fetchone()
        incident_id = link["incident_id"] if link else None
        return {"sample_id": sample_id, "incident_id": incident_id, "duplicate": True, "sample": dict(sample)}

    # -- 迟滞状态机与事件聚合 ------------------------------------------

    @staticmethod
    def _track_key(scenario_id: int, segment_id: int | None, app_id: int, subscriber_hash: str) -> str:
        return f"{scenario_id}:{segment_id or 0}:{app_id}:{subscriber_hash}"

    def _load_state(self, track: sqlite3.Row | None) -> IncidentState:
        if track is None:
            return IncidentState()
        phase = {
            "pending": PHASE_PENDING,
            "open": PHASE_OPEN,
            "cooling": PHASE_COOLING,
        }[track["phase"]]
        return IncidentState(
            phase=phase,
            incident_id=track["incident_id"],
            streak=track["degrade_streak"],
            healthy_streak=track["healthy_streak"],
            peak_severity=track["peak_severity"],
            cooldown_until=from_storage(track["cooldown_until"]) if track["cooldown_until"] else None,
            last_observed_at=from_storage(track["last_observed_at"]),
        )

    def _advance_track(
        self,
        connection: sqlite3.Connection,
        repository: NetworkRepository,
        *,
        scenario_id: int,
        segment_id: int | None,
        app: sqlite3.Row,
        subscriber_hash: str,
        sample_id: int,
        observed_dt: datetime,
        observed: str,
        now: str,
        decision,
        hysteresis,
        policy: sqlite3.Row | None,
    ) -> dict[str, Any]:
        track_key = self._track_key(scenario_id, segment_id, app["id"], subscriber_hash)
        track = repository.track_by_key(scenario_id, segment_id, app["id"], subscriber_hash)
        state = self._load_state(track)

        # 事件进行中（open/cooling）沿用建事件时的策略快照；pending 尚未形成事件，跟随最新策略。
        active_policy, active_hysteresis, stale_pending = self._resolve_active_policy(
            repository, track, policy, hysteresis, app["app_code"]
        )
        if stale_pending:
            connection.execute("DELETE FROM quality_tracks WHERE id=?", (track["id"],))
            track = None
            state = IncidentState()

        result = HysteresisEngine(active_hysteresis).advance(state, decision, observed_dt)
        new_state = result.state

        # 加速会话进行中时，事件的恢复由会话生命周期驱动，样本链路只做归并与升级。
        accelerating = False
        if new_state.incident_id is not None:
            incident_row = repository.incident_by_id(new_state.incident_id)
            accelerating = incident_row is not None and incident_row["state"] == "accelerating"
        suppressed_recovery = accelerating and any(effect.kind in ("recovered", "closed") for effect in result.effects)
        if suppressed_recovery:
            new_state.phase = PHASE_OPEN
            new_state.healthy_streak = 0
            kept = tuple(effect for effect in result.effects if effect.kind not in ("recovered", "closed"))
            result = EngineResult(new_state, kept)
            # 达到恢复窗口的健康样本在加速期内不允许恢复事件，但仍计入事件样本。
            if not kept and new_state.incident_id is not None:
                self._attach_sample(connection, new_state.incident_id, sample_id, decision, observed)

        staging: list[dict[str, Any]] = json.loads(track["staging_json"]) if track is not None else []
        effect_kind = "none"
        incident_id: int | None = None
        attached_targets: set[int] = set()
        current_sample = {
            "sample_id": sample_id,
            "score": decision.score,
            "severity": decision.severity,
            "reasons": list(decision.reasons),
            "degraded": 1 if decision.degraded else 0,
            "observed_at": observed,
        }

        for effect in result.effects:
            target = effect.incident_id
            if effect.kind == "pending":
                staging.append(current_sample)
                effect_kind = "pending"
            elif effect.kind == "opened":
                incident_id = self._open_incident(
                    connection,
                    scenario_id=scenario_id,
                    segment_id=segment_id,
                    app=app,
                    subscriber_hash=subscriber_hash,
                    staging=staging + [current_sample],
                    severity=effect.severity,
                    active_policy=active_policy,
                    active_hysteresis=active_hysteresis,
                )
                new_state.incident_id = incident_id
                staging = []
                effect_kind = "opened"
            elif effect.kind == "attached":
                if target is not None and target not in attached_targets:
                    self._attach_sample(connection, target, sample_id, decision, observed)
                    attached_targets.add(target)
                incident_id = target
                if effect_kind == "none":
                    effect_kind = "attached"
            elif effect.kind == "escalated":
                if target is not None:
                    if target not in attached_targets:
                        self._attach_sample(connection, target, sample_id, decision, observed)
                        attached_targets.add(target)
                    connection.execute(
                        "UPDATE quality_incidents SET severity=?,version=version+1 WHERE id=?",
                        (effect.severity, target),
                    )
                incident_id = target
                effect_kind = "escalated"
            elif effect.kind == "recovered":
                if target is not None:
                    if target not in attached_targets:
                        self._attach_sample(connection, target, sample_id, decision, observed)
                        attached_targets.add(target)
                    connection.execute(
                        "UPDATE quality_incidents SET state='cooling',recovered_at=?,closed_at=NULL,version=version+1 WHERE id=?",
                        (observed, target),
                    )
                incident_id = target
                effect_kind = "recovered"
            elif effect.kind == "reopened":
                if target is not None:
                    if target not in attached_targets:
                        self._attach_sample(connection, target, sample_id, decision, observed)
                        attached_targets.add(target)
                    connection.execute(
                        "UPDATE quality_incidents SET state='open',recovered_at=NULL,closed_at=NULL,"
                        "severity=CASE WHEN ? THEN ? ELSE severity END,version=version+1 WHERE id=?",
                        (1 if effect.escalated else 0, effect.severity, target),
                    )
                incident_id = target
                effect_kind = "reopened"
            elif effect.kind == "closed":
                if target is not None:
                    # 越过冷却点的健康样本是恢复确认，归入原事件；恶化样本则属于新序列不归旧事件。
                    if not decision.degraded and target not in attached_targets:
                        self._attach_sample(connection, target, sample_id, decision, observed)
                        attached_targets.add(target)
                    connection.execute(
                        "UPDATE quality_incidents SET state='resolved',closed_at=?,"
                        "resolved_at=COALESCE(resolved_at,?),version=version+1 WHERE id=?",
                        (observed, observed, target),
                    )
                effect_kind = "closed" if effect_kind == "none" else effect_kind

        if new_state.phase == PHASE_IDLE:
            if track is not None:
                connection.execute("DELETE FROM quality_tracks WHERE id=?", (track["id"],))
        else:
            self._persist_track(
                connection,
                track,
                track_key=track_key,
                scenario_id=scenario_id,
                segment_id=segment_id,
                app=app,
                subscriber_hash=subscriber_hash,
                state=new_state,
                staging=staging,
                observed=observed,
                now=now,
                policy=active_policy,
                hysteresis=active_hysteresis,
            )

        if new_state.phase in (PHASE_OPEN, PHASE_COOLING):
            incident_id = new_state.incident_id
        sample_count = self._incident_sample_count(connection, incident_id) if incident_id else len(staging)
        return {
            "incident_id": incident_id if new_state.phase != PHASE_PENDING else None,
            "phase": new_state.phase,
            "effect": effect_kind,
            "sample_count": sample_count,
        }

    @staticmethod
    def _resolve_active_policy(repository, track, policy, hysteresis, app_code):
        """返回 (生效策略行, 生效迟滞配置, pending 是否因策略切换而作废)。"""
        if track is None:
            return policy, hysteresis, False
        if track["phase"] == "pending":
            current_digest = policy["rules_digest"] if policy is not None else ""
            stale = current_digest != track["rules_digest"]
            return policy, hysteresis, stale
        # open/cooling 事件始终沿用建立时的策略快照与迟滞配置。
        snapshot_policy = repository.policy_by_id(track["policy_version_id"]) if track["policy_version_id"] else None
        snapshot_hysteresis = resolve_hysteresis(json.loads(track["hysteresis_json"]) or None, app_code)
        return snapshot_policy, snapshot_hysteresis, False

    def _open_incident(
        self,
        connection: sqlite3.Connection,
        *,
        scenario_id: int,
        segment_id: int | None,
        app: sqlite3.Row,
        subscriber_hash: str,
        staging: list[dict[str, Any]],
        severity: str | None,
        active_policy: sqlite3.Row | None,
        active_hysteresis,
    ) -> int:
        ordered = sorted(staging, key=lambda item: (item["observed_at"], item["sample_id"]))
        first = ordered[0]
        worst = max(ordered, key=lambda item: item["score"])
        reasons = sorted({reason for item in ordered for reason in item["reasons"]})
        cursor = connection.execute(
            "INSERT INTO quality_incidents(sample_id,scenario_id,segment_id,app_id,subscriber_hash,severity,reasons_json,"
            "state,policy_version_id,policy_version_no,rules_digest,hysteresis_json,sample_count,worst_score,worst_sample_id,"
            "opened_at,first_observed_at,last_observed_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                first["sample_id"], scenario_id, segment_id, app["id"], subscriber_hash, severity,
                json.dumps({"score": worst["score"], "severity": severity, "reasons": reasons}, ensure_ascii=False, sort_keys=True),
                "open",
                active_policy["id"] if active_policy else None,
                active_policy["version_no"] if active_policy else None,
                active_policy["rules_digest"] if active_policy else "",
                json.dumps(active_hysteresis.as_dict(), ensure_ascii=False, sort_keys=True),
                len(ordered), worst["score"], worst["sample_id"],
                ordered[-1]["observed_at"], first["observed_at"], ordered[-1]["observed_at"],
            ),
        )
        incident_id = cursor.lastrowid
        for index, item in enumerate(ordered):
            connection.execute(
                "INSERT INTO incident_samples(incident_id,sample_id,link_role,degraded,score,observed_at) VALUES(?,?,?,?,?,?)",
                (incident_id, item["sample_id"], "trigger" if index == 0 else "attached",
                 item.get("degraded", 1), item["score"], item["observed_at"]),
            )
        return incident_id

    @staticmethod
    def _attach_sample(connection: sqlite3.Connection, incident_id: int, sample_id: int, decision, observed: str) -> None:
        inserted = connection.execute(
            "INSERT OR IGNORE INTO incident_samples(incident_id,sample_id,link_role,degraded,score,observed_at) VALUES(?,?,?,?,?,?)",
            (incident_id, sample_id, "attached", 1 if decision.degraded else 0, decision.score, observed),
        )
        if inserted.rowcount == 0:
            return
        connection.execute(
            "UPDATE quality_incidents SET sample_count=sample_count+1,last_observed_at=?,"
            "worst_sample_id=CASE WHEN ? > worst_score THEN ? ELSE worst_sample_id END,"
            "worst_score=MAX(worst_score,?),version=version+1 WHERE id=?",
            (observed, decision.score, sample_id, decision.score, incident_id),
        )

    @staticmethod
    def _incident_sample_count(connection: sqlite3.Connection, incident_id: int) -> int:
        return int(connection.execute(
            "SELECT COUNT(*) FROM incident_samples WHERE incident_id=?", (incident_id,)
        ).fetchone()[0])

    def _persist_track(
        self,
        connection: sqlite3.Connection,
        track: sqlite3.Row | None,
        *,
        track_key: str,
        scenario_id: int,
        segment_id: int | None,
        app: sqlite3.Row,
        subscriber_hash: str,
        state: IncidentState,
        staging: list[dict[str, Any]],
        observed: str,
        now: str,
        policy: sqlite3.Row | None,
        hysteresis,
    ) -> None:
        phase_name = {PHASE_PENDING: "pending", PHASE_OPEN: "open", PHASE_COOLING: "cooling"}[state.phase]
        sample_count = self._incident_sample_count(connection, state.incident_id) if state.incident_id else 0
        worst_score = 0.0
        if state.incident_id:
            row = connection.execute("SELECT worst_score FROM quality_incidents WHERE id=?", (state.incident_id,)).fetchone()
            worst_score = float(row["worst_score"]) if row else 0.0
        elif staging:
            worst_score = max(item["score"] for item in staging)
        if track is not None:
            first_observed_at = track["first_observed_at"]
        elif staging:
            first_observed_at = min(item["observed_at"] for item in staging)
        else:
            first_observed_at = observed
        fields = {
            "track_key": track_key,
            "scenario_id": scenario_id,
            "segment_id": segment_id,
            "app_id": app["id"],
            "subscriber_hash": subscriber_hash,
            "incident_id": state.incident_id,
            "phase": phase_name,
            "degrade_streak": state.streak,
            "healthy_streak": state.healthy_streak,
            "peak_severity": state.peak_severity,
            "worst_score": worst_score,
            "sample_count": sample_count,
            "cooldown_until": to_storage(state.cooldown_until) if state.cooldown_until else None,
            "staging_json": json.dumps(staging, ensure_ascii=False, sort_keys=True),
            "first_observed_at": first_observed_at,
            "last_observed_at": observed,
            "policy_version_id": policy["id"] if policy else None,
            "policy_version_no": policy["version_no"] if policy else None,
            "rules_digest": policy["rules_digest"] if policy else "",
            "hysteresis_json": json.dumps(hysteresis.as_dict(), ensure_ascii=False, sort_keys=True),
            "now": now,
        }
        NetworkRepository(connection).upsert_track(fields)


    def _scenario(self, code: str) -> sqlite3.Row:
        row = self.repository.scenario_by_code(code)
        if row is None:
            raise NotFoundError("网络场景不存在")
        return row

    def _application(self, code: str) -> sqlite3.Row:
        row = self.repository.application_by_code(code)
        if row is None:
            raise NotFoundError("应用画像不存在")
        return row

    @staticmethod
    def _event(connection: sqlite3.Connection, session_id: int, event_type: str, actor: str, detail: dict[str, Any], now: str) -> None:
        connection.execute(
            "INSERT INTO session_events(session_id,event_type,actor,detail_json,created_at) VALUES(?,?,?,?,?)",
            (session_id, event_type, actor, json.dumps(detail, ensure_ascii=False, sort_keys=True), now),
        )
