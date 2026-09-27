"""质差事件迟滞与冷却状态机。

状态流转（时间一律以样本观测时间 observed_at 为准，保证固定时钟下结果确定）：

    idle ──恶化样本────────► pending ──连续恶化达到 trigger_samples──► open
    ▲                          │                                        │
    │                          └──健康样本打断连续计数                    ├─健康样本连续 recovery_samples─► cooling
    │                                                                   │
    │                              冷却期结束且无新恶化                  │
    └───────────────────────────────────────────────────────────────────┘
                                 ▲                  │
                                 └──冷却期内新恶化──┘（重新归入原事件）

- pending：恶化尚未连续达标，不产生事件，连续计数持久化在 quality_tracks。
- open：事件已打开；冷却期（cooldown_until）内的样本一律并入原事件并更新最差指标，
  严重度真正升级（escalate_immediately）时立即抬升，降级不回写。
- cooling：恢复稳定窗口已走完但仍在冷却期内；冷却期内再恶化则重开原事件而不是新建记录。
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from app.core.errors import ValidationError
from app.network.types import QualityDecision

PHASE_IDLE = "idle"
PHASE_PENDING = "pending"
PHASE_OPEN = "open"
PHASE_COOLING = "cooling"

# opened：打开新事件；attached：样本并入当前事件；escalated：严重度升级；
# recovered：连续健康达标，事件进入冷却；reopened：冷却期内重开原事件；
# closed：冷却结束，事件定稿；pending：恶化累积中，尚未打开事件。
EFFECT_KINDS = frozenset({"opened", "attached", "escalated", "recovered", "reopened", "closed", "pending"})

DEFAULT_HYSTERESIS: dict[str, Any] = {
    "trigger_samples": 1,
    "recovery_samples": 2,
    "cooldown_seconds": 60,
    "escalate_immediately": True,
}

SEVERITY_ORDER = {"minor": 1, "major": 2, "critical": 3}


def validate_hysteresis(data: Any) -> dict[str, Any]:
    if not isinstance(data, dict):
        raise ValidationError("迟滞规则必须是对象")
    normalized: dict[str, Any] = {}
    for key in ("trigger_samples", "recovery_samples", "cooldown_seconds"):
        value = data.get(key, DEFAULT_HYSTERESIS[key])
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValidationError(f"{key} 必须是整数")
        normalized[key] = value
    trigger = normalized["trigger_samples"]
    recovery = normalized["recovery_samples"]
    cooldown = normalized["cooldown_seconds"]
    if not 1 <= trigger <= 100:
        raise ValidationError("恶化触发样本数必须在 1 到 100 之间")
    if not 1 <= recovery <= 100:
        raise ValidationError("恢复稳定样本数必须在 1 到 100 之间")
    if not 0 <= cooldown <= 86_400:
        raise ValidationError("冷却时长必须在 0 到 86400 秒之间")
    immediate = data.get("escalate_immediately", DEFAULT_HYSTERESIS["escalate_immediately"])
    if not isinstance(immediate, bool):
        raise ValidationError("escalate_immediately 必须是布尔值")
    normalized["escalate_immediately"] = immediate
    overrides = data.get("overrides")
    if overrides is not None:
        if not isinstance(overrides, dict):
            raise ValidationError("应用级迟滞覆盖必须是对象")
        for app_code, override in overrides.items():
            if not isinstance(app_code, str) or not app_code:
                raise ValidationError("应用编码不能为空")
            validate_hysteresis(override)
    return normalized


def resolve_hysteresis(data: dict[str, Any] | None, app_code: str | None = None) -> "HysteresisConfig":
    """从策略规则中解析迟滞配置；应用在 overrides 中声明时使用场景级配置的覆盖值。"""
    base = validate_hysteresis(data or DEFAULT_HYSTERESIS)
    overrides = (data or {}).get("overrides")
    if app_code and isinstance(overrides, dict) and app_code in overrides:
        base = validate_hysteresis(overrides[app_code])
    return HysteresisConfig(**base)


@dataclass(frozen=True, slots=True)
class HysteresisConfig:
    trigger_samples: int
    recovery_samples: int
    cooldown_seconds: int
    escalate_immediately: bool = True

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "HysteresisConfig":
        return cls(**validate_hysteresis(data or DEFAULT_HYSTERESIS))

    def as_dict(self) -> dict[str, Any]:
        return {
            "trigger_samples": self.trigger_samples,
            "recovery_samples": self.recovery_samples,
            "cooldown_seconds": self.cooldown_seconds,
            "escalate_immediately": self.escalate_immediately,
        }


@dataclass(slots=True)
class IncidentState:
    """状态机的可持久化状态。incident_id 为 None 表示当前没有关联事件。"""

    phase: str = PHASE_IDLE
    incident_id: int | None = None
    streak: int = 0
    healthy_streak: int = 0
    peak_severity: str | None = None
    cooldown_until: datetime | None = None
    last_observed_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class StateEffect:
    kind: str
    severity: str | None = None
    escalated: bool = False
    incident_id: int | None = None


@dataclass(frozen=True, slots=True)
class EngineResult:
    state: IncidentState
    effects: tuple[StateEffect, ...] = ()


class HysteresisEngine:
    """纯函数式推进：给定持久化状态与一条样本判决，返回新状态和有序副作用。

    调用方负责在推进前记录旧状态的 incident_id：closed 效果定稿的就是该事件，
    opened 效果则要求调用方新建事件并把新 id 写回推进后的状态。
    """

    def __init__(self, config: HysteresisConfig) -> None:
        self.config = config

    def advance(self, state: IncidentState, decision: QualityDecision, observed_at: datetime) -> EngineResult:
        current = IncidentState(
            phase=state.phase,
            incident_id=state.incident_id,
            streak=state.streak,
            healthy_streak=state.healthy_streak,
            peak_severity=state.peak_severity,
            cooldown_until=state.cooldown_until,
            last_observed_at=observed_at,
        )
        if current.phase == PHASE_IDLE:
            return self._from_idle(current, decision, observed_at)
        if current.phase == PHASE_PENDING:
            return self._from_pending(current, decision, observed_at)
        if current.phase == PHASE_OPEN:
            return self._from_open(current, decision, observed_at)
        return self._from_cooling(current, decision, observed_at)

    # -- 各状态分支 -----------------------------------------------------

    def _from_idle(self, state: IncidentState, decision: QualityDecision, at: datetime) -> EngineResult:
        if not decision.degraded:
            return EngineResult(state)
        return self._begin_degradation(state, decision, at)

    def _from_pending(self, state: IncidentState, decision: QualityDecision, at: datetime) -> EngineResult:
        if not decision.degraded:
            # 健康样本打断连续恶化计数，序列回到 idle 等待新的连续序列。
            return EngineResult(IncidentState(last_observed_at=at))
        return self._begin_degradation(state, decision, at)

    def _begin_degradation(self, state: IncidentState, decision: QualityDecision, at: datetime) -> EngineResult:
        state.phase = PHASE_PENDING
        state.streak += 1
        state.peak_severity = self._higher(state.peak_severity, decision.severity)
        if state.streak < self.config.trigger_samples:
            return EngineResult(state, (StateEffect("pending", severity=decision.severity),))
        state.phase = PHASE_OPEN
        state.streak = 0
        state.healthy_streak = 0
        state.cooldown_until = at + timedelta(seconds=self.config.cooldown_seconds)
        return EngineResult(state, (StateEffect("opened", severity=state.peak_severity),))

    def _from_open(self, state: IncidentState, decision: QualityDecision, at: datetime) -> EngineResult:
        if decision.degraded:
            state.healthy_streak = 0
            state.cooldown_until = at + timedelta(seconds=self.config.cooldown_seconds)
            effects: list[StateEffect] = []
            if self.config.escalate_immediately and self._rank(decision.severity) > self._rank(state.peak_severity):
                state.peak_severity = decision.severity
                effects.append(StateEffect("escalated", severity=decision.severity, escalated=True, incident_id=state.incident_id))
            else:
                state.peak_severity = self._higher(state.peak_severity, decision.severity)
            effects.append(StateEffect("attached", severity=state.peak_severity, incident_id=state.incident_id))
            return EngineResult(state, tuple(effects))
        state.healthy_streak += 1
        if state.healthy_streak < self.config.recovery_samples:
            return EngineResult(
                state,
                (StateEffect("attached", severity=state.peak_severity, incident_id=state.incident_id),),
            )
        state.phase = PHASE_COOLING
        state.healthy_streak = 0
        recovered = StateEffect("recovered", severity=state.peak_severity, incident_id=state.incident_id)
        return self._finish_cooling_if_due(state, at, (recovered,))

    def _from_cooling(self, state: IncidentState, decision: QualityDecision, at: datetime) -> EngineResult:
        cooling = state.cooldown_until is not None and at < state.cooldown_until
        if cooling:
            if not decision.degraded:
                return EngineResult(
                    state,
                    (StateEffect("attached", severity=state.peak_severity, incident_id=state.incident_id),),
                )
            escalated = self.config.escalate_immediately and self._rank(decision.severity) > self._rank(state.peak_severity)
            if self._rank(decision.severity) > self._rank(state.peak_severity):
                state.peak_severity = decision.severity
            state.phase = PHASE_OPEN
            state.healthy_streak = 0
            state.cooldown_until = at + timedelta(seconds=self.config.cooldown_seconds)
            return EngineResult(
                state,
                (StateEffect("reopened", severity=state.peak_severity, escalated=escalated, incident_id=state.incident_id),),
            )
        # 冷却期已过：原事件定稿；若当前样本恶化，作为全新序列重新累积。
        closed_incident_id = state.incident_id
        effects = [StateEffect("closed", severity=state.peak_severity, incident_id=closed_incident_id)]
        fresh = IncidentState(last_observed_at=at)
        if decision.degraded:
            begun = self._begin_degradation(fresh, decision, at)
            fresh = begun.state
            effects.extend(begun.effects)
        return EngineResult(fresh, tuple(effects))

    def _finish_cooling_if_due(self, state: IncidentState, at: datetime, prefix: tuple[StateEffect, ...]) -> EngineResult:
        if state.cooldown_until is not None and at < state.cooldown_until:
            return EngineResult(state, prefix)
        effects = list(prefix) + [StateEffect("closed", severity=state.peak_severity, incident_id=state.incident_id)]
        return EngineResult(IncidentState(last_observed_at=at), tuple(effects))

    @staticmethod
    def _rank(severity: str | None) -> int:
        return SEVERITY_ORDER.get(severity or "", 0)

    def _higher(self, left: str | None, right: str | None) -> str | None:
        return right if self._rank(right) > self._rank(left) else left
