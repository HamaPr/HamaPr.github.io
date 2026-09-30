from __future__ import annotations
import json
from datetime import datetime, timezone
from typing import Any
from sqlalchemy import select
from sqlalchemy.orm import Session
from .db import Workout, State

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def _first(d: dict[str, Any], *keys: str):
    for k in keys:
        v = d.get(k)
        if v is not None:
            return v
    return None

def normalize_workout(workout_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    session = payload
    if isinstance(payload.get("sessions"), list) and payload["sessions"]:
        matched = next((x for x in payload["sessions"] if str(x.get("id")) == workout_id), None)
        session = matched or payload["sessions"][0]
    return {
        "source_package": _first(session, "source_package"),
        "exercise_type": _first(session, "exercise_type", "type"),
        "started_at": _first(session, "start", "started_at"),
        "ended_at": _first(session, "end", "ended_at"),
    }

def upsert_workout(db: Session, workout_id: str, payload: dict[str, Any]) -> None:
    raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    meta = normalize_workout(workout_id, payload)
    row = db.get(Workout, workout_id)
    if row is None:
        row = Workout(workout_id=workout_id, payload_json=raw, **meta)
        db.add(row)
    else:
        row.payload_json = raw
        row.source_package = meta["source_package"]
        row.exercise_type = meta["exercise_type"]
        row.started_at = meta["started_at"]
        row.ended_at = meta["ended_at"]
        row.updated_at = datetime.now(timezone.utc)
    db.commit()

def delete_workout(db: Session, workout_id: str) -> bool:
    row = db.get(Workout, workout_id)
    if row is None:
        return False
    db.delete(row)
    db.commit()
    return True

def set_state(db: Session, key: str, value: str) -> None:
    row = db.get(State, key)
    if row is None:
        db.add(State(key=key, value=value))
    else:
        row.value = value
        row.updated_at = datetime.now(timezone.utc)
    db.commit()

def get_state(db: Session, key: str, default: str = "") -> str:
    row = db.get(State, key)
    return row.value if row else default

def unpack(row: Workout) -> dict[str, Any]:
    try:
        payload = json.loads(row.payload_json)
    except Exception:
        payload = {"raw": row.payload_json}
    return {"workout_id": row.workout_id, "updated_at": row.updated_at.isoformat(), "data": payload}

def list_workouts(db: Session, limit: int = 50) -> list[dict[str, Any]]:
    rows = db.scalars(select(Workout).order_by(Workout.updated_at.desc()).limit(limit)).all()
    return [unpack(r) for r in rows]

def _sessions_from_payload(payload: dict[str, Any]) -> list[dict[str, Any]]:
    if isinstance(payload.get("sessions"), list):
        return [x for x in payload["sessions"] if isinstance(x, dict)]
    return [payload]

def build_context(db: Session) -> dict[str, Any]:
    rows = db.scalars(select(Workout).order_by(Workout.updated_at.desc()).limit(100)).all()
    sessions=[]; recovery=[]; latest_vo2=None; seven_day_distance=None; training_plan=None
    for row in rows:
        try:
            p=json.loads(row.payload_json)
        except Exception:
            continue
        sessions.extend(_sessions_from_payload(p))
        if isinstance(p.get("recovery_daily"), list): recovery.extend(p["recovery_daily"])
        if latest_vo2 is None and p.get("latest_vo2max_ml_kg_min") is not None: latest_vo2=p.get("latest_vo2max_ml_kg_min")
        if seven_day_distance is None and p.get("seven_day_distance_km") is not None: seven_day_distance=p.get("seven_day_distance_km")
        if training_plan is None and isinstance(p.get("training_plan"), list): training_plan=p.get("training_plan")
    seen=set(); uniq=[]
    for s in sessions:
        sid=str(s.get("id") or s.get("record_id") or json.dumps(s,sort_keys=True,default=str)[:160])
        if sid in seen: continue
        seen.add(sid); uniq.append(s)
    uniq.sort(key=lambda s: str(s.get("start") or s.get("date") or ""), reverse=True)
    return {"generated_at":now_iso(),"workout_count":len(uniq),"latest_workout":uniq[0] if uniq else None,"recent_workouts":uniq[:10],"recovery_daily":recovery[:14],"latest_vo2max_ml_kg_min":latest_vo2,"seven_day_distance_km":seven_day_distance,"training_plan":training_plan}

def deterministic_summary(db: Session) -> str:
    ctx=build_context(db)
    if not ctx["latest_workout"]:
        return "HealthBridge 연결 완료. 아직 동기화된 운동 데이터가 없습니다."
    w=ctx["latest_workout"]
    parts=["HealthBridge 동기화 완료"]
    if w.get("distance_km") is not None: parts.append(f"최근 운동 {w['distance_km']} km")
    if w.get("elapsed_pace_seconds_per_km") is not None:
        try:
            sec=int(float(w["elapsed_pace_seconds_per_km"])); parts.append(f"평균 페이스 {sec//60}:{sec%60:02d}/km")
        except Exception: pass
    if w.get("average_heart_rate_bpm") is not None: parts.append(f"평균 심박 {w['average_heart_rate_bpm']} bpm")
    return " · ".join(parts)
