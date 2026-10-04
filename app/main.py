from __future__ import annotations
import gzip, json, hmac
from urllib.parse import unquote
from fastapi import FastAPI, Request, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from .settings import get_settings
from .db import SessionLocal, init_db, Workout
from .security import require_write, require_read
from .service import upsert_workout, delete_workout, list_workouts, unpack, build_context, deterministic_summary, get_state, set_state

settings=get_settings()
app=FastAPI(title=settings.app_name, version="1.0.0")

WORKOUT_KEYS=["id","exercise_type","start","end","distance_km","elapsed_pace_seconds_per_km","average_heart_rate_bpm","max_heart_rate_bpm","vo2max_ml_kg_min","calories_kcal","average_cadence_spm","average_power_watts","steps"]
RECOVERY_KEYS=["date","sleep_minutes","resting_heart_rate_bpm","hrv_rmssd_ms","weight_kg"]

def compact_context(db:Session):
    c=build_context(db)
    workouts=[{k:w.get(k) for k in WORKOUT_KEYS if w.get(k) is not None} for w in c.get("recent_workouts",[])[:10] if isinstance(w,dict)]
    recovery=[{k:r.get(k) for k in RECOVERY_KEYS if r.get(k) is not None} for r in c.get("recovery_daily",[])[:14] if isinstance(r,dict)]
    return {"generated_at":c.get("generated_at"),"workout_count":c.get("workout_count"),"seven_day_distance_km":c.get("seven_day_distance_km"),"latest_vo2max_ml_kg_min":c.get("latest_vo2max_ml_kg_min"),"recent_workouts":workouts,"recovery_daily":recovery}

def emit_context(db:Session):
    try: print("HB_CONTEXT "+json.dumps(compact_context(db),ensure_ascii=False,separators=(",",":")),flush=True)
    except Exception as e: print("HB_CONTEXT_ERROR "+repr(e),flush=True)

def stored_sessions(db:Session):
    seen=set()
    for row in list_workouts(db,100):
        payload=row.get("data")
        if not isinstance(payload,dict): continue
        sessions=payload.get("sessions")
        sessions=sessions if isinstance(sessions,list) else [payload]
        for session in sessions:
            if not isinstance(session,dict): continue
            sid=str(session.get("id") or session.get("record_id") or "")
            if sid and sid not in seen:
                seen.add(sid)
                yield session

def emit_interval_counts(db:Session):
    # Count only: no route coordinates, heart rate values or sampled values in logs.
    try:
        running=[s for s in stored_sessions(db) if s.get("exercise_type")==56]
        running.sort(key=lambda s:str(s.get("start") or ""),reverse=True)
        keys=("laps","segments","segment_metrics","speed_samples_meters_per_second",
              "pace_samples_seconds_per_km","distance_intervals")
        counts=[{"id":s.get("id"),"start":s.get("start"),
                 **{key:len(s[key]) if isinstance(s.get(key),list) else 0 for key in keys}}
                for s in running[:10]]
        print("HB_INTERVAL_COUNTS "+json.dumps(counts,separators=(",",":")),flush=True)
    except Exception as e:
        print("HB_INTERVAL_COUNTS_ERROR "+type(e).__name__,flush=True)

@app.on_event("startup")
def startup():
    init_db()
    db=SessionLocal()
    try:
        emit_context(db)
        emit_interval_counts(db)
    finally: db.close()

def db_dep():
    db=SessionLocal()
    try: yield db
    finally: db.close()

async def json_body(request: Request):
    raw=await request.body()
    if len(raw)>settings.max_body_bytes: raise HTTPException(413,"Payload too large")
    if request.headers.get("content-encoding","").lower()=="gzip":
        try: raw=gzip.decompress(raw)
        except Exception as e: raise HTTPException(400,f"Invalid gzip body: {e}")
    if not raw: return {}
    try: return json.loads(raw.decode("utf-8"))
    except Exception as e: raise HTTPException(400,f"Invalid JSON: {e}")

@app.get("/")
def root(): return {"service":"HealthBridge","status":"ok"}

@app.get("/healthz")
def healthz(): return {"ok":True}

@app.put("/v1/workouts/{workout_id:path}", dependencies=[Depends(require_write)])
async def put_workout(workout_id: str, request: Request, db: Session=Depends(db_dep)):
    payload=await json_body(request)
    wid=unquote(workout_id)
    upsert_workout(db,wid,payload)
    set_state(db,"latest_analysis",deterministic_summary(db))
    emit_context(db)
    return {"success":True,"workout_id":wid}

@app.delete("/v1/workouts/{workout_id:path}", dependencies=[Depends(require_write)])
def remove_workout(workout_id: str, db: Session=Depends(db_dep)):
    result=delete_workout(db,unquote(workout_id))
    emit_context(db)
    return {"success":True,"deleted":result}

@app.get("/v1/summary", dependencies=[Depends(require_write)])
def apk_summary(db: Session=Depends(db_dep)):
    analysis=get_state(db,"latest_analysis","") or deterministic_summary(db)
    return {"latest_analysis":analysis}

@app.get("/v1/context", dependencies=[Depends(require_read)])
def context(db: Session=Depends(db_dep)): return build_context(db)

@app.get("/v1/workouts", dependencies=[Depends(require_read)])
def workouts(limit:int=Query(30,ge=1,le=100), db:Session=Depends(db_dep)): return {"items":list_workouts(db,limit)}

@app.get("/v1/workouts/{workout_id:path}", dependencies=[Depends(require_read)])
def workout(workout_id:str, db:Session=Depends(db_dep)):
    row=db.get(Workout,unquote(workout_id))
    if not row: raise HTTPException(404,"Workout not found")
    return unpack(row)

@app.get("/v1/health/today", dependencies=[Depends(require_read)])
def today(db:Session=Depends(db_dep)):
    c=build_context(db)
    return {"generated_at":c["generated_at"],"latest_workout":c["latest_workout"],"recovery":(c["recovery_daily"] or [None])[0],"latest_vo2max_ml_kg_min":c["latest_vo2max_ml_kg_min"]}

@app.get("/v1/health/recovery", dependencies=[Depends(require_read)])
def recovery(db:Session=Depends(db_dep)):
    c=build_context(db); return {"generated_at":c["generated_at"],"recovery_daily":c["recovery_daily"]}

@app.get("/v1/trends/running", dependencies=[Depends(require_read)])
def running(db:Session=Depends(db_dep)):
    c=build_context(db); return {"generated_at":c["generated_at"],"seven_day_distance_km":c["seven_day_distance_km"],"recent_workouts":c["recent_workouts"]}

@app.get("/v1/trends/hrv", dependencies=[Depends(require_read)])
def hrv(db:Session=Depends(db_dep)):
    c=build_context(db); return {"generated_at":c["generated_at"],"items":[{"date":x.get("date"),"hrv_rmssd_ms":x.get("hrv_rmssd_ms")} for x in c["recovery_daily"] if isinstance(x,dict)]}

@app.get("/v1/trends/sleep", dependencies=[Depends(require_read)])
def sleep(db:Session=Depends(db_dep)):
    c=build_context(db); return {"generated_at":c["generated_at"],"items":[{"date":x.get("date"),"sleep_minutes":x.get("sleep_minutes"),"sleep_stages":x.get("sleep_stages")} for x in c["recovery_daily"] if isinstance(x,dict)]}

@app.get("/share/context/{token}")
def shared_context(token:str, db:Session=Depends(db_dep)):
    if not settings.share_enabled or not settings.share_token or not hmac.compare_digest(token,settings.share_token): raise HTTPException(404,"Not found")
    return compact_context(db)

@app.get("/share/workout/{token}/{session_id}")
def shared_workout(token:str, session_id:str, db:Session=Depends(db_dep)):
    if not settings.share_enabled or not settings.share_token or not hmac.compare_digest(token,settings.share_token):
        raise HTTPException(404,"Not found")
    for session in stored_sessions(db):
        if str(session.get("id"))!=session_id: continue
        fields=("id","exercise_type","start","end","distance_km","source_package",
                "recorded_title","laps","segments","segment_metrics",
                "kilometer_splits_estimated","kilometer_split_basis",
                "speed_samples_meters_per_second","pace_samples_seconds_per_km",
                "distance_intervals","heart_rate_samples")
        result={key:session[key] for key in fields if key in session}
        result["counts"]={
            key:len(result[key]) if isinstance(result.get(key),list) else 0
            for key in ("laps","segments","segment_metrics",
                        "speed_samples_meters_per_second",
                        "pace_samples_seconds_per_km","distance_intervals","heart_rate_samples")
        }
        return result
    raise HTTPException(404,"Workout session not found")
