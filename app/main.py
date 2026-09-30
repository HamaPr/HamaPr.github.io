from __future__ import annotations
import gzip, json
from urllib.parse import unquote
from fastapi import FastAPI, Request, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from .settings import get_settings
from .db import SessionLocal, init_db, Workout
from .security import require_write, require_read
from .service import upsert_workout, delete_workout, list_workouts, unpack, build_context, deterministic_summary, get_state, set_state

settings=get_settings()
app=FastAPI(title=settings.app_name, version="1.0.0")

@app.on_event("startup")
def startup(): init_db()

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
    return {"success":True,"workout_id":wid}

@app.delete("/v1/workouts/{workout_id:path}", dependencies=[Depends(require_write)])
def remove_workout(workout_id: str, db: Session=Depends(db_dep)):
    return {"success":True,"deleted":delete_workout(db,unquote(workout_id))}

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
    import hmac
    if not settings.share_enabled or not settings.share_token or not hmac.compare_digest(token,settings.share_token): raise HTTPException(404,"Not found")
    c=build_context(db)
    recent=[]
    for w in c["recent_workouts"][:7]:
        recent.append({k:w.get(k) for k in ["id","exercise_type","start","end","distance_km","elapsed_pace_seconds_per_km","average_heart_rate_bpm","max_heart_rate_bpm","vo2max_ml_kg_min","calories_kcal","average_cadence_spm"]})
    return {"generated_at":c["generated_at"],"seven_day_distance_km":c["seven_day_distance_km"],"latest_vo2max_ml_kg_min":c["latest_vo2max_ml_kg_min"],"recovery_daily":c["recovery_daily"][:7],"recent_workouts":recent,"training_plan":c["training_plan"]}
