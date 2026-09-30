import os,gzip,json,hmac
from datetime import datetime,timezone
from urllib.parse import unquote
from fastapi import FastAPI,Request,Depends,HTTPException,Header,Query
from sqlalchemy import create_engine,String,Text,DateTime,select
from sqlalchemy.orm import DeclarativeBase,Mapped,mapped_column,sessionmaker,Session
DB=os.getenv('DATABASE_URL','sqlite:///./healthbridge.db')
WT=os.getenv('WRITE_TOKEN','change-me-write'); RT=os.getenv('READ_TOKEN','change-me-read')
ST=os.getenv('SHARE_TOKEN',''); SE=os.getenv('SHARE_ENABLED','false').lower()=='true'
eng=create_engine(DB,pool_pre_ping=True,connect_args={'check_same_thread':False} if DB.startswith('sqlite') else {})
SessionLocal=sessionmaker(bind=eng,autoflush=False,autocommit=False)
class Base(DeclarativeBase): pass
class Workout(Base):
    __tablename__='workouts'; workout_id:Mapped[str]=mapped_column(String(255),primary_key=True); payload_json:Mapped[str]=mapped_column(Text,nullable=False); updated_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),default=lambda:datetime.now(timezone.utc),nullable=False)
class State(Base):
    __tablename__='state'; key:Mapped[str]=mapped_column(String(128),primary_key=True); value:Mapped[str]=mapped_column(Text,default='',nullable=False)
Base.metadata.create_all(bind=eng)
app=FastAPI(title='HealthBridge Server')
def db():
    x=SessionLocal()
    try: yield x
    finally: x.close()
def tok(a:str|None,write=False):
    if not a or not a.startswith('Bearer '): raise HTTPException(401,'Bearer token required')
    t=a[7:].strip(); ok=hmac.compare_digest(t,WT) if write else (hmac.compare_digest(t,RT) or hmac.compare_digest(t,WT))
    if not ok: raise HTTPException(403,'Invalid token')
def wr(authorization:str|None=Header(None)): tok(authorization,True)
def rd(authorization:str|None=Header(None)): tok(authorization,False)
def context(d:Session):
    rows=d.scalars(select(Workout).order_by(Workout.updated_at.desc()).limit(100)).all(); sessions=[]; recovery=[]; vo2=None; dist=None; plan=None
    for r in rows:
        try:p=json.loads(r.payload_json)
        except:continue
        sessions += [x for x in p.get('sessions',[]) if isinstance(x,dict)] if isinstance(p.get('sessions'),list) else [p]
        if isinstance(p.get('recovery_daily'),list): recovery += p['recovery_daily']
        if vo2 is None: vo2=p.get('latest_vo2max_ml_kg_min')
        if dist is None: dist=p.get('seven_day_distance_km')
        if plan is None and isinstance(p.get('training_plan'),list): plan=p['training_plan']
    seen=set(); uniq=[]
    for s in sessions:
        k=str(s.get('id') or s.get('record_id') or json.dumps(s,sort_keys=True,default=str)[:160])
        if k not in seen: seen.add(k); uniq.append(s)
    uniq.sort(key=lambda x:str(x.get('start') or x.get('date') or ''),reverse=True)
    return {'generated_at':datetime.now(timezone.utc).isoformat(),'workout_count':len(uniq),'latest_workout':uniq[0] if uniq else None,'recent_workouts':uniq[:10],'recovery_daily':recovery[:14],'latest_vo2max_ml_kg_min':vo2,'seven_day_distance_km':dist,'training_plan':plan}
def summary(d):
    c=context(d); w=c['latest_workout']
    if not w:return 'HealthBridge 연결 완료. 아직 동기화된 운동 데이터가 없습니다.'
    p=['HealthBridge 동기화 완료']
    if w.get('distance_km') is not None:p.append(f"최근 운동 {w['distance_km']} km")
    if w.get('average_heart_rate_bpm') is not None:p.append(f"평균 심박 {w['average_heart_rate_bpm']} bpm")
    return ' · '.join(p)
@app.get('/')
def root():return {'service':'HealthBridge','status':'ok'}
@app.get('/healthz')
def healthz():return {'ok':True}
@app.put('/v1/workouts/{wid:path}',dependencies=[Depends(wr)])
async def put(wid:str,r:Request,d:Session=Depends(db)):
    raw=await r.body(); raw=gzip.decompress(raw) if r.headers.get('content-encoding','').lower()=='gzip' else raw
    try:p=json.loads(raw.decode()) if raw else {}
    except Exception as e:raise HTTPException(400,f'Invalid JSON: {e}')
    k=unquote(wid); row=d.get(Workout,k)
    if row: row.payload_json=json.dumps(p,ensure_ascii=False,separators=(',',':')); row.updated_at=datetime.now(timezone.utc)
    else:d.add(Workout(workout_id=k,payload_json=json.dumps(p,ensure_ascii=False,separators=(',',':'))))
    d.commit(); s=d.get(State,'latest_analysis'); text=summary(d)
    if s:s.value=text
    else:d.add(State(key='latest_analysis',value=text))
    d.commit(); return {'success':True,'workout_id':k}
@app.delete('/v1/workouts/{wid:path}',dependencies=[Depends(wr)])
def dele(wid:str,d:Session=Depends(db)):
    row=d.get(Workout,unquote(wid)); deleted=bool(row)
    if row:d.delete(row);d.commit()
    return {'success':True,'deleted':deleted}
@app.get('/v1/summary',dependencies=[Depends(wr)])
def summ(d:Session=Depends(db)):
    s=d.get(State,'latest_analysis'); return {'latest_analysis':s.value if s else summary(d)}
@app.get('/v1/context',dependencies=[Depends(rd)])
def ctx(d:Session=Depends(db)):return context(d)
@app.get('/v1/workouts',dependencies=[Depends(rd)])
def workouts(limit:int=Query(30,ge=1,le=100),d:Session=Depends(db)):
    rows=d.scalars(select(Workout).order_by(Workout.updated_at.desc()).limit(limit)).all();return {'items':[{'workout_id':r.workout_id,'updated_at':r.updated_at.isoformat(),'data':json.loads(r.payload_json)} for r in rows]}
@app.get('/v1/workouts/{wid:path}',dependencies=[Depends(rd)])
def one(wid:str,d:Session=Depends(db)):
    r=d.get(Workout,unquote(wid))
    if not r:raise HTTPException(404,'Workout not found')
    return {'workout_id':r.workout_id,'updated_at':r.updated_at.isoformat(),'data':json.loads(r.payload_json)}
@app.get('/v1/health/today',dependencies=[Depends(rd)])
def today(d:Session=Depends(db)):
    c=context(d);return {'generated_at':c['generated_at'],'latest_workout':c['latest_workout'],'recovery':(c['recovery_daily'] or [None])[0],'latest_vo2max_ml_kg_min':c['latest_vo2max_ml_kg_min']}
@app.get('/v1/health/recovery',dependencies=[Depends(rd)])
def rec(d:Session=Depends(db)):c=context(d);return {'generated_at':c['generated_at'],'recovery_daily':c['recovery_daily']}
@app.get('/v1/trends/running',dependencies=[Depends(rd)])
def run(d:Session=Depends(db)):c=context(d);return {'generated_at':c['generated_at'],'seven_day_distance_km':c['seven_day_distance_km'],'recent_workouts':c['recent_workouts']}
@app.get('/share/context/{token}')
def share(token:str,d:Session=Depends(db)):
    if not SE or not ST or not hmac.compare_digest(token,ST):raise HTTPException(404,'Not found')
    c=context(d); keep=['id','exercise_type','start','end','distance_km','elapsed_pace_seconds_per_km','average_heart_rate_bpm','max_heart_rate_bpm','vo2max_ml_kg_min','calories_kcal','average_cadence_spm']
    return {'generated_at':c['generated_at'],'seven_day_distance_km':c['seven_day_distance_km'],'latest_vo2max_ml_kg_min':c['latest_vo2max_ml_kg_min'],'recovery_daily':c['recovery_daily'][:7],'recent_workouts':[{k:w.get(k) for k in keep} for w in c['recent_workouts'][:7]],'training_plan':c['training_plan']}
