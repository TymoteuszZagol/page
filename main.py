"""SICARIO APP license API. Set ADMIN_TOKEN and DATABASE_PATH environment variables."""
import os, sqlite3, secrets, hashlib, hmac, time
from pathlib import Path
from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

DB = Path(os.environ.get('DATABASE_PATH','licenses.sqlite3'))
TOKEN = os.environ.get('ADMIN_TOKEN','')
app = FastAPI(title='SICARIO APP License API')
app.add_middleware(CORSMiddleware,allow_origins=[x for x in os.getenv('ADMIN_ORIGINS','http://localhost:8000').split(',') if x],allow_methods=['GET','POST'],allow_headers=['*'])

def connect():
    db=sqlite3.connect(DB)
    db.row_factory=sqlite3.Row
    db.execute('CREATE TABLE IF NOT EXISTS licenses (id INTEGER PRIMARY KEY, key_hash TEXT UNIQUE NOT NULL, key_hint TEXT NOT NULL, tier TEXT NOT NULL, device_id TEXT, revoked INTEGER DEFAULT 0, created_at INTEGER NOT NULL, activated_at INTEGER)')
    db.commit()
    return db

def admin(authorization):
    if not TOKEN or not authorization or not hmac.compare_digest(authorization,'Bearer '+TOKEN):
        raise HTTPException(401,'Unauthorized')

def digest(value):return hashlib.sha256(value.encode()).hexdigest()

class Activation(BaseModel):
    key:str=Field(min_length=10,max_length=200)
    device_id:str=Field(min_length=16,max_length=128)

class Create(BaseModel):
    tier:str

class Revoke(BaseModel):
    id:int

class Reset(BaseModel):
    id:int

@app.get('/api/health')
def health():return {'status':'ok'}

@app.post('/api/activate')
def activate(body:Activation):
    with connect() as db:
        row=db.execute('SELECT * FROM licenses WHERE key_hash=?',(digest(body.key),)).fetchone()
        if not row or row['revoked']:raise HTTPException(403,'Invalid or revoked key')
        if row['device_id'] and not hmac.compare_digest(row['device_id'],body.device_id):raise HTTPException(403,'License assigned to another device')
        if not row['device_id']:
            db.execute('UPDATE licenses SET device_id=?,activated_at=? WHERE id=?',(body.device_id,int(time.time()),row['id']))
            db.commit()
        return {'valid':True,'tier':row['tier']}

@app.post('/api/admin/create')
def create(body:Create,authorization:str|None=Header(None)):
    admin(authorization)
    if body.tier not in ('MACRO ONLY','AUTO QUEUE ONLY','FULL ACCESS'):raise HTTPException(400,'Invalid tier')
    key='SA-'+secrets.token_urlsafe(24)
    with connect() as db:
        db.execute('INSERT INTO licenses(key_hash,key_hint,tier,created_at) VALUES(?,?,?,?)',(digest(key),key[:7]+'…',body.tier,int(time.time())))
        db.commit()
    return {'key':key,'tier':body.tier,'warning':'Copy now: full key is not stored.'}

@app.get('/api/admin/licenses')
def licenses(authorization:str|None=Header(None)):
    admin(authorization)
    with connect() as db:
        rows=db.execute('SELECT id,key_hint,tier,device_id,revoked,created_at,activated_at FROM licenses ORDER BY id DESC LIMIT 500').fetchall()
        return {'licenses':[dict(x) for x in rows]}

@app.post('/api/admin/revoke')
def revoke(body:Revoke,authorization:str|None=Header(None)):
    admin(authorization)
    with connect() as db:
        db.execute('UPDATE licenses SET revoked=1 WHERE id=?',(body.id,));db.commit()
    return {'ok':True}

@app.post('/api/admin/reset-device')
def reset(body:Reset,authorization:str|None=Header(None)):
    admin(authorization)
    with connect() as db:
        db.execute('UPDATE licenses SET device_id=NULL,activated_at=NULL WHERE id=? AND revoked=0',(body.id,));db.commit()
    return {'ok':True}

from fastapi.responses import FileResponse

@app.get("/sicario_app.exe")
def download_app():
    return FileResponse(
        "sicario_app.exe",
        media_type="application/octet-stream",
        filename="sicario_app.exe"
    )

from fastapi.responses import HTMLResponse

@app.get("/", response_class=HTMLResponse)
def homepage():
    return Path("index.html").read_text(encoding="utf-8")
