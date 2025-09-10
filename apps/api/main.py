import os
from datetime import datetime
from fastapi import FastAPI, Depends, Request, Form
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from core import store, security

app = FastAPI(title="IDS Starter")
app.mount("/static", StaticFiles(directory="ui/static"), name="static")
templates = Jinja2Templates(directory="ui/templates")
store.init_db()

# change this shit later this only to test it
userpass = {"admin": security.hash_password("admin")}

def require_auth(request: Request):
    token = request.cookies.get("auth", "")
    data = security.decode_token(token) if token else None
    return data

#render dash
@app.get("/", response_class=HTMLResponse)
def home(request: Request, user=Depends(require_auth)):
    alerts = store.list_alerts(100)
    blocks = store.list_blocks(50)
    return templates.TemplateResponse("index.html", {"request": request, "user": user, "alerts": alerts, "blocks": blocks})

@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

#validates against userpass and issues a jwt token also CHANGE THIS LATER
@app.post("/login")
def login(username: str = Form(...), password: str = Form(...)):
    hp = userpass.get(username)
    if not hp or not security.verify_password(password, hp):
        return RedirectResponse("/login", status_code=303)
    token = security.issue_token(username)
    resp = RedirectResponse("/", status_code=303)
    resp.set_cookie("auth", token, httponly=True)
    return resp

#saves in the database (block and unblock dont actually do anything right now just saves it in database)
@app.post("/block")
def block(ip: str = Form(...), user=Depends(require_auth)):
    if not user: return RedirectResponse("/login", status_code=303)
    store.block_ip(ip)
    return RedirectResponse("/", status_code=303)

#same here
@app.post("/unblock")
def unblock(ip: str = Form(...), user=Depends(require_auth)):
    if not user: return RedirectResponse("/login", status_code=303)
    store.unblock_ip(ip)
    return RedirectResponse("/", status_code=303)

#json endpoints
@app.get("/api/alerts")
def api_alerts():
    return {"alerts": store.list_alerts(200)}

@app.get("/healthz")
def healthz():
    return {"ok": True, "time": datetime.utcnow().isoformat()}
