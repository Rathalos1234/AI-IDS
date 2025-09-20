from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime
import uuid, webdb

app = Flask(__name__)
CORS(app)
webdb.init()

@app.get("/api/alerts")
def alerts():
    return jsonify(webdb.list_alerts(limit=int(request.args.get("limit", 100))))

@app.get("/api/blocks")
def blocks():
    return jsonify(webdb.list_blocks(limit=int(request.args.get("limit", 100))))

@app.post("/api/block")

def post_block():
    body = request.get_json(force=True) or {}
    ip = (body.get("ip") or "").strip()
    if not ip:
        return {"error": "ip required"}, 400

    webdb.delete_action_by_ip(ip, "unblock")
    webdb.delete_action_by_ip(ip, "block")
    webdb.insert_block({
        "id": str(uuid.uuid4()),
        "ts": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "ip": ip,
        "action": "block",
    })
    return {"ok": True}

@app.post("/api/unblock")
def post_unblock():
    body = request.get_json(force=True) or {}
    ip = (body.get("ip") or "").strip()
    if not ip:
        return {"error": "ip required"}, 400

    webdb.delete_action_by_ip(ip, "block")
    webdb.delete_action_by_ip(ip, "unblock")
    webdb.insert_block({
        "id": str(uuid.uuid4()),
        "ts": datetime.now().isoformat(timespec="seconds") + "Z",
        "ip": ip,
        "action": "unblock",
    })
    return {"ok": True}

if __name__ == "__main__":
    app.run("127.0.0.1", 5000, debug=True)
