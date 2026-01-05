from flask import Flask, render_template, request, redirect, url_for, send_file
from datetime import datetime, timedelta
import json, sqlite3
import tempfile
import json
import os

RULES_FILE = "rules.json"
DB_FILE = "fw.db"
DOS_CONFIG_FILE = "dos_state.json"

app = Flask(__name__)

def load_dos_config():
    default_cfg = {"warn_5s": 50, "drop_5s": 110}
    if not os.path.exists(DOS_CONFIG_FILE):
        return default_cfg
    try:
        with open(DOS_CONFIG_FILE, "r") as f:
            cfg = json.load(f)
        warn_5s = int(cfg.get("warn_5s", default_cfg["warn_5s"]))
        drop_5s = int(cfg.get("drop_5s", default_cfg["drop_5s"]))
        return {"warn_5s": warn_5s, "drop_5s": drop_5s}
    except Exception:
        return default_cfg

def save_dos_config(warn_5s: int, drop_5s: int):
    with open(DOS_CONFIG_FILE, "w") as f:
        json.dump({"warn_5s": warn_5s, "drop_5s": drop_5s}, f, indent=2)

def load_rules():
    with open(RULES_FILE, "r") as f:
        return json.load(f)

def save_rules(rules):
    with open(RULES_FILE, "w") as f:
        json.dump(rules, f, indent=2)

MANAGED_PRESET_COMMENTS = {"Allow DNS", "Allow HTTPS", "Block HTTP", "Block ping"}

def _is_localhost_rule(r):
    return str(r.get("comment", "")) == "Allow localhost"

def _is_default_policy_rule(r):
    c = str(r.get("comment", "")).strip().lower()
    return c.startswith("default allow") or c.startswith("default deny")

def _default_action_to_comment(action: str) -> str:
    return "Default deny" if str(action).upper() == "DROP" else "Default allow"

def _find_default_index(rules):
    for i, r in enumerate(rules):
        if _is_default_policy_rule(r):
            return i
    return None

def _ensure_default_policy(rules, action: str):
    idx = _find_default_index(rules)
    comment = _default_action_to_comment(action)
    act = "DROP" if str(action).upper() == "DROP" else "ACCEPT"

    if idx is None:
        nid = max((r.get("id", 0) for r in rules), default=0) + 1
        rules.append({
            "id": nid,
            "action": act,
            "proto": "any",
            "src": "any",
            "dst": "any",
            "dport": "any",
            "comment": comment,
        })
        return rules

    dr = rules.pop(idx)
    dr["action"] = act
    dr["comment"] = comment
    dr["proto"] = "any"
    dr["src"] = "any"
    dr["dst"] = "any"
    dr["dport"] = "any"
    rules.append(dr)
    return rules

def _insert_before_default(rules, rule_obj):
    idx = _find_default_index(rules)
    if idx is None:
        rules.append(rule_obj)
    else:
        rules.insert(idx, rule_obj)
    return rules

def _strip_managed_preset_rules(rules):
    return [r for r in rules if str(r.get("comment", "")) not in MANAGED_PRESET_COMMENTS]

def _ensure_localhost_rule(rules):
    idx = None
    for i, r in enumerate(rules):
        if _is_localhost_rule(r):
            idx = i
            break

    if idx is None:
        nid = max((r.get("id", 0) for r in rules), default=0) + 1
        rules.insert(0, {
            "id": nid,
            "action": "ACCEPT",
            "proto": "any",
            "src": "any",
            "dst": "127.0.0.1",
            "dport": "any",
            "comment": "Allow localhost",
        })
        return rules

    if idx != 0:
        r = rules.pop(idx)
        rules.insert(0, r)

    return rules

def move_rule(rules, rid, direction):
    i = next((idx for idx, r in enumerate(rules) if int(r.get("id", -1)) == rid), None)
    if i is None:
        return rules

    if _is_localhost_rule(rules[i]):
        return rules

    if direction == "up" and i > 0:
        if i - 1 == 0 and len(rules) > 0 and _is_localhost_rule(rules[0]):
            return rules
        rules[i - 1], rules[i] = rules[i], rules[i - 1]

    if direction == "down" and i < len(rules) - 1:
        rules[i + 1], rules[i] = rules[i], rules[i + 1]

    return rules

@app.post("/move/up/<int:rid>")
def move_up(rid):
    rules = load_rules()
    rules = move_rule(rules, rid, "up")
    save_rules(rules)
    return redirect(url_for("index"))

@app.post("/move/down/<int:rid>")
def move_down(rid):
    rules = load_rules()
    rules = move_rule(rules, rid, "down")
    save_rules(rules)
    return redirect(url_for("index"))

@app.get("/")
def index():
    preset = request.args.get("preset", "")
    return render_template("index.html", rules=load_rules(), preset=preset)

@app.post("/add")
def add():
    rules = load_rules()

    default_idx = _find_default_index(rules)
    default_action = "ACCEPT"
    if default_idx is not None:
        default_action = rules[default_idx].get("action", "ACCEPT")
    rules = _ensure_default_policy(rules, default_action)

    nid = max((r.get("id", 0) for r in rules), default=0) + 1
    dport_raw = request.form.get("dport", "any").strip().lower()
    dport = "any" if dport_raw in ("", "any") else int(dport_raw)

    new_rule = {
        "id": nid,
        "action": request.form.get("action", "ACCEPT").upper(),
        "proto": request.form.get("proto", "any").lower(),
        "src": request.form.get("src", "any").strip() or "any",
        "dst": request.form.get("dst", "any").strip() or "any",
        "dport": dport,
        "comment": request.form.get("comment", "").strip()
    }

    rules = _insert_before_default(rules, new_rule)

    save_rules(rules)
    return redirect(url_for("index"))

@app.post("/delete/<int:rid>")
def delete(rid):
    rules = load_rules()
    out = []
    for r in rules:
        if int(r.get("id", -1)) != rid:
            out.append(r)
            continue

        if _is_localhost_rule(r) or _is_default_policy_rule(r):
            out.append(r)

    save_rules(out)
    return redirect(url_for("index"))

@app.get("/logs")
def logs():
    verdict = request.args.get("verdict", "all").lower()
    proto = request.args.get("proto", "all").lower()

    where = []
    params = []

    if verdict != "all":
        where.append("verdict = ?")
        params.append(verdict.upper())

    if proto != "all":
        where.append("proto = ?")
        params.append(proto)

    where_sql = ("WHERE " + " AND ".join(where)) if where else ""

    con = sqlite3.connect(DB_FILE)
    cur = con.cursor()
    cur.execute(
        f"SELECT id, ts, verdict, proto, src, dst, sport, dport, note FROM logs {where_sql} "
        "ORDER BY id DESC LIMIT 300",
        params
    )
    rows = cur.fetchall()
    con.close()

    return render_template("logs.html", rows=rows, verdict=verdict, proto=proto)

@app.post("/logs/clear")
def clear_logs():
    con = sqlite3.connect(DB_FILE)
    cur = con.cursor()
    cur.execute("DELETE FROM logs")
    con.commit()
    con.close()
    return redirect(url_for("logs"))

@app.post("/preset/professional")
def preset_professional():
    rules = load_rules()
    rules = _strip_managed_preset_rules(rules)
    rules = _ensure_localhost_rule(rules)
    rules = _ensure_default_policy(rules, "DROP")

    nid = max((r.get("id", 0) for r in rules), default=0) + 1
    allow_dns = {
        "id": nid,
        "action": "ACCEPT",
        "proto": "udp",
        "src": "any",
        "dst": "any",
        "dport": 53,
        "comment": "Allow DNS"
    }
    nid += 1
    allow_https = {
        "id": nid,
        "action": "ACCEPT",
        "proto": "tcp",
        "src": "any",
        "dst": "any",
        "dport": 443,
        "comment": "Allow HTTPS"
    }

    rules = _insert_before_default(rules, allow_dns)
    rules = _insert_before_default(rules, allow_https)

    save_rules(rules)
    return redirect(url_for("index", preset="professional"))

@app.post("/preset/safer")
def preset_safer():
    rules = load_rules()

    rules = _strip_managed_preset_rules(rules)
    rules = _ensure_localhost_rule(rules)

    rules = _ensure_default_policy(rules, "ACCEPT")

    nid = max((r.get("id", 0) for r in rules), default=0) + 1
    block_http = {
        "id": nid,
        "action": "DROP",
        "proto": "tcp",
        "src": "any",
        "dst": "any",
        "dport": 80,
        "comment": "Block HTTP"
    }
    nid += 1
    block_ping = {
        "id": nid,
        "action": "DROP",
        "proto": "icmp",
        "src": "any",
        "dst": "any",
        "dport": "any",
        "comment": "Block ping"
    }

    rules = _insert_before_default(rules, block_http)
    rules = _insert_before_default(rules, block_ping)

    save_rules(rules)
    return redirect(url_for("index", preset="safer"))

@app.get("/export")
def export_rules():
    rules = load_rules()

    tmp = tempfile.NamedTemporaryFile(mode="w+", delete=False, suffix=".json")
    json.dump(rules, tmp, indent=2)
    tmp.flush()
    tmp.close()

    return send_file(
        tmp.name,
        as_attachment=True,
        download_name="rules.json",
        mimetype="application/json"
    )

@app.get("/stats")
def stats():
    cfg = load_dos_config()

    con = sqlite3.connect(DB_FILE)
    cur = con.cursor()

    cur.execute("SELECT COUNT(*) FROM logs")
    total = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM logs WHERE verdict='ACCEPT'")
    accept = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM logs WHERE verdict='DROP'")
    drop = cur.fetchone()[0]

    # packets per second over last 5 seconds
    window_sec = 5
    cutoff = (datetime.now() - timedelta(seconds=window_sec)).strftime("%Y-%m-%d %H:%M:%S")
    cur.execute("SELECT COUNT(*) FROM logs WHERE ts >= ?", (cutoff,))
    recent = cur.fetchone()[0]
    pps = recent / window_sec

    con.close()
    return {
        "total": total,
        "accept": accept,
        "drop": drop,
        "pps": round(pps, 2),
        "warn_5s": cfg["warn_5s"],
        "drop_5s": cfg["drop_5s"],
    }

@app.get("/logs_tail")
def logs_tail():
    since = request.args.get("since", "0")
    con = sqlite3.connect(DB_FILE)
    cur = con.cursor()
    cur.execute(
        "SELECT id, ts, verdict, proto, src, dst, sport, dport, note "
        "FROM logs WHERE id > ? ORDER BY id ASC LIMIT 20",
        (since,)
    )
    rows = cur.fetchall()
    con.close()
    return {"rows": rows}

@app.get("/about")
def about():
    return render_template("about.html")

@app.post("/dos_config")
def dos_config_update():
    warn_raw = request.form.get("warn_5s", "50")
    drop_raw = request.form.get("drop_5s", "110")

    try:
        warn_5s = int(warn_raw)
        drop_5s = int(drop_raw)
    except ValueError:
        return redirect("/logs")

    warn_5s = max(10, min(warn_5s, 2000))
    drop_5s = max(10, min(drop_5s, 2000))

    if drop_5s <= warn_5s:
        drop_5s = warn_5s + 10

    save_dos_config(warn_5s, drop_5s)
    return redirect("/logs")

def is_default_rule(r):
    c = (r.get("comment") or "").strip().lower()
    return c.startswith("default allow") or c.startswith("default deny")

def make_default_rule(mode: str, new_id: int):
    mode = mode.lower()
    if mode == "deny":
        return {
            "id": new_id,
            "action": "DROP",
            "proto": "any",
            "src": "any",
            "dst": "any",
            "dport": "any",
            "comment": "Default deny"
        }
    else:
        return {
            "id": new_id,
            "action": "ACCEPT",
            "proto": "any",
            "src": "any",
            "dst": "any",
            "dport": "any",
            "comment": "Default allow"
        }

def toggle_default_policy(rules: list[dict]) -> list[dict]:
    current = "allow"
    for r in rules:
        c = (r.get("comment") or "").strip().lower()
        if c.startswith("default deny"):
            current = "deny"
            break
        if c.startswith("default allow"):
            current = "allow"
            break

    new_mode = "deny" if current == "allow" else "allow"

    rules = [r for r in rules if not is_default_rule(r)]

    new_id = (max((int(r.get("id", 0)) for r in rules), default=0) + 1)
    rules.append(make_default_rule(new_mode, new_id))
    return rules

@app.post("/default/toggle")
def default_toggle():
    rules = load_rules()
    rules = toggle_default_policy(rules)
    save_rules(rules)
    return redirect("/")

if __name__ == "__main__":
    app.run("127.0.0.1", 5000, debug=True)
