import json, os, sqlite3, time
from collections import defaultdict, deque

from netfilterqueue import NetfilterQueue
from scapy.all import IP, TCP, UDP, ICMP

RULES_FILE = "rules.json"
DB_FILE = "fw.db"
QUEUE_NUM = 1

DOS_CONFIG_FILE = "dos_config.json"
DOS_STATE_FILE = "dos_state.json"
DOS_WINDOW_SEC = 5
DOS_BLOCK_SEC = 10

ip_times = defaultdict(deque)
temp_block = {}
last_cfg_reload = 0.0
dos_cfg = {"warn_5s": 50, "drop_5s": 110}
dos_state = "safe"

def init_db():
    con = sqlite3.connect(DB_FILE)
    cur = con.cursor()
    cur.execute("""
      CREATE TABLE IF NOT EXISTS logs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT NOT NULL,
        verdict TEXT NOT NULL,
        proto TEXT, src TEXT, dst TEXT,
        sport INTEGER, dport INTEGER, note TEXT
       )
    """)
    con.commit()
    con.close()


def log_event(verdict, proto, src, dst, sport, dport, note=""):
    if dst == "127.0.0.1":
        return

    con = sqlite3.connect(DB_FILE)
    cur = con.cursor()
    cur.execute(
        "INSERT INTO logs(ts, verdict, proto, src, dst, sport, dport, note) "
        "VALUES(datetime('now'),?,?,?,?,?,?,?)",
        (verdict, proto, src, dst, sport, dport, note),
    )
    con.commit()
    con.close()


def load_rules():
    if not os.path.exists(RULES_FILE):
        return [{
            "id": 1,
            "action": "ACCEPT",
            "proto": "any",
            "dport": "any",
            "src": "any",
            "dst": "any",
            "comment": "fallback accept"
        }]
    with open(RULES_FILE, "r") as f:
        return json.load(f)


def match(rule, info):
    rp = rule.get("proto", "any")
    if rp != "any" and rp != info["proto"]:
        return False

    if rule.get("src", "any") != "any" and rule["src"] != info["src"]:
        return False

    if rule.get("dst", "any") != "any" and rule["dst"] != info["dst"]:
        return False

    rd = rule.get("dport", "any")
    if rd != "any":
        try:
            return info.get("dport") == int(rd)
        except Exception:
            return False

    return True


def decide(rules, info):
    for r in rules:
        if match(r, info):
            return r.get("action", "ACCEPT").upper(), r.get("comment", "")
    return "ACCEPT", "fallback accept"


def load_dos_config():
    cfg = {"warn_5s": 50, "drop_5s": 110}
    if os.path.exists(DOS_CONFIG_FILE):
        try:
            with open(DOS_CONFIG_FILE, "r") as f:
                data = json.load(f)
            cfg["warn_5s"] = int(data.get("warn_5s", cfg["warn_5s"]))
            cfg["drop_5s"] = int(data.get("drop_5s", cfg["drop_5s"]))
        except Exception:
            pass

    cfg["warn_5s"] = max(10, min(cfg["warn_5s"], 2000))
    cfg["drop_5s"] = max(cfg["warn_5s"] + 10, min(cfg["drop_5s"], 2000))
    return cfg


def cleanup_old(dq, now):
    cutoff = now - DOS_WINDOW_SEC
    while dq and dq[0] < cutoff:
        dq.popleft()


def write_dos_state(state, src=None, rate=None):
    try:
        payload = {
            "state": state,
            "warn_5s": dos_cfg.get("warn_5s", 50),
            "drop_5s": dos_cfg.get("drop_5s", 110),
            "window_sec": DOS_WINDOW_SEC,
            "block_sec": DOS_BLOCK_SEC,
        }
        if src is not None:
            payload["src"] = src
        if rate is not None:
            payload["rate_5s"] = rate

        with open(DOS_STATE_FILE, "w") as f:
            json.dump(payload, f)
    except Exception:
        pass


def dos_check_and_maybe_drop(info):
    global last_cfg_reload, dos_cfg, dos_state

    src = info["src"]
    dst = info["dst"]

    if dst == "127.0.0.1":
        dos_state = "safe"
        return None, ""

    now = time.time()

    if now - last_cfg_reload > 2:
        dos_cfg = load_dos_config()
        last_cfg_reload = now

    unblock = temp_block.get(src)
    if unblock is not None:
        if now < unblock:
            dos_state = "drop"
            write_dos_state("drop", src=src, rate=None)
            return "DROP", f"DoS temp-drop active ({int(unblock - now)}s left)"
        else:
            temp_block.pop(src, None)

    dq = ip_times[src]
    dq.append(now)
    cleanup_old(dq, now)
    rate = len(dq)

    if rate >= dos_cfg["drop_5s"]:
        temp_block[src] = now + DOS_BLOCK_SEC
        dos_state = "drop"
        write_dos_state("drop", src=src, rate=rate)
        return "DROP", f"DoS temp-drop triggered ({rate}/{DOS_WINDOW_SEC}s)"
    elif rate >= dos_cfg["warn_5s"]:
        dos_state = "warn"
        write_dos_state("warn", src=src, rate=rate)
        return None, f"DoS warning ({rate}/{DOS_WINDOW_SEC}s)"
    else:
        dos_state = "safe"
        write_dos_state("safe", src=src, rate=rate)
        return None, ""


def cb(pkt):
    # parse packet
    try:
        p = IP(pkt.get_payload())
        info = {"src": p.src, "dst": p.dst, "proto": "other", "sport": None, "dport": None}

        if p.haslayer(TCP):
            info["proto"] = "tcp"
            info["sport"] = int(p[TCP].sport)
            info["dport"] = int(p[TCP].dport)
        elif p.haslayer(UDP):
            info["proto"] = "udp"
            info["sport"] = int(p[UDP].sport)
            info["dport"] = int(p[UDP].dport)
        elif p.haslayer(ICMP):
            info["proto"] = "icmp"
        else:
            info["proto"] = "other"

    except Exception:
        pkt.accept()
        return

    forced, dos_note = dos_check_and_maybe_drop(info)
    if forced == "DROP":
        pkt.drop()
        log_event("DROP", info["proto"], info["src"], info["dst"], info["sport"], info["dport"], dos_note)
        return

    rules = load_rules()
    verdict, note = decide(rules, info)

    final_note = note
    if dos_note:
        final_note = (note + " | " + dos_note).strip(" |")

    if verdict == "DROP":
        pkt.drop()
    else:
        pkt.accept()

    log_event(verdict, info["proto"], info["src"], info["dst"], info["sport"], info["dport"], final_note)


def main():
    init_db()
    write_dos_state("safe")

    nfq = NetfilterQueue()
    nfq.bind(QUEUE_NUM, cb)
    print(f"[engine] listening on NFQUEUE {QUEUE_NUM}")
    nfq.run()


if __name__ == "__main__":
    main()
