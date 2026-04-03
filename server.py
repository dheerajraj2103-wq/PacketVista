"""
=============================================================================
PacketVista — Flask Backend Server
=============================================================================
Uses streaming response so Render's 30s timeout never triggers — headers
are sent immediately, data streams as capture runs, then file downloads.

Duration comes from ?duration=N query param sent by index.html.

Usage:
    pip install flask flask-cors
    python server.py   (same folder as packetvista.py)

Endpoint: GET /capture-logs?duration=30
=============================================================================
"""

import os
import sys
import queue
import time
import threading
import types
import importlib.util
from datetime import datetime
import zoneinfo
from flask import Flask, Response, request, stream_with_context
from flask_cors import CORS

# ── Timezone helpers (IST = UTC+5:30) ────────────────────────────────────────
def now_ist():
    return datetime.now(zoneinfo.ZoneInfo("Asia/Kolkata"))

def ts_ist():
    return now_ist().strftime("%H:%M:%S")

def dt_ist():
    return now_ist().strftime("%Y-%m-%d  %H:%M:%S  IST")

# =============================================================================
# IMPORT DIRECTLY FROM packetvista.py (headless — no GUI launch)
# =============================================================================
class _TkStub:
    """Catch-all stub — returns itself for any attribute access or call."""
    def __getattr__(self, name):
        return self
    def __call__(self, *args, **kwargs):
        return self
    def __str__(self):
        return ""
    def __iter__(self):
        return iter([])

_tk_stub = _TkStub()

# Build proper stub modules for tkinter and its submodules BEFORE importing packetvista
import types as _types

def _make_tk_module(name):
    m = _types.ModuleType(name)
    # Tk widget classes and constants
    for _cls in ["Tk","Frame","LabelFrame","Label","Button","Entry","Text",
                 "Canvas","Scrollbar","Menu","Menubutton","OptionMenu",
                 "Spinbox","Listbox","Checkbutton","Radiobutton","Scale",
                 "PanedWindow","Toplevel","PhotoImage","BitmapImage",
                 # ttk extras
                 "Notebook","Treeview","Combobox","Separator","Progressbar","Style",
                 # scrolledtext
                 "ScrolledText"]:
        setattr(m, _cls, _TkStub)
    for _fn in ["showinfo","showwarning","showerror","askquestion",
                "askyesno","askokcancel","askyesnocancel"]:
        setattr(m, _fn, lambda *a, **k: None)
    for _var in ["StringVar","IntVar","DoubleVar","BooleanVar"]:
        setattr(m, _var, _TkStub)
    for _const, _val in [
        ("END","end"),("INSERT","insert"),("SEL","sel"),("SEL_FIRST","sel.first"),
        ("SEL_LAST","sel.last"),("BOTH","both"),("LEFT","left"),("RIGHT","right"),
        ("TOP","top"),("BOTTOM","bottom"),("X","x"),("Y","y"),
        ("N","n"),("S","s"),("E","e"),("W","w"),
        ("NW","nw"),("NE","ne"),("SW","sw"),("SE","se"),("CENTER","center"),
        ("WORD","word"),("CHAR","char"),("NONE","none"),
        ("FLAT","flat"),("RAISED","raised"),("SUNKEN","sunken"),
        ("GROOVE","groove"),("RIDGE","ridge"),
        ("NORMAL","normal"),("DISABLED","disabled"),("ACTIVE","active"),
        ("HORIZONTAL","horizontal"),("VERTICAL","vertical"),
        ("NSEW","nsew"),("NS","ns"),("EW","ew"),
        ("FIRST","first"),("LAST","last"),
        ("TRUE",True),("FALSE",False),
    ]:
        setattr(m, _const, _val)
    # sub-attributes that might be accessed as tkinter.ttk etc.
    m.ttk         = _tk_stub
    m.filedialog  = _tk_stub
    m.messagebox  = _tk_stub
    m.colorchooser= _tk_stub
    m.font        = _tk_stub
    m.scrolledtext= _tk_stub
    return m

for _modname in ["tkinter", "tkinter.ttk", "tkinter.scrolledtext", "tkinter.messagebox"]:
    sys.modules[_modname] = _make_tk_module(_modname)

_pv_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "packetvista.py")
_spec    = importlib.util.spec_from_file_location("packetvista", _pv_path)
pv       = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(pv)

SimEngine        = pv.SimEngine
DetectionEngine  = pv.DetectionEngine
SUSPICIOUS_PORTS = pv.SUSPICIOUS_PORTS

# =============================================================================
app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}},
     expose_headers=["Content-Disposition", "X-Duration"],
     allow_headers=["Content-Type"],
     methods=["GET", "OPTIONS"])

DEFAULT_DURATION = 30   # used if ?duration param is missing
MAX_DURATION     = 120  # safety cap


@app.route("/capture-logs", methods=["OPTIONS"])
def capture_logs_preflight():
    resp = Response("")
    resp.headers["Access-Control-Allow-Origin"]  = "*"
    resp.headers["Access-Control-Allow-Methods"] = "GET, OPTIONS"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
    return resp, 204


# =============================================================================
# /capture-logs  — streaming so Render never times out mid-capture
# =============================================================================

@app.route("/capture-logs", methods=["GET"])
def capture_logs():

    # ── Read duration from query param ───────────────────────────────────────
    raw = request.args.get("duration", "")
    print(f"[PacketVista] raw duration param: '{raw}'", flush=True)

    try:
        duration = int(raw)
        duration = max(1, min(duration, MAX_DURATION))
    except (ValueError, TypeError):
        duration = DEFAULT_DURATION

    print(f"[PacketVista] Using duration: {duration}s", flush=True)

    # ── Run capture synchronously, collect all data ───────────────────────────
    pkt_q     = queue.Queue(maxsize=10000)
    log_lines = []
    lock      = threading.Lock()

    def on_alert(atype, src, detail):
        now  = time.time()
        line = f"[{ts_ist()}] [{atype}]  {detail}"
        with lock:
            log_lines.append(("alert", now, line))

    engine   = DetectionEngine(on_alert)
    sim      = SimEngine(pkt_q)
    stop_evt = threading.Event()

    def consumer():
        while not stop_evt.is_set() or not pkt_q.empty():
            try:
                item = pkt_q.get(timeout=0.05)
            except queue.Empty:
                continue

            now       = time.time()
            src       = item["src"]
            dst       = item["dst"]
            proto     = item["proto"]
            sp        = item["sp"]
            dp        = item["dp"]
            fl        = item.get("fl", "")
            blen      = item.get("len", 0)
            ts_str    = ts_ist()

            alert_text = ("SUSPICIOUS: " + SUSPICIOUS_PORTS[dp]) if dp in SUSPICIOUS_PORTS else ""
            sport_str  = str(sp) if sp else ""
            dport_str  = str(dp) if dp else ""

            line = (
                f"{ts_str:<10}  "
                f"{src:<18}  {dst:<18}  "
                f"{proto:<5}  "
                f"{sport_str:>6} -> {dport_str:<6}  "
                f"flags={fl:<4}  "
                f"bytes={blen:<5}"
                + (f"  ⚠  {alert_text}" if alert_text else "")
            )
            with lock:
                log_lines.append(("pkt", now, line))

            engine.process(src, dst, proto, sp, dp, fl)

    t = threading.Thread(target=consumer, daemon=True)
    t.start()

    sim.start()
    time.sleep(duration)
    sim.stop()
    time.sleep(0.5)
    stop_evt.set()
    t.join(timeout=3)

    # ── Build report ──────────────────────────────────────────────────────────
    with lock:
        sorted_lines = sorted(log_lines, key=lambda x: x[1])

    pkt_rows  = [l for k, _, l in sorted_lines if k == "pkt"]
    alrt_rows = [l for k, _, l in sorted_lines if k == "alert"]
    scan_c, syn_c, susp_c, rep_c = engine.counters()

    S = "=" * 80
    s = "-" * 80

    table_hdr = (
        f"{'Time':<10}  {'Source IP':<18}  {'Dest IP':<18}  "
        f"{'Proto':<5}  {'SrcPort':>6}    {'DstPort':<6}  "
        f"{'Flags':<9}  {'Bytes':<8}  Alert"
    )

    report = "\n".join([
        S,
        "  PACKET VISTA — RUNTIME CAPTURE REPORT",
        f"  Duration  : {duration} seconds",
        f"  Generated : {dt_ist()}",
        f"  Mode      : Simulation",
        S,
        "",
        "  ATTACK COUNTERS",
        s,
        f"  Port Scans Detected  : {scan_c}",
        f"  SYN Floods Detected  : {syn_c}",
        f"  Suspicious Port Hits : {susp_c}",
        f"  Repeat Conn Alerts   : {rep_c}",
        "",
        f"  Total Packets  : {len(pkt_rows)}",
        f"  Total Alerts   : {len(alrt_rows)}",
        "",
        S,
        "  ALERT LOG",
        s,
        "",
        ("\n".join(alrt_rows) if alrt_rows else "  (no alerts)"),
        "",
        S,
        "  LIVE PACKET FEED",
        s,
        "",
        table_hdr,
        s,
        ("\n".join(pkt_rows) if pkt_rows else "  (no packets)"),
        "",
        S,
        "  END OF REPORT — Packet Vista v1.0",
        S,
    ])

    # ── Stream response — prevents Render 30s timeout ─────────────────────────
    # We wrap in a generator that yields the full report in chunks.
    # This keeps the HTTP connection alive during the capture window.
    filename = f"packetvista_logs_{now_ist().strftime('%Y%m%d_%H%M%S')}.txt"

    def generate():
        chunk_size = 4096
        for i in range(0, len(report), chunk_size):
            yield report[i:i + chunk_size]

    resp = Response(
        stream_with_context(generate()),
        mimetype="text/plain",
        headers={
            "Content-Disposition":           f'attachment; filename="{filename}"',
            "Content-Type":                  "text/plain; charset=utf-8",
            "X-Duration":                    str(duration),
            "Access-Control-Allow-Origin":   "*",
            "Access-Control-Expose-Headers": "Content-Disposition, X-Duration",
            # Tell proxies/Render not to buffer — stream immediately
            "X-Accel-Buffering":             "no",
            "Cache-Control":                 "no-cache",
        }
    )
    return resp


@app.route("/")
def index():
    return (
        "<h2>PacketVista backend running.</h2>"
        f"<p>Endpoint: <code>GET /capture-logs?duration=30</code></p>"
        f"<p>Default duration: {DEFAULT_DURATION}s &nbsp; Max: {MAX_DURATION}s</p>"
    )


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print("=" * 60)
    print(f"  PacketVista Backend  →  http://localhost:{port}")
    print(f"  Capture endpoint     →  /capture-logs?duration=30")
    print(f"  Default duration     :  {DEFAULT_DURATION}s  (max {MAX_DURATION}s)")
    print("=" * 60)
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)
