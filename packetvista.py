"""
=============================================================================
Packet Vista - Network Security Monitor
=============================================================================
INSTALLATION:
    pip install scapy requests

LIVE CAPTURE (optional):
    1. Install Npcap: https://npcap.com  (tick WinPcap-compatible mode)
    2. Run as Administrator

SIMULATION MODE works without Npcap or admin rights.
=============================================================================
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import queue
import time
import random
import ipaddress
from collections import defaultdict, deque
from datetime import datetime

# --- Optional imports ---
try:
    import requests
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, conf, get_if_list
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False


# =============================================================================
# CONSTANTS
# =============================================================================

SUSPICIOUS_PORTS = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet",
    25: "SMTP", 135: "MS-RPC", 139: "NetBIOS", 445: "SMB",
    1433: "MSSQL", 3306: "MySQL", 3389: "RDP",
    4444: "Metasploit", 5900: "VNC", 6667: "IRC",
}

# Detection thresholds
PS_PORTS   = 12    # distinct ports in window = port scan
PS_WINDOW  = 10    # seconds
SF_COUNT   = 40    # SYN packets in window = flood
SF_WINDOW  = 5     # seconds
RC_COUNT   = 15    # repeat connections in window
RC_WINDOW  = 5     # seconds

TABLE_MAX  = 500
REFRESH_MS = 200   # GUI poll interval


# =============================================================================
# UTILITIES
# =============================================================================

def ts():
    return datetime.now().strftime("%H:%M:%S")

def is_public(ip):
    try:
        a = ipaddress.ip_address(ip)
        return not (a.is_private or a.is_loopback or a.is_link_local
                    or a.is_multicast or a.is_reserved or a.is_unspecified)
    except ValueError:
        return False


# =============================================================================
# GEO LOCATOR
# =============================================================================

class GeoLocator:
    def __init__(self):
        self._cache = {}
        self._lock  = threading.Lock()

    def lookup_async(self, ip, done_cb):
        threading.Thread(target=self._work, args=(ip, done_cb), daemon=True).start()

    def _work(self, ip, done_cb):
        if not is_public(ip):
            done_cb(ip, "Private")
            return
        with self._lock:
            if ip in self._cache:
                done_cb(ip, self._cache[ip])
                return
        result = self._fetch(ip)
        with self._lock:
            self._cache[ip] = result
        done_cb(ip, result)

    def _fetch(self, ip):
        if not REQUESTS_OK:
            return "N/A"
        try:
            r = requests.get(f"http://ip-api.com/json/{ip}?fields=country,status", timeout=3)
            d = r.json()
            if d.get("status") == "success":
                return d.get("country", "Unknown")
        except Exception:
            pass
        return "Unknown"


# =============================================================================
# DETECTION ENGINE
# =============================================================================

class DetectionEngine:
    def __init__(self, alert_cb):
        self._cb   = alert_cb
        self._lock = threading.Lock()

        self._scan_dq   = defaultdict(deque)  # ip -> [(ts, port)]
        self._syn_dq    = defaultdict(deque)  # ip -> [ts]
        self._rep_dq    = defaultdict(deque)  # (ip,port) -> [ts]

        self._alerted_scan = set()
        self._alerted_syn  = set()
        self._alerted_rep  = set()

        self.c_scan = 0
        self.c_syn  = 0
        self.c_susp = 0
        self.c_rep  = 0

    def process(self, src, dst, proto, sport, dport, flags):
        now = time.time()
        with self._lock:
            self._susp(src, dst, dport)
            if proto == "TCP":
                self._syn_flood(src, flags, now)
                self._port_scan(src, dport, now)
                self._repeat(src, dport, now)

    def counters(self):
        with self._lock:
            return (self.c_scan, self.c_syn, self.c_susp, self.c_rep)

    def _susp(self, src, dst, port):
        if port in SUSPICIOUS_PORTS:
            self.c_susp += 1
            self._cb("SUSPICIOUS PORT", src,
                     f"Port {port} ({SUSPICIOUS_PORTS[port]})  {src} -> {dst}")

    def _syn_flood(self, src, flags, now):
        if "S" not in str(flags):
            return
        dq = self._syn_dq[src]
        dq.append(now)
        cut = now - SF_WINDOW
        while dq and dq[0] < cut:
            dq.popleft()
        if len(dq) >= SF_COUNT:
            if src not in self._alerted_syn:
                self._alerted_syn.add(src)
                self.c_syn += 1
                self._cb("SYN FLOOD", src,
                         f"{len(dq)} SYN pkts from {src} in {SF_WINDOW}s")
        else:
            self._alerted_syn.discard(src)

    def _port_scan(self, src, port, now):
        dq = self._scan_dq[src]
        dq.append((now, port))
        cut = now - PS_WINDOW
        while dq and dq[0][0] < cut:
            dq.popleft()
        distinct = len({p for _, p in dq})
        if distinct >= PS_PORTS:
            if src not in self._alerted_scan:
                self._alerted_scan.add(src)
                self.c_scan += 1
                self._cb("PORT SCAN", src,
                         f"{src} hit {distinct} ports in {PS_WINDOW}s")
        else:
            self._alerted_scan.discard(src)

    def _repeat(self, src, port, now):
        key = (src, port)
        dq  = self._rep_dq[key]
        dq.append(now)
        cut = now - RC_WINDOW
        while dq and dq[0] < cut:
            dq.popleft()
        if len(dq) >= RC_COUNT:
            if key not in self._alerted_rep:
                self._alerted_rep.add(key)
                self.c_rep += 1
                self._cb("REPEAT CONN", src,
                         f"{src} -> port {port}  x{len(dq)} in {RC_WINDOW}s")
        else:
            self._alerted_rep.discard(key)


# =============================================================================
# LIVE CAPTURE ENGINE
# =============================================================================

class LiveCapture:
    def __init__(self, pkt_q):
        self._q    = pkt_q
        self._stop = threading.Event()

    def start(self):
        self._stop.clear()
        threading.Thread(target=self._run, daemon=True).start()

    def stop(self):
        self._stop.set()

    def _run(self):
        # Try to pick the best interface automatically
        iface = self._best_iface()
        try:
            kwargs = dict(prn=self._handle, store=False,
                          stop_filter=lambda _: self._stop.is_set())
            if iface:
                kwargs["iface"] = iface
            sniff(**kwargs)
        except Exception as e:
            self._q.put({"t": "err", "msg": str(e)})

    def _best_iface(self):
        """Pick first non-loopback interface Scapy can see."""
        if not SCAPY_OK:
            return None
        try:
            ifaces = get_if_list()
            for i in ifaces:
                if "loopback" not in i.lower() and "lo" != i.lower():
                    return i
        except Exception:
            pass
        return None

    def _handle(self, pkt):
        try:
            if IP not in pkt:
                return
            proto = "OTHER"
            sp = dp = 0
            fl = ""
            if TCP in pkt:
                proto = "TCP"
                sp    = pkt[TCP].sport
                dp    = pkt[TCP].dport
                fl    = str(pkt[TCP].flags)
            elif UDP in pkt:
                proto = "UDP"
                sp    = pkt[UDP].sport
                dp    = pkt[UDP].dport
            elif ICMP in pkt:
                proto = "ICMP"
            self._q.put({
                "t": "pkt",
                "src": pkt[IP].src, "dst": pkt[IP].dst,
                "proto": proto, "sp": sp, "dp": dp,
                "fl": fl, "len": len(pkt),
            })
        except Exception:
            pass


# =============================================================================
# SIMULATION ENGINE
# =============================================================================

class SimEngine:
    """
    Generates fake packets entirely in memory.
    Uses its own thread + a queue — guaranteed to work without Npcap.
    """
    _SRCS = [
        "203.0.113.10", "198.51.100.5", "185.220.101.34",
        "91.108.4.200",  "104.21.30.1",  "45.33.32.156",
        "192.0.2.77",    "8.8.8.8",      "1.1.1.1",
    ]
    _DSTS = ["10.0.0.1", "10.0.0.2", "192.168.1.100"]

    def __init__(self, pkt_q):
        self._q    = pkt_q
        self._stop = threading.Event()
        self._tick = 0

    def start(self):
        self._stop.clear()
        t = threading.Thread(target=self._loop, daemon=True)
        t.start()

    def stop(self):
        self._stop.set()

    def _loop(self):
        while not self._stop.is_set():
            self._tick += 1
            # Normal traffic burst
            for _ in range(random.randint(3, 8)):
                self._normal()
            # Inject attack patterns on schedule
            if self._tick % 5  == 0: self._inject_susp_port()
            if self._tick % 7  == 0: self._inject_port_scan()
            if self._tick % 10 == 0: self._inject_syn_flood()
            if self._tick % 8  == 0: self._inject_repeat()
            time.sleep(0.3)

    def _emit(self, src, dst, proto, sp, dp, fl=""):
        try:
            self._q.put_nowait({
                "t": "pkt",
                "src": src, "dst": dst,
                "proto": proto, "sp": sp, "dp": dp,
                "fl": fl, "len": random.randint(40, 1500),
            })
        except queue.Full:
            pass

    def _normal(self):
        src   = random.choice(self._SRCS)
        dst   = random.choice(self._DSTS)
        proto = random.choice(["TCP", "TCP", "UDP", "ICMP"])
        if proto == "TCP":
            self._emit(src, dst, "TCP",
                       random.randint(1024, 65535),
                       random.choice([80, 443, 8080, 53, 8443]), "PA")
        elif proto == "UDP":
            self._emit(src, dst, "UDP",
                       random.randint(1024, 65535),
                       random.choice([53, 123, 161, 5353]))
        else:
            self._emit(src, dst, "ICMP", 0, 0)

    def _inject_susp_port(self):
        src  = random.choice(self._SRCS)
        dst  = random.choice(self._DSTS)
        port = random.choice(list(SUSPICIOUS_PORTS.keys()))
        self._emit(src, dst, "TCP", random.randint(1024, 65535), port, "S")

    def _inject_port_scan(self):
        src  = random.choice(self._SRCS)
        dst  = self._DSTS[0]
        ports = random.sample(range(1, 1025), PS_PORTS + 3)
        for p in ports:
            self._emit(src, dst, "TCP", random.randint(1024, 65535), p, "S")

    def _inject_syn_flood(self):
        src = random.choice(self._SRCS)
        dst = self._DSTS[1]
        for _ in range(SF_COUNT + 15):
            self._emit(src, dst, "TCP", random.randint(1024, 65535), 80, "S")

    def _inject_repeat(self):
        src = random.choice(self._SRCS)
        dst = self._DSTS[2]
        for _ in range(RC_COUNT + 5):
            self._emit(src, dst, "TCP", random.randint(1024, 65535), 443, "S")


# =============================================================================
# MAIN APPLICATION
# =============================================================================

class PacketVista(tk.Tk):

    def __init__(self):
        super().__init__()
        self.title("Packet Vista - Network Security Monitor")
        self.geometry("1280x780")
        self.minsize(960, 600)
        self.configure(bg="#181f2e")

        self._q        = queue.Queue(maxsize=20000)
        self._geo      = GeoLocator()
        self._engine   = DetectionEngine(self._on_alert)
        self._live     = LiveCapture(self._q)
        self._sim      = SimEngine(self._q)

        self._running  = False
        self._use_sim  = tk.BooleanVar(value=True)   # Simulation ON by default

        self._total    = 0
        self._rate_dq  = deque()
        self._row_n    = 0

        self._build()
        self.after(REFRESH_MS, self._poll)
        self.protocol("WM_DELETE_WINDOW", self._close)

    # -------------------------------------------------------------------------
    # BUILD UI
    # -------------------------------------------------------------------------

    def _build(self):
        self._build_header()
        self._build_toolbar()
        self._build_body()

    def _build_header(self):
        f = tk.Frame(self, bg="#0e1420", pady=10)
        f.pack(fill=tk.X)
        tk.Label(f, text="Packet Vista",
                 font=("Consolas", 16, "bold"),
                 bg="#0e1420", fg="#d8eaf8").pack(side=tk.LEFT, padx=16)
        tk.Label(f, text="Network Security Monitor  |  Real-Time Packet Dashboard",
                 font=("Consolas", 9),
                 bg="#0e1420", fg="#4a6680").pack(side=tk.LEFT)

    def _build_toolbar(self):
        f = tk.Frame(self, bg="#1e2b3c", pady=8, padx=12)
        f.pack(fill=tk.X)

        self._btn_start = tk.Button(
            f, text="  Start Capture  ",
            font=("Consolas", 10, "bold"),
            bg="#1e6b3a", fg="#ffffff",
            activebackground="#28a050",
            relief=tk.FLAT, pady=5,
            command=self._start)
        self._btn_start.pack(side=tk.LEFT, padx=(0, 6))

        self._btn_stop = tk.Button(
            f, text="  Stop Capture  ",
            font=("Consolas", 10, "bold"),
            bg="#6b1e1e", fg="#ffffff",
            activebackground="#a02828",
            relief=tk.FLAT, pady=5,
            state=tk.DISABLED,
            command=self._stop)
        self._btn_stop.pack(side=tk.LEFT, padx=(0, 20))

        self._chk = tk.Checkbutton(
            f, text="Simulation Mode",
            font=("Consolas", 10),
            bg="#1e2b3c", fg="#b0c8e0",
            selectcolor="#0e1420",
            activebackground="#1e2b3c",
            activeforeground="#d8eaf8",
            variable=self._use_sim)
        self._chk.pack(side=tk.LEFT, padx=(0, 20))

        self._lbl_status = tk.Label(
            f, text="Status: Idle",
            font=("Consolas", 10),
            bg="#1e2b3c", fg="#4a6680")
        self._lbl_status.pack(side=tk.LEFT, padx=(0, 24))

        self._lbl_rate = tk.Label(
            f, text="0.0 pkt/s",
            font=("Consolas", 11, "bold"),
            bg="#1e2b3c", fg="#38b8e0")
        self._lbl_rate.pack(side=tk.LEFT)

        self._lbl_total = tk.Label(
            f, text="  |  Total: 0",
            font=("Consolas", 10),
            bg="#1e2b3c", fg="#4a6680")
        self._lbl_total.pack(side=tk.LEFT, padx=6)

    def _build_body(self):
        body = tk.Frame(self, bg="#181f2e")
        body.pack(fill=tk.BOTH, expand=True, padx=8, pady=6)

        # Left panel (fixed width)
        left = tk.Frame(body, bg="#181f2e", width=300)
        left.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 8))
        left.pack_propagate(False)
        self._build_counters(left)
        self._build_log(left)

        # Right panel (packet table)
        right = tk.Frame(body, bg="#181f2e")
        right.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self._build_table(right)

    def _build_counters(self, parent):
        frm = tk.LabelFrame(parent, text=" Attack Counters ",
                             font=("Consolas", 10, "bold"),
                             bg="#1e2b3c", fg="#b0c8e0",
                             relief=tk.GROOVE, bd=2,
                             padx=14, pady=12)
        frm.pack(fill=tk.X, pady=(0, 8))

        rows = [
            ("Port Scans Detected:",  "scan", "#e8c040"),
            ("SYN Floods Detected:",  "syn",  "#e86030"),
            ("Suspicious Port Hits:", "susp", "#e83060"),
            ("Repeat Conn Alerts:",   "rep",  "#9060e8"),
        ]
        self._cv = {}
        for i, (lbl, key, color) in enumerate(rows):
            tk.Label(frm, text=lbl, font=("Consolas", 9),
                     bg="#1e2b3c", fg="#6a8aaa", anchor="w"
                     ).grid(row=i, column=0, sticky="w", pady=5)
            v = tk.StringVar(value="0")
            self._cv[key] = v
            tk.Label(frm, textvariable=v,
                     font=("Consolas", 15, "bold"),
                     bg="#1e2b3c", fg=color,
                     width=5, anchor="e"
                     ).grid(row=i, column=1, sticky="e", padx=(10, 0))
        frm.columnconfigure(1, weight=1)

    def _build_log(self, parent):
        frm = tk.LabelFrame(parent, text=" Alert Log ",
                             font=("Consolas", 10, "bold"),
                             bg="#1e2b3c", fg="#b0c8e0",
                             relief=tk.GROOVE, bd=2,
                             padx=4, pady=4)
        frm.pack(fill=tk.BOTH, expand=True)

        self._log = scrolledtext.ScrolledText(
            frm,
            font=("Consolas", 8),
            bg="#0a1018", fg="#c8dce8",
            insertbackground="#c8dce8",
            state=tk.DISABLED,
            wrap=tk.WORD, relief=tk.FLAT)
        self._log.pack(fill=tk.BOTH, expand=True)

        self._log.tag_configure("PORT SCAN",       foreground="#e8c040")
        self._log.tag_configure("SYN FLOOD",       foreground="#e86030")
        self._log.tag_configure("SUSPICIOUS PORT", foreground="#e83060")
        self._log.tag_configure("REPEAT CONN",     foreground="#9060e8")
        self._log.tag_configure("ts",              foreground="#334455")

    def _build_table(self, parent):
        hdr = tk.Frame(parent, bg="#181f2e")
        hdr.pack(fill=tk.X, pady=(0, 4))
        tk.Label(hdr, text="Live Packet Feed",
                 font=("Consolas", 11, "bold"),
                 bg="#181f2e", fg="#b0c8e0").pack(side=tk.LEFT)
        tk.Label(hdr, text=f"  (last {TABLE_MAX} packets shown)",
                 font=("Consolas", 9),
                 bg="#181f2e", fg="#334455").pack(side=tk.LEFT)

        tf = tk.Frame(parent, bg="#181f2e")
        tf.pack(fill=tk.BOTH, expand=True)

        cols = ("time","src","dst","proto","sport","dport","flags","bytes","country","alert")
        self._tree = ttk.Treeview(tf, columns=cols, show="headings", selectmode="browse")

        spec = {
            "time":   ("Time",       78,  "center"),
            "src":    ("Source IP",  128, "w"),
            "dst":    ("Dest IP",    128, "w"),
            "proto":  ("Proto",      54,  "center"),
            "sport":  ("SrcPort",    66,  "center"),
            "dport":  ("DstPort",    66,  "center"),
            "flags":  ("Flags",      54,  "center"),
            "bytes":  ("Bytes",      58,  "center"),
            "country":("Country",    100, "w"),
            "alert":  ("Alert",      190, "w"),
        }
        for col, (h, w, a) in spec.items():
            self._tree.heading(col, text=h)
            self._tree.column(col, width=w, anchor=a, stretch=False)

        vsb = ttk.Scrollbar(tf, orient=tk.VERTICAL,   command=self._tree.yview)
        hsb = ttk.Scrollbar(tf, orient=tk.HORIZONTAL, command=self._tree.xview)
        self._tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self._tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        tf.rowconfigure(0, weight=1)
        tf.columnconfigure(0, weight=1)

        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("Treeview",
            background="#10161f", foreground="#b8ccdc",
            fieldbackground="#10161f", rowheight=23,
            font=("Consolas", 9))
        style.configure("Treeview.Heading",
            background="#1e2b3c", foreground="#6a8aaa",
            font=("Consolas", 9, "bold"))
        style.map("Treeview", background=[("selected", "#1e3c5a")])

        self._tree.tag_configure("even",  background="#10161f")
        self._tree.tag_configure("odd",   background="#151c2a")
        self._tree.tag_configure("susp",  background="#2a0d16")
        self._tree.tag_configure("scan",  background="#2a2008")
        self._tree.tag_configure("syn",   background="#2a1008")
        self._tree.tag_configure("rep",   background="#160828")

    # -------------------------------------------------------------------------
    # CAPTURE CONTROL
    # -------------------------------------------------------------------------

    def _start(self):
        if self._running:
            return

        use_sim = self._use_sim.get()

        if not use_sim and not SCAPY_OK:
            messagebox.showerror(
                "Scapy Not Found",
                "Scapy is not installed.\n\n"
                "Fix:  pip install scapy\n\n"
                "Also install Npcap from https://npcap.com/\n"
                "and run as Administrator.\n\n"
                "Or enable Simulation Mode to demo without Npcap.")
            return

        self._running = True
        self._btn_start.config(state=tk.DISABLED)
        self._btn_stop.config(state=tk.NORMAL)
        self._chk.config(state=tk.DISABLED)   # lock checkbox while running

        if use_sim:
            self._lbl_status.config(text="Status: Running (Simulation)", fg="#38b8e0")
            self._sim.start()
        else:
            self._lbl_status.config(text="Status: Running (Live)", fg="#38e888")
            self._live.start()

    def _stop(self):
        if not self._running:
            return
        self._running = False
        self._sim.stop()
        self._live.stop()
        self._btn_start.config(state=tk.NORMAL)
        self._btn_stop.config(state=tk.DISABLED)
        self._chk.config(state=tk.NORMAL)
        self._lbl_status.config(text="Status: Stopped", fg="#4a6680")

    # -------------------------------------------------------------------------
    # ALERT CALLBACK  (called from DetectionEngine, possibly background thread)
    # -------------------------------------------------------------------------

    def _on_alert(self, atype, src, detail):
        try:
            self._q.put_nowait({"t": "alert", "atype": atype, "detail": detail})
        except queue.Full:
            pass

    # -------------------------------------------------------------------------
    # MAIN POLL LOOP  (runs on Tkinter main thread via after())
    # -------------------------------------------------------------------------

    def _poll(self):
        try:
            self._drain()
            self._refresh_counters()
            self._refresh_rate()
        except Exception:
            pass   # Never let the poll loop die
        finally:
            self.after(REFRESH_MS, self._poll)

    def _drain(self):
        """Process up to 300 items from the queue per tick."""
        for _ in range(300):
            try:
                item = self._q.get_nowait()
            except queue.Empty:
                break
            t = item.get("t")
            if t == "pkt":
                self._handle_pkt(item)
            elif t == "alert":
                self._handle_alert(item)
            elif t == "err":
                messagebox.showerror("Capture Error", item.get("msg", "Unknown error"))
                self._stop()

    # -------------------------------------------------------------------------
    # PACKET HANDLING
    # -------------------------------------------------------------------------

    def _handle_pkt(self, item):
        src   = item["src"]
        dst   = item["dst"]
        proto = item["proto"]
        sp    = item["sp"]
        dp    = item["dp"]
        fl    = item.get("fl", "")
        blen  = item.get("len", 0)

        # Run detection (may enqueue alert items)
        self._engine.process(src, dst, proto, sp, dp, fl)

        # Choose row tag
        if dp in SUSPICIOUS_PORTS:
            tag        = "susp"
            alert_text = "SUSPICIOUS: " + SUSPICIOUS_PORTS[dp]
        else:
            tag        = "even" if self._row_n % 2 == 0 else "odd"
            alert_text = ""

        self._total   += 1
        self._row_n   += 1
        self._rate_dq.append(time.time())

        iid = self._tree.insert("", tk.END,
            values=(
                ts(),
                src, dst, proto,
                sp if sp else "",
                dp if dp else "",
                fl, blen,
                "",          # country filled async
                alert_text,
            ),
            tags=(tag,))

        # Trim old rows
        kids = self._tree.get_children()
        if len(kids) > TABLE_MAX:
            for old in kids[:len(kids) - TABLE_MAX]:
                self._tree.delete(old)

        self._tree.yview_moveto(1.0)
        self._lbl_total.config(text=f"  |  Total: {self._total}")

        # Async geo lookup — result written back on main thread
        self._geo.lookup_async(
            src,
            lambda ip, country, i=iid: self.after(0, self._set_country, i, country))

    def _set_country(self, iid, country):
        try:
            if self._tree.exists(iid):
                self._tree.set(iid, "country", country)
        except tk.TclError:
            pass

    # -------------------------------------------------------------------------
    # ALERT LOG
    # -------------------------------------------------------------------------

    def _handle_alert(self, item):
        atype  = item["atype"]
        detail = item["detail"]
        self._log.config(state=tk.NORMAL)
        self._log.insert(tk.END, f"[{ts()}] ", "ts")
        self._log.insert(tk.END, f"[{atype}]  ", atype)
        self._log.insert(tk.END, detail + "\n")
        self._log.see(tk.END)
        self._log.config(state=tk.DISABLED)

    # -------------------------------------------------------------------------
    # COUNTER + RATE REFRESH
    # -------------------------------------------------------------------------

    def _refresh_counters(self):
        s, y, sp, r = self._engine.counters()
        self._cv["scan"].set(str(s))
        self._cv["syn"].set(str(y))
        self._cv["susp"].set(str(sp))
        self._cv["rep"].set(str(r))

    def _refresh_rate(self):
        now = time.time()
        cut = now - 3.0
        while self._rate_dq and self._rate_dq[0] < cut:
            self._rate_dq.popleft()
        rate = len(self._rate_dq) / 3.0
        self._lbl_rate.config(text=f"{rate:.1f} pkt/s")

    # -------------------------------------------------------------------------
    # CLOSE
    # -------------------------------------------------------------------------

    def _close(self):
        self._stop()
        self.destroy()


# =============================================================================
# ENTRY POINT
# =============================================================================

if __name__ == "__main__":
    app = PacketVista()
    app.mainloop()
