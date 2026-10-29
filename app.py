import csv
import hmac
import io
import ipaddress
import os
import platform
import re
import subprocess
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

from flask import Flask, Response, jsonify, render_template_string, request

app = Flask(__name__)

USER = os.environ.get("APP_USER", "admin")
PASSWORD = os.environ.get("APP_PASSWORD")  # required
MAX_HOSTS = 1024
MAX_THREADS = 50
IS_WIN = platform.system() == "Windows"
HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.\-]{0,252}$")  # no leading "-"
JOBS = {}


@app.before_request
def require_login():
    if not PASSWORD:
        return Response("Server error: APP_PASSWORD is not set.", 500)
    a = request.authorization
    if not a or not hmac.compare_digest(a.username or "", USER) or \
            not hmac.compare_digest(a.password or "", PASSWORD):
        return Response("Login required", 401,
                        {"WWW-Authenticate": 'Basic realm="Ping Sweep"'})


def expand_targets(text):
    hosts = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if "/" in line:
            net = ipaddress.ip_network(line, strict=False)
            hosts.extend(str(h) for h in net.hosts())
        elif HOST_RE.match(line):
            hosts.append(line)
        else:
            raise ValueError(f"Invalid target: {line[:60]}")
        if len(hosts) > MAX_HOSTS:
            raise ValueError(f"Too many hosts (max {MAX_HOSTS}).")
    return list(dict.fromkeys(hosts))


def ping(host, timeout):
    if IS_WIN:
        cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), host]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, round(timeout))), host]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 3)
        if r.returncode == 0:
            m = re.search(r"time[=<]\s*([\d.]+)", r.stdout)
            return True, float(m.group(1)) if m else None
    except Exception:
        pass
    return False, None


def run_job(job, targets, timeout, threads):
    def work(host):
        if job["stop"]:
            return
        ok, ms = ping(host, timeout)
        job["results"].append({"host": host, "status": "up" if ok else "down", "ms": ms})
        job["done"] += 1

    with ThreadPoolExecutor(max_workers=threads) as ex:
        list(ex.map(work, targets))
    job["finished"] = True


@app.post("/api/scan")
def start_scan():
    data = request.get_json(force=True)
    try:
        targets = expand_targets(data.get("targets", ""))
        timeout = min(max(float(data.get("timeout", 1)), 0.5), 5)
        threads = min(max(int(data.get("threads", 20)), 1), MAX_THREADS)
    except (ValueError, TypeError) as e:
        return jsonify(error=str(e)), 400
    if not targets:
        return jsonify(error="No targets given."), 400
    job_id = uuid.uuid4().hex
    job = {"total": len(targets), "done": 0, "results": [], "stop": False,
           "finished": False, "started": time.time()}
    JOBS[job_id] = job
    threading.Thread(target=run_job, args=(job, targets, timeout, threads), daemon=True).start()
    return jsonify(id=job_id, total=len(targets))


@app.get("/api/status/<job_id>")
def status(job_id):
    job = JOBS.get(job_id)
    if not job:
        return jsonify(error="Unknown job"), 404
    return jsonify(total=job["total"], done=job["done"], finished=job["finished"],
                   results=job["results"])


@app.post("/api/stop/<job_id>")
def stop(job_id):
    if job_id in JOBS:
        JOBS[job_id]["stop"] = True
    return jsonify(ok=True)


@app.get("/api/export/<job_id>.csv")
def export(job_id):
    job = JOBS.get(job_id)
    if not job:
        return "Unknown job", 404
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["host", "status", "latency_ms"])
    for r in job["results"]:
        w.writerow([r["host"], r["status"], r["ms"] if r["ms"] is not None else ""])
    return Response(buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=ping_results.csv"})


@app.get("/")
def index():
    return render_template_string(PAGE)


PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Network Ping Sweep</title>
<style>
  body{font-family:system-ui,sans-serif;background:#f1f3f8;margin:0;color:#1c2333}
  main{max-width:1000px;margin:0 auto;padding:24px}
  h1{margin:0 0 4px} .sub{color:#667;margin-bottom:20px}
  .grid{display:grid;grid-template-columns:2fr 1fr;gap:16px}
  @media(max-width:700px){.grid{grid-template-columns:1fr}}
  .card{background:#fff;border-radius:8px;padding:16px;box-shadow:0 1px 3px #0001}
  textarea{width:100%;height:180px;box-sizing:border-box;font-family:monospace;padding:8px}
  input[type=number]{width:100%;box-sizing:border-box;padding:6px;margin-bottom:10px}
  button{width:100%;padding:10px;border:0;border-radius:6px;font-weight:600;cursor:pointer;margin-top:8px}
  #run{background:#2563eb;color:#fff} #stop{background:#ddd} #exp{background:#1c2333;color:#fff}
  progress{width:100%;margin-top:12px} table{width:100%;border-collapse:collapse;margin-top:8px}
  th,td{text-align:left;padding:6px 8px;border-bottom:1px solid #eee}
  .up{color:#15803d;font-weight:600} .down{color:#b91c1c}
  .stats span{margin-right:16px}
</style></head><body><main>
<h1>Network Ping Sweep</h1>
<div class="sub">Multithreaded host detection tool</div>
<div class="grid">
  <div class="card">
    <b>Scan targets</b> <small>(one IP, hostname, or CIDR per line)</small>
    <textarea id="targets">8.8.8.8
1.1.1.1
example.com</textarea>
    <progress id="bar" value="0" max="1"></progress>
    <div id="msg">Ready to scan.</div>
  </div>
  <div class="card">
    <b>Settings</b><br><br>
    <label>Ping timeout (sec)</label><input id="timeout" type="number" value="1" step="0.5" min="0.5" max="5">
    <label>Concurrent threads</label><input id="threads" type="number" value="20" min="1" max="50">
    <button id="run">Run sweep</button>
    <button id="stop" disabled>Stop scan</button>
    <button id="exp" disabled>Export CSV</button>
  </div>
</div>
<div class="card" style="margin-top:16px">
  <div class="stats"><b>Results</b> &nbsp; <span>Up: <b id="up">0</b></span><span>Down: <b id="down">0</b></span></div>
  <table><thead><tr><th>Host</th><th>Status</th><th>Latency</th></tr></thead><tbody id="rows"></tbody></table>
</div>
</main>
<script>
let job = null, timer = null;
const $ = id => document.getElementById(id);

$("run").onclick = async () => {
  $("rows").innerHTML = ""; $("up").textContent = $("down").textContent = 0;
  const res = await fetch("/api/scan", {method:"POST", headers:{"Content-Type":"application/json"},
    body: JSON.stringify({targets:$("targets").value, timeout:$("timeout").value, threads:$("threads").value})});
  const data = await res.json();
  if (!res.ok) { $("msg").textContent = data.error; return; }
  job = data.id; $("run").disabled = true; $("stop").disabled = false; $("exp").disabled = true;
  timer = setInterval(poll, 1000);
};
$("stop").onclick = () => fetch("/api/stop/" + job, {method:"POST"});
$("exp").onclick = () => location = "/api/export/" + job + ".csv";

async function poll() {
  const d = await (await fetch("/api/status/" + job)).json();
  $("bar").max = d.total; $("bar").value = d.done;
  $("msg").textContent = `Scanned ${d.done} / ${d.total}`;
  const rs = d.results.slice().sort((a,b) => a.host.localeCompare(b.host, undefined, {numeric:true}));
  $("rows").innerHTML = rs.map(r => `<tr><td>${r.host}</td><td class="${r.status}">${r.status.toUpperCase()}</td><td>${r.ms ?? "-"}${r.ms!=null?" ms":""}</td></tr>`).join("");
  $("up").textContent = rs.filter(r => r.status === "up").length;
  $("down").textContent = rs.filter(r => r.status === "down").length;
  if (d.finished) {
    clearInterval(timer); $("run").disabled = false; $("stop").disabled = true; $("exp").disabled = false;
    $("msg").textContent = "Scan complete.";
  }
}
</script></body></html>
"""

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000)
