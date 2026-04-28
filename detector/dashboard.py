import psutil
from flask import Flask, jsonify, Response


def create_dashboard(engine):
    app = Flask(__name__)

    @app.route("/api/metrics")
    def api_metrics():
        data = engine.metrics()
        data["cpu_percent"] = psutil.cpu_percent(interval=None)
        data["memory_percent"] = psutil.virtual_memory().percent
        return jsonify(data)

    @app.route("/")
    def index():
        html = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>HNG Stage 3 Anomaly Detection Dashboard</title>
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <style>
    body { margin:0; font-family: Arial, sans-serif; background:#0f172a; color:#e5e7eb; }
    header { padding:24px; background:#111827; border-bottom:1px solid #334155; }
    h1 { margin:0; font-size:26px; }
    .sub { color:#94a3b8; margin-top:6px; }
    .grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(220px,1fr)); gap:16px; padding:20px; }
    .card { background:#111827; border:1px solid #334155; border-radius:16px; padding:18px; box-shadow:0 10px 30px rgba(0,0,0,.25); }
    .label { color:#94a3b8; font-size:13px; }
    .value { font-size:28px; font-weight:700; margin-top:8px; }
    table { width:100%; border-collapse:collapse; margin-top:10px; }
    th, td { padding:10px; border-bottom:1px solid #334155; text-align:left; font-size:14px; }
    th { color:#93c5fd; }
    .danger { color:#f87171; }
    .ok { color:#86efac; }
    .wide { grid-column:1/-1; }
    .bar { height:12px; background:#1e293b; border-radius:20px; overflow:hidden; margin-top:6px; }
    .bar span { display:block; height:100%; background:#38bdf8; }
    code { color:#fde68a; }
  </style>
</head>
<body>
<header>
  <h1>HNG Stage 3 Anomaly Detection Dashboard</h1>
  <div class="sub">Live metrics refresh every 3 seconds | Detector + Nginx + Nextcloud</div>
</header>

<section class="grid">
  <div class="card">
    <div class="label">Global Requests/Sec</div>
    <div class="value" id="global_rate">0</div>
  </div>
  <div class="card">
    <div class="label">Logs Processed</div>
    <div class="value" id="logs">0</div>
  </div>
  <div class="card">
    <div class="label">Banned IPs</div>
    <div class="value danger" id="banned_count">0</div>
  </div>
  <div class="card">
    <div class="label">Uptime</div>
    <div class="value" id="uptime">0s</div>
  </div>
  <div class="card">
    <div class="label">CPU Usage</div>
    <div class="value" id="cpu">0%</div>
    <div class="bar"><span id="cpu_bar" style="width:0%"></span></div>
  </div>
  <div class="card">
    <div class="label">Memory Usage</div>
    <div class="value" id="memory">0%</div>
    <div class="bar"><span id="memory_bar" style="width:0%"></span></div>
  </div>
  <div class="card wide">
    <h2>Effective Baseline</h2>
    <p>
      Mean: <code id="mean">0</code> |
      Stddev: <code id="std">0</code> |
      Source: <code id="source">loading</code> |
      Updated: <code id="updated">n/a</code>
    </p>
  </div>
  <div class="card wide">
    <h2>Top 10 Source IPs</h2>
    <table>
      <thead><tr><th>IP</th><th>Total Requests Seen</th></tr></thead>
      <tbody id="top_ips"></tbody>
    </table>
  </div>
  <div class="card wide">
    <h2>Banned IPs</h2>
    <table>
      <thead><tr><th>IP</th><th>Condition</th><th>Rate</th><th>Baseline</th><th>Duration</th><th>Banned At</th></tr></thead>
      <tbody id="banned_ips"></tbody>
    </table>
  </div>
  <div class="card wide">
    <h2>Baseline Graph: Hourly Slots</h2>
    <p class="sub">Use this section for Baseline-graph.png after at least two hourly slots are visible.</p>
    <table>
      <thead><tr><th>Hour UTC</th><th>Effective Mean</th><th>Points</th><th>Visual</th></tr></thead>
      <tbody id="hourly"></tbody>
    </table>
  </div>
</section>

<script>
function fmtUptime(s){
  let h=Math.floor(s/3600), m=Math.floor((s%3600)/60), sec=s%60;
  return `${h}h ${m}m ${sec}s`;
}
async function refresh(){
  try{
    const r = await fetch('/api/metrics');
    const d = await r.json();

    document.getElementById('global_rate').textContent = d.global_rate;
    document.getElementById('logs').textContent = d.logs_processed;
    document.getElementById('banned_count').textContent = d.banned_ips.length;
    document.getElementById('uptime').textContent = fmtUptime(d.uptime_seconds);

    document.getElementById('cpu').textContent = d.cpu_percent + '%';
    document.getElementById('memory').textContent = d.memory_percent + '%';
    document.getElementById('cpu_bar').style.width = d.cpu_percent + '%';
    document.getElementById('memory_bar').style.width = d.memory_percent + '%';

    document.getElementById('mean').textContent = Number(d.global_baseline.mean).toFixed(4);
    document.getElementById('std').textContent = Number(d.global_baseline.std).toFixed(4);
    document.getElementById('source').textContent = d.global_baseline.source;
    document.getElementById('updated').textContent = d.global_baseline.updated_at || 'n/a';

    document.getElementById('top_ips').innerHTML = d.top_ips.map(x =>
      `<tr><td>${x.ip}</td><td>${x.count}</td></tr>`
    ).join('') || '<tr><td colspan="2">No traffic yet</td></tr>';

    document.getElementById('banned_ips').innerHTML = d.banned_ips.map(x =>
      `<tr><td>${x.ip}</td><td>${x.condition}</td><td>${x.rate}</td><td>${x.baseline}</td><td>${x.duration === 0 ? 'permanent' : x.duration + 's'}</td><td>${x.banned_at}</td></tr>`
    ).join('') || '<tr><td colspan="6" class="ok">No banned IPs</td></tr>';

    document.getElementById('hourly').innerHTML = d.hourly_baseline.map(x => {
      let width = Math.min(100, Math.max(3, x.effective_mean * 60));
      return `<tr><td>${x.hour}:00</td><td>${x.effective_mean}</td><td>${x.points}</td><td><div class="bar"><span style="width:${width}%"></span></div></td></tr>`;
    }).join('') || '<tr><td colspan="4">Hourly baseline is still learning</td></tr>';

  }catch(e){ console.error(e); }
}
refresh();
setInterval(refresh, 3000);
</script>
</body>
</html>
"""
        return Response(html, mimetype="text/html")

    return app
