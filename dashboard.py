"""Local web dashboard (standard library only). Binds to 127.0.0.1; passwords are analyzed in
memory and never written to disk or logs. History (opt-in) keeps aggregate metadata only."""
import json
import sys
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from . import history
from .analyzer import analyze
from .suggestions import HYGIENE

HTML = r"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>PassGuard</title>
<style>
:root{--bg:#f6f7fb;--card:#fff;--tx:#1b1f2a;--mu:#667;--bd:#dde1ea}
@media(prefers-color-scheme:dark){:root{--bg:#12141a;--card:#1b1e27;--tx:#e8eaf0;--mu:#99a;--bd:#2c3040}}
body{margin:0;font:16px system-ui,sans-serif;background:var(--bg);color:var(--tx)}
main{max-width:760px;margin:auto;padding:16px}.card{background:var(--card);border:1px solid var(--bd);border-radius:12px;padding:16px;margin:12px 0}
input[type=password],input[type=text]{width:100%;box-sizing:border-box;padding:12px;font-size:16px;border-radius:8px;border:1px solid var(--bd);background:var(--bg);color:var(--tx)}
.bar{height:14px;border-radius:7px;background:var(--bd);overflow:hidden}.bar>div{height:100%;width:0;transition:width .25s}
.lbl{font-size:22px;font-weight:700}.mu{color:var(--mu);font-size:14px}ul{padding-left:20px}button{padding:8px 12px;border-radius:8px;border:1px solid var(--bd);background:var(--card);color:var(--tx)}
.row{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
</style></head><body><main>
<h1>PassGuard</h1><p class="mu">Analyzed locally on your machine. Use demo passwords, never real ones, for screenshots.</p>
<div class="card"><input id="pw" type="password" autocomplete="off" placeholder="Type a password to analyze">
<div class="row" style="margin-top:8px"><label><input type="checkbox" id="show"> Show</label>
<label><input type="checkbox" id="save"> Save safe aggregate stats</label></div>
<input id="ctx" type="text" style="margin-top:8px" placeholder="Optional context, comma-separated (name, pet, ...)"></div>
<div class="card"><div class="lbl" id="label">-</div><div class="mu" id="meta"></div>
<div class="bar" style="margin:8px 0"><div id="fill"></div></div>
<b>Weaknesses</b><ul id="finds"></ul><b>Suggestions</b><ul id="sugg"></ul><p class="mu" id="disc"></p></div>
<div class="card"><b>History (aggregate only)</b> <button id="clr">Clear</button><div id="hist" class="mu"></div></div>
<div class="card"><b>Password hygiene</b><ul id="hyg"></ul></div>
<script>
const $=id=>document.getElementById(id);const COL={"VERY WEAK":"#d33","WEAK":"#e8742a","MODERATE":"#e0b020","STRONG":"#5aa832","VERY STRONG":"#1f9d55"};
function fill(ul,items){ul.replaceChildren(...items.map(t=>{const li=document.createElement("li");li.textContent=t;return li}))}
let timer;
async function run(){const pw=$("pw").value;
 const r=await fetch("/api/analyze",{method:"POST",headers:{"Content-Type":"application/json"},
  body:JSON.stringify({password:pw,context:$("ctx").value.split(",").map(s=>s.trim()).filter(Boolean),save:$("save").checked&&pw.length>0})});
 const d=await r.json();$("label").textContent=d.label+" ("+d.score+"/100)";$("label").style.color=COL[d.label];
 $("fill").style.width=d.score+"%";$("fill").style.background=COL[d.label];
 $("meta").textContent=pw?`Length ${d.length} | pool ${d.pool} | naive ${d.bits_naive} bits -> adjusted ${d.bits_adjusted} bits`:"";
 fill($("finds"),d.findings.map(f=>"["+f.severity+"] "+f.message));fill($("sugg"),d.suggestions);$("disc").textContent=d.disclaimer||"";
 if($("save").checked&&pw)loadHist();}
async function loadHist(){const s=await (await fetch("/api/history")).json();
 $("hist").textContent=s.count?`${s.count} checks, avg score ${s.avg_score}. Labels: ${JSON.stringify(s.labels)}. Top flags: ${JSON.stringify(s.flags)}`:"No saved history.";}
$("pw").addEventListener("input",()=>{clearTimeout(timer);timer=setTimeout(run,200)});$("ctx").addEventListener("input",run);
$("show").onchange=e=>$("pw").type=e.target.checked?"text":"password";
$("clr").onclick=async()=>{await fetch("/api/history/clear",{method:"POST"});loadHist()};
fetch("/api/hygiene").then(r=>r.json()).then(h=>fill($("hyg"),h));loadHist();run();
</script></main></body></html>"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):          # silence request logging (never log anything user-related)
        pass

    def _host_ok(self):                    # blocks DNS-rebinding / cross-site calls to localhost
        host = (self.headers.get("Host") or "").split(":")[0]
        return host in ("127.0.0.1", "localhost")

    def _send(self, code, body, ctype="application/json"):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype + "; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if not self._host_ok(): return self._send(403, "{}")
        if self.path == "/": self._send(200, HTML, "text/html")
        elif self.path == "/api/history": self._send(200, json.dumps(history.summary()))
        elif self.path == "/api/hygiene": self._send(200, json.dumps(HYGIENE))
        else: self._send(404, "{}")

    def do_POST(self):
        if not self._host_ok(): return self._send(403, "{}")
        if self.path == "/api/history/clear":
            history.clear(); return self._send(200, "{}")
        if self.path != "/api/analyze": return self._send(404, "{}")
        try:
            size = min(int(self.headers.get("Content-Length", 0)), 10_000)
            body = json.loads(self.rfile.read(size) or b"{}")
            result = analyze(str(body.get("password", ""))[:256], [str(c) for c in body.get("context", [])][:10])
        except Exception:
            return self._send(400, '{"error":"bad request"}')
        if body.get("save"):
            history.record(result)
        self._send(200, json.dumps(result))


def serve(port=8765, open_browser=True):
    srv = HTTPServer(("127.0.0.1", port), Handler)
    url = f"http://127.0.0.1:{port}"
    print(f"PassGuard dashboard: {url}  (Ctrl+C to stop)")
    if open_browser:
        webbrowser.open(url)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    serve(int(sys.argv[1]) if len(sys.argv) > 1 else 8765)
