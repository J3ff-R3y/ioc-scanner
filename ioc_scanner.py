#!/usr/bin/env python3
"""
IOC Enrichment Scanner
Types: IP, domein, URL, MD5/SHA1/SHA256, e-mailadres
Bronnen: VirusTotal, AlienVault OTX, AbuseIPDB, URLScan.io, HaveIBeenPwned
Output: HTML dashboard + CSV
"""

import requests, csv, re, sys, os, time, hashlib, datetime, argparse
from pathlib import Path
from urllib.parse import quote, urlparse

# ─── Config — API keys via env vars ─────────────────────────────────────────
CFG = {
    "vt_key":      os.getenv("VT_API_KEY", ""),
    "abuse_key":   os.getenv("ABUSEIPDB_API_KEY", ""),
    "otx_key":     os.getenv("OTX_API_KEY", ""),
    "urlscan_key": os.getenv("URLSCAN_API_KEY", ""),
    "timeout":     15,
    "delay":       1.2,   # sec tussen calls (respect rate limits)
}

# ─── IOC type detectie ────────────────────────────────────────────────────────
def detect_type(v: str) -> str:
    v = v.strip()
    if re.fullmatch(r"[a-fA-F0-9]{32}", v): return "md5"
    if re.fullmatch(r"[a-fA-F0-9]{40}", v): return "sha1"
    if re.fullmatch(r"[a-fA-F0-9]{64}", v): return "sha256"
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", v): return "ip"
    if re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", v): return "email"
    if v.startswith("http://") or v.startswith("https://"): return "url"
    if re.fullmatch(r"[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}", v): return "domain"
    return "unknown"

# ─── API helpers ─────────────────────────────────────────────────────────────
def get(url, headers=None, params=None) -> dict | None:
    try:
        r = requests.get(url, headers=headers or {}, params=params,
                         timeout=CFG["timeout"])
        return r if r.status_code in (200, 404) else None
    except Exception:
        return None

# ─── VirusTotal ───────────────────────────────────────────────────────────────
def vt(ioc: str, ioc_type: str) -> dict:
    key = CFG["vt_key"]
    if not key:
        return {"source":"VirusTotal","error":"Geen API key (VT_API_KEY)"}
    hdrs = {"x-apikey": key}
    base = "https://www.virustotal.com/api/v3"
    if ioc_type in ("md5","sha1","sha256"):
        url = f"{base}/files/{ioc}"
    elif ioc_type == "ip":
        url = f"{base}/ip_addresses/{ioc}"
    elif ioc_type == "domain":
        url = f"{base}/domains/{ioc}"
    elif ioc_type == "url":
        url = f"{base}/urls/{hashlib.sha256(ioc.encode()).hexdigest()}"
    else:
        return {"source":"VirusTotal","error":f"Type '{ioc_type}' niet ondersteund"}

    r = get(url, hdrs)
    if r is None:
        return {"source":"VirusTotal","error":"Request mislukt"}
    if r.status_code == 404:
        return {"source":"VirusTotal","verdict":"NOT_FOUND","malicious":0,"suspicious":0}
    d = r.json().get("data",{}).get("attributes",{})
    s = d.get("last_analysis_stats",{})
    mal = s.get("malicious",0)
    sus = s.get("suspicious",0)
    return {
        "source":"VirusTotal",
        "malicious": mal, "suspicious": sus,
        "harmless": s.get("harmless",0), "undetected": s.get("undetected",0),
        "reputation": d.get("reputation",""),
        "tags": d.get("tags",[])[:6],
        "verdict": "MALICIOUS" if mal>2 else "SUSPICIOUS" if mal>0 or sus>2 else "CLEAN"
    }

# ─── AlienVault OTX ──────────────────────────────────────────────────────────
def otx(ioc: str, ioc_type: str) -> dict:
    hdrs = {"X-OTX-API-KEY": CFG["otx_key"]} if CFG["otx_key"] else {}
    tm = {"ip":"IPv4","domain":"domain","url":"url",
          "md5":"file","sha1":"file","sha256":"file","email":"email"}
    ot = tm.get(ioc_type)
    if not ot:
        return {"source":"AlienVault OTX","error":"Type niet ondersteund"}
    r = get(f"https://otx.alienvault.com/api/v1/indicators/{ot}/{quote(ioc,safe='')}/general", hdrs)
    if r is None:
        return {"source":"AlienVault OTX","error":"Request mislukt"}
    d = r.json()
    pc = d.get("pulse_info",{}).get("count",0)
    tags = list({t for p in d.get("pulse_info",{}).get("pulses",[])[:5] for t in p.get("tags",[])})[:8]
    return {
        "source":"AlienVault OTX",
        "pulse_count": pc,
        "tags": tags,
        "verdict": "MALICIOUS" if pc>3 else "SUSPICIOUS" if pc>0 else "CLEAN"
    }

# ─── AbuseIPDB ────────────────────────────────────────────────────────────────
def abuseipdb(ioc: str, ioc_type: str) -> dict:
    if ioc_type != "ip":
        return {"source":"AbuseIPDB","error":"Alleen IP-adressen"}
    key = CFG["abuse_key"]
    if not key:
        return {"source":"AbuseIPDB","error":"Geen API key (ABUSEIPDB_API_KEY)"}
    r = get("https://api.abuseipdb.com/api/v2/check",
            {"Key": key, "Accept": "application/json"},
            {"ipAddress": ioc, "maxAgeInDays": 90})
    if r is None:
        return {"source":"AbuseIPDB","error":"Request mislukt"}
    d = r.json().get("data",{})
    score = d.get("abuseConfidenceScore",0)
    return {
        "source":"AbuseIPDB",
        "abuse_score": score,
        "total_reports": d.get("totalReports",0),
        "country": d.get("countryCode",""),
        "isp": d.get("isp",""),
        "usage_type": d.get("usageType",""),
        "is_whitelisted": d.get("isWhitelisted",False),
        "last_reported": (d.get("lastReportedAt","") or "")[:10],
        "verdict": "MALICIOUS" if score>=75 else "SUSPICIOUS" if score>=25 else "CLEAN"
    }

# ─── URLScan.io ───────────────────────────────────────────────────────────────
def urlscan(ioc: str, ioc_type: str) -> dict:
    if ioc_type not in ("url","domain","ip"):
        return {"source":"URLScan.io","error":"Alleen URL/domein/IP"}
    hdrs = {"API-Key": CFG["urlscan_key"]} if CFG["urlscan_key"] else {}
    q = ioc if ioc_type != "url" else (urlparse(ioc).hostname or ioc)
    r = get("https://urlscan.io/api/v1/search/", hdrs, {"q":f"domain:{q}","size":5})
    if r is None:
        return {"source":"URLScan.io","error":"Request mislukt"}
    results = r.json().get("results",[])
    if not results:
        return {"source":"URLScan.io","verdict":"NOT_FOUND","scan_count":0}
    v = results[0].get("verdicts",{}).get("overall",{})
    score = v.get("score",0)
    return {
        "source":"URLScan.io",
        "scan_count": len(results),
        "malicious": v.get("malicious",False),
        "score": score,
        "categories": v.get("categories",[])[:4],
        "last_scan": (results[0].get("task",{}).get("time","") or "")[:10],
        "verdict": "MALICIOUS" if v.get("malicious") else "SUSPICIOUS" if score>50 else "CLEAN"
    }

# ─── HaveIBeenPwned (domein) ─────────────────────────────────────────────────
def hibp(ioc: str, ioc_type: str) -> dict:
    if ioc_type != "email":
        return {"source":"HaveIBeenPwned","error":"Alleen e-mailadressen"}
    domain = ioc.split("@")[-1]
    r = get(f"https://haveibeenpwned.com/api/v3/breacheddomain/{domain}",
            {"User-Agent":"IOC-Scanner"})
    if r is None:
        return {"source":"HaveIBeenPwned","error":"Request mislukt"}
    if r.status_code == 404:
        return {"source":"HaveIBeenPwned","domain_breached":False,"breach_count":0,"verdict":"CLEAN"}
    breaches = list(r.json().keys()) if isinstance(r.json(), dict) else []
    return {
        "source":"HaveIBeenPwned",
        "domain_breached": True,
        "breach_count": len(breaches),
        "breaches": breaches[:5],
        "verdict": "SUSPICIOUS" if breaches else "CLEAN"
    }

# ─── Hoofd enrichment ─────────────────────────────────────────────────────────
def enrich(ioc: str) -> dict:
    ioc = ioc.strip()
    ioc_type = detect_type(ioc)
    result = {
        "ioc": ioc, "type": ioc_type,
        "timestamp": datetime.datetime.utcnow().isoformat()+"Z",
        "enrichments": [], "overall_verdict": "UNKNOWN", "verdict_score": 0
    }
    if ioc_type == "unknown":
        return result

    checks = []
    for fn, types in [
        (vt,        None),
        (otx,       None),
        (abuseipdb, ["ip"]),
        (urlscan,   ["url","domain","ip"]),
        (hibp,      ["email"]),
    ]:
        if types is None or ioc_type in types:
            time.sleep(CFG["delay"])
            checks.append(fn(ioc, ioc_type))

    result["enrichments"] = checks
    verdicts = [c.get("verdict","") for c in checks if "verdict" in c]
    if "MALICIOUS"  in verdicts: result["overall_verdict"]="MALICIOUS";  result["verdict_score"]=3
    elif "SUSPICIOUS" in verdicts: result["overall_verdict"]="SUSPICIOUS"; result["verdict_score"]=2
    elif "CLEAN"    in verdicts: result["overall_verdict"]="CLEAN";     result["verdict_score"]=1
    return result

# ─── Output: CSV ─────────────────────────────────────────────────────────────
def save_csv(results: list, path: Path):
    fields = ["ioc","type","timestamp","overall_verdict",
              "vt_malicious","vt_suspicious","vt_verdict",
              "otx_pulses","otx_verdict",
              "abuseipdb_score","abuseipdb_verdict",
              "urlscan_verdict","hibp_breaches"]
    with open(path,"w",newline="",encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for r in results:
            row = {"ioc":r["ioc"],"type":r["type"],"timestamp":r["timestamp"],"overall_verdict":r["overall_verdict"]}
            for e in r.get("enrichments",[]):
                s = e.get("source","")
                if "VirusTotal"  in s: row.update({"vt_malicious":e.get("malicious",""),"vt_suspicious":e.get("suspicious",""),"vt_verdict":e.get("verdict","")})
                if "AlienVault"  in s: row.update({"otx_pulses":e.get("pulse_count",""),"otx_verdict":e.get("verdict","")})
                if "AbuseIPDB"   in s: row.update({"abuseipdb_score":e.get("abuse_score",""),"abuseipdb_verdict":e.get("verdict","")})
                if "URLScan"     in s: row["urlscan_verdict"] = e.get("verdict","")
                if "HaveIBeen"   in s: row["hibp_breaches"] = e.get("breach_count","")
            w.writerow(row)
    print(f"[+] CSV: {path}")

# ─── Output: HTML dashboard ──────────────────────────────────────────────────
def save_html(results: list, path: Path):
    ts = datetime.datetime.now().strftime("%d-%m-%Y %H:%M:%S")

    mal_c = sum(1 for r in results if r["overall_verdict"]=="MALICIOUS")
    sus_c = sum(1 for r in results if r["overall_verdict"]=="SUSPICIOUS")
    cln_c = sum(1 for r in results if r["overall_verdict"]=="CLEAN")
    unk_c = sum(1 for r in results if r["overall_verdict"]=="UNKNOWN")

    vc = lambda v: {"MALICIOUS":"mal","SUSPICIOUS":"sus","CLEAN":"clean","UNKNOWN":"unk","NOT_FOUND":"unk"}.get(v,"unk")
    vi = lambda v: {"MALICIOUS":"⛔","SUSPICIOUS":"⚠️","CLEAN":"✅","UNKNOWN":"❓","NOT_FOUND":"🔍"}.get(v,"❓")

    rows = ""
    cards = ""
    for r in results:
        v = r["overall_verdict"]
        c = vc(v)

        # Tabelrij
        cells = ""
        for src in ["VirusTotal","AlienVault OTX","AbuseIPDB","URLScan.io","HaveIBeenPwned"]:
            e = next((x for x in r["enrichments"] if src in x.get("source","")), None)
            if e and "verdict" in e:
                cells += f'<td><span class="vm {vc(e["verdict"])}">{vi(e["verdict"])}</span></td>'
            elif e and "error" in e:
                cells += '<td><span class="vm unk" title="Fout">⚙️</span></td>'
            else:
                cells += '<td><span class="vm unk">—</span></td>'

        rows += f"""<tr data-v="{v}">
          <td><code class="ioc-v">{r['ioc']}</code></td>
          <td><span class="badge-t">{r['type'].upper()}</span></td>
          <td><span class="vb {c}">{vi(v)} {v}</span></td>
          {cells}
          <td class="ts-c">{r['timestamp'][:19].replace('T',' ')}</td>
        </tr>"""

        # Detail cards
        enr_html = ""
        for e in r["enrichments"]:
            src = e.get("source","")
            ec = vc(e.get("verdict","UNKNOWN"))
            drows = ""
            for k, val in e.items():
                if k in ("source","verdict"): continue
                if k == "error":
                    drows += f'<div class="dr err">⚠ {val}</div>'; continue
                if isinstance(val, list): val = ", ".join(str(x) for x in val[:5]) or "—"
                if isinstance(val, bool): val = "Ja" if val else "Nee"
                drows += f'<div class="dr"><span class="dk">{k}</span><span class="dv">{val}</span></div>'
            enr_html += f'<div class="ec {ec}"><div class="eh"><span class="en">{src}</span><span class="vm {ec}">{vi(e.get("verdict","UNKNOWN"))}</span></div>{drows}</div>'

        cards += f"""<details class="ioc-det">
          <summary><span class="vb {c}">{vi(v)} {v}</span> <code>{r['ioc']}</code> <span class="badge-t">{r['type'].upper()}</span></summary>
          <div class="eg">{enr_html}</div>
        </details>"""

    html = f"""<!DOCTYPE html>
<html lang="nl">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>IOC Rapport</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Syne:wght@400;600;800&display=swap');
:root{{
  --bg:#080b12;--sf:#0e1220;--bd:#1a2035;
  --acc:#00e5ff;--acc2:#7c3aed;
  --mal:#ff3b5c;--sus:#f59e0b;--cln:#10b981;--unk:#6b7280;
  --txt:#e2e8f0;--mut:#64748b;
  --mono:'JetBrains Mono',monospace;--sans:'Syne',sans-serif;
}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:var(--bg);color:var(--txt);font-family:var(--sans);min-height:100vh;}}
body::before{{content:'';position:fixed;inset:0;pointer-events:none;z-index:999;
  background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,229,255,.008) 2px,rgba(0,229,255,.008) 4px);}}

/* Header */
header{{padding:2rem 2.5rem;border-bottom:1px solid var(--bd);position:relative;overflow:hidden;
  background:linear-gradient(135deg,#0a0e18,var(--bg));}}
header::after{{content:'SOC';position:absolute;right:2rem;top:50%;transform:translateY(-50%);
  font-size:5rem;font-weight:800;color:rgba(0,229,255,.04);font-family:var(--mono);pointer-events:none;}}
.logo{{font-family:var(--mono);font-size:.68rem;color:var(--acc);letter-spacing:.2em;text-transform:uppercase;margin-bottom:.4rem;}}
h1{{font-size:1.7rem;font-weight:800;color:#fff;}}
.meta{{font-size:.73rem;color:var(--mut);margin-top:.35rem;font-family:var(--mono);}}

/* Stats */
.stats{{display:grid;grid-template-columns:repeat(5,1fr);gap:1px;background:var(--bd);border-bottom:1px solid var(--bd);}}
.stat{{background:var(--sf);padding:1rem 1.5rem;}}
.sn{{font-size:2.2rem;font-weight:800;font-family:var(--mono);line-height:1;}}
.sl{{font-size:.62rem;text-transform:uppercase;letter-spacing:.12em;color:var(--mut);margin-top:.25rem;}}
.s-tot .sn{{color:var(--acc);}} .s-mal .sn{{color:var(--mal);}} .s-sus .sn{{color:var(--sus);}}
.s-cln .sn{{color:var(--cln);}} .s-unk .sn{{color:var(--unk);}}

/* Toolbar */
.toolbar{{padding:.8rem 2.5rem;background:var(--sf);border-bottom:1px solid var(--bd);display:flex;gap:.6rem;align-items:center;flex-wrap:wrap;}}
.toolbar input{{flex:1;max-width:280px;padding:.4rem .75rem;background:var(--bg);border:1px solid var(--bd);border-radius:5px;color:var(--txt);font-family:var(--mono);font-size:.78rem;outline:none;}}
.toolbar input:focus{{border-color:var(--acc);}}
.fb{{padding:.35rem .8rem;border:1px solid var(--bd);border-radius:5px;background:transparent;color:var(--mut);font-size:.72rem;cursor:pointer;font-family:var(--sans);transition:.12s;}}
.fb:hover,.fb.on{{background:var(--acc);color:#000;border-color:var(--acc);font-weight:600;}}
#tc{{margin-left:auto;font-size:.7rem;color:var(--mut);font-family:var(--mono);}}

/* Table */
.tw{{overflow-x:auto;}}
table{{width:100%;border-collapse:collapse;font-size:.79rem;}}
th{{background:#0a0e1a;color:#7891b8;padding:.55rem 1rem;text-align:left;font-size:.62rem;
  text-transform:uppercase;letter-spacing:.1em;white-space:nowrap;position:sticky;top:0;z-index:5;border-bottom:1px solid var(--bd);}}
td{{padding:.55rem 1rem;border-bottom:1px solid var(--bd);vertical-align:middle;}}
tr:hover td{{background:rgba(255,255,255,.022);}}
tr:last-child td{{border-bottom:none;}}
code.ioc-v{{font-family:var(--mono);color:var(--acc);font-size:.8rem;word-break:break-all;}}
.ts-c{{font-family:var(--mono);font-size:.7rem;color:var(--mut);white-space:nowrap;}}
.badge-t{{padding:.15rem .5rem;border-radius:4px;font-size:.65rem;font-weight:700;font-family:var(--mono);
  background:rgba(124,58,237,.2);color:#a78bfa;border:1px solid rgba(124,58,237,.3);}}

/* Verdict badges */
.vb{{display:inline-flex;align-items:center;gap:.3rem;padding:.2rem .65rem;border-radius:99px;font-size:.72rem;font-weight:700;font-family:var(--mono);white-space:nowrap;}}
.vm{{display:inline-flex;align-items:center;justify-content:center;width:1.6rem;height:1.6rem;border-radius:50%;font-size:.78rem;}}
.mal{{background:rgba(255,59,92,.15);color:var(--mal);border:1px solid rgba(255,59,92,.3);}}
.sus{{background:rgba(245,158,11,.15);color:var(--sus);border:1px solid rgba(245,158,11,.3);}}
.clean{{background:rgba(16,185,129,.15);color:var(--cln);border:1px solid rgba(16,185,129,.3);}}
.unk{{background:rgba(107,114,128,.15);color:var(--unk);border:1px solid rgba(107,114,128,.3);}}

/* Detail cards */
main{{padding:1.5rem 2.5rem 2.5rem;}}
section{{margin-bottom:2.5rem;}}
h2{{font-size:.85rem;font-weight:700;text-transform:uppercase;letter-spacing:.1em;color:var(--acc);margin-bottom:.9rem;}}
.ioc-det{{border:1px solid var(--bd);border-radius:7px;margin-bottom:.5rem;overflow:hidden;}}
.ioc-det summary{{display:flex;align-items:center;gap:.65rem;padding:.75rem 1.25rem;
  cursor:pointer;background:var(--sf);list-style:none;font-size:.83rem;}}
.ioc-det summary::-webkit-details-marker{{display:none;}}
.ioc-det summary:hover{{background:#111629;}}
.eg{{display:grid;grid-template-columns:repeat(auto-fill,minmax(230px,1fr));gap:.85rem;padding:1rem 1.25rem;background:#0a0c14;}}
.ec{{border:1px solid var(--bd);border-radius:6px;padding:.85rem;background:var(--sf);}}
.ec.mal{{border-color:rgba(255,59,92,.35);}} .ec.sus{{border-color:rgba(245,158,11,.35);}} .ec.clean{{border-color:rgba(16,185,129,.35);}}
.eh{{display:flex;justify-content:space-between;align-items:center;margin-bottom:.65rem;}}
.en{{font-weight:700;font-size:.77rem;color:#fff;}}
.dr{{display:flex;justify-content:space-between;gap:.4rem;padding:.18rem 0;font-size:.72rem;border-bottom:1px solid rgba(255,255,255,.04);}}
.dr:last-child{{border-bottom:none;}}
.dk{{color:var(--mut);font-family:var(--mono);flex-shrink:0;}}
.dv{{color:var(--txt);text-align:right;word-break:break-all;}}
.err{{color:var(--sus);font-family:var(--mono);font-size:.7rem;justify-content:flex-start;}}

footer{{padding:1.25rem 2.5rem;border-top:1px solid var(--bd);font-size:.7rem;color:var(--mut);font-family:var(--mono);display:flex;justify-content:space-between;background:var(--sf);}}
</style>
</head>
<body>
<header>
  <div class="logo">IOC Enrichment Scanner</div>
  <h1>IOC Reputatie Rapport</h1>
  <div class="meta">Gegenereerd: {ts} UTC &nbsp;·&nbsp; {len(results)} IOC's geanalyseerd &nbsp;·&nbsp; Bronnen: VT · OTX · AbuseIPDB · URLScan · HIBP</div>
</header>

<div class="stats">
  <div class="stat s-tot"><div class="sn">{len(results)}</div><div class="sl">Totaal</div></div>
  <div class="stat s-mal"><div class="sn">{mal_c}</div><div class="sl">Malicious</div></div>
  <div class="stat s-sus"><div class="sn">{sus_c}</div><div class="sl">Suspicious</div></div>
  <div class="stat s-cln"><div class="sn">{cln_c}</div><div class="sl">Clean</div></div>
  <div class="stat s-unk"><div class="sn">{unk_c}</div><div class="sl">Onbekend</div></div>
</div>

<div class="toolbar">
  <input type="text" id="s" placeholder="Zoek IOC, verdict, type..." oninput="ft()">
  <button class="fb on" onclick="sf('ALL',this)">Alle</button>
  <button class="fb" onclick="sf('MALICIOUS',this)">⛔ Malicious</button>
  <button class="fb" onclick="sf('SUSPICIOUS',this)">⚠️ Suspicious</button>
  <button class="fb" onclick="sf('CLEAN',this)">✅ Clean</button>
  <span id="tc">{len(results)} IOC's weergegeven</span>
</div>

<div class="tw">
<table><thead><tr>
  <th>IOC</th><th>Type</th><th>Verdict</th>
  <th>VirusTotal</th><th>AlienVault OTX</th><th>AbuseIPDB</th><th>URLScan</th><th>HIBP</th>
  <th>Tijdstip</th>
</tr></thead>
<tbody id="tb">{rows}</tbody>
</table>
</div>

<main>
  <section>
    <h2>Gedetailleerde resultaten per IOC</h2>
    {cards}
  </section>
</main>

<footer>
  <span>IOC Enrichment Scanner · Eigen gebruik · Alleen voor eigen gebruik</span>
  <span>{ts} · {len(results)} IOC's</span>
</footer>

<script>
let af='ALL';
function ft(){{
  const q=document.getElementById('s').value.toLowerCase();
  let v=0;
  document.querySelectorAll('#tb tr').forEach(r=>{{
    const ok=(af==='ALL'||r.dataset.v===af)&&(!q||r.textContent.toLowerCase().includes(q));
    r.style.display=ok?'':'none';if(ok)v++;
  }});
  document.getElementById('tc').textContent=v+' IOC\'s weergegeven';
}}
function sf(t,b){{af=t;document.querySelectorAll('.fb').forEach(x=>x.classList.remove('on'));b.classList.add('on');ft();}}
</script>
</body>
</html>"""

    with open(path,"w",encoding="utf-8") as f:
        f.write(html)
    print(f"[+] HTML dashboard: {path}")

# ─── Main ─────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="IOC Enrichment Scanner")
    grp = parser.add_mutually_exclusive_group(required=True)
    grp.add_argument("-i","--ioc", help="Enkel IOC")
    grp.add_argument("-f","--file", help="Tekstbestand met IOC's (één per regel)")
    parser.add_argument("-o","--output", default="./ioc_output")
    args = parser.parse_args()

    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)

    iocs = [args.ioc] if args.ioc else [
        l.strip() for l in open(args.file) if l.strip() and not l.startswith("#")
    ]

    print("=" * 60)
    print("  IOC Enrichment Scanner")
    print(f"  IOC's : {len(iocs)}")
    print(f"  Output: {out.resolve()}")
    print("  Bronnen: VT · OTX · AbuseIPDB · URLScan · HIBP")
    print("=" * 60)

    results = []
    for idx, ioc in enumerate(iocs, 1):
        print(f"\n[{idx}/{len(iocs)}] {ioc}")
        r = enrich(ioc)
        results.append(r)
        print(f"  → {r['overall_verdict']}")

    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    save_csv(results,  out / f"ioc_report_{ts}.csv")
    save_html(results, out / f"ioc_report_{ts}.html")

    mal = sum(1 for r in results if r["overall_verdict"]=="MALICIOUS")
    sus = sum(1 for r in results if r["overall_verdict"]=="SUSPICIOUS")
    print(f"\n  Malicious: {mal}  Suspicious: {sus}  "
          f"Clean: {sum(1 for r in results if r['overall_verdict']=='CLEAN')}")
    print("=" * 60)

if __name__ == "__main__":
    main()
