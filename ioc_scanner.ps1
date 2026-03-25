#Requires -Version 5.1
<#
.SYNOPSIS
    IOC Enrichment Scanner — PowerShell editie
    Bronnen: VirusTotal, AlienVault OTX, AbuseIPDB, URLScan.io, HaveIBeenPwned
    Output: HTML dashboard + CSV

.DESCRIPTION
    Analyseert IOC's (IP, domein, URL, hash, e-mail) via gratis threat intel API's.
    Geen Python vereist. Werkt op zakelijke Windows laptops met PS 5.1+.

.PARAMETER IOC
    Enkel IOC om te scannen.

.PARAMETER File
    Pad naar tekstbestand met IOC's (één per regel, # = commentaar).

.PARAMETER Output
    Output directory (default: .\ioc_output).

.PARAMETER VTKey
    VirusTotal API key (of stel env var VT_API_KEY in).

.PARAMETER AbuseKey
    AbuseIPDB API key (of stel env var ABUSEIPDB_API_KEY in).

.PARAMETER OTXKey
    AlienVault OTX API key (of stel env var OTX_API_KEY in).

.PARAMETER URLScanKey
    URLScan.io API key — optioneel (of stel env var URLSCAN_API_KEY in).

.EXAMPLE
    .\ioc_scanner.ps1 -IOC "185.220.101.1" -VTKey "jouw_key"
    .\ioc_scanner.ps1 -File .\iocs.txt -Output C:\Reports\IOC
    .\ioc_scanner.ps1 -File .\iocs.txt  # keys uit env vars

.NOTES
    Execution policy: Run-As-Admin of:
    Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
#>

[CmdletBinding()]
param(
    [Parameter(ParameterSetName='Single', Mandatory=$true)]
    [string]$IOC,

    [Parameter(ParameterSetName='File', Mandatory=$true)]
    [string]$File,

    [string]$Output = ".\ioc_output",

    [string]$VTKey      = $env:VT_API_KEY,
    [string]$AbuseKey   = $env:ABUSEIPDB_API_KEY,
    [string]$OTXKey     = $env:OTX_API_KEY,
    [string]$URLScanKey = $env:URLSCAN_API_KEY
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "SilentlyContinue"

# TLS 1.2 forceren (vereist voor moderne API's)
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# ─── Helpers ─────────────────────────────────────────────────────────────────
function Invoke-API {
    param([string]$Uri, [hashtable]$Headers = @{}, [hashtable]$Query = @{})
    try {
        $ub = [System.UriBuilder]$Uri
        if ($Query.Count -gt 0) {
            $qs = ($Query.GetEnumerator() | ForEach-Object {
                "$([Uri]::EscapeDataString($_.Key))=$([Uri]::EscapeDataString($_.Value))"
            }) -join "&"
            $ub.Query = $qs
        }
        $resp = Invoke-WebRequest -Uri $ub.Uri.ToString() -Headers $Headers `
                    -UseBasicParsing -TimeoutSec 15 -ErrorAction Stop
        return $resp.Content | ConvertFrom-Json
    } catch {
        return $null
    }
}

function Get-SHA256([string]$text) {
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($text)
    $hash  = [System.Security.Cryptography.SHA256]::Create().ComputeHash($bytes)
    return -join ($hash | ForEach-Object { $_.ToString("x2") })
}

# ─── IOC type detectie ────────────────────────────────────────────────────────
function Get-IOCType([string]$value) {
    $value = $value.Trim()
    if ($value -match '^[a-fA-F0-9]{32}$')  { return "md5" }
    if ($value -match '^[a-fA-F0-9]{40}$')  { return "sha1" }
    if ($value -match '^[a-fA-F0-9]{64}$')  { return "sha256" }
    if ($value -match '^\d{1,3}(\.\d{1,3}){3}$') { return "ip" }
    if ($value -match '^[^@\s]+@[^@\s]+\.[^@\s]+$') { return "email" }
    if ($value -match '^https?://') { return "url" }
    if ($value -match '^[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$') { return "domain" }
    return "unknown"
}

# ─── VirusTotal ───────────────────────────────────────────────────────────────
function Invoke-VirusTotal([string]$IOC, [string]$Type) {
    if (-not $VTKey) {
        return @{ Source="VirusTotal"; Error="Geen API key (gebruik -VTKey of VT_API_KEY env var)" }
    }
    $hdrs = @{ "x-apikey" = $VTKey }
    $base = "https://www.virustotal.com/api/v3"

    switch ($Type) {
        "md5"    { $uri = "$base/files/$IOC" }
        "sha1"   { $uri = "$base/files/$IOC" }
        "sha256" { $uri = "$base/files/$IOC" }
        "ip"     { $uri = "$base/ip_addresses/$IOC" }
        "domain" { $uri = "$base/domains/$IOC" }
        "url"    { $uri = "$base/urls/$(Get-SHA256 $IOC)" }
        default  { return @{ Source="VirusTotal"; Error="Type '$Type' niet ondersteund" } }
    }

    $data = Invoke-API -Uri $uri -Headers $hdrs
    if (-not $data) { return @{ Source="VirusTotal"; Error="Request mislukt of niet gevonden" } }

    $attrs = $data.data.attributes
    $stats = $attrs.last_analysis_stats
    $mal   = if ($stats.malicious)  { $stats.malicious }  else { 0 }
    $sus   = if ($stats.suspicious) { $stats.suspicious } else { 0 }

    $verdict = if ($mal -gt 2)              { "MALICIOUS" }
               elseif ($mal -gt 0 -or $sus -gt 2) { "SUSPICIOUS" }
               else                          { "CLEAN" }

    return @{
        Source      = "VirusTotal"
        Malicious   = $mal
        Suspicious  = $sus
        Harmless    = if ($stats.harmless)   { $stats.harmless }   else { 0 }
        Undetected  = if ($stats.undetected) { $stats.undetected } else { 0 }
        Reputation  = if ($attrs.reputation) { $attrs.reputation } else { "" }
        Tags        = ($attrs.tags -join ", ")
        Verdict     = $verdict
    }
}

# ─── AlienVault OTX ──────────────────────────────────────────────────────────
function Invoke-OTX([string]$IOC, [string]$Type) {
    $hdrs = if ($OTXKey) { @{ "X-OTX-API-KEY" = $OTXKey } } else { @{} }
    $typeMap = @{ ip="IPv4"; domain="domain"; url="url"; md5="file"; sha1="file"; sha256="file"; email="email" }
    $otxType = $typeMap[$Type]
    if (-not $otxType) { return @{ Source="AlienVault OTX"; Error="Type niet ondersteund" } }

    $encoded = [Uri]::EscapeDataString($IOC)
    $data = Invoke-API -Uri "https://otx.alienvault.com/api/v1/indicators/$otxType/$encoded/general" -Headers $hdrs
    if (-not $data) { return @{ Source="AlienVault OTX"; Error="Request mislukt" } }

    $pc   = if ($data.pulse_info.count) { $data.pulse_info.count } else { 0 }
    $tags = ($data.pulse_info.pulses | Select-Object -First 5 | ForEach-Object { $_.tags } |
             Select-Object -Unique -First 8) -join ", "

    return @{
        Source      = "AlienVault OTX"
        PulseCount  = $pc
        Tags        = $tags
        Verdict     = if ($pc -gt 3) { "MALICIOUS" } elseif ($pc -gt 0) { "SUSPICIOUS" } else { "CLEAN" }
    }
}

# ─── AbuseIPDB ────────────────────────────────────────────────────────────────
function Invoke-AbuseIPDB([string]$IOC, [string]$Type) {
    if ($Type -ne "ip") { return @{ Source="AbuseIPDB"; Error="Alleen IP-adressen" } }
    if (-not $AbuseKey) { return @{ Source="AbuseIPDB"; Error="Geen API key (gebruik -AbuseKey of ABUSEIPDB_API_KEY)" } }

    $hdrs = @{ "Key" = $AbuseKey; "Accept" = "application/json" }
    $data = Invoke-API -Uri "https://api.abuseipdb.com/api/v2/check" -Headers $hdrs `
                -Query @{ ipAddress=$IOC; maxAgeInDays="90" }
    if (-not $data) { return @{ Source="AbuseIPDB"; Error="Request mislukt" } }

    $d     = $data.data
    $score = if ($d.abuseConfidenceScore) { $d.abuseConfidenceScore } else { 0 }
    return @{
        Source        = "AbuseIPDB"
        AbuseScore    = $score
        TotalReports  = if ($d.totalReports) { $d.totalReports } else { 0 }
        Country       = if ($d.countryCode)  { $d.countryCode }  else { "" }
        ISP           = if ($d.isp)          { $d.isp }          else { "" }
        UsageType     = if ($d.usageType)    { $d.usageType }    else { "" }
        IsWhitelisted = if ($d.isWhitelisted){ "Ja" }            else { "Nee" }
        LastReported  = if ($d.lastReportedAt) { ($d.lastReportedAt -split 'T')[0] } else { "" }
        Verdict       = if ($score -ge 75) { "MALICIOUS" } elseif ($score -ge 25) { "SUSPICIOUS" } else { "CLEAN" }
    }
}

# ─── URLScan.io ───────────────────────────────────────────────────────────────
function Invoke-URLScan([string]$IOC, [string]$Type) {
    if ($Type -notin @("url","domain","ip")) { return @{ Source="URLScan.io"; Error="Alleen URL/domein/IP" } }
    $hdrs = if ($URLScanKey) { @{ "API-Key" = $URLScanKey } } else { @{} }

    $query = if ($Type -eq "url") {
        try { ([Uri]$IOC).Host } catch { $IOC }
    } else { $IOC }

    $data = Invoke-API -Uri "https://urlscan.io/api/v1/search/" -Headers $hdrs `
                -Query @{ q="domain:$query"; size="5" }
    if (-not $data -or -not $data.results) {
        return @{ Source="URLScan.io"; Verdict="NOT_FOUND"; ScanCount=0 }
    }

    $latest  = $data.results[0]
    $verdict = $latest.verdicts.overall
    $score   = if ($verdict.score) { $verdict.score } else { 0 }
    $mal     = if ($verdict.malicious) { $true } else { $false }

    return @{
        Source      = "URLScan.io"
        ScanCount   = $data.results.Count
        Malicious   = if ($mal) { "Ja" } else { "Nee" }
        Score       = $score
        Categories  = ($verdict.categories -join ", ")
        LastScan    = if ($latest.task.time) { ($latest.task.time -split 'T')[0] } else { "" }
        Verdict     = if ($mal) { "MALICIOUS" } elseif ($score -gt 50) { "SUSPICIOUS" } else { "CLEAN" }
    }
}

# ─── HaveIBeenPwned ───────────────────────────────────────────────────────────
function Invoke-HIBP([string]$IOC, [string]$Type) {
    if ($Type -ne "email") { return @{ Source="HaveIBeenPwned"; Error="Alleen e-mailadressen" } }
    $domain  = $IOC.Split("@")[-1]
    $hdrs    = @{ "User-Agent" = "IOC-Scanner" }
    $data = Invoke-API -Uri "https://haveibeenpwned.com/api/v3/breacheddomain/$domain" -Headers $hdrs
    if (-not $data) {
        return @{ Source="HaveIBeenPwned"; DomainBreached="Nee"; BreachCount=0; Verdict="CLEAN" }
    }
    $count = if ($data -is [System.Collections.IDictionary]) { $data.Keys.Count } else { 0 }
    return @{
        Source        = "HaveIBeenPwned"
        DomainBreached= "Ja"
        BreachCount   = $count
        Verdict       = if ($count -gt 0) { "SUSPICIOUS" } else { "CLEAN" }
    }
}

# ─── IOC enrichment ──────────────────────────────────────────────────────────
function Invoke-EnrichIOC([string]$IOC) {
    $iocType = Get-IOCType $IOC
    $result  = [ordered]@{
        IOC             = $IOC
        Type            = $iocType
        Timestamp       = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        OverallVerdict  = "UNKNOWN"
        VerdictScore    = 0
        Enrichments     = @()
    }

    if ($iocType -eq "unknown") { return $result }

    $checks = @()

    # VirusTotal — alle types
    Start-Sleep -Milliseconds 1200
    $checks += Invoke-VirusTotal $IOC $iocType

    # OTX — alle types
    Start-Sleep -Milliseconds 1200
    $checks += Invoke-OTX $IOC $iocType

    # AbuseIPDB — alleen IP
    if ($iocType -eq "ip") {
        Start-Sleep -Milliseconds 1200
        $checks += Invoke-AbuseIPDB $IOC $iocType
    }

    # URLScan — url, domain, ip
    if ($iocType -in @("url","domain","ip")) {
        Start-Sleep -Milliseconds 1200
        $checks += Invoke-URLScan $IOC $iocType
    }

    # HIBP — email
    if ($iocType -eq "email") {
        Start-Sleep -Milliseconds 1200
        $checks += Invoke-HIBP $IOC $iocType
    }

    $result.Enrichments = $checks

    # Overall verdict
    $verdicts = $checks | ForEach-Object { $_.Verdict } | Where-Object { $_ }
    if ("MALICIOUS"  -in $verdicts) { $result.OverallVerdict = "MALICIOUS";  $result.VerdictScore = 3 }
    elseif ("SUSPICIOUS" -in $verdicts) { $result.OverallVerdict = "SUSPICIOUS"; $result.VerdictScore = 2 }
    elseif ("CLEAN"      -in $verdicts) { $result.OverallVerdict = "CLEAN";     $result.VerdictScore = 1 }

    return $result
}

# ─── Output: CSV ─────────────────────────────────────────────────────────────
function Save-CSV([array]$Results, [string]$Path) {
    $rows = foreach ($r in $Results) {
        $row = [ordered]@{
            ioc             = $r.IOC
            type            = $r.Type
            timestamp       = $r.Timestamp
            overall_verdict = $r.OverallVerdict
            vt_malicious    = ""
            vt_suspicious   = ""
            vt_verdict      = ""
            otx_pulses      = ""
            otx_verdict     = ""
            abuseipdb_score = ""
            abuseipdb_verdict=""
            urlscan_verdict = ""
            hibp_breaches   = ""
        }
        foreach ($e in $r.Enrichments) {
            switch -Wildcard ($e.Source) {
                "VirusTotal"    { $row.vt_malicious=$e.Malicious; $row.vt_suspicious=$e.Suspicious; $row.vt_verdict=$e.Verdict }
                "AlienVault*"   { $row.otx_pulses=$e.PulseCount; $row.otx_verdict=$e.Verdict }
                "AbuseIPDB"     { $row.abuseipdb_score=$e.AbuseScore; $row.abuseipdb_verdict=$e.Verdict }
                "URLScan*"      { $row.urlscan_verdict=$e.Verdict }
                "HaveIBeen*"    { $row.hibp_breaches=$e.BreachCount }
            }
        }
        [PSCustomObject]$row
    }
    $rows | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
    Write-Host "[+] CSV: $Path" -ForegroundColor Green
}

# ─── Output: HTML dashboard ──────────────────────────────────────────────────
function Save-HTML([array]$Results, [string]$Path) {
    $ts     = Get-Date -Format "dd-MM-yyyy HH:mm:ss"
    $malC   = ($Results | Where-Object { $_.OverallVerdict -eq "MALICIOUS"  }).Count
    $susC   = ($Results | Where-Object { $_.OverallVerdict -eq "SUSPICIOUS" }).Count
    $clnC   = ($Results | Where-Object { $_.OverallVerdict -eq "CLEAN"      }).Count
    $unkC   = ($Results | Where-Object { $_.OverallVerdict -eq "UNKNOWN"    }).Count

    function Get-VClass($v) {
        switch ($v) { "MALICIOUS" {"mal"} "SUSPICIOUS" {"sus"} "CLEAN" {"clean"} default {"unk"} }
    }
    function Get-VIcon($v) {
        switch ($v) { "MALICIOUS" {"⛔"} "SUSPICIOUS" {"⚠️"} "CLEAN" {"✅"} "NOT_FOUND" {"🔍"} default {"❓"} }
    }

    $rows  = ""
    $cards = ""

    foreach ($r in $Results) {
        $vc  = Get-VClass $r.OverallVerdict
        $vi  = Get-VIcon  $r.OverallVerdict

        # Tabelcellen per bron
        $cells = ""
        foreach ($src in @("VirusTotal","AlienVault OTX","AbuseIPDB","URLScan.io","HaveIBeenPwned")) {
            $e = $r.Enrichments | Where-Object { $_.Source -like "$src*" } | Select-Object -First 1
            if ($e -and $e.Verdict) {
                $ec = Get-VClass $e.Verdict
                $ei = Get-VIcon  $e.Verdict
                $cells += "<td><span class=`"vm $ec`">$ei</span></td>"
            } elseif ($e -and $e.Error) {
                $cells += "<td><span class=`"vm unk`" title=`"$($e.Error)`">⚙️</span></td>"
            } else {
                $cells += "<td><span class=`"vm unk`">—</span></td>"
            }
        }

        $rows += @"
<tr data-v="$($r.OverallVerdict)">
  <td><code class="ioc-v">$($r.IOC)</code></td>
  <td><span class="badge-t">$($r.Type.ToUpper())</span></td>
  <td><span class="vb $vc">$vi $($r.OverallVerdict)</span></td>
  $cells
  <td class="ts-c">$($r.Timestamp.Substring(0,19).Replace('T',' '))</td>
</tr>
"@

        # Detail cards per bron
        $enrHtml = ""
        foreach ($e in $r.Enrichments) {
            $ec = Get-VClass ($e.Verdict)
            $drows = ""
            foreach ($key in $e.Keys) {
                if ($key -in @("Source","Verdict")) { continue }
                $val = $e[$key]
                if ($key -eq "Error") {
                    $drows += "<div class=`"dr err`">⚠ $val</div>"
                    continue
                }
                $drows += "<div class=`"dr`"><span class=`"dk`">$key</span><span class=`"dv`">$val</span></div>"
            }
            $enrHtml += @"
<div class="ec $ec">
  <div class="eh"><span class="en">$($e.Source)</span><span class="vm $ec">$(Get-VIcon $e.Verdict)</span></div>
  $drows
</div>
"@
        }

        $cards += @"
<details class="ioc-det">
  <summary><span class="vb $vc">$vi $($r.OverallVerdict)</span> <code>$($r.IOC)</code> <span class="badge-t">$($r.Type.ToUpper())</span></summary>
  <div class="eg">$enrHtml</div>
</details>
"@
    }

    $total = $Results.Count
    $html  = @"
<!DOCTYPE html>
<html lang="nl">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>IOC Rapport</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Syne:wght@400;600;800&display=swap');
:root{--bg:#080b12;--sf:#0e1220;--bd:#1a2035;--acc:#00e5ff;
  --mal:#ff3b5c;--sus:#f59e0b;--cln:#10b981;--unk:#6b7280;
  --txt:#e2e8f0;--mut:#64748b;--mono:'JetBrains Mono',monospace;--sans:'Syne',sans-serif;}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--txt);font-family:var(--sans);min-height:100vh;}
body::before{content:'';position:fixed;inset:0;pointer-events:none;z-index:999;
  background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,229,255,.007) 2px,rgba(0,229,255,.007) 4px);}
header{padding:2rem 2.5rem;border-bottom:1px solid var(--bd);background:linear-gradient(135deg,#0a0e18,var(--bg));position:relative;overflow:hidden;}
header::after{content:'IOC';position:absolute;right:2rem;top:50%;transform:translateY(-50%);
  font-size:8rem;font-weight:800;color:rgba(0,229,255,.04);font-family:var(--mono);pointer-events:none;}
.logo{font-family:var(--mono);font-size:.68rem;color:var(--acc);letter-spacing:.2em;text-transform:uppercase;margin-bottom:.4rem;}
h1{font-size:1.7rem;font-weight:800;color:#fff;}
.meta{font-size:.72rem;color:var(--mut);margin-top:.3rem;font-family:var(--mono);}
.stats{display:grid;grid-template-columns:repeat(5,1fr);gap:1px;background:var(--bd);border-bottom:1px solid var(--bd);}
.stat{background:var(--sf);padding:1rem 1.5rem;}
.sn{font-size:2.2rem;font-weight:800;font-family:var(--mono);line-height:1;}
.sl{font-size:.6rem;text-transform:uppercase;letter-spacing:.12em;color:var(--mut);margin-top:.25rem;}
.s-tot .sn{color:var(--acc);} .s-mal .sn{color:var(--mal);} .s-sus .sn{color:var(--sus);}
.s-cln .sn{color:var(--cln);} .s-unk .sn{color:var(--unk);}
.toolbar{padding:.8rem 2.5rem;background:var(--sf);border-bottom:1px solid var(--bd);display:flex;gap:.6rem;align-items:center;flex-wrap:wrap;}
.toolbar input{flex:1;max-width:260px;padding:.38rem .75rem;background:var(--bg);border:1px solid var(--bd);border-radius:5px;color:var(--txt);font-family:var(--mono);font-size:.77rem;outline:none;}
.toolbar input:focus{border-color:var(--acc);}
.fb{padding:.33rem .8rem;border:1px solid var(--bd);border-radius:5px;background:transparent;color:var(--mut);font-size:.72rem;cursor:pointer;font-family:var(--sans);transition:.1s;}
.fb:hover,.fb.on{background:var(--acc);color:#000;border-color:var(--acc);font-weight:600;}
#tc{margin-left:auto;font-size:.7rem;color:var(--mut);font-family:var(--mono);}
.tw{overflow-x:auto;}
table{width:100%;border-collapse:collapse;font-size:.78rem;}
th{background:#0a0e1a;color:#7891b8;padding:.55rem 1rem;text-align:left;font-size:.62rem;text-transform:uppercase;letter-spacing:.09em;white-space:nowrap;position:sticky;top:0;z-index:5;border-bottom:1px solid var(--bd);}
td{padding:.5rem 1rem;border-bottom:1px solid var(--bd);vertical-align:middle;}
tr:hover td{background:rgba(255,255,255,.02);}
tr:last-child td{border-bottom:none;}
code.ioc-v{font-family:var(--mono);color:var(--acc);font-size:.79rem;word-break:break-all;}
.ts-c{font-family:var(--mono);font-size:.68rem;color:var(--mut);white-space:nowrap;}
.badge-t{padding:.14rem .48rem;border-radius:4px;font-size:.63rem;font-weight:700;font-family:var(--mono);background:rgba(124,58,237,.2);color:#a78bfa;border:1px solid rgba(124,58,237,.3);}
.vb{display:inline-flex;align-items:center;gap:.28rem;padding:.18rem .62rem;border-radius:99px;font-size:.7rem;font-weight:700;font-family:var(--mono);white-space:nowrap;}
.vm{display:inline-flex;align-items:center;justify-content:center;width:1.55rem;height:1.55rem;border-radius:50%;font-size:.77rem;}
.mal{background:rgba(255,59,92,.15);color:var(--mal);border:1px solid rgba(255,59,92,.3);}
.sus{background:rgba(245,158,11,.15);color:var(--sus);border:1px solid rgba(245,158,11,.3);}
.clean{background:rgba(16,185,129,.15);color:var(--cln);border:1px solid rgba(16,185,129,.3);}
.unk{background:rgba(107,114,128,.15);color:var(--unk);border:1px solid rgba(107,114,128,.3);}
main{padding:1.5rem 2.5rem 2.5rem;}
section{margin-bottom:2rem;}
h2{font-size:.83rem;font-weight:700;text-transform:uppercase;letter-spacing:.1em;color:var(--acc);margin-bottom:.85rem;}
.ioc-det{border:1px solid var(--bd);border-radius:7px;margin-bottom:.45rem;overflow:hidden;}
.ioc-det summary{display:flex;align-items:center;gap:.6rem;padding:.7rem 1.2rem;cursor:pointer;background:var(--sf);list-style:none;font-size:.82rem;}
.ioc-det summary::-webkit-details-marker{display:none;}
.ioc-det summary:hover{background:#111629;}
.eg{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:.8rem;padding:.9rem 1.2rem;background:#0a0c14;}
.ec{border:1px solid var(--bd);border-radius:6px;padding:.8rem;background:var(--sf);}
.ec.mal{border-color:rgba(255,59,92,.35);} .ec.sus{border-color:rgba(245,158,11,.35);} .ec.clean{border-color:rgba(16,185,129,.35);}
.eh{display:flex;justify-content:space-between;align-items:center;margin-bottom:.6rem;}
.en{font-weight:700;font-size:.76rem;color:#fff;}
.dr{display:flex;justify-content:space-between;gap:.35rem;padding:.16rem 0;font-size:.7rem;border-bottom:1px solid rgba(255,255,255,.04);}
.dr:last-child{border-bottom:none;}
.dk{color:var(--mut);font-family:var(--mono);flex-shrink:0;}
.dv{color:var(--txt);text-align:right;word-break:break-all;}
.err{color:var(--sus);font-family:var(--mono);font-size:.69rem;justify-content:flex-start;}
footer{padding:1.2rem 2.5rem;border-top:1px solid var(--bd);font-size:.68rem;color:var(--mut);font-family:var(--mono);display:flex;justify-content:space-between;background:var(--sf);}
</style>
</head>
<body>
<header>
  <div class="logo">IOC Enrichment Scanner</div>
  <h1>IOC Reputatie Rapport</h1>
  <div class="meta">Gegenereerd: $ts UTC &nbsp;·&nbsp; $total IOC's geanalyseerd &nbsp;·&nbsp; Bronnen: VT · OTX · AbuseIPDB · URLScan · HIBP</div>
</header>
<div class="stats">
  <div class="stat s-tot"><div class="sn">$total</div><div class="sl">Totaal</div></div>
  <div class="stat s-mal"><div class="sn">$malC</div><div class="sl">Malicious</div></div>
  <div class="stat s-sus"><div class="sn">$susC</div><div class="sl">Suspicious</div></div>
  <div class="stat s-cln"><div class="sn">$clnC</div><div class="sl">Clean</div></div>
  <div class="stat s-unk"><div class="sn">$unkC</div><div class="sl">Onbekend</div></div>
</div>
<div class="toolbar">
  <input type="text" id="s" placeholder="Zoek IOC, type, verdict..." oninput="ft()">
  <button class="fb on" onclick="sf('ALL',this)">Alle</button>
  <button class="fb" onclick="sf('MALICIOUS',this)">⛔ Malicious</button>
  <button class="fb" onclick="sf('SUSPICIOUS',this)">⚠️ Suspicious</button>
  <button class="fb" onclick="sf('CLEAN',this)">✅ Clean</button>
  <span id="tc">$total IOC's weergegeven</span>
</div>
<div class="tw">
<table><thead><tr>
  <th>IOC</th><th>Type</th><th>Verdict</th>
  <th>VirusTotal</th><th>AlienVault OTX</th><th>AbuseIPDB</th><th>URLScan</th><th>HIBP</th>
  <th>Tijdstip</th>
</tr></thead>
<tbody id="tb">$rows</tbody>
</table>
</div>
<main>
  <section>
    <h2>Gedetailleerde resultaten per IOC</h2>
    $cards
  </section>
</main>
<footer>
  <span>IOC Enrichment Scanner · PowerShell editie · Eigen gebruik</span>
  <span>$ts · $total IOC's</span>
</footer>
<script>
let af='ALL';
function ft(){
  const q=document.getElementById('s').value.toLowerCase();
  let v=0;
  document.querySelectorAll('#tb tr').forEach(r=>{
    const ok=(af==='ALL'||r.dataset.v===af)&&(!q||r.textContent.toLowerCase().includes(q));
    r.style.display=ok?'':'none';if(ok)v++;
  });
  document.getElementById('tc').textContent=v+' IOC\'s weergegeven';
}
function sf(t,b){af=t;document.querySelectorAll('.fb').forEach(x=>x.classList.remove('on'));b.classList.add('on');ft();}
</script>
</body>
</html>
"@
    $html | Out-File -FilePath $Path -Encoding UTF8
    Write-Host "[+] HTML dashboard: $Path" -ForegroundColor Green
}

# ─── Main ────────────────────────────────────────────────────────────────────
$null = New-Item -ItemType Directory -Path $Output -Force

# IOC's laden
$iocList = @()
if ($PSCmdlet.ParameterSetName -eq "Single") {
    $iocList = @($IOC)
} else {
    if (-not (Test-Path $File)) {
        Write-Error "Bestand niet gevonden: $File"; exit 1
    }
    $iocList = Get-Content $File |
               Where-Object { $_ -and $_.Trim() -and -not $_.TrimStart().StartsWith("#") } |
               ForEach-Object { $_.Trim() }
}

Write-Host ("=" * 60) -ForegroundColor Cyan
Write-Host "  IOC Enrichment Scanner (PowerShell)" -ForegroundColor Cyan
Write-Host "  IOC's  : $($iocList.Count)"
Write-Host "  Output : $(Resolve-Path $Output -ErrorAction SilentlyContinue)"
Write-Host "  Bronnen: VT · OTX · AbuseIPDB · URLScan · HIBP"
Write-Host "  VT Key : $(if ($VTKey) { 'Ingesteld ✓' } else { 'ONTBREEKT — VirusTotal overgeslagen' })"
Write-Host "  Abuse  : $(if ($AbuseKey) { 'Ingesteld ✓' } else { 'ONTBREEKT — AbuseIPDB overgeslagen' })"
Write-Host ("=" * 60) -ForegroundColor Cyan

$results = @()
$i = 0
foreach ($ioc in $iocList) {
    $i++
    Write-Host "`n[$i/$($iocList.Count)] " -NoNewline -ForegroundColor Yellow
    Write-Host $ioc
    $r = Invoke-EnrichIOC $ioc
    $results += $r
    $color = switch ($r.OverallVerdict) {
        "MALICIOUS"  { "Red" }
        "SUSPICIOUS" { "Yellow" }
        "CLEAN"      { "Green" }
        default      { "Gray" }
    }
    Write-Host "  → $($r.OverallVerdict)" -ForegroundColor $color
}

$ts = Get-Date -Format "yyyyMMdd_HHmmss"
Save-CSV  $results "$Output\ioc_report_$ts.csv"
Save-HTML $results "$Output\ioc_report_$ts.html"

$malFinal = ($results | Where-Object { $_.OverallVerdict -eq "MALICIOUS"  }).Count
$susFinal = ($results | Where-Object { $_.OverallVerdict -eq "SUSPICIOUS" }).Count
$clnFinal = ($results | Where-Object { $_.OverallVerdict -eq "CLEAN"      }).Count

Write-Host "`n$("=" * 60)" -ForegroundColor Cyan
Write-Host "  Malicious  : $malFinal" -ForegroundColor Red
Write-Host "  Suspicious : $susFinal" -ForegroundColor Yellow
Write-Host "  Clean      : $clnFinal" -ForegroundColor Green
Write-Host "$("=" * 60)" -ForegroundColor Cyan

# Open HTML automatisch in browser
$htmlPath = "$Output\ioc_report_$ts.html"
if (Test-Path $htmlPath) {
    Start-Process $htmlPath
}
