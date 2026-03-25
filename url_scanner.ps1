#Requires -Version 5.1
<#
.SYNOPSIS
    URL Batch Scanner — PowerShell editie
    Input: CSV met kolom 'url' of 'domain' (of .txt lijst)
    Bronnen: VirusTotal, AlienVault OTX, URLScan.io
    Extra checks: actieve HTTP check, SSL/TLS certificate check, phishing detectie
    Output: HTML dashboard + CSV rapport

.EXAMPLE
    .\url_scanner.ps1 -CsvFile .\urls.csv
    .\url_scanner.ps1 -CsvFile .\urls.csv -UrlColumn "domain" -VTKey "abc123"
    .\url_scanner.ps1 -TxtFile .\urls.txt -Output C:\url-rapporten
#>

[CmdletBinding()]
param(
    [Parameter(ParameterSetName='CSV', Mandatory=$true)]
    [string]$CsvFile,

    [Parameter(ParameterSetName='TXT', Mandatory=$true)]
    [string]$TxtFile,

    [string]$UrlColumn    = "url",       # Kolomnaam in CSV (ook 'domain' werkt automatisch)
    [string]$Output       = ".\url_output",
    [string]$VTKey        = $env:VT_API_KEY,
    [string]$OTXKey       = $env:OTX_API_KEY,
    [string]$URLScanKey   = $env:URLSCAN_API_KEY,
    [int]$TimeoutSec      = 15,
    [int]$MaxWorkers      = 5,           # Parallelle HTTP checks
    [switch]$SkipHTTP,                   # Sla actieve HTTP check over
    [switch]$SkipCert,                   # Sla certificate check over
    [switch]$SkipReputation              # Sla API reputatie checks over
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "SilentlyContinue"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
# Accepteer alle certificaten (voor scannen van potentieel verdachte sites)
[Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

# ─── Helpers ──────────────────────────────────────────────────────────────────
function Write-Status($msg, $color = "Cyan") {
    Write-Host $msg -ForegroundColor $color
}

function Invoke-API {
    param([string]$Uri, [hashtable]$Headers = @{}, [hashtable]$Query = @{})
    try {
        if ($Query.Count -gt 0) {
            $qs  = ($Query.GetEnumerator() | ForEach-Object {
                "$([Uri]::EscapeDataString($_.Key))=$([Uri]::EscapeDataString($_.Value))"
            }) -join "&"
            $Uri = "$Uri`?$qs"
        }
        $resp = Invoke-WebRequest -Uri $Uri -Headers $Headers `
                    -UseBasicParsing -TimeoutSec 15 -ErrorAction Stop
        return $resp.Content | ConvertFrom-Json
    } catch { return $null }
}

function Get-SHA256([string]$text) {
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($text)
    $hash  = [System.Security.Cryptography.SHA256]::Create().ComputeHash($bytes)
    return -join ($hash | ForEach-Object { $_.ToString("x2") })
}

function Get-Domain([string]$url) {
    # Haal het domein op uit een URL of return de waarde zelf
    try {
        if ($url -match '^https?://') {
            return ([Uri]$url).Host
        }
        return $url -replace '^[^/]+://', '' -replace '/.*$', ''
    } catch { return $url }
}

function Normalize-URL([string]$input) {
    # Voeg https:// toe als ontbreekt
    if ($input -notmatch '^https?://') {
        return "https://$input"
    }
    return $input
}

# ─── Actieve HTTP check ───────────────────────────────────────────────────────
function Invoke-HTTPCheck([string]$url) {
    $url     = Normalize-URL $url
    $result  = @{
        Reachable      = $false
        StatusCode     = 0
        FinalURL       = ""
        RedirectChain  = @()
        ServerHeader   = ""
        ContentType    = ""
        ResponseTimeMs = 0
        TechStack      = @()
        SecurityHeaders= @()
        MissingSecHeaders = @()
        Title          = ""
        Error          = ""
    }

    $required_sec_headers = @(
        "strict-transport-security",
        "x-frame-options",
        "x-content-type-options",
        "content-security-policy",
        "referrer-policy"
    )

    try {
        $sw    = [System.Diagnostics.Stopwatch]::StartNew()
        $resp  = Invoke-WebRequest -Uri $url -UseBasicParsing `
                     -TimeoutSec $TimeoutSec -MaximumRedirection 5 `
                     -ErrorAction Stop
        $sw.Stop()

        $result.Reachable       = $true
        $result.StatusCode      = $resp.StatusCode
        $result.FinalURL        = $resp.BaseResponse.ResponseUri.ToString()
        $result.ResponseTimeMs  = $sw.ElapsedMilliseconds
        $result.ContentType     = ($resp.Headers["Content-Type"] ?? "")

        # Headers
        $hdrs = @{}
        $resp.Headers.GetEnumerator() | ForEach-Object { $hdrs[$_.Key.ToLower()] = $_.Value }
        $result.ServerHeader = $hdrs["server"] ?? ""

        # Security headers
        foreach ($sh in $required_sec_headers) {
            if ($hdrs.ContainsKey($sh)) {
                $result.SecurityHeaders += $sh
            } else {
                $result.MissingSecHeaders += $sh
            }
        }

        # Tech stack uit headers
        $tech = @()
        if ($hdrs["x-powered-by"]) { $tech += $hdrs["x-powered-by"] }
        if ($hdrs["x-aspnet-version"]) { $tech += "ASP.NET $($hdrs['x-aspnet-version'])" }
        if ($hdrs["x-generator"]) { $tech += $hdrs["x-generator"] }
        if ($result.ServerHeader -match "nginx|apache|iis|tomcat|caddy") {
            $tech += $result.ServerHeader -replace "\s*\(.*?\)", ""
        }
        $result.TechStack = $tech

        # Title uit body
        if ($resp.Content -match '<title[^>]*>([^<]{1,120})</title>') {
            $result.Title = $Matches[1].Trim()
        }

    } catch [System.Net.WebException] {
        $result.StatusCode = [int]$_.Exception.Response.StatusCode
        $result.Error      = $_.Exception.Message
    } catch {
        $result.Error = $_.Exception.Message -replace "Exception calling.*?:", "" -replace '"',""
    }

    return $result
}

# ─── SSL Certificate check ────────────────────────────────────────────────────
function Invoke-CertCheck([string]$url) {
    $domain = Get-Domain $url
    $result = @{
        HasCert       = $false
        Subject       = ""
        Issuer        = ""
        ValidFrom     = ""
        ValidUntil    = ""
        DaysRemaining = 0
        IsExpired     = $false
        ExpiresSoon   = $false   # < 30 dagen
        SANs          = @()
        TLSVersion    = ""
        CipherSuite   = ""
        SelfSigned    = $false
        Error         = ""
    }

    try {
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $tcpClient.Connect($domain, 443)
        $sslStream = New-Object System.Net.Security.SslStream(
            $tcpClient.GetStream(), $false,
            { param($s,$c,$ch,$e) $true }   # Accepteer alles
        )
        $sslStream.AuthenticateAsClient($domain)

        $cert     = $sslStream.RemoteCertificate
        $cert2    = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($cert)

        $result.HasCert    = $true
        $result.Subject    = $cert2.Subject
        $result.Issuer     = $cert2.Issuer
        $result.ValidFrom  = $cert2.NotBefore.ToString("yyyy-MM-dd")
        $result.ValidUntil = $cert2.NotAfter.ToString("yyyy-MM-dd")

        $days = ($cert2.NotAfter - (Get-Date)).Days
        $result.DaysRemaining = $days
        $result.IsExpired     = $days -lt 0
        $result.ExpiresSoon   = $days -ge 0 -and $days -lt 30
        $result.SelfSigned    = $cert2.Subject -eq $cert2.Issuer

        # TLS versie
        $result.TLSVersion  = $sslStream.SslProtocol.ToString()
        $result.CipherSuite = $sslStream.CipherAlgorithm.ToString()

        # SANs
        $sanExt = $cert2.Extensions | Where-Object { $_.Oid.FriendlyName -eq "Subject Alternative Name" }
        if ($sanExt) {
            $result.SANs = $sanExt.Format($false) -split ", " |
                           Where-Object { $_ -match "DNS Name=" } |
                           ForEach-Object { $_ -replace "DNS Name=", "" }
        }

        $sslStream.Close()
        $tcpClient.Close()

    } catch {
        $result.Error = $_.Exception.Message -replace '"', ""
    }

    return $result
}

# ─── VirusTotal URL check ─────────────────────────────────────────────────────
function Invoke-VT_URL([string]$url) {
    if (-not $VTKey) {
        return @{ Source="VirusTotal"; Error="Geen API key" }
    }
    $hdrs   = @{ "x-apikey" = $VTKey }
    $urlId  = Get-SHA256 (Normalize-URL $url)
    $data   = Invoke-API -Uri "https://www.virustotal.com/api/v3/urls/$urlId" -Headers $hdrs
    if (-not $data) {
        # Probeer domein lookup
        $domain = Get-Domain $url
        $data   = Invoke-API -Uri "https://www.virustotal.com/api/v3/domains/$domain" -Headers $hdrs
    }
    if (-not $data) { return @{ Source="VirusTotal"; Error="Niet gevonden" } }

    $attrs = $data.data.attributes
    $stats = $attrs.last_analysis_stats
    $mal   = if ($stats.malicious)  { [int]$stats.malicious }  else { 0 }
    $sus   = if ($stats.suspicious) { [int]$stats.suspicious } else { 0 }

    return @{
        Source     = "VirusTotal"
        Malicious  = $mal
        Suspicious = $sus
        Harmless   = if ($stats.harmless)   { [int]$stats.harmless }   else { 0 }
        Categories = ($attrs.categories.PSObject.Properties.Value -join ", ")
        Tags       = ($attrs.tags -join ", ")
        Reputation = if ($attrs.reputation) { $attrs.reputation } else { 0 }
        Verdict    = if ($mal -gt 2) { "MALICIOUS" } elseif ($mal -gt 0 -or $sus -gt 2) { "SUSPICIOUS" } else { "CLEAN" }
    }
}

# ─── AlienVault OTX URL check ─────────────────────────────────────────────────
function Invoke-OTX_URL([string]$url) {
    $hdrs   = if ($OTXKey) { @{ "X-OTX-API-KEY" = $OTXKey } } else { @{} }
    $domain = Get-Domain $url
    $enc    = [Uri]::EscapeDataString($domain)
    $data   = Invoke-API -Uri "https://otx.alienvault.com/api/v1/indicators/domain/$enc/general" -Headers $hdrs
    if (-not $data) { return @{ Source="AlienVault OTX"; Error="Request mislukt" } }

    $pc   = if ($data.pulse_info.count) { [int]$data.pulse_info.count } else { 0 }
    $tags = ($data.pulse_info.pulses | Select-Object -First 5 |
             ForEach-Object { $_.tags } | Select-Object -Unique -First 8) -join ", "

    return @{
        Source     = "AlienVault OTX"
        PulseCount = $pc
        Tags       = $tags
        Verdict    = if ($pc -gt 3) { "MALICIOUS" } elseif ($pc -gt 0) { "SUSPICIOUS" } else { "CLEAN" }
    }
}

# ─── URLScan.io — reputatie + phishing categorieën ───────────────────────────
function Invoke-URLScan_URL([string]$url) {
    $hdrs   = if ($URLScanKey) { @{ "API-Key" = $URLScanKey } } else { @{} }
    $domain = Get-Domain $url
    $data   = Invoke-API -Uri "https://urlscan.io/api/v1/search/" -Headers $hdrs `
                  -Query @{ q="domain:$domain"; size="5" }

    if (-not $data -or -not $data.results) {
        return @{ Source="URLScan.io"; Verdict="NOT_FOUND"; ScanCount=0; Categories=@() }
    }

    $latest   = $data.results[0]
    $verdict  = $latest.verdicts.overall
    $score    = if ($verdict.score) { [int]$verdict.score } else { 0 }
    $mal      = if ($verdict.malicious) { $true } else { $false }
    $cats     = $verdict.categories ?? @()

    # Phishing detectie uit categorieën
    $phishCats = @("phishing","malware","malicious","fraud","scam","fake")
    $isPhish   = ($cats | Where-Object { $phishCats -contains $_.ToLower() }).Count -gt 0

    return @{
        Source      = "URLScan.io"
        ScanCount   = $data.results.Count
        Malicious   = if ($mal) { "Ja" } else { "Nee" }
        Score       = $score
        Categories  = ($cats -join ", ")
        IsPhishing  = $isPhish
        LastScan    = if ($latest.task.time) { ($latest.task.time -split 'T')[0] } else { "" }
        Screenshot  = if ($latest.screenshot) { $latest.screenshot } else { "" }
        Verdict     = if ($mal -or $isPhish) { "MALICIOUS" } elseif ($score -gt 50) { "SUSPICIOUS" } else { "CLEAN" }
    }
}

# ─── Hoofd URL scan ───────────────────────────────────────────────────────────
function Invoke-ScanURL([string]$url) {
    $url = $url.Trim()
    $result = [ordered]@{
        URL             = $url
        Domain          = Get-Domain $url
        Timestamp       = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        OverallVerdict  = "UNKNOWN"
        IsPhishing      = $false
        # HTTP check
        HTTP_Reachable  = $false
        HTTP_Status     = 0
        HTTP_FinalURL   = ""
        HTTP_Server     = ""
        HTTP_Title      = ""
        HTTP_ResponseMs = 0
        HTTP_Tech       = ""
        HTTP_MissingSecHeaders = ""
        HTTP_Error      = ""
        # Cert check
        Cert_HasCert    = $false
        Cert_Subject    = ""
        Cert_Issuer     = ""
        Cert_ValidUntil = ""
        Cert_DaysLeft   = 0
        Cert_Expired    = $false
        Cert_ExpiresSoon= $false
        Cert_SelfSigned = $false
        Cert_TLS        = ""
        Cert_SANs       = ""
        Cert_Error      = ""
        # Reputatie
        VT_Malicious    = ""
        VT_Suspicious   = ""
        VT_Categories   = ""
        VT_Verdict      = ""
        OTX_Pulses      = ""
        OTX_Verdict     = ""
        US_Score        = ""
        US_Categories   = ""
        US_IsPhishing   = ""
        US_Verdict      = ""
        Enrichments     = @()
    }

    $verdicts = @()

    # ── 1. Actieve HTTP check ─────────────────────────────────────────────────
    if (-not $SkipHTTP) {
        $http = Invoke-HTTPCheck $url
        $result.HTTP_Reachable  = $http.Reachable
        $result.HTTP_Status     = $http.StatusCode
        $result.HTTP_FinalURL   = $http.FinalURL
        $result.HTTP_Server     = $http.ServerHeader
        $result.HTTP_Title      = $http.Title
        $result.HTTP_ResponseMs = $http.ResponseTimeMs
        $result.HTTP_Tech       = ($http.TechStack -join "; ")
        $result.HTTP_MissingSecHeaders = ($http.MissingSecHeaders -join "; ")
        $result.HTTP_Error      = $http.Error
        $result.Enrichments    += @{ Type="HTTP"; Data=$http }
    }

    # ── 2. SSL Certificate check ──────────────────────────────────────────────
    if (-not $SkipCert) {
        $cert = Invoke-CertCheck $url
        $result.Cert_HasCert    = $cert.HasCert
        $result.Cert_Subject    = $cert.Subject
        $result.Cert_Issuer     = $cert.Issuer
        $result.Cert_ValidUntil = $cert.ValidUntil
        $result.Cert_DaysLeft   = $cert.DaysRemaining
        $result.Cert_Expired    = $cert.IsExpired
        $result.Cert_ExpiresSoon= $cert.ExpiresSoon
        $result.Cert_SelfSigned = $cert.SelfSigned
        $result.Cert_TLS        = $cert.TLSVersion
        $result.Cert_SANs       = ($cert.SANs -join "; ")
        $result.Cert_Error      = $cert.Error
        $result.Enrichments    += @{ Type="Cert"; Data=$cert }

        if ($cert.IsExpired)    { $verdicts += "SUSPICIOUS" }
        if ($cert.SelfSigned)   { $verdicts += "SUSPICIOUS" }
    }

    # ── 3. Reputatie checks ───────────────────────────────────────────────────
    if (-not $SkipReputation) {
        Start-Sleep -Milliseconds 1200
        $vt = Invoke-VT_URL $url
        $result.VT_Malicious   = $vt.Malicious
        $result.VT_Suspicious  = $vt.Suspicious
        $result.VT_Categories  = $vt.Categories
        $result.VT_Verdict     = $vt.Verdict
        if ($vt.Verdict) { $verdicts += $vt.Verdict }

        Start-Sleep -Milliseconds 1200
        $otx = Invoke-OTX_URL $url
        $result.OTX_Pulses  = $otx.PulseCount
        $result.OTX_Verdict = $otx.Verdict
        if ($otx.Verdict) { $verdicts += $otx.Verdict }

        Start-Sleep -Milliseconds 1200
        $us = Invoke-URLScan_URL $url
        $result.US_Score       = $us.Score
        $result.US_Categories  = $us.Categories
        $result.US_IsPhishing  = if ($us.IsPhishing) { "Ja" } else { "Nee" }
        $result.US_Verdict     = $us.Verdict
        $result.IsPhishing     = $us.IsPhishing
        if ($us.Verdict) { $verdicts += $us.Verdict }
        $result.Enrichments   += @{ Type="URLScan"; Data=$us }
    }

    # ── Overall verdict ───────────────────────────────────────────────────────
    if ("MALICIOUS"  -in $verdicts) { $result.OverallVerdict = "MALICIOUS" }
    elseif ("SUSPICIOUS" -in $verdicts) { $result.OverallVerdict = "SUSPICIOUS" }
    elseif ("CLEAN"      -in $verdicts) { $result.OverallVerdict = "CLEAN" }

    return $result
}

# ─── Output: CSV ─────────────────────────────────────────────────────────────
function Save-CSV([array]$Results, [string]$Path) {
    $cols = @("URL","Domain","Timestamp","OverallVerdict","IsPhishing",
              "HTTP_Reachable","HTTP_Status","HTTP_FinalURL","HTTP_Server",
              "HTTP_Title","HTTP_ResponseMs","HTTP_Tech","HTTP_MissingSecHeaders","HTTP_Error",
              "Cert_HasCert","Cert_Subject","Cert_Issuer","Cert_ValidUntil",
              "Cert_DaysLeft","Cert_Expired","Cert_ExpiresSoon","Cert_SelfSigned",
              "Cert_TLS","Cert_SANs","Cert_Error",
              "VT_Malicious","VT_Suspicious","VT_Categories","VT_Verdict",
              "OTX_Pulses","OTX_Verdict",
              "US_Score","US_Categories","US_IsPhishing","US_Verdict")

    $rows = $Results | ForEach-Object {
        $r = $_
        $obj = [ordered]@{}
        foreach ($c in $cols) { $obj[$c] = $r[$c] ?? "" }
        [PSCustomObject]$obj
    }
    $rows | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
    Write-Host "[+] CSV: $Path" -ForegroundColor Green
}

# ─── Output: HTML dashboard ───────────────────────────────────────────────────
function Save-HTML([array]$Results, [string]$Path) {
    $ts    = Get-Date -Format "dd-MM-yyyy HH:mm:ss"
    $malC  = ($Results | Where-Object { $_.OverallVerdict -eq "MALICIOUS"  }).Count
    $susC  = ($Results | Where-Object { $_.OverallVerdict -eq "SUSPICIOUS" }).Count
    $clnC  = ($Results | Where-Object { $_.OverallVerdict -eq "CLEAN"      }).Count
    $phish = ($Results | Where-Object { $_.IsPhishing -eq $true }).Count
    $reach = ($Results | Where-Object { $_.HTTP_Reachable }).Count
    $certX = ($Results | Where-Object { $_.Cert_Expired }).Count

    function Get-VClass($v) {
        switch ($v) { "MALICIOUS" {"mal"} "SUSPICIOUS" {"sus"} "CLEAN" {"clean"} default {"unk"} }
    }
    function Get-VIcon($v) {
        switch ($v) { "MALICIOUS" {"⛔"} "SUSPICIOUS" {"⚠️"} "CLEAN" {"✅"} default {"❓"} }
    }

    $rows = ""
    foreach ($r in $Results) {
        $vc   = Get-VClass $r.OverallVerdict
        $vi   = Get-VIcon  $r.OverallVerdict

        $httpBadge = if ($r.HTTP_Reachable) {
            $sc = $r.HTTP_Status
            $bc = if ($sc -lt 300) {"ok"} elseif ($sc -lt 400) {"redir"} else {"err"}
            "<span class='http-badge http-$bc'>HTTP $sc</span>"
        } else { "<span class='http-badge http-err'>Onbereikbaar</span>" }

        $certBadge = if (-not $r.Cert_HasCert) {
            "<span class='cert-badge cert-none'>Geen cert</span>"
        } elseif ($r.Cert_Expired) {
            "<span class='cert-badge cert-exp'>Verlopen</span>"
        } elseif ($r.Cert_ExpiresSoon) {
            "<span class='cert-badge cert-soon'>Verloopt ($($r.Cert_DaysLeft)d)</span>"
        } elseif ($r.Cert_SelfSigned) {
            "<span class='cert-badge cert-self'>Self-signed</span>"
        } else {
            "<span class='cert-badge cert-ok'>OK ($($r.Cert_DaysLeft)d)</span>"
        }

        $phishBadge = if ($r.IsPhishing) { "<span class='phish-badge'>🎣 Phishing</span>" } else { "" }

        $secHdrBadge = if ($r.HTTP_MissingSecHeaders) {
            "<span class='miss-hdr' title='Ontbrekend: $($r.HTTP_MissingSecHeaders)'>⚠️ $($r.HTTP_MissingSecHeaders.Split(';').Count) headers</span>"
        } else { "" }

        $vtBadge  = if ($r.VT_Verdict)  { "<span class='src-badge $(Get-VClass $r.VT_Verdict)'>VT: $($r.VT_Verdict)</span>" }  else { "" }
        $otxBadge = if ($r.OTX_Verdict) { "<span class='src-badge $(Get-VClass $r.OTX_Verdict)'>OTX: $($r.OTX_Verdict)</span>" } else { "" }
        $usBadge  = if ($r.US_Verdict)  { "<span class='src-badge $(Get-VClass $r.US_Verdict)'>US: $($r.US_Verdict)</span>" }   else { "" }

        $rows += @"
<tr data-v="$($r.OverallVerdict)">
  <td>
    <div class="url-cell"><span class="vb $vc">$vi $($r.OverallVerdict)</span> $phishBadge</div>
    <code class="url-v" title="$($r.URL)">$($r.Domain)</code>
    <div class="url-full muted">$($r.URL -replace 'https?://','' | ForEach-Object { if ($_.Length -gt 60) { $_.Substring(0,60)+"…" } else { $_ } })</div>
  </td>
  <td>$httpBadge<br><small class="muted">$($r.HTTP_ResponseMs)ms</small><br><small class="muted">$($r.HTTP_Title | ForEach-Object { if ($_.Length -gt 35) { $_.Substring(0,35)+"…" } else { $_ } })</small></td>
  <td>$certBadge<br><small class="muted">$($r.Cert_TLS)</small></td>
  <td class="src-cell">$vtBadge $otxBadge $usBadge</td>
  <td class="muted">$($r.HTTP_Server)<br>$($r.HTTP_Tech | ForEach-Object { if ($_.Length -gt 40) { $_.Substring(0,40) } else { $_ } })</td>
  <td>$secHdrBadge</td>
  <td class="muted ts-c">$($r.Timestamp.Substring(0,19).Replace('T',' '))</td>
</tr>
"@
    }

    $html = @"
<!DOCTYPE html>
<html lang="nl">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>URL Scan Rapport</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Syne:wght@400;600;800&display=swap');
:root{--bg:#080b12;--sf:#0e1220;--bd:#1a2035;--acc:#00e5ff;
  --mal:#ff3b5c;--sus:#f59e0b;--cln:#10b981;--unk:#6b7280;
  --txt:#e2e8f0;--mut:#64748b;--mono:'JetBrains Mono',monospace;--sans:'Syne',sans-serif;}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--txt);font-family:var(--sans);min-height:100vh;}
body::before{content:'';position:fixed;inset:0;pointer-events:none;z-index:999;
  background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,229,255,.007) 2px,rgba(0,229,255,.007) 4px);}
header{padding:1.8rem 2.5rem;border-bottom:1px solid var(--bd);background:linear-gradient(135deg,#0a0e18,var(--bg));position:relative;overflow:hidden;}
header::after{content:'URL';position:absolute;right:2rem;top:50%;transform:translateY(-50%);
  font-size:8rem;font-weight:800;color:rgba(0,229,255,.04);font-family:var(--mono);pointer-events:none;}
.logo{font-family:var(--mono);font-size:.67rem;color:var(--acc);letter-spacing:.2em;text-transform:uppercase;margin-bottom:.35rem;}
h1{font-size:1.6rem;font-weight:800;color:#fff;}
.meta{font-size:.7rem;color:var(--mut);margin-top:.3rem;font-family:var(--mono);}
.stats{display:grid;grid-template-columns:repeat(6,1fr);gap:1px;background:var(--bd);border-bottom:1px solid var(--bd);}
.stat{background:var(--sf);padding:.9rem 1.25rem;}
.sn{font-size:1.9rem;font-weight:800;font-family:var(--mono);line-height:1;}
.sl{font-size:.58rem;text-transform:uppercase;letter-spacing:.11em;color:var(--mut);margin-top:.2rem;}
.s-tot .sn{color:var(--acc);} .s-mal .sn{color:var(--mal);} .s-sus .sn{color:var(--sus);}
.s-cln .sn{color:var(--cln);} .s-ph .sn{color:#f97316;} .s-cert .sn{color:#a78bfa;}
.toolbar{padding:.75rem 2.5rem;background:var(--sf);border-bottom:1px solid var(--bd);display:flex;gap:.55rem;align-items:center;flex-wrap:wrap;}
.toolbar input{flex:1;max-width:260px;padding:.38rem .75rem;background:var(--bg);border:1px solid var(--bd);border-radius:5px;color:var(--txt);font-family:var(--mono);font-size:.77rem;outline:none;}
.toolbar input:focus{border-color:var(--acc);}
.fb{padding:.32rem .78rem;border:1px solid var(--bd);border-radius:5px;background:transparent;color:var(--mut);font-size:.71rem;cursor:pointer;font-family:var(--sans);transition:.1s;}
.fb:hover,.fb.on{background:var(--acc);color:#000;border-color:var(--acc);font-weight:600;}
#tc{margin-left:auto;font-size:.7rem;color:var(--mut);font-family:var(--mono);}
.tw{overflow-x:auto;}
table{width:100%;border-collapse:collapse;font-size:.77rem;}
th{background:#0a0e1a;color:#7891b8;padding:.5rem 1rem;text-align:left;font-size:.61rem;text-transform:uppercase;letter-spacing:.09em;white-space:nowrap;position:sticky;top:0;z-index:5;border-bottom:1px solid var(--bd);}
td{padding:.55rem 1rem;border-bottom:1px solid var(--bd);vertical-align:top;}
tr:hover td{background:rgba(255,255,255,.02);}
tr:last-child td{border-bottom:none;}
.url-cell{margin-bottom:.3rem;}
code.url-v{font-family:var(--mono);color:var(--acc);font-size:.79rem;word-break:break-all;}
.url-full{font-size:.67rem;font-family:var(--mono);word-break:break-all;margin-top:.15rem;}
.ts-c{font-family:var(--mono);font-size:.67rem;white-space:nowrap;}
.muted{color:var(--mut);font-size:.72rem;}
.vb{display:inline-flex;align-items:center;gap:.28rem;padding:.17rem .6rem;border-radius:99px;font-size:.7rem;font-weight:700;font-family:var(--mono);white-space:nowrap;}
.mal{background:rgba(255,59,92,.15);color:var(--mal);border:1px solid rgba(255,59,92,.3);}
.sus{background:rgba(245,158,11,.15);color:var(--sus);border:1px solid rgba(245,158,11,.3);}
.clean{background:rgba(16,185,129,.15);color:var(--cln);border:1px solid rgba(16,185,129,.3);}
.unk{background:rgba(107,114,128,.15);color:var(--unk);border:1px solid rgba(107,114,128,.3);}
.http-badge{display:inline-block;padding:.12rem .45rem;border-radius:4px;font-family:var(--mono);font-size:.67rem;font-weight:600;}
.http-ok  {background:rgba(16,185,129,.15);color:var(--cln);border:1px solid rgba(16,185,129,.3);}
.http-redir{background:rgba(245,158,11,.15);color:var(--sus);border:1px solid rgba(245,158,11,.3);}
.http-err {background:rgba(255,59,92,.15);color:var(--mal);border:1px solid rgba(255,59,92,.3);}
.cert-badge{display:inline-block;padding:.12rem .45rem;border-radius:4px;font-size:.67rem;font-weight:600;}
.cert-ok  {background:rgba(16,185,129,.15);color:var(--cln);border:1px solid rgba(16,185,129,.3);}
.cert-exp {background:rgba(255,59,92,.15);color:var(--mal);border:1px solid rgba(255,59,92,.3);}
.cert-soon{background:rgba(245,158,11,.15);color:var(--sus);border:1px solid rgba(245,158,11,.3);}
.cert-self{background:rgba(167,139,250,.15);color:#a78bfa;border:1px solid rgba(167,139,250,.3);}
.cert-none{background:rgba(107,114,128,.15);color:var(--unk);border:1px solid rgba(107,114,128,.3);}
.phish-badge{display:inline-block;padding:.12rem .45rem;border-radius:4px;font-size:.67rem;font-weight:700;background:rgba(249,115,22,.2);color:#f97316;border:1px solid rgba(249,115,22,.4);}
.src-cell{white-space:nowrap;}
.src-badge{display:inline-block;padding:.1rem .4rem;border-radius:4px;font-size:.63rem;font-family:var(--mono);margin:.08rem .02rem;}
.miss-hdr{display:inline-block;padding:.1rem .4rem;border-radius:4px;font-size:.65rem;background:rgba(245,158,11,.15);color:var(--sus);border:1px solid rgba(245,158,11,.3);cursor:help;}
footer{padding:1.2rem 2.5rem;border-top:1px solid var(--bd);font-size:.68rem;color:var(--mut);font-family:var(--mono);display:flex;justify-content:space-between;background:var(--sf);}
</style>
</head>
<body>
<header>
  <div class="logo">Security Operations · URL Reputatie Scan</div>
  <h1>URL Batch Rapport</h1>
  <div class="meta">Gegenereerd: $ts &nbsp;·&nbsp; $($Results.Count) URLs gescand &nbsp;·&nbsp; VT · OTX · URLScan · HTTP · SSL</div>
</header>
<div class="stats">
  <div class="stat s-tot"><div class="sn">$($Results.Count)</div><div class="sl">Totaal URLs</div></div>
  <div class="stat s-mal"><div class="sn">$malC</div><div class="sl">Malicious</div></div>
  <div class="stat s-sus"><div class="sn">$susC</div><div class="sl">Suspicious</div></div>
  <div class="stat s-cln"><div class="sn">$clnC</div><div class="sl">Clean</div></div>
  <div class="stat s-ph"><div class="sn">$phish</div><div class="sl">Phishing</div></div>
  <div class="stat s-cert"><div class="sn">$certX</div><div class="sl">Cert verlopen</div></div>
</div>
<div class="toolbar">
  <input type="text" id="s" placeholder="Zoek URL, domein, verdict..." oninput="ft()">
  <button class="fb on" onclick="sf('ALL',this)">Alle</button>
  <button class="fb" onclick="sf('MALICIOUS',this)">⛔ Malicious</button>
  <button class="fb" onclick="sf('SUSPICIOUS',this)">⚠️ Suspicious</button>
  <button class="fb" onclick="sf('CLEAN',this)">✅ Clean</button>
  <span id="tc">$($Results.Count) URLs weergegeven</span>
</div>
<div class="tw">
<table><thead><tr>
  <th>URL / Verdict</th><th>HTTP Check</th><th>Certificaat</th>
  <th>Reputatiebronnen</th><th>Tech Stack</th><th>Sec. Headers</th><th>Tijdstip</th>
</tr></thead>
<tbody id="tb">$rows</tbody>
</table>
</div>
<footer>
  <span>URL Scanner · PowerShell editie · Eigen gebruik</span>
  <span>$ts · $($Results.Count) URLs</span>
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
  document.getElementById('tc').textContent=v+' URLs weergegeven';
}
function sf(t,b){af=t;document.querySelectorAll('.fb').forEach(x=>x.classList.remove('on'));b.classList.add('on');ft();}
</script>
</body></html>
"@
    $html | Out-File -FilePath $Path -Encoding UTF8
    Write-Host "[+] HTML dashboard: $Path" -ForegroundColor Green
}

# ─── Main ─────────────────────────────────────────────────────────────────────
$null = New-Item -ItemType Directory -Path $Output -Force

# ── URLs inladen ──────────────────────────────────────────────────────────────
$urls = @()
if ($PSCmdlet.ParameterSetName -eq 'CSV') {
    if (-not (Test-Path $CsvFile)) { Write-Error "CSV niet gevonden: $CsvFile"; exit 1 }
    $csv = Import-Csv $CsvFile
    # Auto-detecteer kolom: url, domain, URL, Domain, etc.
    $col = $csv[0].PSObject.Properties.Name |
           Where-Object { $_ -imatch '^(url|domain|website|link|host)$' } |
           Select-Object -First 1
    if (-not $col) { $col = $UrlColumn }
    if (-not $col -or -not ($csv[0].PSObject.Properties.Name -contains $col)) {
        Write-Error "Kolom '$col' niet gevonden. Beschikbare kolommen: $($csv[0].PSObject.Properties.Name -join ', ')"
        exit 1
    }
    $urls = $csv | ForEach-Object { $_.$col } | Where-Object { $_ -and $_.Trim() }
    Write-Status "[+] CSV geladen: $($urls.Count) URLs uit kolom '$col'"
} else {
    if (-not (Test-Path $TxtFile)) { Write-Error "Bestand niet gevonden: $TxtFile"; exit 1 }
    $urls = Get-Content $TxtFile |
            Where-Object { $_ -and $_.Trim() -and -not $_.TrimStart().StartsWith("#") } |
            ForEach-Object { $_.Trim() }
}

Write-Status ("=" * 65)
Write-Status "  URL Batch Scanner (PowerShell)"
Write-Status "  URLs    : $($urls.Count)"
Write-Status "  Output  : $(Resolve-Path $Output -ErrorAction SilentlyContinue)"
Write-Status "  HTTP    : $(if ($SkipHTTP) { 'Overgeslagen' } else { 'Actief' })"
Write-Status "  Cert    : $(if ($SkipCert) { 'Overgeslagen' } else { 'Actief' })"
Write-Status "  VT Key  : $(if ($VTKey) { 'Ingesteld ✓' } else { 'ONTBREEKT' })"
Write-Status ("=" * 65)

$results = @()
$i = 0
foreach ($url in $urls) {
    $i++
    Write-Host "`n[$i/$($urls.Count)] " -NoNewline -ForegroundColor Yellow
    Write-Host $url

    $r = Invoke-ScanURL $url
    $results += $r

    $color = switch ($r.OverallVerdict) {
        "MALICIOUS"  { "Red" }
        "SUSPICIOUS" { "Yellow" }
        "CLEAN"      { "Green" }
        default      { "Gray" }
    }
    $phishFlag = if ($r.IsPhishing) { " 🎣 PHISHING" } else { "" }
    $httpFlag  = if ($r.HTTP_Reachable) { " HTTP:$($r.HTTP_Status)" } else { " (onbereikbaar)" }
    $certFlag  = if ($r.Cert_Expired) { " CERT:VERLOPEN" } elseif ($r.Cert_ExpiresSoon) { " CERT:$($r.Cert_DaysLeft)d" } else { "" }
    Write-Host "  → $($r.OverallVerdict)$phishFlag$httpFlag$certFlag" -ForegroundColor $color
}

$ts = Get-Date -Format "yyyyMMdd_HHmmss"
Save-CSV  $results "$Output\url_report_$ts.csv"
Save-HTML $results "$Output\url_report_$ts.html"

$malF  = ($results | Where-Object { $_.OverallVerdict -eq "MALICIOUS"  }).Count
$susF  = ($results | Where-Object { $_.OverallVerdict -eq "SUSPICIOUS" }).Count
$phF   = ($results | Where-Object { $_.IsPhishing }).Count
$certF = ($results | Where-Object { $_.Cert_Expired }).Count

Write-Status "`n$("=" * 65)"
Write-Host "  Malicious   : $malF"  -ForegroundColor Red
Write-Host "  Suspicious  : $susF"  -ForegroundColor Yellow
Write-Host "  Phishing    : $phF"   -ForegroundColor $(if ($phF -gt 0) { "Red" } else { "Green" })
Write-Host "  Cert verlopen: $certF" -ForegroundColor $(if ($certF -gt 0) { "Yellow" } else { "Green" })
Write-Status ("=" * 65)

# Open HTML
$htmlPath = "$Output\url_report_$ts.html"
if (Test-Path $htmlPath) { Start-Process $htmlPath }
