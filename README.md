# IOC Scanner

Multi-source IOC enrichment tool voor threat intelligence onderzoek.
Ondersteunt: IP-adressen, domeinen, URLs, file hashes (MD5/SHA256), e-mailadressen.

## Bronnen

| Bron | Waarvoor | Limiet gratis |
|---|---|---|
| VirusTotal | Alle types | 4 req/min, 500/dag |
| AlienVault OTX | Alle types | Ruim |
| AbuseIPDB | IP-adressen | 1.000/dag |
| URLScan.io | URL, domein, IP | 1.000/dag |
| HaveIBeenPwned | E-mailadressen | Geen key nodig |

## Varianten

### Optie A — HTML GUI (aanbevolen voor laptop)

```
Dubbelklik op ioc_scanner_gui.html → opent in browser
```

- Geen installatie nodig
- Plakken vanuit clipboard, handmatig typen of CSV uploaden
- Resultaten direct zichtbaar in de GUI
- API keys opslaan via knop rechtsboven
- Export naar CSV en HTML

### Optie B — PowerShell (laptop, geen Python nodig)

```powershell
# Enkel IOC
.\ioc_scanner.ps1 -IOC "185.220.101.1"

# Batch vanuit bestand
.\ioc_scanner.ps1 -File .\iocs.txt

# URL-lijst met HTTP check + certificaat check
.\url_scanner.ps1 -CsvFile .\urls.csv
```

### Optie C — Python (stand-alone machine met internet)

```bash
pip3 install requests
python3 ioc_scanner.py -i 185.220.101.1
python3 ioc_scanner.py -f iocs.txt
```

## API keys instellen (PowerShell / Python)

```powershell
$env:VT_API_KEY        = "jouw_key"
$env:ABUSEIPDB_API_KEY = "jouw_key"
$env:OTX_API_KEY       = "jouw_key"
$env:URLSCAN_API_KEY   = "jouw_key"
```

## URL scanner extra functies

- Actieve HTTP check (bereikbaar, statuscode, redirect, response tijd)
- SSL/TLS certificaat check (geldigheid, verlopen, self-signed, TLS versie)
- Phishing detectie via URLScan categorieën
- Ontbrekende security headers detectie

## Gemaakt door

Gemaakt door Jeffrey
