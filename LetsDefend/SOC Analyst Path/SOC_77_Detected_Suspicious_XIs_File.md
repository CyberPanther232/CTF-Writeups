# LetsDefend Monitoring Alert SOC138 - Detected Suspicious XLS File

## Walkthrough

Author: CyberPanther232

<img src="https://github.com/CyberPanther232/CTF-Writeups/blob/7dc6598b260327dca6220bd4bf0f0df276de0f35/logo.png?raw=true" alt="Logo" width="200"/>

## Alert Overview

| Field | Value |
| --- | --- |
| Event ID | 77 |
| Event Time | Mar 13, 2021, 08:20 PM |
| Rule | SOC138 - Detected Suspicious XLS File |
| Analyst Level | Security Analyst |
| Source Address | 172.16.17.56 |
| Source Hostname | Sofia |
| File Name | ORDER SHEET & SPEC.xlsm |
| File Hash (MD5) | 7ccf88c0bbe3b29bf19d877c4596a8d |
| File Size | 2.66 MB |
| Device Action | Allowed |

Initial triage conclusion: the malicious attachment was not blocked, so this case should be treated as an active compromise until proven otherwise.

## Endpoint Security Analysis

![image](https://github.com/CyberPanther232/CTF-Writeups/blob/524b69cb7b7e65abe48e108655150607f8b84321/LetsDefend/SOC%20Analyst%20Path/Screenshots/Screenshot%202026-04-06%20204029.png)

In the Endpoint Security (EDR) command-line telemetry, a suspicious PowerShell command was executed with mixed-case obfuscation and a shortened encoded argument (Hit the CommandLine tab, then hit the magnifying glass):

1. `POwersheLL` casing variation: often used to evade simple pattern-based detections.
2. `-ENCOD`: short form of `-EncodedCommand`, commonly used to run base64 payloads.

### Why this matters

Encoded PowerShell can be legitimate, but in this context it is suspicious due to obfuscation, downloader behavior, and external network communication.

### Decoding tip

PowerShell encoded commands are typically UTF-16. If you decode in CyberChef, remove null bytes to make the output readable.

## Key Behavioral Findings from Decoded Script

The decoded script reveals classic dropper behavior:

1. Creates a web client object (`New-Object Net.WebClient`) to make outbound HTTP requests.
2. Forces TLS 1.2 (`ServicePointManager.SecurityProtocol = TLS12`) for secure transport.
3. Builds and splits a list of multiple external URLs.
4. Iterates through those URLs in a `foreach` loop.
5. Attempts to `DownloadFile` an executable into the user profile path.
6. Executes the downloaded payload via `Win32_Process.Create` if size checks pass.

### Defanged URLs observed in script

1. hxxp[:]//tudorinvest[.]com/wp-admin/rGtnUb5f/
2. hxxp[:]//dp-womenbasket[.]com/wp-admin/Li/
3. hxxp[:]//stylefix[.]co/guillotine-cross/CTRNOQ/
4. hxxp[:]//ardos[.]com[.]br/simulador/bPNx/
5. hxxp[:]//drtheurelplasticsurgery[.]com/generalo/rhrhflv92/
6. hxxp[:]//bodyinnovation[.]co[.]za/wp-content/2ssHvi/
7. hxxp[:]//nomadco[.]es/wp-admin/MvwVHCG/

## Log Management Findings

![image](https://github.com/CyberPanther232/CTF-Writeups/blob/cf830fdd2e53ef10a1e73b14f15e6d945a847297/LetsDefend/SOC%20Analyst%20Path/Screenshots/Screenshot%202026-04-06%20204121.png)

Using the source host IP (`172.16.17.56`) on the alert date, logs show outbound communication with an external destination and suspicious encrypted-looking payload content (`{Data: }`).

Confirmed C2 destination:

- `177[.]53[.]143[.]89`

This indicates successful command-and-control communication, not just blocked attempts.

## Containment Decision

Contain the host immediately.

Rationale:

1. Malicious macro-enabled file was allowed.
2. Obfuscated PowerShell executed successfully.
3. Outbound communication to suspected C2 is present.

## Root Cause Analysis (RCA) Hypothesis

![image](https://github.com/CyberPanther232/CTF-Writeups/blob/cf830fdd2e53ef10a1e73b14f15e6d945a847297/LetsDefend/SOC%20Analyst%20Path/Screenshots/Screenshot%202026-04-06%20215311.png)

No direct web download evidence was found for the initial XLSM from the affected endpoint logs. A likely delivery path is email.

From the Email Security panel, a matching filename was observed in an allowed message:

| Field | Value |
| --- | --- |
| From | jack@avenatech.io |
| To | nolan@letsdefend.io |
| Subject | Order Sheet and Specifications |
| Date | Apr 10, 2023, 08:30 AM |
| Action | Allowed |

Although the email timestamp differs from the original alert timeline, it supports a realistic and recurring phishing delivery pattern using the same lure filename.

## Incident Summary

1. Obfuscated, encoded PowerShell was executed on the endpoint.
2. Endpoint behavior is consistent with malware dropper activity.
3. Successful communication with an external C2 IP was observed.
4. The host should be considered compromised and contained.

## Artifacts and IOCs

![image](https://github.com/CyberPanther232/CTF-Writeups/blob/cf830fdd2e53ef10a1e73b14f15e6d945a847297/LetsDefend/SOC%20Analyst%20Path/Screenshots/Screenshot%202026-04-06%20222854.png)

| Type | Value | Notes |
| --- | --- | --- |
| C2 IP | 177[.]53[.]143[.]89 | Destination seen in suspicious outbound traffic |
| Email Sender | jack[@]avenatech[.]io | Potential phishing source |
| File Hash (MD5) | 7ccf88c0bbe3b29bf19d877c4596a8d | Malicious attachment hash |
| Attachment Name | ORDER SHEET & SPEC.xlsm | Initial payload filename |

## Recommended Follow-Up Actions

![image](https://github.com/CyberPanther232/CTF-Writeups/blob/cf830fdd2e53ef10a1e73b14f15e6d945a847297/LetsDefend/SOC%20Analyst%20Path/Screenshots/Screenshot%202026-04-06%20215307.png)

1. Block all listed domains and the confirmed C2 IP at network controls.
2. Search environment-wide for the MD5 and filename to identify additional impacted hosts.
3. Hunt for parent-child process chains involving Office spawning PowerShell.
4. Quarantine and reimage affected endpoint(s) as needed.
5. Add detections for encoded PowerShell, mixed-case bypass patterns, and suspicious `DownloadFile` usage.
