# LetsDefend Walkthrough: SOC138 - Detected Suspicious XLS File

Author: CyberPanther232

<img src="https://github.com/CyberPanther232/CTF-Writeups/blob/7dc6598b260327dca6220bd4bf0f0df276de0f35/logo.png?raw=true" alt="Logo" width="200"/>

## Objective

Investigate alert SOC138, confirm whether compromise occurred, extract IOCs, and identify probable initial access.

## Scenario Snapshot

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

Initial assessment: this is high risk because the payload was allowed and not quarantined.

## Walkthrough Steps

<<<<<<< HEAD
### Step 1: Review the Alert Metadata
=======
![image](https://github.com/CyberPanther232/CTF-Writeups/blob/524b69cb7b7e65abe48e108655150607f8b84321/LetsDefend/SOC%20Analyst%20Path/Screenshots/Screenshot%202026-04-06%20204029.png)

In the Endpoint Security (EDR) command-line telemetry, a suspicious PowerShell command was executed with mixed-case obfuscation and a shortened encoded argument (Hit the CommandLine tab, then hit the magnifying glass):
>>>>>>> 2b9e4eb97c21131478d31f8efba85839b3591346

Action:

1. Open the alert details and collect all core fields.
2. Note the source host, file name, hash, and device action.

What to look for:

- Malicious file type (`.xlsm` macro-enabled Office file).
- Security control result (`Allowed` instead of blocked).

Analyst decision:

- Treat as potentially active compromise and continue triage immediately.

### Step 2: Validate Endpoint Execution Activity

Action:

1. Open Endpoint Security (EDR) for host `Sofia`.
2. Inspect command-line history around alert timestamp.
3. Look for PowerShell with encoded or obfuscated arguments.

Evidence found:

1. Mixed-case `POwersheLL` command usage.
2. `-ENCOD` (short form of `-EncodedCommand`).

Why this matters:

- Mixed-case and encoded execution are common evasion techniques in malicious scripting.

### Step 3: Decode and Triage the PowerShell Payload

Action:

1. Decode the base64 command in a safe analysis tool (for example, CyberChef).
2. If output appears broken, account for UTF-16 encoding and remove null bytes.
3. Focus on behavior first, not full beautification.

Key decoded behaviors:

1. `New-Object Net.WebClient` is used for outbound web requests.
2. TLS is forced (`ServicePointManager.SecurityProtocol = TLS12`).
3. A URL list is built and split into multiple candidates.
4. A `foreach` loop attempts `DownloadFile` from each URL.
5. Downloaded executable is launched via `Win32_Process.Create` when size threshold is met.

Analyst decision:

- Classify as downloader/dropper behavior with execution intent.

### Step 4: Extract Network IOCs from Script

Action:

1. Pull all external URLs referenced by the decoded script.
2. Defang the URLs before documentation.

Defanged URLs:

1. hxxp[:]//tudorinvest[.]com/wp-admin/rGtnUb5f/
2. hxxp[:]//dp-womenbasket[.]com/wp-admin/Li/
3. hxxp[:]//stylefix[.]co/guillotine-cross/CTRNOQ/
4. hxxp[:]//ardos[.]com[.]br/simulador/bPNx/
5. hxxp[:]//drtheurelplasticsurgery[.]com/generalo/rhrhflv92/
6. hxxp[:]//bodyinnovation[.]co[.]za/wp-content/2ssHvi/
7. hxxp[:]//nomadco[.]es/wp-admin/MvwVHCG/

### Step 5: Confirm Outbound Communication in Logs

<<<<<<< HEAD
Action:
=======
![image](https://github.com/CyberPanther232/CTF-Writeups/blob/cf830fdd2e53ef10a1e73b14f15e6d945a847297/LetsDefend/SOC%20Analyst%20Path/Screenshots/Screenshot%202026-04-06%20204121.png)

Using the source host IP (`172.16.17.56`) on the alert date, logs show outbound communication with an external destination and suspicious encrypted-looking payload content (`{Data: }`).
>>>>>>> 2b9e4eb97c21131478d31f8efba85839b3591346

1. Open Log Management for the same date and source IP `172.16.17.56`.
2. Filter for outbound events and suspicious raw payloads.

Evidence found:

1. Successful external communication from endpoint.
2. Destination IP: `177[.]53[.]143[.]89` over port `443`.
3. Raw payload contains encrypted-looking data (`{Data: ...}`).

Analyst decision:

- This is not just an attempted infection; C2 communication likely succeeded.

### Step 6: Contain the Endpoint

Action:

1. Isolate/contain host `Sofia` in EDR immediately.
2. Prevent further beaconing and data exfiltration.

<<<<<<< HEAD
Containment rationale:
=======
![image](https://github.com/CyberPanther232/CTF-Writeups/blob/cf830fdd2e53ef10a1e73b14f15e6d945a847297/LetsDefend/SOC%20Analyst%20Path/Screenshots/Screenshot%202026-04-06%20215311.png)

No direct web download evidence was found for the initial XLSM from the affected endpoint logs. A likely delivery path is email.
>>>>>>> 2b9e4eb97c21131478d31f8efba85839b3591346

1. Malicious XLSM was allowed.
2. Obfuscated PowerShell executed.
3. C2 traffic is observed.

### Step 7: Investigate Initial Access (RCA)

Action:

1. Check whether the file was downloaded directly from the web.
2. If not found, pivot to Email Security for same filename/sender patterns.

Email evidence observed:

| Field | Value |
| --- | --- |
| From | jack[@]avenatech[.]io |
| To | nolan@letsdefend.io |
| Subject | Order Sheet and Specifications |
| Date | Apr 10, 2023, 08:30 AM |
| Action | Allowed |

RCA hypothesis:

- The attachment was likely delivered via phishing email using the same lure naming pattern.

## Final Analyst Conclusion

1. Host executed obfuscated encoded PowerShell from a malicious Office context.
2. Script behavior matches malware dropper/downloader tactics.
3. External C2 communication occurred successfully.
4. Host should be treated as compromised and handled through full IR workflow.

## Artifacts and IOCs

![image](https://github.com/CyberPanther232/CTF-Writeups/blob/cf830fdd2e53ef10a1e73b14f15e6d945a847297/LetsDefend/SOC%20Analyst%20Path/Screenshots/Screenshot%202026-04-06%20222854.png)

| Type | Value | Notes |
| --- | --- | --- |
| C2 IP | 177[.]53[.]143[.]89 | Destination seen in suspicious outbound traffic |
| Email Sender | jack[@]avenatech[.]io | Potential phishing source |
| File Hash (MD5) | 7ccf88c0bbe3b29bf19d877c4596a8d | Malicious attachment hash |
| Attachment Name | ORDER SHEET & SPEC.xlsm | Initial payload filename |

## Recommended SOC Actions

<<<<<<< HEAD
1. Block confirmed C2 IP and all extracted domains at firewall/proxy controls.
2. Run environment-wide IOC sweep for hash, filename, sender, and destination IP.
3. Hunt for Office-to-PowerShell process chains and encoded command patterns.
4. Reimage affected endpoint(s) if persistence or secondary payload execution is suspected.
5. Tune detections for mixed-case PowerShell, `-EncodedCommand`, and suspicious `DownloadFile` usage.
=======
![image](https://github.com/CyberPanther232/CTF-Writeups/blob/cf830fdd2e53ef10a1e73b14f15e6d945a847297/LetsDefend/SOC%20Analyst%20Path/Screenshots/Screenshot%202026-04-06%20215307.png)

1. Block all listed domains and the confirmed C2 IP at network controls.
2. Search environment-wide for the MD5 and filename to identify additional impacted hosts.
3. Hunt for parent-child process chains involving Office spawning PowerShell.
4. Quarantine and reimage affected endpoint(s) as needed.
5. Add detections for encoded PowerShell, mixed-case bypass patterns, and suspicious `DownloadFile` usage.
>>>>>>> 2b9e4eb97c21131478d31f8efba85839b3591346
