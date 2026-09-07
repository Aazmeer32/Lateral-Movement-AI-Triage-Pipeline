# 🛡️ Autonomous Purple Team Lab & AI Triage Pipeline

[![Architecture](https://img.shields.io/badge/Architecture-4--Node%20VirtualBox-blue?style=flat-square&logo=virtualbox)](https://www.virtualbox.org/)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-T1047%20%7C%20T1021.002-red?style=flat-square)](https://attack.mitre.org/)
[![SIEM](https://img.shields.io/badge/SIEM-Splunk%20Enterprise-green?style=flat-square&logo=splunk)](https://www.splunk.com/)
[![Local AI](https://img.shields.io/badge/AI%20Engine-Ollama%20%2F%20Qwen2--0.5B-purple?style=flat-square)](https://ollama.com/)
[![Status](https://img.shields.io/badge/Phase%201-Completed-brightgreen?style=flat-square)]()

---

## 📌 Executive Overview

This repository documents the end-to-end design, execution, and detection of enterprise threat vectors inside an isolated 4-node VirtualBox environment. 

The core objective of this project is to bridge **offensive adversary emulation**, **granular endpoint/kernel telemetry collection**, **vendor-agnostic detection engineering**, and **automated on-premise AI incident response triage**.

> **Note on Data Privacy:** All AI threat triage operations are processed entirely on-premises using localized LLMs via Ollama. No internal log telemetry or system metadata is exposed to public cloud APIs.

---

## 🏗️ Virtual Environment Architecture

                   ┌────────────────────────────────┐
                   │          Arch Linux            │
                   │    (Offensive Operator)        │
                   │   IP: 192.168.30.x (Local)     │
                   └───────────────┬────────────────┘
                                   │
                     [WMI / RPC]   │ [SMB / Port 445]
                                   ▼
                   ┌────────────────────────────────┐
                   │       Windows 10 Target        │
                   │   (Sysmon Telemetry Agent)     │
                   │        IP: 192.168.30.3        │
                   └───────────────┬────────────────┘
                                   │
                      [Forwarder]  │ [Sysmon Event ID 1]
                                   ▼
                   ┌────────────────────────────────┐
                   │     Ubuntu SOC / SIEM Server   │
                   │ Splunk Enterprise & Ollama API │
                   │        IP: 192.168.30.4        │
                   └────────────────────────────────┘

---

## 🚀 Execution Lifecycle: Phase 1 — WMI Lateral Movement & AI Triage

### 1. Offensive Emulation (Red Team)
* **Technique Executed:** Non-interactive remote code execution via Windows Management Instrumentation (WMI).
* **Tools Used:** Impacket (`wmiexec.py`).
* **Underlying Protocol Mechanics:** Negotiated authentication via SMB (`TCP 445`), initialized DCOM session over RPC Endpoint Mapper (`TCP 135`), and executed commands through dynamic RPC high-ports without dropping physical binaries to disk.
* **Redirection Artifact:** Output written temporarily to administrative shares (`\\127.0.0.1\ADMIN$\`).

```bash
# Execute remote command shell via WMI
wmiexec.py Administrator:'<PASSWORD>'@192.168.30.3
2. Telemetry & Forensics (Blue Team)Captured granular, kernel-level process creation traces from Sysmon Event ID 1 on the target Windows endpoint:Field NameExtracted ValueBehavioral SignificanceParentImageC:\Windows\System32\wbem\WmiPrvSE.exeWMI Provider Host acting as parent processImageC:\Windows\System32\cmd.exeInteractive command interpreter spawnedParentUserNT AUTHORITY\NETWORK SERVICENetwork service account executing high-privilege shellCommandLinecmd.exe /Q /c whoami /all 1>\\127.0.0.1\ADMIN$\...Standard output redirected back to hidden SMB share3. Detection EngineeringTo catch this activity, a custom Sigma Rule was written and translated into Splunk Search Processing Language (SPL) utilizing inline regular expressions to parse raw XML event data (XmlWinEventLog:Microsoft-Windows-Sysmon/Operational):Splunk SPLsourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1 "WmiPrvSE.exe" "ADMIN$"
| rex field=_raw "<Data Name="ParentImage">(?<ParentImage>[^<]+)</Data>"
| rex field=_raw "<Data Name="Image">(?<Image>[^<]+)</Data>"
| rex field=_raw "<Data Name="CommandLine">(?<CommandLine>[^<]+)</Data>"
| rex field=_raw "<Data Name="User">(?<User>[^<]+)</Data>"
| search ParentImage="*\\WmiPrvSE.exe" Image="*\\cmd.exe" CommandLine="*ADMIN$*"
| table _time Host User ParentImage Image CommandLine
4. Automated AI Incident Triage PipelineA custom Python automation bridge (triage_ai.py) extracts raw JSON log payloads from the SIEM and transmits structured prompts to a local Ollama REST API instance running qwen2:0.5b on the Ubuntu SOC server (192.168.30.4:11434).Python Bridge Snippet:Pythonimport json
import requests

def generate_ai_triage(sysmon_event):
    url = "[http://192.168.30.4:11434/api/generate](http://192.168.30.4:11434/api/generate)"
    prompt = f"""
    You are an AI SOC Analyst evaluating a potential security incident.
    Analyze the following Sysmon log payload and provide an operational triage report:
    
    Log Data:
    {json.dumps(sysmon_event, indent=2)}
    
    Format:
    1. Threat Summary
    2. Threat Actor Technique (MITRE ATT&CK Mapping)
    3. Severity Level (Low/Medium/High/Critical)
    4. Recommended Immediate Containment Steps
    """
    
    payload = {"model": "qwen2:0.5b", "prompt": prompt, "stream": False}
    response = requests.post(url, json=payload)
    return response.json().get('response', '')
📊 Sample AI Triage OutputPlaintext[!] EXECUTING AUTOMATED AI TRIAGE PIPELINE ---

1. Threat Summary:
Unsanctioned remote execution detected on endpoint Win10-RDP-Target via WMI provider process.

2. Threat Actor Technique (MITRE ATT&CK Mapping):
- MITRE ATT&CK T1047: Windows Management Instrumentation
- MITRE ATT&CK T1021.002: Remote Services - SMB/Windows Admin Shares

3. Severity Level: 
HIGH (Execution under NT AUTHORITY\NETWORK SERVICE spawning cmd.exe with ADMIN$ stdout redirection)

4. Recommended Immediate Containment Steps:
- Isolate host Win10-RDP-Target from local subnet via network firewall rules.
- Terminate child process cmd.exe and inspect parent process WmiPrvSE.exe.
- Audit Network Logon (Event ID 4624 Type 3) events for user account compromise.
🗺️ Project Roadmap[x] Phase 1: WMI Lateral Movement, Sysmon Process Lineage Analysis, Splunk Regex Extraction, and Local LLM Triage.[ ] Phase 2 (In Development): Active Directory Kerberoasting (GetUserSPNs.py), Event ID 4769 Analysis, & Ticket Hash Triage.[ ] Phase 3 (Planned): LSASS Memory Credential Dumping (secretsdump.py), Sysmon Event 10 Detection, & AI Remediation.[ ] Phase 4 (Planned): Cross-Platform Network Pivoting, TShark/PCAP Packet Analysis, & Full Automated Triage.
