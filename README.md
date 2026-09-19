<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:0d1117,50:0a3d62,100:00e5ff&height=210&section=header&text=Gaurav%20Ghandat&fontSize=52&fontColor=ffffff&animation=fadeIn&fontAlignY=36&desc=SOC%20Analyst%20%C2%B7%20Blue%20Team%20%C2%B7%20Splunk%20SIEM&descAlignY=58&descSize=18" width="100%" alt="Gaurav Ghandat banner"/>

<a href="https://github.com/GauravGhandat-23">
  <img src="https://readme-typing-svg.demolab.com?font=JetBrains+Mono&weight=600&size=21&duration=3200&pause=900&color=00E5FF&center=true&vCenter=true&width=760&lines=Turning+raw+logs+into+detections;Hunting+brute-force%2C+DNS+tunneling+%26+C2+beacons;Splunk+SIEM+%7C+MITRE+ATT%26CK+%7C+Incident+Response;Windows+Server+%2B+Active+Directory+%2B+Linux+admin;Securing+systems%2C+one+log+at+a+time" alt="Typing SVG"/>
</a>

<br/>

![Profile Views](https://komarev.com/ghpvc/?username=GauravGhandat-23&label=Profile%20views&color=0e75b6&style=flat-square)
![Followers](https://img.shields.io/github/followers/GauravGhandat-23?style=flat-square&logo=github&label=Followers&color=0e75b6)
![Location](https://img.shields.io/badge/Nashik-India-138808?style=flat-square&logo=googlemaps&logoColor=white)
![Status](https://img.shields.io/badge/Status-Monitoring%20the%20logs-00e5ff?style=flat-square&labelColor=0d1117)

</div>

---

## 🖥️ `whoami`

```bash
gaurav@soc-nashik:~$ whoami
gaurav_uttam_ghandat  # SOC Analyst | System Administrator | Blue Teamer

gaurav@soc-nashik:~$ cat /etc/mission
Turn noisy logs into high-fidelity detections,
and high-fidelity detections into fast decisions.

gaurav@soc-nashik:~$ cat ~/.stack
SIEM      : Splunk Enterprise (SPL, dashboards, alerting, correlation)
FRAMEWORK : MITRE ATT&CK | Cyber Kill Chain | OWASP Top 10 | ITIL
INFRA     : Windows Server 2012-2025 | Active Directory | RHEL / Rocky / Ubuntu
LANGUAGES : Python | PowerShell | Bash | SQL

gaurav@soc-nashik:~$ uptime
System Administrator @ Bits & Bytes Services Pvt. Ltd  (since 06/2025)
```

---

## 🔄 How I Work: Detection Pipeline

Every project here follows the same loop: **collect → correlate → alert → triage → respond → tune.**

```mermaid
flowchart LR
    A[("🖥️ Windows / Linux<br/>Endpoint Logs")] --> S
    B[("🌐 Zeek · Apache<br/>Network & Web")] --> S
    C[("☁️ AWS GuardDuty<br/>Cloud Findings")] --> S
    S{{"Splunk Enterprise<br/>Ingest · Parse · Index"}} --> D["SPL Correlation<br/>& Detection Rules"]
    D --> E["🚨 Real-time<br/>Alerts"]
    E --> F["🔍 Triage &<br/>IOC Analysis"]
    F --> G["🛡️ Contain &<br/>Respond"]
    G -. "tune & feedback" .-> D

    classDef src fill:#0a3d62,stroke:#00e5ff,color:#ffffff;
    classDef core fill:#00e5ff,stroke:#0a3d62,color:#0d1117;
    classDef act fill:#1b2838,stroke:#00e5ff,color:#ffffff;
    class A,B,C src;
    class S core;
    class D,E,F,G act;
```

---

## 🎯 Detection Coverage (MITRE ATT&CK)

| Tactic | Technique | How I detect it | Data source |
|:--|:--|:--|:--|
| Credential Access | **T1110** Brute Force | Failed-auth spikes per source IP within a time window, plus many distinct usernames | Linux SSH / auth logs |
| Command & Control | **T1071.004** DNS | Abnormally long or high-volume queries per host (tunneling patterns) | Zeek `dns.log` |
| Command & Control | **T1071.001** Web Protocols | Near-constant connection intervals with low jitter (beaconing) | Zeek `conn.log` |
| Initial Access | **T1190** Exploit Public-Facing App | Traversal, SQLi and XSS patterns in web requests | Apache access logs |
| Multi-stage | Cross-source correlation | Linking network, host and cloud signals into one attack story | Zeek + SSH + Apache + GuardDuty |

<details>
<summary><b>🔬 Peek inside the detection lab: sample SPL (click to expand)</b></summary>

<br/>

> Index and sourcetype names are examples. Adjust them to your own environment.

**SSH brute-force (T1110)**

```spl
index=linux sourcetype=linux_secure "Failed password"
| rex "from (?<src_ip>\d{1,3}(?:\.\d{1,3}){3})"
| rex "for (?:invalid user )?(?<user>\S+)"
| bin _time span=5m
| stats count AS attempts, dc(user) AS users_tried BY _time, src_ip
| where attempts > 10
| sort - attempts
```

**DNS tunneling (T1071.004)**

```spl
index=zeek sourcetype=bro:dns:json
| eval src='id.orig_h', qlen=len(query)
| stats count AS queries, dc(query) AS unique_queries, avg(qlen) AS avg_len BY src
| where avg_len > 40 AND unique_queries > 100
| sort - unique_queries
```

**C2 beaconing (T1071.001)**

```spl
index=zeek sourcetype=bro:conn:json
| eval src='id.orig_h', dst='id.resp_h'
| sort 0 src dst _time
| streamstats current=f last(_time) AS prev BY src dst
| eval delta=_time-prev
| stats count, avg(delta) AS avg_interval, stdev(delta) AS jitter BY src dst
| where count > 30 AND jitter < 5
```

**Web exploitation attempts (T1190)**

```spl
index=web sourcetype=access_combined
| where match(_raw, "(?i)(\.\./|union(\s|%20|\+)+select|<script|etc/passwd)")
| stats count, values(uri_path) AS paths BY clientip
| sort - count
```

</details>

---

## 📌 Featured Projects

<table>
<tr>
<td width="50%" valign="top">

### 🔹 Enterprise Log Analysis & Threat Detection
`Splunk Enterprise` `Zeek` `Apache` `Linux SSH` `AWS GuardDuty`

- Centralized DNS, HTTP, SSH, Apache and cloud logs in one SIEM
- Wrote SPL detections for brute force, DNS tunneling, malware beaconing and web exploitation
- Built real-time alert rules for incident response
- Correlated multi-source logs to surface advanced attack patterns

</td>
<td width="50%" valign="top">

### 🔹 SOC Monitoring Dashboard
`Splunk Enterprise` `SPL`

- Designed enterprise SOC dashboards for analysts
- Visualized authentication anomalies, attack trends, firewall events and web traffic
- Built brute-force detection views for at-a-glance triage
- Turned raw telemetry into actionable security insight

</td>
</tr>
</table>

---

## 🧰 Tech Arsenal

<table>
<tr>
<td><b>🛡️ SIEM & SOC</b></td>
<td>

![Splunk](https://img.shields.io/badge/Splunk-000000?style=flat-square&logo=splunk&logoColor=white)
![SPL](https://img.shields.io/badge/SPL-Queries-FF6F00?style=flat-square)
![MITRE](https://img.shields.io/badge/MITRE-ATT%26CK-B22222?style=flat-square)
![Alert Triage](https://img.shields.io/badge/Alert-Triage-0a3d62?style=flat-square)
![IR](https://img.shields.io/badge/Incident-Response-0a3d62?style=flat-square)
![Threat Detection](https://img.shields.io/badge/Threat-Detection-0a3d62?style=flat-square)

</td>
</tr>
<tr>
<td><b>🪟 Windows</b></td>
<td>

![Windows Server](https://img.shields.io/badge/Windows%20Server-2012%E2%80%932025-0078D4?style=flat-square&logo=windows&logoColor=white)
![Active Directory](https://img.shields.io/badge/Active%20Directory-PDC%20%7C%20CDC%20%7C%20RODC-0078D4?style=flat-square)
![Group Policy](https://img.shields.io/badge/Group-Policy-0078D4?style=flat-square)
![DNS DHCP](https://img.shields.io/badge/DNS-DHCP-0078D4?style=flat-square)
![Hyper-V](https://img.shields.io/badge/Hyper--V-Virtualization-0078D4?style=flat-square)

</td>
</tr>
<tr>
<td><b>🐧 Linux</b></td>
<td>

![Ubuntu](https://img.shields.io/badge/Ubuntu-E95420?style=flat-square&logo=ubuntu&logoColor=white)
![RHEL](https://img.shields.io/badge/RHEL-EE0000?style=flat-square&logo=redhat&logoColor=white)
![Rocky](https://img.shields.io/badge/Rocky%20Linux-10B981?style=flat-square&logo=rockylinux&logoColor=white)
![Kali](https://img.shields.io/badge/Kali%20Linux-557C94?style=flat-square&logo=kalilinux&logoColor=white)
![Hardening](https://img.shields.io/badge/System-Hardening-333333?style=flat-square)
![YUM](https://img.shields.io/badge/YUM-Server-EE0000?style=flat-square)

</td>
</tr>
<tr>
<td><b>🔧 Security Tools</b></td>
<td>

![Wireshark](https://img.shields.io/badge/Wireshark-1679A7?style=flat-square&logo=wireshark&logoColor=white)
![Nmap](https://img.shields.io/badge/Nmap-4682B4?style=flat-square)
![Burp Suite](https://img.shields.io/badge/Burp%20Suite-FF6633?style=flat-square)
![Metasploit](https://img.shields.io/badge/Metasploit-2596CD?style=flat-square&logo=metasploit&logoColor=white)
![Zeek](https://img.shields.io/badge/Zeek-Network%20Monitor-0a3d62?style=flat-square)

</td>
</tr>
<tr>
<td><b>⚙️ Automation</b></td>
<td>

![Python](https://img.shields.io/badge/Python-3776AB?style=flat-square&logo=python&logoColor=white)
![PowerShell](https://img.shields.io/badge/PowerShell-5391FE?style=flat-square&logo=powershell&logoColor=white)
![Bash](https://img.shields.io/badge/Bash-4EAA25?style=flat-square&logo=gnubash&logoColor=white)
![SQL](https://img.shields.io/badge/SQL-336791?style=flat-square&logo=postgresql&logoColor=white)

</td>
</tr>
<tr>
<td><b>🌐 Networking & Cloud</b></td>
<td>

![TCP/IP](https://img.shields.io/badge/TCP%2FIP-Routing-0a3d62?style=flat-square)
![VPN](https://img.shields.io/badge/VPN-Firewall-0a3d62?style=flat-square)
![LAN/WAN](https://img.shields.io/badge/LAN%2FWAN-Monitoring-0a3d62?style=flat-square)
![OCI](https://img.shields.io/badge/Oracle%20Cloud-OCI-F80000?style=flat-square&logo=oracle&logoColor=white)
![AWS](https://img.shields.io/badge/AWS-GuardDuty-FF9900?style=flat-square&logo=amazonaws&logoColor=white)

</td>
</tr>
</table>

---

## 💼 Experience

| | |
|:--|:--|
| **Role** | System Administrator, *Bits & Bytes Services Pvt. Ltd*, Nashik |
| **Since** | 06/2025 |
| **Scope** | Windows Server & Linux infrastructure for enterprise clients |
| **Identity & Access** | Active Directory, Group Policy, DNS, DHCP, user access control |
| **Operations** | SLA-driven L1/L2 support, LAN/WAN & VPN monitoring, ITIL incident management |
| **Security** | System hardening, patch management, backup, access control |
| **Infrastructure** | Server deployment, virtualization, storage and data center operations |

---

## 🏆 Certifications

| Domain | Credentials |
|:--|:--|
| 🔴 **Offensive** | ![CRTA](https://img.shields.io/badge/CRTA-Certified%20Red%20Team%20Analyst-c0392b?style=flat-square) ![PEH](https://img.shields.io/badge/PEH%20%7C%20EH-Netleap-c0392b?style=flat-square) |
| 🔵 **Defensive** | ![SBT](https://img.shields.io/badge/Security%20Blue%20Team-Network%20Analysis-0a3d62?style=flat-square) ![arcX](https://img.shields.io/badge/arcX-Threat%20Intelligence%20Analyst-0a3d62?style=flat-square) |
| ☁️ **Cloud** | ![OCI](https://img.shields.io/badge/Oracle%20OCI%202025-Architect%20Associate-F80000?style=flat-square&logo=oracle&logoColor=white) |
| 🛡️ **Cyber Foundations** | ![Google](https://img.shields.io/badge/Google-Professional%20Cybersecurity-4285F4?style=flat-square&logo=google&logoColor=white) ![Cisco](https://img.shields.io/badge/Cisco-Intro%20to%20Cybersecurity-1BA0D7?style=flat-square&logo=cisco&logoColor=white) ![Reliance](https://img.shields.io/badge/Reliance%20Foundation-Cyber%20Security%20Associate-555555?style=flat-square) ![TechM](https://img.shields.io/badge/Tech%20Mahindra-Cyber%20Security%20Program-E31837?style=flat-square) |
| 🖧 **Infrastructure** | ![CCNA](https://img.shields.io/badge/CCNA-Cisco-1BA0D7?style=flat-square) ![MCSA](https://img.shields.io/badge/MCSA-Microsoft-0078D4?style=flat-square) ![RHCSA](https://img.shields.io/badge/RHCSA-Red%20Hat-EE0000?style=flat-square) ![RHCE](https://img.shields.io/badge/RHCE-Red%20Hat-EE0000?style=flat-square) ![Edureka](https://img.shields.io/badge/Edureka-Linux%20Fundamentals-333333?style=flat-square) |

---

## 🚀 Where I'm Heading

- [x] Centralized log monitoring and multi-source correlation in Splunk
- [x] Real-time alerting and SOC dashboards
- [ ] Detection-as-code: version-controlled detection rules
- [ ] Automating repetitive triage steps with Python and PowerShell
- [ ] Deeper cloud security monitoring across AWS and OCI

---

## 📊 GitHub Analytics

<div align="center">

<img height="170" src="https://github-readme-stats.vercel.app/api?username=GauravGhandat-23&show_icons=true&theme=tokyonight&hide_border=true&count_private=true&include_all_commits=true" alt="GitHub Stats"/>
<img height="170" src="https://github-readme-stats.vercel.app/api/top-langs/?username=GauravGhandat-23&layout=compact&theme=tokyonight&hide_border=true" alt="Top Languages"/>

<img src="https://streak-stats.demolab.com?user=GauravGhandat-23&theme=tokyonight&hide_border=true" alt="GitHub Streak"/>

</div>

---

## 🐍 Contribution Snake

<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/GauravGhandat-23/GauravGhandat-23/output/github-snake-dark.svg"/>
  <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/GauravGhandat-23/GauravGhandat-23/output/github-snake.svg"/>
  <img alt="Contribution snake animation" src="https://raw.githubusercontent.com/GauravGhandat-23/GauravGhandat-23/output/github-snake.svg"/>
</picture>

</div>

---

## 🎓 Education

**B.E. Computer Engineering**, Brahma Valley College of Engineering, Nashik
`06/2022 – 05/2025` · CGPA **7.66 / 10**

---

## 📫 Let's Connect

<div align="center">

<a href="mailto:gauravghandat23@gmail.com"><img src="https://img.shields.io/badge/Email-D14836?style=for-the-badge&logo=gmail&logoColor=white" alt="Email"/></a>
<a href="https://linkedin.com/in/gaurav-ghandat-68a5a22b4"><img src="https://img.shields.io/badge/LinkedIn-0077B5?style=for-the-badge&logo=linkedin&logoColor=white" alt="LinkedIn"/></a>
<a href="https://github.com/GauravGhandat-23"><img src="https://img.shields.io/badge/GitHub-100000?style=for-the-badge&logo=github&logoColor=white" alt="GitHub"/></a>

<br/><br/>

<i>🔐 "Securing systems, one log at a time."</i>

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:00e5ff,50:0a3d62,100:0d1117&height=120&section=footer" width="100%" alt="footer"/>

</div>
