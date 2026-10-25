<div align="center">

<!-- 🎬 1. HERO — Animated Cyber Defender Banner + Name + Viewfinder -->
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="./assets/hero.svg?v=21"/>
  <source media="(prefers-color-scheme: light)" srcset="./assets/hero.svg?v=21"/>
  <img src="./assets/hero.svg?v=21" width="100%" alt="Gaurav Ghandat — SOC Analyst &amp; Blue Team Defender"/>
</picture>

<br/><br/>

[![Profile Views](https://komarev.com/ghpvc/?username=GauravGhandat-23&color=00e5ff&style=for-the-badge&label=PROFILE+VIEWS)](https://github.com/GauravGhandat-23)
[![Followers](https://img.shields.io/github/followers/GauravGhandat-23?style=for-the-badge&logo=github&label=Followers&color=38bdf8)](https://github.com/GauravGhandat-23)
![Location](https://img.shields.io/badge/Nashik-India-10b981?style=for-the-badge&logo=googlemaps&logoColor=white)
![Status](https://img.shields.io/badge/SOC%20DEFENSE-ACTIVE%20MONITORING-00e5ff?style=for-the-badge&logo=splunk&logoColor=white)

<br/><br/>

<!-- 🖥️ 2. ABOUT — WHOAMI & DEFENDER MINDSET -->
<img src="./assets/about-life.svg?v=21" alt="Whoami, SOC Operations &amp; Life Beyond the Console" width="100%"/>

<br/><br/>

<!-- 🛡️ 3. WHAT I DO — 4 COMPACT DEFENSE CARDS -->
<img src="./assets/what-i-do.svg?v=21" alt="What I Do — SOC Monitoring, SIEM Analysis, Threat Detection, Incident Response" width="100%"/>

<br/><br/>

<!-- ⚛️ 4. TECHNOLOGIES & SECURITY TOOLS — CONNECTED NODES VISUALIZATION -->
<img src="./assets/stack.svg?v=21" alt="Cybersecurity Tech Arsenal &amp; Defensive Tooling" width="100%"/>

<br/><br/>

<!-- 📊 5. SOC DASHBOARD — SECURITY OPERATIONS COMMAND -->
<img src="./assets/soc-dashboard.svg?v=21" alt="Cybersecurity Operations Dashboard — Telemetry &amp; Detection Metrics" width="100%"/>

<br/><br/>

</div>

---

## 🎯 Detection Coverage & MITRE ATT&CK Matrix

> *All techniques listed below reflect active detection engineering and hands-on laboratory investigation.*  
> *Detection coverage status: **Learning / Detection Focus**.*

| Technique | ID | Description | Detection Data Source | Coverage Status |
|:---|:---|:---|:---|:---:|
| **Command & Scripting Interpreter** | `T1059` | PowerShell & CMD malicious execution strings | Windows Security Logs (4688) / Sysmon | Learning Focus |
| **Valid Accounts** | `T1078` | Credential-based unauthorized persistence & abuse | Authentication Logs / Active Directory | Learning Focus |
| **Account Discovery** | `T1087` | Local and domain user enumeration reconnaissance | Windows EventCode 4720 / 4688 | Learning Focus |
| **Remote Services** | `T1021` | Lateral movement via RDP, SMB, and SSH | Network telemetry / Windows Logs | Learning Focus |
| **Brute Force** | `T1110` | High-frequency authentication failures per source IP | Linux SSH (`/var/log/secure`) | Learning Focus |
| **DNS Tunneling** | `T1071.004` | High-entropy, abnormally long query burst counts | Zeek `dns.log` | Learning Focus |
| **Web C2 Beaconing** | `T1071.001` | Periodic HTTP delta intervals with low jitter | Zeek `conn.log` / Apache | Learning Focus |
| **Exploitation of Public-Facing Apps** | `T1190` | SQL injection, path traversal (`../`), XSS patterns | Web Server Access Logs / WAF | Learning Focus |

<details>
<summary><b>🔬 Peek inside the detection lab: Production-grade SPL queries (click to expand)</b></summary>

<br/>

> *Index and sourcetype configurations are modular and adapt to multi-tier enterprise SIEM architectures.*

#### 1. SSH Brute-Force Spike Detection (T1110)
```spl
index=linux sourcetype=linux_secure "Failed password"
| rex "from (?<src_ip>\d{1,3}(?:\.\d{1,3}){3})"
| rex "for (?:invalid user )?(?<user>\S+)"
| bin _time span=5m
| stats count AS attempts, dc(user) AS users_tried BY _time, src_ip
| where attempts > 10
| sort - attempts
```

#### 2. DNS Tunneling & High-Entropy Query Detection (T1071.004)
```spl
index=zeek sourcetype=bro:dns:json
| eval src='id.orig_h', qlen=len(query)
| stats count AS queries, dc(query) AS unique_queries, avg(qlen) AS avg_len BY src
| where avg_len > 40 AND unique_queries > 100
| sort - unique_queries
```

#### 3. Command & Control Beaconing Detection (T1071.001)
```spl
index=zeek sourcetype=bro:conn:json
| eval src='id.orig_h', dst='id.resp_h'
| sort 0 src dst _time
| streamstats current=f last(_time) AS prev BY src dst
| eval delta=_time-prev
| stats count, avg(delta) AS avg_interval, stdev(delta) AS jitter BY src dst
| where count > 30 AND jitter < 5
```

#### 4. Web Application Attack Vector Detection (T1190)
```spl
index=web sourcetype=access_combined
| where match(_raw, "(?i)(\.\./|union(\s|%20|\+)+select|<script|etc/passwd)")
| stats count, values(uri_path) AS paths BY clientip
| sort - count
```

</details>

---

## ⚡ SOC Detection & Incident Response Pipeline

<div align="center">
  <img src="./assets/detection-pipeline.svg?v=21" alt="SOC Detection &amp; Incident Response Pipeline" width="100%"/>
</div>

```
LOG SOURCE  ──▶  COLLECTION  ──▶  SIEM / SPLUNK  ──▶  NORMALIZATION  ──▶  CORRELATION
                                                                               │
RESPONSE    ◀──  INVESTIGATION  ◀──  ALERT TRIAGE  ◀──  DETECTION RULE  ◀──────┘
```

---

## 🚀 Featured Projects

| Project | Description | Tech Stack | Status | Link |
|:---|:---|:---|:---:|:---:|
| [**SSH Log Analysis Using Splunk**](https://github.com/GauravGhandat-23/SSH-Log-Analysis-using-Splunk) | Enterprise SSH authentication log ingestion and analysis detecting brute-force spikes, credential spraying, and anomalous remote logins with real-time alerting. | `Splunk` `SPL` `Linux SSH` `Security` | Active | [Explore](https://github.com/GauravGhandat-23/SSH-Log-Analysis-using-Splunk) |
| [**DNS Log Analysis Using Splunk**](https://github.com/GauravGhandat-23/DNS-Log-Analysis-Using-Splunk) | Parsing Zeek JSON DNS logs to expose data exfiltration, abnormal domain query lengths, and malicious C2 tunneling infrastructure. | `Splunk` `Zeek` `SPL` `DNS Forensics` | Active | [Explore](https://github.com/GauravGhandat-23/DNS-Log-Analysis-Using-Splunk) |
| [**HTTP Log Analysis Using Splunk**](https://github.com/GauravGhandat-23/HTTP-Log-Analysis-using-Splunk) | Deep analysis of Apache and web proxy logs identifying SQL injection, cross-site scripting (XSS), path traversal attacks, and web scanners. | `Splunk` `Apache` `SPL` `Web Sec` | Active | [Explore](https://github.com/GauravGhandat-23/HTTP-Log-Analysis-using-Splunk) |
| [**SOC Monitoring Dashboard for SSH**](https://github.com/GauravGhandat-23/Splunk-Dashboard-for-SSH-Logs) | High-visibility enterprise SOC dashboard monitoring Linux authentication activity, visualizing top attack source countries and failed login distributions. | `Splunk` `XML Dashboards` `SPL` | Active | [Explore](https://github.com/GauravGhandat-23/Splunk-Dashboard-for-SSH-Logs) |
| [**Cloudflare Logs Splunk Dashboard**](https://github.com/GauravGhandat-23/Splunk-Dashboard-for-Cloudflare-Logs) | Real-time monitoring dashboard for Cloudflare edge telemetry, visualizing WAF challenge blocks, rate limits, and geographic client traffic patterns. | `Splunk` `Cloudflare` `WAF` `SPL` | Active | [Explore](https://github.com/GauravGhandat-23/Splunk-Dashboard-for-Cloudflare-Logs) |
| [**Quantum-Resistant AI Cybersecurity**](https://github.com/GauravGhandat-23/Quantum-Resistant-AI-Powered-Cybersecurity) | AI-powered security threat analysis tool integrating Groq AI models with post-quantum cryptography algorithms for resilient data protection. | `Python` `AI / Groq` `Post-Quantum` | Active | [Explore](https://github.com/GauravGhandat-23/Quantum-Resistant-AI-Powered-Cybersecurity) |
| [**Network Reconnaissance on Linux**](https://github.com/GauravGhandat-23/Information-Gathering-on-Websites-Using-Linux) | Comprehensive laboratory framework for discovery, port auditing, OS fingerprinting, and packet inspection using Linux-native network security utilities. | `Linux` `Nmap` `Wireshark` `Recon` | Active | [Explore](https://github.com/GauravGhandat-23/Information-Gathering-on-Websites-Using-Linux) |
| [**Secure IAM in Linux Environments**](https://github.com/GauravGhandat-23/Secure-User-Access-Management-in-Linux) | Defense-in-depth Linux user access control system implementing granular POSIX permissions, File Access Control Lists (FACL), and audit compliance. | `Linux` `FACL` `IAM` `Security Hardening` | Active | [Explore](https://github.com/GauravGhandat-23/Secure-User-Access-Management-in-Linux) |

---

## 💼 Experience

### 🏢 **System Administrator — Bits & Bytes Services Pvt. Ltd, Nashik**
*Since **06/2025** · Nashik, India*
- **Enterprise Infrastructure**: Managing Windows Server (2012–2025) and enterprise Linux distributions (RHEL, Ubuntu, Rocky Linux).
- **Directory Services & Identity**: Administering Active Directory Domain Services (AD DS), Group Policy Objects (GPO), and role-based access control (RBAC).
- **Network Administration**: Configuring LAN/WAN infrastructure, enterprise VPN tunnels, DNS servers, and DHCP scopes.
- **Defensive Maintenance**: Executing system hardening, vulnerability patch management, automated backup strategies, and ITIL service continuity.

---

## 🏆 Certifications

| Certification | Area | Status |
|:---|:---|:---:|
| **CRTA (Certified Red Team Analyst)** | Offensive Security & Adversary Tactics | Verified |
| **Security Blue Team (Network Analysis)** | Defensive Security & Packet Forensics | Verified |
| **arcX Threat Intelligence Analyst** | Cyber Threat Intelligence (CTI) | Verified |
| **Oracle OCI 2025 Certified Architect Associate** | Cloud Infrastructure & Architecture | Verified |
| **Google Professional Cybersecurity Certificate** | Cyber Foundations & Security Operations | Verified |
| **Cisco Introduction to Cybersecurity** | Network Defense Fundamentals | Verified |
| **Reliance Foundation Cyber Security Associate** | Defensive Operations | Verified |
| **CCNA · MCSA · RHCSA · RHCE** | Networking & Enterprise Linux Systems | Verified |

---

## 🎓 Education

**Bachelor of Engineering (B.E.) in Computer Engineering**  
*Brahma Valley College of Engineering & Research Institute, Nashik*  
`06/2022 – 05/2025` · Cumulative Grade Point Average: **7.66 / 10**

---

<div align="center">

## 📊 GitHub Analytics

<!-- Custom Animated Stats + Languages Cards -->
<img src="./assets/gaurav-stats.svg?v=21" alt="Gaurav Ghandat's Animated GitHub Stats" width="49%"/>
<img src="./assets/gaurav-langs.svg?v=21" alt="Gaurav Ghandat's Animated Language Distribution" width="49%"/>

<br/><br/>

<!-- Custom Animated Trophies Banner -->
<img src="./assets/gaurav-trophies.svg?v=21" alt="Gaurav Ghandat's GitHub Trophies" width="100%"/>

<br/><br/>

## 🌃 My GitHub Contribution City

*Every commit builds another tower — rebuilt automatically every day.*

<img src="./profile-3d-contrib/profile-night-view.svg?v=21" alt="Gaurav Ghandat's 3D Contribution City" width="100%"/>

<br/><br/>

## 🐍 Contribution Snake

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/GauravGhandat-23/GauravGhandat-23/output/github-contribution-grid-snake-dark.svg?v=21"/>
  <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/GauravGhandat-23/GauravGhandat-23/output/github-contribution-grid-snake.svg?v=21"/>
  <img src="https://raw.githubusercontent.com/GauravGhandat-23/GauravGhandat-23/output/github-contribution-grid-snake.svg?v=21" alt="Contribution Snake Animation" width="100%"/>
</picture>

<br/><br/>

## 🪪 Security ID Card

<img src="./assets/id-dashboard.svg?v=21" alt="Gaurav Ghandat — Verified SOC Defender ID &amp; Telemetry Dashboard" width="100%"/>

<br/><br/>

<!-- 💌 LET'S CONNECT SECTION -->
<img src="./assets/connect.svg?v=21" alt="Connect with Gaurav Ghandat" width="100%"/>

<br/>

<a href="https://github.com/GauravGhandat-23"><img src="https://img.shields.io/badge/GitHub-GauravGhandat--23-00e5ff?style=for-the-badge&logo=github&logoColor=070a12" alt="GitHub"/></a>
<a href="https://linkedin.com/in/gaurav-ghandat-68a5a22b4" target="_blank"><img src="https://img.shields.io/badge/LinkedIn-Gaurav%20Ghandat-38bdf8?style=for-the-badge&logo=linkedin&logoColor=070a12" alt="LinkedIn"/></a>
<a href="mailto:gauravghandat23@gmail.com"><img src="https://img.shields.io/badge/Email-gauravghandat23%40gmail.com-f472b6?style=for-the-badge&logo=gmail&logoColor=070a12" alt="Email"/></a>

<br/><br/>

<!-- 🗂️ PROJECT / LEARNING REPOSITORY CARDS -->
<img src="./assets/learning-cards.svg?v=21" alt="Project &amp; Defense Framework Cards" width="100%"/>

<br/><br/>

## 📈 GitHub Contributions &amp; Activity

<img src="https://github-readme-activity-graph.vercel.app/graph?username=GauravGhandat-23&bg_color=0d1117&color=58a6ff&line=22d3ee&point=3fb950&area=true&hide_border=true" alt="Gaurav Ghandat's Contribution Activity Graph" width="100%"/>

<br/><br/>

<!-- ⚓ FOOTER -->
<hr style="border-color: #30363d;" />

### **GAURAV GHANDAT**
**SOC ANALYST • BLUE TEAM • CYBERSECURITY**  
*“Securing systems, one log at a time.”*  

[**GitHub**](https://github.com/GauravGhandat-23) · [**LinkedIn**](https://linkedin.com/in/gaurav-ghandat-68a5a22b4) · [**Email**](mailto:gauravghandat23@gmail.com)

</div>
