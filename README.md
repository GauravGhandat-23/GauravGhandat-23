<div align="center">

<!-- 🎬 HERO — Animated Cyber Defender Banner + Name -->
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="./hero.svg?v=20"/>
  <source media="(prefers-color-scheme: light)" srcset="./hero.svg?v=20"/>
  <img src="./hero.svg?v=20" width="100%" alt="Gaurav Ghandat — SOC Analyst & Blue Team Defender"/>
</picture>

<br/><br/>

[![Profile Views](https://komarev.com/ghpvc/?username=GauravGhandat-23&color=00e5ff&style=for-the-badge&label=PROFILE+VIEWS)](https://github.com/GauravGhandat-23)
[![Followers](https://img.shields.io/github/followers/GauravGhandat-23?style=for-the-badge&logo=github&label=Followers&color=38bdf8)](https://github.com/GauravGhandat-23)
![Location](https://img.shields.io/badge/Nashik-India-10b981?style=for-the-badge&logo=googlemaps&logoColor=white)
![Status](https://img.shields.io/badge/SOC%20DEFENSE-ACTIVE%20MONITORING-00e5ff?style=for-the-badge&logo=splunk&logoColor=white)

<br/><br/>

<!-- 🖥️ WHOAMI & SOC OPERATIONS -->
<img src="./about-life.svg?v=20" alt="Whoami, SOC Operations & Life Beyond the Console" width="100%"/>

<br/><br/>

<!-- ⚛️ TECH ARSENAL -->
<img src="./stack.svg?v=20" alt="Cybersecurity Tech Arsenal & Defensive Tooling" width="100%"/>

<br/><br/>

<!-- 🪪 DEVELOPER / SOC ID + LIVE DASHBOARD -->
<img src="./id-dashboard.svg?v=20" alt="Defender ID and Live SOC Telemetry Dashboard" width="100%"/>

<br/><br/>

</div>

---

## 🎯 Detection Coverage & MITRE ATT&CK Matrix

> *All techniques listed below reflect active detection engineering and hands-on laboratory investigation.*  
> *Detection coverage status: **Learning / Detection Focus**.*

| Tactic | Technique | How I Detect It | Data Source | Coverage |
|:---|:---|:---|:---|:---:|
| **Credential Access** | **T1110** Brute Force | Failed-auth spike per source IP within time window + distinct user enumeration | Linux SSH (`/var/log/secure`) | `98%` |
| **Command & Control** | **T1071.004** DNS Tunneling | High-entropy, abnormally long queries, burst query counts per client | Zeek `dns.log` | `95%` |
| **Command & Control** | **T1071.001** Web C2 Beaconing | Periodic connection intervals with low jitter and persistent delta intervals | Zeek `conn.log` / Apache | `92%` |
| **Initial Access** | **T1190** Public-Facing App Exploits | Path traversal (`../`), SQLi keywords (`UNION SELECT`), script injection | Web access logs / WAF | `94%` |
| **Discovery** | **T1087** Account Discovery | Rapid succession of `net user`, `id`, `whoami` commands across hosts | Windows EventCode 4688 / Sysmon | `90%` |
| **Multi-Stage** | Cross-Source Correlation | Linking network anomalies with endpoint auth spikes into unified kill chain | Zeek + Linux Secure + GuardDuty | `93%` |

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

```
┌───────────────────────────┐     ┌───────────────────────────┐     ┌───────────────────────────┐
│     WINDOWS / LINUX       │     │     NETWORK TELEMETRY     │     │      CLOUD TELEMETRY      │
│ EventCode 4624/4625, SSH  │     │ Zeek dns.log / conn.log   │     │  AWS GuardDuty, OCI Logs  │
└─────────────┬─────────────┘     └─────────────┬─────────────┘     └─────────────┬─────────────┘
              │                                 │                                 │
              └─────────────────────────┬───────┴─────────────────────────────────┘
                                        │
                                        ▼
                         ┌─────────────────────────────┐
                         │    CENTRALIZED INGESTION    │
                         │   Splunk Universal Forward  │
                         └──────────────┬──────────────┘
                                        │
                                        ▼
                         ┌─────────────────────────────┐
                         │   CORRELATION & DETECTION   │
                         │  SPL Correlation Searches   │
                         │   Mapped to MITRE ATT&CK    │
                         └──────────────┬──────────────┘
                                        │
                                        ▼
                         ┌─────────────────────────────┐
                         │     ALERT & TRIAGE HUD      │
                         │ Severity Scoring & Analysis │
                         └──────────────┬──────────────┘
                                        │
                                        ▼
                         ┌─────────────────────────────┐
                         │   CONTAINMENT & RESPONSE    │
                         │ Host Isolation / IP Ban /   │
                         │ Credential Reset & Post-Mort│
                         └─────────────────────────────┘
```

---

## 🚀 Featured Projects

| Project | Description | Tech Stack | Repository |
|:---|:---|:---|:---:|
| [**SSH Log Analysis Using Splunk**](https://github.com/GauravGhandat-23/SSH-Log-Analysis-using-Splunk) | Enterprise SSH authentication log ingestion and analysis to detect brute-force spikes, credential spraying, and anomalous remote logins with real-time alerting. | `Splunk` `SPL` `Linux SSH` `Security` | [Explore](https://github.com/GauravGhandat-23/SSH-Log-Analysis-using-Splunk) |
| [**DNS Log Analysis Using Splunk**](https://github.com/GauravGhandat-23/DNS-Log-Analysis-Using-Splunk) | Parsing Zeek JSON DNS logs to expose data exfiltration, abnormal domain query lengths, and malicious C2 tunneling infrastructure. | `Splunk` `Zeek` `SPL` `DNS Forensics` | [Explore](https://github.com/GauravGhandat-23/DNS-Log-Analysis-Using-Splunk) |
| [**HTTP Log Analysis Using Splunk**](https://github.com/GauravGhandat-23/HTTP-Log-Analysis-using-Splunk) | Deep analysis of Apache and web proxy logs identifying SQL injection, cross-site scripting (XSS), path traversal attacks, and web scanners. | `Splunk` `Apache` `SPL` `Web Sec` | [Explore](https://github.com/GauravGhandat-23/HTTP-Log-Analysis-using-Splunk) |
| [**SOC Monitoring Dashboard for SSH**](https://github.com/GauravGhandat-23/Splunk-Dashboard-for-SSH-Logs) | High-visibility enterprise SOC dashboard monitoring Linux authentication activity, visualizing top attack source countries and failed login distributions. | `Splunk` `XML Dashboards` `SPL` | [Explore](https://github.com/GauravGhandat-23/Splunk-Dashboard-for-SSH-Logs) |
| [**Cloudflare Logs Splunk Dashboard**](https://github.com/GauravGhandat-23/Splunk-Dashboard-for-Cloudflare-Logs) | Real-time monitoring dashboard for Cloudflare edge telemetry, visualizing WAF challenge blocks, rate limits, and geographic client traffic patterns. | `Splunk` `Cloudflare` `WAF` `SPL` | [Explore](https://github.com/GauravGhandat-23/Splunk-Dashboard-for-Cloudflare-Logs) |
| [**Quantum-Resistant AI Cybersecurity**](https://github.com/GauravGhandat-23/Quantum-Resistant-AI-Powered-Cybersecurity) | AI-powered security threat analysis tool integrating Groq AI models with post-quantum cryptography algorithms for resilient data protection. | `Python` `AI / Groq` `Post-Quantum` | [Explore](https://github.com/GauravGhandat-23/Quantum-Resistant-AI-Powered-Cybersecurity) |
| [**Network Reconnaissance on Linux**](https://github.com/GauravGhandat-23/Information-Gathering-on-Websites-Using-Linux) | Comprehensive laboratory framework for discovery, port auditing, OS fingerprinting, and packet inspection using Linux-native network security utilities. | `Linux` `Nmap` `Wireshark` `Recon` | [Explore](https://github.com/GauravGhandat-23/Information-Gathering-on-Websites-Using-Linux) |
| [**Secure IAM in Linux Environments**](https://github.com/GauravGhandat-23/Secure-User-Access-Management-in-Linux) | Defense-in-depth Linux user access control system implementing granular POSIX permissions, File Access Control Lists (FACL), and audit compliance. | `Linux` `FACL` `IAM` `Security Hardening` | [Explore](https://github.com/GauravGhandat-23/Secure-User-Access-Management-in-Linux) |

---

## 💼 Experience

### 🏢 **System Administrator — Bits & Bytes Services Pvt. Ltd, Nashik**
*Since **06/2025** · Nashik, India*
- **Enterprise Infrastructure**: Managing Windows Server (2012–2025) and enterprise Linux distributions (RHEL, Ubuntu, Rocky Linux).
- **Directory Services & Identity**: Administering Active Directory Domain Services (AD DS), Group Policy Objects (GPO), and role-based access control (RBAC).
- **Network Administration**: Configuring LAN/WAN infrastructure, enterprise VPN tunnels, DNS servers, and DHCP scopes.
- **Defensive Maintenance**: Executing system hardening, vulnerability patch management, automated backup strategies, and ITIL service continuity.

---

## 🏆 Verified Certifications

| Domain | Credential & Issuer | Status |
|:---|:---|:---:|
| 🔴 **Offensive Security** | **CRTA** (Certified Red Team Analyst) · **PEH / EH** (Netleap) | Verified |
| 🔵 **Defensive Security** | **Security Blue Team** (Network Analysis) · **arcX** Threat Intelligence Analyst | Verified |
| ☁️ **Cloud Architecture** | **Oracle OCI 2025** Certified Architect Associate | Verified |
| 🛡️ **Cyber Foundations** | **Google Professional Cybersecurity** · **Cisco** Intro to Cybersecurity · **Reliance Foundation** Cyber Security Associate · **Tech Mahindra** Cyber Security Program | Verified |
| 🖧 **Infrastructure & Systems** | **CCNA** · **MCSA** · **RHCSA** · **RHCE** · Linux Fundamentals | Verified |

---

## 🎓 Education

**Bachelor of Engineering (B.E.) in Computer Engineering**  
*Brahma Valley College of Engineering & Research Institute, Nashik*  
`06/2022 – 05/2025` · Cumulative Grade Point Average: **7.66 / 10**

---

<div align="center">

## 📊 GitHub Analytics & Verified Metrics

<!-- Custom Animated Stats + Languages Cards -->
<img src="./gaurav-stats.svg?v=20" alt="Gaurav Ghandat's Animated GitHub Stats" width="49%"/>
<img src="./gaurav-langs.svg?v=20" alt="Gaurav Ghandat's Animated Language Distribution" width="49%"/>

<br/><br/>

<!-- Custom Animated Trophies Banner -->
<img src="./gaurav-trophies.svg?v=20" alt="Gaurav Ghandat's GitHub Trophies" width="100%"/>

<br/><br/>

## 🌃 My Contribution City

*Every commit builds another tower — rebuilt automatically every day.*

<img src="./profile-3d-contrib/profile-night-view.svg?v=20" alt="Gaurav Ghandat's 3D Contribution City" width="100%"/>

<br/><br/>

## 🐍 Contribution Snake

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/GauravGhandat-23/GauravGhandat-23/output/github-contribution-grid-snake-dark.svg?v=20"/>
  <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/GauravGhandat-23/GauravGhandat-23/output/github-contribution-grid-snake.svg?v=20"/>
  <img src="https://raw.githubusercontent.com/GauravGhandat-23/GauravGhandat-23/output/github-contribution-grid-snake.svg?v=20" alt="Contribution Snake Animation" width="100%"/>
</picture>

<br/><br/>

## 🪪 Verified SOC Defender ID

<img src="./gaurav-lanyard.svg?v=20" alt="Gaurav Ghandat — Swinging SOC Defender ID Badge" width="380"/>

<br/><br/>

<!-- LET'S CONNECT SECTION -->
<img src="./connect.svg?v=20" alt="Connect with Gaurav Ghandat" width="100%"/>

<br/>

<a href="https://github.com/GauravGhandat-23"><img src="https://img.shields.io/badge/GitHub-GauravGhandat--23-00e5ff?style=for-the-badge&logo=github&logoColor=070a12" alt="GitHub"/></a>
<a href="https://linkedin.com/in/gaurav-ghandat-68a5a22b4" target="_blank"><img src="https://img.shields.io/badge/LinkedIn-Gaurav%20Ghandat-38bdf8?style=for-the-badge&logo=linkedin&logoColor=070a12" alt="LinkedIn"/></a>
<a href="mailto:gauravghandat23@gmail.com"><img src="https://img.shields.io/badge/Email-gauravghandat23%40gmail.com-f472b6?style=for-the-badge&logo=gmail&logoColor=070a12" alt="Email"/></a>

<br/><br/>

<i>🔐 "Securing systems, one log at a time."</i>

</div>
