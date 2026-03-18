#  LIGHTUS-AI-Insider-Threat-Detector

[![AWS](https://img.shields.io/badge/AWS-FF9900?style=for-the-badge&logo=amazonaws&logoColor=white)](https://aws.amazon.com)
[![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT&CK-red?style=for-the-badge)](https://attack.mitre.org)

---

## 🎯 What is LIGHTUS?

LIGHTUS is a **stealth insider threat detection system** that uses an **agentic AI approach** to analyze AWS CloudTrail logs.

It identifies **anomalous user behavior**, evaluates intent using an LLM (Claude via AWS Bedrock), and maps actions to **MITRE ATT&CK techniques** to generate prioritized security alerts.

Unlike traditional tools, LIGHTUS focuses on **behavioral patterns and intent**, not just rule-based detection.

---

## ⚠️ Why This Matters

- Insider threats take **~197 days** on average to detect  
- Traditional SIEM tools are **expensive and noisy (~$50k+/year)**  
- Static rule-based systems miss **novel or subtle attacks**

**LIGHTUS solves this with:**
- AI-driven reasoning  
- Behavioral context analysis  
- Stealth monitoring  
- Low-cost architecture  

---

## ✨ Key Features

| Feature | Description | Why It Matters |
|---------|-------------|----------------|
| 🕵️ **Stealth Operation** | No CloudTrail footprint (S3 Data Events disabled) | Insiders can't detect monitoring |
| 🤖 **AI-Powered Reasoning** | LLM analyzes behavior patterns | Detects unknown threats |
| 🗺️ **MITRE ATT&CK Mapping** | Maps activity to TTPs | Industry-standard threat understanding |
| 👥 **User Context Awareness** | Sliding time window per user | Detects intent, not isolated events |
| 📊 **Baseline Filtering** | Learns normal behavior over 7 days | Reduces noise and cost |
| 🚨 **Severity-Based Alerts** | Low / Medium / High / Critical | Focus on high-risk activity |
| 💰 **Cost Optimized** | Filters ~90% logs before LLM calls | Runs at minimal cost |

---

## 🏗️ Architecture
CloudTrail Logs → S3 Bucket → EC2 Parser → Baseline Filter → LLM Agent (Bedrock)
↓
User Context Engine
↓
MITRE ATT&CK Mapping
↓
Alerting System


---

## 🧠 How It Works

### 1. Log Ingestion
CloudTrail logs are continuously pulled from S3 by an EC2-based parser.

### 2. Baseline Filtering
The system tracks frequent events over a 7-day window and ignores normal activity.

### 3. Context Building
User actions are grouped within short time windows (5–10 minutes) to detect patterns.

### 4. AI Reasoning
Suspicious behavior is sent to an LLM, which evaluates intent and identifies insider threat patterns.

### 5. MITRE ATT&CK Mapping
Detected behaviors are mapped to relevant MITRE techniques for structured analysis.

### 6. Alerting
Alerts are classified into severity levels and triggered based on risk.

---

## 🔒 Stealth Design

- EC2 uses IAM role-based access to read logs  
- No CloudTrail logs generated during analysis  
- S3 Data Events disabled for log bucket  
- Monitoring activity remains invisible  

This ensures the system operates in **true stealth mode**.

---

## 🚀 Tech Stack

- **AWS EC2** — Processing engine  
- **AWS S3** — Log storage  
- **AWS IAM** — Secure access  
- **AWS Bedrock (Claude)** — AI reasoning  
- **Python** — Core logic  

---

## 📌 Use Cases

LIGHTUS can detect:

- Privilege escalation attempts  
- Suspicious IAM activity (e.g., access key creation)  
- Unusual access patterns  
- Data access anomalies  
- Insider reconnaissance behavior  

---

## 🔍 Example Insider Threat Scenario

A SOC analyst creates an **IAM access key** for a break-glass admin account under the pretext of investigation.

- No immediate data exfiltration  
- No log deletion  
- Appears legitimate at surface level  

**LIGHTUS detects this as:**
- Abnormal behavior for the user  
- High-risk privilege misuse  
- Potential persistence setup  

→ Flags as **High/Critical alert with MITRE mapping**

---

## ⚡ Why LIGHTUS?

Traditional systems:
- Rule-based  
- High false positives  
- Expensive  
- Lack behavioral context  

LIGHTUS:
- ✅ AI-driven reasoning  
- ✅ Behavioral detection  
- ✅ Stealth monitoring  
- ✅ Cost-efficient  
- ✅ MITRE-aligned insights  

---

## 📈 Future Enhancements

- Automated response (remediation engine)  
- Integration with SIEM tools  
- Dashboard for visualization  
- Expanded threat intelligence correlation  

---

## 📜 License

This project is for educational and research purposes.
