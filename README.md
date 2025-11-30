# 🛡️ SentinelGuard – Advanced Vulnerability Scanner  

| <img width="1280" height="640" alt="Sentinel" src="https://github.com/user-attachments/assets/ef1dd7e6-a84a-486f-b450-4d1f90f4f38f" /> |
|---|

- ©Thorsten Bylicki | ©BYLICKILABS  
- Version 1.0.0
- Support Language DE/EN

---

## 📛 Badges

| Category | Badge | Description |
|-----------|-------|--------------|
| **Version & Release** | ![Version](https://img.shields.io/badge/version-1.0.0-blue.svg) | Current stable release |
| **Build Status** | ![Build Status](https://img.shields.io/github/actions/workflow/status/bylickilabs/SentinelGuard/main.yml?branch=main) | CI/CD Pipeline status |
| **License** | ![License: MIT](https://img.shields.io/badge/license-MIT-green.svg) | Open source license |
| **Python Version** | ![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg) ![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)| Supported versions |
| **Platform** | ![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-lightgrey.svg) | Compatible OS |

---

## EN

### 🔍 Overview
**SentinelGuard** is a full-featured vulnerability scanner for Python projects.  
It analyzes **source code**, **dependencies**, and **secrets** in a unified desktop interface.  

Developed by **BYLICKILABS – Intelligence Systems & Communications**, it enables **secure-by-design** workflows for modern developers.

### 💡 Key Features
- ✅ Static code analysis (SAST)
- ✅ Dependency vulnerability detection
- ✅ Secret & credential exposure scanning
- ✅ Bilingual interface (EN/DE)
- ✅ Real-time scanning log
- ✅ Exportable reports (`.txt`)
- ✅ Tkinter-based graphical interface

### ⚙️ Installation

```bash
git clone https://github.com/bylickilabs/SentinelGuard.git
cd SentinelGuard
python app.py
```

### 🧩 Usage
1. Launch the application: `python app.py`
2. Select project folder
3. Choose analysis types (code, dependencies, secrets)
4. Click **Start Scan**
5. View results in the log and save the report

<br>

---

<br>

## DE

### 🔍 Übersicht
**Sentinel Guard** ist ein vollständiger Schwachstellenscanner für Python-Projekte.  
Er analysiert **Quellcode**, **Abhängigkeiten** und **Geheimnisse** über eine einheitliche Desktop-Oberfläche.  

Entwickelt von **BYLICKILABS – Intelligence Systems & Communications**, ermöglicht er einen **Security-by-Design** Ansatz in der Softwareentwicklung.

### 💡 Hauptfunktionen
- ✅ Statische Codeanalyse (SAST)
- ✅ Prüfung veralteter Abhängigkeiten
- ✅ Erkennung von API-Keys, Passwörtern & Tokens
- ✅ Zweisprachige Oberfläche (DE/EN)
- ✅ Live-Scanprotokoll
- ✅ Exportierbarer Report (`.txt`)
- ✅ Benutzerfreundliche GUI mit **Tkinter**

### ⚙️ Installation

```bash
git clone https://github.com/bylickilabs/SentinelGuard.git
cd SentinelGuard
python app.py
```

### 🧩 Verwendung
1. Anwendung starten: `python app.py`
2. Projektverzeichnis auswählen
3. Scanoptionen aktivieren (Code, Dependencies, Secrets)
4. **Scan starten**
5. Ergebnisse im Log einsehen & Report speichern

---

## 🧠 Architecture Overview
Sentinel Guard consists of three independent yet integrated modules:

| Module | Purpose |
|--------|----------|
| **Code Analyzer** | Scans Python files for dangerous function calls using pattern-based matching |
| **Dependency Auditor** | Analyzes `requirements.txt` for insecure versions |
| **Secret Detector** | Identifies API keys, passwords, or tokens in project files |

All modules are unified under a graphical interface and generate a summarized vulnerability report.

---

## 🧑‍💻 Author & Credits
- **Author:** Thorsten Bylicki  
- **Company:** BYLICKILABS – Intelligence Systems & Communications  
- **License:** [LICENSE](LICENSE) 
- **Contact:** [GitHub Profile](https://github.com/bylickilabs)
- **Website:** [LINK](https://bylickilabs.de)
- **Shop:** [LINK](https://bylickilabs.com)

---

### 🏆 Additional Highlights
- Optimized for DevSecOps pipelines  
- Fully modular rule system  
- Extensible for corporate security frameworks  
- Made in Germany 🇩🇪 – Engineered with precision

---
