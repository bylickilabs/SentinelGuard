import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import webbrowser
from datetime import datetime
import os
import re

APP_NAME = "Sentinel Guard – Vulnerability Scanner"
APP_COMPANY = "©Thorsten Bylicki | ©BYLICKILABS"
APP_VERSION = "1.0.0"
APP_AUTHOR = "Thorsten Bylicki"
GITHUB_URL = "https://github.com/bylickilabs"

RULES = [
    {
        "id": "PY-EVAL-001",
        "pattern": re.compile(r"\beval\s*\("),
        "severity": "HIGH",
        "category": "Code Execution",
        "de": "Unsichere dynamische Codeausführung mit eval().",
        "en": "Unsafe dynamic code execution using eval().",
    },
    {
        "id": "PY-EXEC-002",
        "pattern": re.compile(r"\bexec\s*\("),
        "severity": "HIGH",
        "category": "Code Execution",
        "de": "Unsichere dynamische Codeausführung mit exec().",
        "en": "Unsafe dynamic code execution using exec().",
    },
    {
        "id": "PY-OS-SYSTEM-003",
        "pattern": re.compile(r"\bos\.system\s*\("),
        "severity": "HIGH",
        "category": "Command Execution",
        "de": "Betriebssystembefehle über os.system() können zu Kommandoinjektionen führen.",
        "en": "Operating system commands via os.system() may lead to command injection.",
    },
    {
        "id": "PY-SUBPROCESS-SHELL-004",
        "pattern": re.compile(r"subprocess\.(Popen|run|call)\s*\([^)]*shell\s*=\s*True"),
        "severity": "HIGH",
        "category": "Command Execution",
        "de": "subprocess.* mit shell=True erhöht das Risiko von Kommandoinjektionen.",
        "en": "subprocess.* with shell=True increases the risk of command injection.",
    },
    {
        "id": "PY-REQUESTS-NOVERIFY-005",
        "pattern": re.compile(r"requests\.(get|post|put|delete|patch)\s*\([^)]*verify\s*=\s*False"),
        "severity": "MEDIUM",
        "category": "TLS / Certificates",
        "de": "HTTP-Requests mit verify=False deaktivieren die Zertifikatsprüfung.",
        "en": "HTTP requests with verify=False disable certificate verification.",
    },
    {
        "id": "PY-PICKLE-006",
        "pattern": re.compile(r"pickle\.loads\s*\("),
        "severity": "HIGH",
        "category": "Deserialization",
        "de": "Unsichere Deserialisierung mit pickle.loads() kann Codeausführung ermöglichen.",
        "en": "Unsafe deserialization with pickle.loads() may allow code execution.",
    },
    {
        "id": "PY-SQL-STRING-007",
        "pattern": re.compile(r"execute\s*\(\s*f?['\"][^'\"]*SELECT[^'\"]*['\"]\s*\+"),
        "severity": "HIGH",
        "category": "SQL Injection",
        "de": "String-Konkatenation in SQL-Statements kann zu SQL-Injection führen.",
        "en": "String concatenation in SQL statements may lead to SQL injection.",
    },
]

SECRET_PATTERNS = [
    {
        "id": "SC-AWS-ACCESS-KEY",
        "pattern": re.compile(r"AKIA[0-9A-Z]{16}"),
        "severity": "HIGH",
        "category": "AWS Credentials",
        "de": "Möglicher AWS Access Key erkannt.",
        "en": "Possible AWS access key detected.",
    },
    {
        "id": "SC-GENERIC-API-KEY",
        "pattern": re.compile(r"(api_key|apikey|API_KEY)\s*[:=]\s*['\"][A-Za-z0-9_\-]{20,}['\"]"),
        "severity": "HIGH",
        "category": "API Keys",
        "de": "Möglicher API-Schlüssel in Konfigurationsdatei oder Code.",
        "en": "Possible API key in configuration file or code.",
    },
    {
        "id": "SC-PASSWORD-IN-CODE",
        "pattern": re.compile(r"(password|passwd|pwd)\s*[:=]\s*['\"][^'\"]+['\"]", re.IGNORECASE),
        "severity": "MEDIUM",
        "category": "Credentials",
        "de": "Hartkodiertes Passwort im Code oder in einer Konfiguration.",
        "en": "Hardcoded password in code or configuration.",
    },
    {
        "id": "SC-DJANGO-SECRET-KEY",
        "pattern": re.compile(r"SECRET_KEY\s*=\s*['\"][^'\"]+['\"]"),
        "severity": "HIGH",
        "category": "Framework Secrets",
        "de": "Django SECRET_KEY im Klartext gefunden.",
        "en": "Django SECRET_KEY found in plain text.",
    },
]

INSECURE_DEPENDENCIES = {
    "django": {
        "max_major": 1,
        "severity": "HIGH",
        "de": "Veraltete Django-Hauptversion erkannt (<2.x). Upgrade empfohlen.",
        "en": "Outdated Django major version detected (<2.x). Upgrade recommended.",
    },
    "flask": {
        "max_major": 0,
        "severity": "MEDIUM",
        "de": "Sehr alte Flask-Version erkannt (<1.x). Upgrade empfohlen.",
        "en": "Very old Flask version detected (<1.x). Upgrade recommended.",
    },
    "requests": {
        "max_major": 1,
        "severity": "MEDIUM",
        "de": "Alte Requests-Version erkannt (<2.x). Upgrade empfohlen.",
        "en": "Old requests version detected (<2.x). Upgrade recommended.",
    },
}

LANG = {
    "de": {
        "window_title": APP_NAME,
        "header_title": APP_NAME,
        "header_subtitle": "Vulnerability Scanner für Quellcode, Abhängigkeiten und Geheimnisse",
        "language_label": "Sprache",
        "language_de": "Deutsch",
        "language_en": "Englisch",

        "scan_path_label": "Projektverzeichnis",
        "browse_button": "Durchsuchen...",
        "options_frame": "Scan-Optionen",
        "opt_code": "Quellcode-Analyse (SAST)",
        "opt_deps": "Abhängigkeits-Scan (requirements.txt)",
        "opt_secrets": "Geheimnisse & Tokens (Secrets)",
        "start_scan": "Scan starten",

        "status_idle": "Status: Bereit.",
        "status_running": "Status: Scan läuft...",
        "status_done": "Status: Scan abgeschlossen.",
        "status_no_path": "Bitte ein Projektverzeichnis auswählen.",
        "status_no_option": "Bitte mindestens eine Scan-Option auswählen.",

        "log_header": "VULN Sentinel – Scanprotokoll\n",
        "log_sep": "────────────────────────────────────────\n",
        "log_no_path": "[WARN] Kein Projektverzeichnis ausgewählt.\n",
        "log_scan_start": "[INFO] Starte Scan für: {path}\n",
        "log_scan_option": "[INFO] Aktiviert: {option}\n",
        "log_scan_step": "[TASK] Analysiere Datei: {module}\n",
        "log_dep_step": "[TASK] Analysiere Abhängigkeit: {dep}\n",
        "log_secret_step": "[TASK] Prüfe Datei auf Geheimnisse: {file}\n",
        "log_finding": "[FINDING] {severity} | {rule_id} | {category} | {file}:{line} – {message}\n",
        "log_dep_finding": "[FINDING] {severity} | DEP-{name} | {file} – {message}\n",
        "log_summary": "[SUMMARY] Funde: {count} | Pfad: {path}\n",
        "log_report_file": "[INFO] Report gespeichert unter: {file}\n",

        "info_button": "Info",
        "github_button": "GitHub / Social",
        "info_title": "Informationen zur Anwendung",
        "info_text": (
            f"{APP_NAME}\n\n"
            "BYLICKILABS – Intelligence Systems & Communications\n\n"
            "VULN Sentinel ist ein statischer Vulnerability Scanner für Python-Projekte.\n"
            "Er analysiert Quellcode, requirements.txt und Konfigurationsdateien auf typische\n"
            "Sicherheitsrisiken wie unsichere Funktionen, veraltete Abhängigkeiten und\n"
            "hartkodierte Geheimnisse.\n\n"
            "Einsatzszenarien:\n"
            "- Integration in lokale Entwicklungsumgebungen\n"
            "- Vorab-Checks vor Commits oder Releases\n"
            "- Ergänzung zu bestehenden CI/CD-Pipelines\n\n"
            "Meta-Daten:\n"
            f"Unternehmen: {APP_COMPANY}\n"
            f"Version: {APP_VERSION}\n"
            f"Autor: {APP_AUTHOR}\n"
        ),

        "footer_company": APP_COMPANY,
        "footer_version": f"Version: {APP_VERSION}",
        "footer_author": f"Autor: {APP_AUTHOR}",

        "dialog_no_requirements": "Keine requirements.txt im Projektverzeichnis gefunden.",
        "dialog_scan_finished_title": "Scan abgeschlossen",
        "dialog_scan_finished_body": "Der Scan wurde abgeschlossen.\nGefundene Einträge: {count}\nReport-Datei:\n{file}",
    },
    "en": {
        "window_title": APP_NAME,
        "header_title": APP_NAME,
        "header_subtitle": "Vulnerability scanner for source code, dependencies and secrets",
        "language_label": "Language",
        "language_de": "German",
        "language_en": "English",

        "scan_path_label": "Project directory",
        "browse_button": "Browse...",
        "options_frame": "Scan options",
        "opt_code": "Source code analysis (SAST)",
        "opt_deps": "Dependency scan (requirements.txt)",
        "opt_secrets": "Secrets & tokens",
        "start_scan": "Start scan",

        "status_idle": "Status: Ready.",
        "status_running": "Status: Scan in progress...",
        "status_done": "Status: Scan completed.",
        "status_no_path": "Please select a project directory.",
        "status_no_option": "Please select at least one scan option.",

        "log_header": "VULN Sentinel – Scan log\n",
        "log_sep": "────────────────────────────────────────\n",
        "log_no_path": "[WARN] No project directory selected.\n",
        "log_scan_start": "[INFO] Starting scan for: {path}\n",
        "log_scan_option": "[INFO] Enabled: {option}\n",
        "log_scan_step": "[TASK] Analyzing file: {module}\n",
        "log_dep_step": "[TASK] Analyzing dependency: {dep}\n",
        "log_secret_step": "[TASK] Checking file for secrets: {file}\n",
        "log_finding": "[FINDING] {severity} | {rule_id} | {category} | {file}:{line} – {message}\n",
        "log_dep_finding": "[FINDING] {severity} | DEP-{name} | {file} – {message}\n",
        "log_summary": "[SUMMARY] Findings: {count} | Path: {path}\n",
        "log_report_file": "[INFO] Report written to: {file}\n",

        "info_button": "Info",
        "github_button": "GitHub / Social",
        "info_title": "Application information",
        "info_text": (
            f"{APP_NAME}\n\n"
            "BYLICKILABS – Intelligence Systems & Communications\n\n"
            "VULN Sentinel is a static vulnerability scanner for Python projects.\n"
            "It analyzes source code, requirements.txt and configuration files for common\n"
            "security risks such as unsafe functions, outdated dependencies and\n"
            "hard-coded secrets.\n\n"
            "Use cases:\n"
            "- Integration into local development environments\n"
            "- Pre-commit or pre-release checks\n"
            "- Additional layer for CI/CD pipelines\n\n"
            "Meta data:\n"
            f"Company: {APP_COMPANY}\n"
            f"Version: {APP_VERSION}\n"
            f"Author: {APP_AUTHOR}\n"
        ),

        "footer_company": APP_COMPANY,
        "footer_version": f"Version: {APP_VERSION}",
        "footer_author": f"Author: {APP_AUTHOR}",

        "dialog_no_requirements": "No requirements.txt found in the selected project directory.",
        "dialog_scan_finished_title": "Scan completed",
        "dialog_scan_finished_body": "Scan completed.\nFindings: {count}\nReport file:\n{file}",
    },
}

class VulnScannerApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.current_lang = "de"
        self.findings = []

        self.root.title(LANG[self.current_lang]["window_title"])
        self.root.geometry("1040x700")
        self.root.minsize(960, 640)

        self._create_style()
        self._create_header()
        self._create_main()
        self._create_footer()
        self.update_language()

    def _create_style(self):
        style = ttk.Style()
        style.configure("Header.TLabel", font=("Segoe UI", 16, "bold"))
        style.configure("SubHeader.TLabel", font=("Segoe UI", 10))
        style.configure("Section.TLabelframe", font=("Segoe UI", 10, "bold"))
        style.configure("Section.TLabelframe.Label", font=("Segoe UI", 10, "bold"))

    def _create_header(self):
        header_frame = ttk.Frame(self.root, padding=(10, 10, 10, 5))
        header_frame.pack(side=tk.TOP, fill=tk.X)

        self.lbl_title = ttk.Label(header_frame, text="", style="Header.TLabel")
        self.lbl_title.pack(anchor=tk.W)

        self.lbl_subtitle = ttk.Label(header_frame, text="", style="SubHeader.TLabel")
        self.lbl_subtitle.pack(anchor=tk.W, pady=(2, 0))

        top_right = ttk.Frame(header_frame)
        top_right.pack(anchor=tk.E, fill=tk.X, pady=(10, 0))

        lang_frame = ttk.Frame(top_right)
        lang_frame.pack(side=tk.LEFT, anchor=tk.E, expand=True)

        self.lbl_language = ttk.Label(lang_frame, text="")
        self.lbl_language.pack(side=tk.LEFT, padx=(0, 6))

        self.language_var = tk.StringVar(value="de")
        self.cbo_language = ttk.Combobox(
            lang_frame,
            textvariable=self.language_var,
            state="readonly",
            width=10,
            values=["Deutsch", "English"],
        )
        self.cbo_language.pack(side=tk.LEFT)
        self.cbo_language.bind("<<ComboboxSelected>>", self.on_language_change)

        btn_frame = ttk.Frame(top_right)
        btn_frame.pack(side=tk.RIGHT)

        self.btn_info = ttk.Button(btn_frame, text="", command=self.show_info)
        self.btn_info.pack(side=tk.LEFT, padx=(0, 5))

        self.btn_github = ttk.Button(btn_frame, text="", command=self.open_github)
        self.btn_github.pack(side=tk.LEFT)

    def _create_main(self):
        main_frame = ttk.Frame(self.root, padding=(10, 5, 10, 5))
        main_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True)


        path_frame = ttk.Frame(main_frame)
        path_frame.pack(side=tk.TOP, fill=tk.X, pady=(0, 8))

        self.lbl_path = ttk.Label(path_frame, text="")
        self.lbl_path.pack(side=tk.LEFT)

        self.path_var = tk.StringVar()
        self.entry_path = ttk.Entry(path_frame, textvariable=self.path_var)
        self.entry_path.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(6, 6))

        self.btn_browse = ttk.Button(path_frame, text="", width=14, command=self.browse_folder)
        self.btn_browse.pack(side=tk.LEFT)


        self.options_frame = ttk.Labelframe(
            main_frame, text="", style="Section.TLabelframe", padding=(10, 8)
        )
        self.options_frame.pack(side=tk.TOP, fill=tk.X, pady=(0, 8))

        self.var_code = tk.BooleanVar(value=True)
        self.var_deps = tk.BooleanVar(value=True)
        self.var_secrets = tk.BooleanVar(value=True)

        self.chk_code = ttk.Checkbutton(self.options_frame, text="", variable=self.var_code)
        self.chk_code.pack(anchor=tk.W, pady=2)

        self.chk_deps = ttk.Checkbutton(self.options_frame, text="", variable=self.var_deps)
        self.chk_deps.pack(anchor=tk.W, pady=2)

        self.chk_secrets = ttk.Checkbutton(self.options_frame, text="", variable=self.var_secrets)
        self.chk_secrets.pack(anchor=tk.W, pady=2)


        scan_frame = ttk.Frame(main_frame)
        scan_frame.pack(side=tk.TOP, fill=tk.X, pady=(4, 4))

        self.btn_scan = ttk.Button(scan_frame, text="", command=self.start_scan)
        self.btn_scan.pack(anchor=tk.E)


        log_frame = ttk.Frame(main_frame)
        log_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

        self.txt_log = scrolledtext.ScrolledText(
            log_frame,
            wrap=tk.NONE,
            height=18,
            font=("Consolas", 9),
        )
        self.txt_log.pack(fill=tk.BOTH, expand=True)
        self.txt_log.configure(state=tk.NORMAL)
        self.txt_log.insert(tk.END, LANG[self.current_lang]["log_header"])
        self.txt_log.insert(tk.END, LANG[self.current_lang]["log_sep"])
        self.txt_log.configure(state=tk.DISABLED)


        self.status_var = tk.StringVar(value="")
        self.status_bar = ttk.Label(
            self.root,
            textvariable=self.status_var,
            anchor=tk.W,
            relief=tk.SUNKEN,
            padding=(8, 2),
        )
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def _create_footer(self):
        footer = ttk.Frame(self.root, padding=(10, 2, 10, 6))
        footer.pack(side=tk.BOTTOM, fill=tk.X)

        self.lbl_footer_company = ttk.Label(footer, text="")
        self.lbl_footer_company.pack(side=tk.LEFT)

        self.lbl_footer_version = ttk.Label(footer, text="")
        self.lbl_footer_version.pack(side=tk.RIGHT)

        self.lbl_footer_author = ttk.Label(footer, text="")
        self.lbl_footer_author.pack(side=tk.RIGHT, padx=(0, 12))

    def on_language_change(self, event=None):
        value = self.language_var.get()
        if value.lower().startswith("deutsch") or value.lower().startswith("german"):
            self.current_lang = "de"
        else:
            self.current_lang = "en"
        self.update_language()

    def update_language(self):
        t = LANG[self.current_lang]

        self.root.title(t["window_title"])
        self.lbl_title.config(text=t["header_title"])
        self.lbl_subtitle.config(text=t["header_subtitle"])
        self.lbl_language.config(text=t["language_label"] + ":")

        self.lbl_path.config(text=t["scan_path_label"] + ":")
        self.btn_browse.config(text=t["browse_button"])
        self.options_frame.config(text=t["options_frame"])

        self.chk_code.config(text=t["opt_code"])
        self.chk_deps.config(text=t["opt_deps"])
        self.chk_secrets.config(text=t["opt_secrets"])

        self.btn_scan.config(text=t["start_scan"])
        self.btn_info.config(text=t["info_button"])
        self.btn_github.config(text=t["github_button"])

        self.status_var.set(t["status_idle"])

        self.lbl_footer_company.config(text=t["footer_company"])
        self.lbl_footer_version.config(text=t["footer_version"])
        self.lbl_footer_author.config(text=t["footer_author"])

    def browse_folder(self):
        directory = filedialog.askdirectory()
        if directory:
            self.path_var.set(directory)

    def append_log(self, text: str):
        self.txt_log.configure(state=tk.NORMAL)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.txt_log.insert(tk.END, f"[{timestamp}] {text}")
        self.txt_log.see(tk.END)
        self.txt_log.configure(state=tk.DISABLED)

    def start_scan(self):
        t = LANG[self.current_lang]
        path = self.path_var.get().strip()
        self.findings = []

        if not path:
            self.status_var.set(t["status_no_path"])
            self.append_log(t["log_no_path"])
            return

        if not (self.var_code.get() or self.var_deps.get() or self.var_secrets.get()):
            self.status_var.set(t["status_no_option"])
            return

        self.status_var.set(t["status_running"])
        self.append_log(t["log_sep"])
        self.append_log(t["log_scan_start"].format(path=path))

        if self.var_code.get():
            self.append_log(t["log_scan_option"].format(option=t["opt_code"]))
            self.scan_code(path)

        if self.var_deps.get():
            self.append_log(t["log_scan_option"].format(option=t["opt_deps"]))
            self.scan_dependencies(path)

        if self.var_secrets.get():
            self.append_log(t["log_scan_option"].format(option=t["opt_secrets"]))
            self.scan_secrets(path)

        report_file = self.write_report(path)
        self.append_log(t["log_summary"].format(count=len(self.findings), path=path))
        self.append_log(t["log_report_file"].format(file=report_file))
        self.status_var.set(t["status_done"])

        messagebox.showinfo(
            t["dialog_scan_finished_title"],
            t["dialog_scan_finished_body"].format(count=len(self.findings), file=report_file),
        )

    def scan_code(self, root_path: str):
        t = LANG[self.current_lang]
        for dirpath, _, filenames in os.walk(root_path):
            for name in filenames:
                if not name.endswith(".py"):
                    continue
                full_path = os.path.join(dirpath, name)
                rel_path = os.path.relpath(full_path, root_path)
                self.append_log(t["log_scan_step"].format(module=rel_path))
                try:
                    with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                        for lineno, line in enumerate(f, start=1):
                            for rule in RULES:
                                if rule["pattern"].search(line):
                                    msg = rule[self.current_lang]
                                    finding = {
                                        "rule_id": rule["id"],
                                        "severity": rule["severity"],
                                        "category": rule["category"],
                                        "file": rel_path,
                                        "line": lineno,
                                        "message": msg,
                                    }
                                    self.findings.append(finding)
                                    self.append_log(
                                        t["log_finding"].format(
                                            severity=rule["severity"],
                                            rule_id=rule["id"],
                                            category=rule["category"],
                                            file=rel_path,
                                            line=lineno,
                                            message=msg,
                                        )
                                    )
                except OSError:
                    continue

    def scan_dependencies(self, root_path: str):
        t = LANG[self.current_lang]
        req_file = os.path.join(root_path, "requirements.txt")
        if not os.path.isfile(req_file):
            messagebox.showwarning("requirements.txt", t["dialog_no_requirements"])
            return

        try:
            with open(req_file, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if "==" in line:
                        name, version = line.split("==", 1)
                    else:
                        name, version = line, ""
                    pkg = name.strip().lower()
                    self.append_log(t["log_dep_step"].format(dep=line))

                    if pkg in INSECURE_DEPENDENCIES:
                        rule = INSECURE_DEPENDENCIES[pkg]
                        major = 0
                        try:
                            major = int(version.split(".")[0]) if version else 0
                        except ValueError:
                            major = 0
                        if major <= rule["max_major"]:
                            msg = rule[self.current_lang]
                            finding = {
                                "rule_id": f"DEP-{pkg.upper()}",
                                "severity": rule["severity"],
                                "category": "Outdated Dependency",
                                "file": "requirements.txt",
                                "line": 0,
                                "message": msg,
                            }
                            self.findings.append(finding)
                            self.append_log(
                                t["log_dep_finding"].format(
                                    severity=rule["severity"],
                                    name=pkg,
                                    file="requirements.txt",
                                    message=msg,
                                )
                            )
        except OSError:
            return

    def scan_secrets(self, root_path: str):
        t = LANG[self.current_lang]
        exts = (".py", ".env", ".txt", ".ini", ".cfg", ".conf", ".json", ".yaml", ".yml")
        for dirpath, _, filenames in os.walk(root_path):
            for name in filenames:
                if not name.lower().endswith(exts):
                    continue
                full_path = os.path.join(dirpath, name)
                rel_path = os.path.relpath(full_path, root_path)
                self.append_log(t["log_secret_step"].format(file=rel_path))
                try:
                    with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                        for rule in SECRET_PATTERNS:
                            for _ in rule["pattern"].finditer(content):
                                msg = rule[self.current_lang]
                                finding = {
                                    "rule_id": rule["id"],
                                    "severity": rule["severity"],
                                    "category": rule["category"],
                                    "file": rel_path,
                                    "line": 0,
                                    "message": msg,
                                }
                                self.findings.append(finding)
                                self.append_log(
                                    t["log_finding"].format(
                                        severity=rule["severity"],
                                        rule_id=rule["id"],
                                        category=rule["category"],
                                        file=rel_path,
                                        line=0,
                                        message=msg,
                                    )
                                )
                except OSError:
                    continue

    def write_report(self, root_path: str) -> str:
        report_path = os.path.join(root_path, "vuln_sentinel_report.txt")
        try:
            with open(report_path, "w", encoding="utf-8") as f:
                f.write(f"{APP_NAME} – Report\n")
                f.write(f"{APP_COMPANY}\n")
                f.write(f"Version: {APP_VERSION}\n")
                f.write(f"Author: {APP_AUTHOR}\n")
                f.write(f"Scanned path: {root_path}\n")
                f.write(f"Findings: {len(self.findings)}\n")
                f.write("=" * 80 + "\n\n")
                for finding in self.findings:
                    f.write(
                        f"{finding['severity']} | {finding['rule_id']} | {finding['category']}\n"
                        f"  File: {finding['file']}:{finding['line']}\n"
                        f"  Message: {finding['message']}\n\n"
                    )
        except OSError:
            return report_path
        return report_path

    def show_info(self):
        t = LANG[self.current_lang]
        messagebox.showinfo(t["info_title"], t["info_text"])

    def open_github(self):
        webbrowser.open(GITHUB_URL)

def main():
    root = tk.Tk()
    app = VulnScannerApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
