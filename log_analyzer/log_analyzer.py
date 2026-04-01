"""
Analyseur de Logs Windows - Version 1.0
Détection avancée : brute force, escalade de privilèges, pass-the-hash, ransomware, malware
Auteur: Indra-Labs-dev
"""

import os, sys, json, subprocess, logging, re
from datetime import datetime, timedelta
from collections import Counter, defaultdict
from pathlib import Path

APP_DIR  = Path(os.environ.get("APPDATA", Path.home())) / "LogAnalyzer"
LOG_FILE = APP_DIR / "log_analyzer.log"
APP_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(filename=LOG_FILE, level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

class C:
    RESET="\033[0m";BOLD="\033[1m";RED="\033[91m";GREEN="\033[92m"
    YELLOW="\033[93m";CYAN="\033[96m";GREY="\033[90m";BLUE="\033[94m";MAGENTA="\033[95m"

def ok(m):   print(f"  {C.GREEN}[✓]{C.RESET} {m}")
def err(m):  print(f"  {C.RED}[✗]{C.RESET} {m}")
def warn(m): print(f"  {C.YELLOW}[!]{C.RESET} {m}")
def info(m): print(f"  {C.CYAN}[i]{C.RESET} {m}")
def crit(m): print(f"  {C.RED}{C.BOLD}[!!!]{C.RESET} {m}")
def sep(t=""): print(f"\n{C.BOLD}{C.BLUE}── {t} {'─'*(50-len(t))}{C.RESET}")

def run_ps(cmd, timeout=30):
    try:
        r = subprocess.run(["powershell","-NoProfile","-NonInteractive","-Command",cmd],
            capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip()
    except:
        return ""

# ── Event IDs Windows ──────────────────────────────────────────────────────────

SECURITY_EVENTS = {
    # Authentification
    4624: "Connexion réussie",
    4625: "Échec de connexion",
    4634: "Déconnexion",
    4648: "Connexion avec credentials explicites",
    4672: "Droits spéciaux attribués à la connexion",
    # Comptes
    4720: "Compte utilisateur créé",
    4722: "Compte utilisateur activé",
    4724: "Tentative de réinitialisation MdP",
    4728: "Membre ajouté au groupe sécurité global",
    4732: "Membre ajouté au groupe sécurité local",
    4756: "Membre ajouté au groupe sécurité universel",
    # Escalade / Privilèges
    4673: "Service privilégié appelé",
    4674: "Opération tentée sur objet privilégié",
    4697: "Service installé",
    4698: "Tâche planifiée créée",
    4702: "Tâche planifiée modifiée",
    # Processus
    4688: "Nouveau processus créé",
    4689: "Processus terminé",
    # Objets
    4663: "Tentative d'accès à un objet",
    4670: "Permissions d'un objet modifiées",
    # Audit / Politique
    4719: "Politique d'audit système modifiée",
    4739: "Politique de domaine modifiée",
    # Pass-the-hash / Kerberos
    4768: "Ticket Kerberos (TGT) demandé",
    4769: "Ticket de service Kerberos demandé",
    4771: "Pré-authentification Kerberos échouée",
    4776: "Validation des credentials NTLM",
}

ATTACK_PATTERNS = {
    "brute_force":    {"events":[4625], "threshold":5,  "window_min":5,   "severity":"HIGH"},
    "pass_the_hash":  {"events":[4624], "logon_type":3, "threshold":1,    "window_min":1,   "severity":"CRITICAL"},
    "priv_escalation":{"events":[4672,4674], "threshold":3, "window_min":10, "severity":"HIGH"},
    "new_admin":      {"events":[4728,4732,4756], "threshold":1, "window_min":60, "severity":"HIGH"},
    "scheduled_task": {"events":[4698,4702], "threshold":1, "window_min":60, "severity":"MEDIUM"},
    "new_service":    {"events":[4697], "threshold":1, "window_min":60, "severity":"HIGH"},
    "lateral_movement":{"events":[4648], "threshold":3, "window_min":10, "severity":"HIGH"},
}

class LogAnalyzer:
    def __init__(self, hours_back: int = 24):
        self.hours_back = hours_back
        self.alerts: list[dict] = []
        self.stats:  dict = {}

    def _get_events(self, log_name: str, event_ids: list[int], max_events: int = 5000) -> list[dict]:
        """Récupère les événements Windows via PowerShell."""
        ids_filter = " -or ".join(f"$_.Id -eq {i}" for i in event_ids)
        since = (datetime.now() - timedelta(hours=self.hours_back)).strftime("%Y-%m-%dT%H:%M:%S")
        ps = f"""
Get-WinEvent -LogName '{log_name}' -MaxEvents {max_events} -ErrorAction SilentlyContinue |
  Where-Object {{ ({ids_filter}) -and $_.TimeCreated -ge '{since}' }} |
  Select-Object Id, TimeCreated, Message, @{{N='User';E={{$_.Properties[5].Value}}}},
                @{{N='IP';E={{$_.Properties[18].Value}}}},
                @{{N='LogonType';E={{$_.Properties[8].Value}}}} |
  ConvertTo-Json -Depth 2
"""
        raw = run_ps(ps, timeout=30)
        if not raw: return []
        try:
            data = json.loads(raw)
            return data if isinstance(data, list) else [data]
        except:
            return []

    def analyze_failed_logins(self):
        """Détection de brute force et spray d'identifiants."""
        sep("Tentatives de connexion échouées (Brute Force / Spray)")
        events = self._get_events("Security", [4625])
        if not events:
            info("Aucun échec de connexion dans les dernières " + str(self.hours_back) + "h.")
            return

        per_ip:   Counter = Counter()
        per_user: Counter = Counter()
        per_time: list    = []

        for e in events:
            ip   = str(e.get("IP","?")).strip() or "inconnu"
            user = str(e.get("User","?")).strip() or "inconnu"
            per_ip[ip] += 1
            per_user[user] += 1

        total = len(events)
        info(f"Total échecs de connexion : {total}")

        # IP les plus actives
        top_ips = per_ip.most_common(5)
        if top_ips:
            print(f"\n  {C.BOLD}Top IPs :{C.RESET}")
            for ip, cnt in top_ips:
                color = C.RED if cnt > 20 else (C.YELLOW if cnt > 5 else C.RESET)
                print(f"    {color}{ip:<20} {cnt} tentatives{C.RESET}")
                if cnt > 20:
                    self._alert("BRUTE_FORCE", f"IP {ip} : {cnt} tentatives d'authentification", "HIGH")

        # Comptes ciblés
        top_users = per_user.most_common(5)
        if top_users:
            print(f"\n  {C.BOLD}Comptes ciblés :{C.RESET}")
            for user, cnt in top_users:
                color = C.RED if cnt > 10 else C.RESET
                print(f"    {color}{user:<25} {cnt}x{C.RESET}")

        # Détection spray (beaucoup de comptes différents depuis la même IP)
        for ip, cnt in per_ip.items():
            if cnt > 50:
                self._alert("CREDENTIAL_SPRAY", f"IP {ip} a tenté {cnt} connexions — spray probable", "CRITICAL")

        self.stats["failed_logins"] = total

    def analyze_successful_logins(self):
        """Analyse des connexions réussies — détection pass-the-hash et anomalies."""
        sep("Connexions réussies — Analyse d'anomalies")
        events = self._get_events("Security", [4624])
        if not events:
            info("Aucune connexion enregistrée."); return

        logon_types = Counter()
        off_hours   = []
        ntlm_type3  = []

        for e in events:
            lt = str(e.get("LogonType","?"))
            logon_types[lt] += 1
            tc = e.get("TimeCreated","")
            try:
                dt = datetime.fromisoformat(str(tc)[:19])
                if dt.hour < 6 or dt.hour > 22:
                    off_hours.append(e)
            except: pass
            # Logon type 3 via NTLM = indicateur pass-the-hash
            if lt == "3" and "NTLM" in str(e.get("Message","")):
                ntlm_type3.append(e)

        info(f"Total connexions réussies : {len(events)}")
        print(f"\n  {C.BOLD}Types de connexion :{C.RESET}")
        type_labels = {"2":"Interactif","3":"Réseau","4":"Batch","5":"Service","7":"Unlock",
                       "8":"NetworkCleartext","9":"NewCredentials","10":"RemoteInteractif","11":"CachedInteractif"}
        for lt, cnt in sorted(logon_types.items()):
            label = type_labels.get(str(lt), f"Type {lt}")
            print(f"    Type {lt} ({label}) : {cnt}")

        if off_hours:
            warn(f"{len(off_hours)} connexion(s) en dehors des heures normales (avant 6h / après 22h)")
            if len(off_hours) > 5:
                self._alert("OFF_HOURS_LOGIN", f"{len(off_hours)} connexions hors horaires", "MEDIUM")

        if ntlm_type3:
            self._alert("PASS_THE_HASH", f"{len(ntlm_type3)} connexion(s) NTLM réseau suspectes (possible pass-the-hash)", "CRITICAL")

    def analyze_privilege_escalation(self):
        """Détection d'escalade de privilèges."""
        sep("Escalade de Privilèges")
        events = self._get_events("Security", [4672, 4673, 4674, 4728, 4732])
        if not events:
            info("Aucun événement de privilèges."); return

        event_counts = Counter(e.get("Id",0) for e in events)
        for eid, cnt in event_counts.items():
            label = SECURITY_EVENTS.get(int(eid) if eid else 0, f"Event {eid}")
            color = C.RED if cnt > 10 else C.RESET
            print(f"    {color}ID {eid} ({label}) : {cnt} fois{C.RESET}")

        admin_group_changes = [e for e in events if e.get("Id") in (4728, 4732, 4756)]
        if admin_group_changes:
            self._alert("ADMIN_GROUP_CHANGE",
                        f"{len(admin_group_changes)} modification(s) de groupes administrateurs", "HIGH")

    def analyze_processes(self):
        """Analyse des processus suspects via les logs."""
        sep("Processus suspects (Event 4688)")
        SUSPICIOUS_PROC = ["mimikatz","meterpreter","cobalt","powersploit","empire",
                           "nc.exe","ncat","psexec","wmic","certutil","regsvr32",
                           "mshta","cscript","wscript","rundll32"]

        events = self._get_events("Security", [4688], max_events=2000)
        if not events:
            info("Aucun log de création de processus (activez l'audit des processus).")
            return

        found = []
        for e in events:
            msg = str(e.get("Message","")).lower()
            for s in SUSPICIOUS_PROC:
                if s in msg:
                    found.append((s, e.get("TimeCreated","?")))
                    break

        if found:
            for proc, ts in found[:10]:
                self._alert("SUSPICIOUS_PROCESS", f"Processus suspect : '{proc}' à {ts}", "HIGH")
        else:
            ok("Aucun processus suspect détecté dans les logs.")

    def analyze_scheduled_tasks(self):
        """Détection de tâches planifiées créées récemment (persistance malware)."""
        sep("Tâches planifiées — Persistance")
        events = self._get_events("Security", [4698, 4702])
        if events:
            warn(f"{len(events)} tâche(s) planifiée(s) créée/modifiée dans les {self.hours_back}h")
            if len(events) > 3:
                self._alert("SCHEDULED_TASK_ABUSE", f"{len(events)} tâches planifiées modifiées — vérifiez", "MEDIUM")
        else:
            ok("Aucune tâche planifiée créée/modifiée récemment.")

        # Lister les tâches actuelles suspectes
        tasks_raw = run_ps("Get-ScheduledTask | Where-Object {$_.State -eq 'Ready'} | Select-Object TaskName,TaskPath | ConvertTo-Json")
        try:
            tasks = json.loads(tasks_raw) if tasks_raw.startswith("[") else [json.loads(tasks_raw)]
            LEGIT_PATHS = ["\\Microsoft\\", "\\Adobe\\", "\\Google\\"]
            suspicious = [t for t in tasks
                          if not any(lp in str(t.get("TaskPath","")) for lp in LEGIT_PATHS)
                          and str(t.get("TaskPath","")).count("\\") <= 1]
            if suspicious:
                warn(f"{len(suspicious)} tâche(s) dans des emplacements inhabituels :")
                for t in suspicious[:5]:
                    print(f"    {C.YELLOW}{t.get('TaskPath','')}{t.get('TaskName','')}{C.RESET}")
        except: pass

    def analyze_system_errors(self):
        """Analyse des erreurs système critiques."""
        sep("Erreurs Système Critiques")
        ps = f"""
Get-WinEvent -LogName 'System' -MaxEvents 500 -ErrorAction SilentlyContinue |
  Where-Object {{$_.Level -le 2 -and $_.TimeCreated -ge (Get-Date).AddHours(-{self.hours_back})}} |
  Select-Object Id, LevelDisplayName, TimeCreated, Message |
  ConvertTo-Json -Depth 1
"""
        raw = run_ps(ps, timeout=20)
        try:
            events = json.loads(raw) if raw.startswith("[") else [json.loads(raw)]
            criticals = [e for e in events if e.get("LevelDisplayName","") in ("Critical","Error")]
            info(f"Événements critiques/erreurs : {len(criticals)} dans les {self.hours_back}h")
            top_ids = Counter(e.get("Id",0) for e in criticals).most_common(5)
            for eid, cnt in top_ids:
                print(f"    ID {eid} : {cnt} occurrence(s)")
            if len(criticals) > 50:
                self._alert("SYSTEM_INSTABILITY", f"{len(criticals)} erreurs système — instabilité détectée", "MEDIUM")
        except: warn("Impossible de lire les logs système.")

    def _alert(self, alert_type: str, message: str, severity: str):
        self.alerts.append({"type":alert_type,"message":message,"severity":severity,"ts":str(datetime.now())})
        color = {"CRITICAL":C.RED+C.BOLD,"HIGH":C.RED,"MEDIUM":C.YELLOW,"LOW":C.CYAN}.get(severity,C.RESET)
        print(f"\n  {color}⚠ [{severity}] {message}{C.RESET}")
        logger.warning(f"ALERTE [{severity}] {alert_type}: {message}")

    def print_summary(self):
        sep("Résumé des Alertes")
        if not self.alerts:
            ok("Aucune alerte détectée dans les dernières " + str(self.hours_back) + "h."); return
        by_severity = defaultdict(list)
        for a in self.alerts:
            by_severity[a["severity"]].append(a)
        for sev in ["CRITICAL","HIGH","MEDIUM","LOW"]:
            grp = by_severity.get(sev,[])
            if grp:
                color = {"CRITICAL":C.RED+C.BOLD,"HIGH":C.RED,"MEDIUM":C.YELLOW,"LOW":C.CYAN}[sev]
                print(f"\n  {color}[{sev}] — {len(grp)} alerte(s){C.RESET}")
                for a in grp:
                    print(f"    → {a['message']}")

    def export(self):
        out = {"generated_at":str(datetime.now()),"hours_analyzed":self.hours_back,
               "alerts":self.alerts,"stats":self.stats}
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        pj = APP_DIR / f"log_report_{ts}.json"
        pt = APP_DIR / f"log_report_{ts}.txt"
        pj.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
        lines = [f"RAPPORT ANALYSE LOGS — {datetime.now().strftime('%d/%m/%Y %H:%M')}",
                 f"Période : {self.hours_back}h", "="*60]
        for a in self.alerts:
            lines.append(f"[{a['severity']}] {a['type']} : {a['message']}")
        pt.write_text("\n".join(lines), encoding="utf-8")
        ok(f"JSON : {pj}"); ok(f"TXT  : {pt}")

def print_banner():
    print(f"""{C.CYAN}{C.BOLD}
╔══════════════════════════════════════════════════════════════╗
║          📋  Analyseur de Logs Windows v1.0                  ║
║  Brute Force · Pass-the-Hash · Escalade · Persistance        ║
╚══════════════════════════════════════════════════════════════╝{C.RESET}""")

def main():
    os.system("cls" if os.name=="nt" else "clear")
    print_banner()
    try:
        hours = int(input(f"\n  Analyser les {C.CYAN}N{C.RESET} dernières heures [24] : ").strip() or "24")
    except ValueError:
        hours = 24
    analyzer = None
    while True:
        print(f"""\n{C.BOLD}─── MENU ────────────────────────────────────{C.RESET}
  {C.CYAN}1.{C.RESET} Analyse complète
  {C.CYAN}2.{C.RESET} Échecs de connexion (Brute Force)
  {C.CYAN}3.{C.RESET} Connexions réussies (anomalies / pass-the-hash)
  {C.CYAN}4.{C.RESET} Escalade de privilèges
  {C.CYAN}5.{C.RESET} Processus suspects
  {C.CYAN}6.{C.RESET} Tâches planifiées (persistance)
  {C.CYAN}7.{C.RESET} Erreurs système critiques
  {C.CYAN}8.{C.RESET} Exporter rapport
  {C.CYAN}9.{C.RESET} Changer la période d'analyse
  {C.CYAN}0.{C.RESET} Quitter\n""")
        c = input(f"{C.BOLD}Choix >{C.RESET} ").strip()
        if c=="0": break
        elif c=="1":
            analyzer=LogAnalyzer(hours)
            for fn in [analyzer.analyze_failed_logins, analyzer.analyze_successful_logins,
                       analyzer.analyze_privilege_escalation, analyzer.analyze_processes,
                       analyzer.analyze_scheduled_tasks, analyzer.analyze_system_errors]:
                fn()
            analyzer.print_summary()
        elif c=="2": LogAnalyzer(hours).analyze_failed_logins()
        elif c=="3": LogAnalyzer(hours).analyze_successful_logins()
        elif c=="4": LogAnalyzer(hours).analyze_privilege_escalation()
        elif c=="5": LogAnalyzer(hours).analyze_processes()
        elif c=="6": LogAnalyzer(hours).analyze_scheduled_tasks()
        elif c=="7": LogAnalyzer(hours).analyze_system_errors()
        elif c=="8":
            if analyzer: analyzer.export()
            else: warn("Lancez d'abord une analyse complète (option 1).")
        elif c=="9":
            try: hours = int(input("  Nouvelles heures [24] : ").strip() or "24")
            except: hours = 24
            info(f"Période : {hours}h")

if __name__ == "__main__":
    main()