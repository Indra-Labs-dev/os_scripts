"""
Gestionnaire de Services Windows - Version 1.0
Lister, démarrer/arrêter, modifier, détecter services suspects, analyse dépendances
Auteur: Indra-Labs-dev
"""

import os, sys, json, subprocess, logging
from datetime import datetime
from pathlib import Path

APP_DIR  = Path(os.environ.get("APPDATA", Path.home())) / "ServiceManager"
LOG_FILE = APP_DIR / "service_manager.log"
APP_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(filename=LOG_FILE, level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

class C:
    RESET="\033[0m";BOLD="\033[1m";RED="\033[91m";GREEN="\033[92m"
    YELLOW="\033[93m";CYAN="\033[96m";GREY="\033[90m";BLUE="\033[94m"

def ok(m):   print(f"  {C.GREEN}[✓]{C.RESET} {m}")
def err(m):  print(f"  {C.RED}[✗]{C.RESET} {m}")
def warn(m): print(f"  {C.YELLOW}[!]{C.RESET} {m}")
def info(m): print(f"  {C.CYAN}[i]{C.RESET} {m}")
def sep(t=""): print(f"\n{C.BOLD}{C.BLUE}── {t} {'─'*(50-len(t))}{C.RESET}")

def run_ps(cmd, timeout=15):
    try:
        r = subprocess.run(["powershell","-NoProfile","-NonInteractive","-Command",cmd],
            capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip(), r.returncode
    except Exception as e:
        return str(e), -1

def is_admin():
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except: return False

# ── Services suspects / inutiles ───────────────────────────────────────────────

RISKY_SERVICES = {
    "RemoteRegistry":  ("Accès au registre à distance",    "HIGH"),
    "Telnet":          ("Protocole non chiffré",            "HIGH"),
    "TlntSvr":         ("Serveur Telnet",                   "HIGH"),
    "SNMP":            ("SNMP v1/v2 non chiffré",           "MEDIUM"),
    "simptcp":         ("Simple TCP/IP Services",           "LOW"),
    "SharedAccess":    ("Partage connexion Internet (ICS)", "LOW"),
    "RasMan":          ("Gestionnaire connexions RAS",      "LOW"),
    "WinRM":           ("Remote Management (WinRM)",        "MEDIUM"),
    "W3SVC":           ("IIS Web Server",                   "MEDIUM"),
    "FTPSvc":          ("Serveur FTP IIS",                  "HIGH"),
    "MSSQLSERVER":     ("SQL Server",                       "MEDIUM"),
    "MySQL":           ("MySQL Server",                     "MEDIUM"),
}

UNNECESSARY_SERVICES = {
    "Fax":            "Service Télécopie",
    "WMPNetworkSvc":  "Windows Media Player Sharing",
    "HomeGroupListener":"HomeGroup Listener",
    "HomeGroupProvider":"HomeGroup Provider",
    "XblAuthManager": "Xbox Live Auth Manager",
    "XblGameSave":    "Xbox Live Game Save",
    "XboxNetApiSvc":  "Xbox Live Networking",
    "WSearch":        "Windows Search (indexation)",
    "SysMain":        "Superfetch",
    "DiagTrack":      "Connected User Experiences (télémétrie)",
    "dmwappushservice":"WAP Push Message Routing (télémétrie)",
    "MapsBroker":     "Downloaded Maps Manager",
    "RetailDemo":     "Retail Demo Service",
}

# ── Opérations services ────────────────────────────────────────────────────────

def list_services(filter_status: str = None) -> list[dict]:
    """Récupère la liste des services Windows."""
    ps = """
Get-Service | Select-Object Name, DisplayName, Status, StartType |
  Sort-Object DisplayName | ConvertTo-Json
"""
    raw, _ = run_ps(ps, timeout=20)
    try:
        svcs = json.loads(raw) if raw.startswith("[") else [json.loads(raw)]
        if filter_status:
            svcs = [s for s in svcs if str(s.get("Status","")).lower() == filter_status.lower()]
        return svcs
    except:
        return []

def get_service_details(name: str) -> dict:
    ps = f"""
$s = Get-WmiObject Win32_Service -Filter "Name='{name}'" -ErrorAction SilentlyContinue
if ($s) {{
  [PSCustomObject]@{{
    Name=$s.Name; DisplayName=$s.DisplayName; State=$s.State
    StartMode=$s.StartMode; PathName=$s.PathName
    StartName=$s.StartName; Description=$s.Description
    ProcessId=$s.ProcessId
  }} | ConvertTo-Json
}}
"""
    raw, _ = run_ps(ps)
    try: return json.loads(raw)
    except: return {}

def start_service(name: str) -> bool:
    _, rc = run_ps(f"Start-Service '{name}' -ErrorAction Stop")
    if rc == 0:
        ok(f"Service '{name}' démarré."); logger.info(f"Service démarré: {name}"); return True
    else:
        err(f"Impossible de démarrer '{name}'."); return False

def stop_service(name: str) -> bool:
    _, rc = run_ps(f"Stop-Service '{name}' -Force -ErrorAction Stop")
    if rc == 0:
        ok(f"Service '{name}' arrêté."); logger.info(f"Service arrêté: {name}"); return True
    else:
        err(f"Impossible d'arrêter '{name}'."); return False

def restart_service(name: str) -> bool:
    _, rc = run_ps(f"Restart-Service '{name}' -Force -ErrorAction Stop")
    if rc == 0:
        ok(f"Service '{name}' redémarré."); logger.info(f"Service redémarré: {name}"); return True
    else:
        err(f"Impossible de redémarrer '{name}'."); return False

def set_startup_type(name: str, startup_type: str) -> bool:
    types = {"auto":"Automatic","manual":"Manual","disabled":"Disabled","delayed":"AutomaticDelayedStart"}
    t = types.get(startup_type.lower(), startup_type)
    _, rc = run_ps(f"Set-Service '{name}' -StartupType {t} -ErrorAction Stop")
    if rc == 0:
        ok(f"Type de démarrage de '{name}' → {t}"); logger.info(f"StartupType {name}: {t}"); return True
    else:
        err(f"Impossible de modifier '{name}'."); return False

def get_dependencies(name: str) -> tuple[list, list]:
    """Retourne (services dont dépend name, services qui dépendent de name)."""
    ps_dep = f"(Get-Service '{name}').DependentServices | Select-Object -ExpandProperty Name"
    ps_req = f"(Get-Service '{name}').ServicesDependedOn | Select-Object -ExpandProperty Name"
    dep, _ = run_ps(ps_dep)
    req, _ = run_ps(ps_req)
    return dep.splitlines(), req.splitlines()

# ── Menus ──────────────────────────────────────────────────────────────────────

def menu_list(services: list[dict] = None):
    sep("Liste des services")
    print("  (1) Tous  (2) En cours  (3) Arrêtés  (4) Désactivés")
    choice = input("  Filtre [1] : ").strip()
    filt   = {2:"Running",3:"Stopped",4:"Disabled"}.get(int(choice) if choice.isdigit() else 1, None)
    svcs   = list_services(filt) or services or []
    total  = {"Running":0,"Stopped":0,"Disabled":0}
    for s in svcs:
        status = str(s.get("Status","?"))
        total[status] = total.get(status,0) + 1

    print(f"\n  {len(svcs)} service(s) — "
          f"{C.GREEN}En cours:{total.get('Running',0)}{C.RESET}  "
          f"{C.YELLOW}Arrêtés:{total.get('Stopped',0)}{C.RESET}  "
          f"{C.GREY}Désactivés:{total.get('Disabled',0)}{C.RESET}\n")

    for s in svcs[:50]:  # Limite affichage
        name    = s.get("Name","?")
        display = s.get("DisplayName","")[:35]
        status  = str(s.get("Status","?"))
        st_type = str(s.get("StartType","?"))
        color   = C.GREEN if status=="Running" else (C.GREY if status=="Disabled" else C.YELLOW)
        print(f"  {color}{status:<10}{C.RESET} {display:<36} {C.GREY}{name:<30} {st_type}{C.RESET}")
    if len(svcs) > 50:
        info(f"... et {len(svcs)-50} autres (utilisez le filtre pour affiner)")

def menu_details():
    sep("Détails d'un service")
    name = input("  Nom du service : ").strip()
    d    = get_service_details(name)
    if not d: err(f"Service '{name}' introuvable."); return
    print(f"""
  {C.BOLD}Nom         :{C.RESET} {d.get('Name','?')}
  {C.BOLD}Description :{C.RESET} {d.get('DisplayName','?')}
  {C.BOLD}État        :{C.RESET} {d.get('State','?')}
  {C.BOLD}Démarrage   :{C.RESET} {d.get('StartMode','?')}
  {C.BOLD}PID         :{C.RESET} {d.get('ProcessId','?')}
  {C.BOLD}Compte      :{C.RESET} {d.get('StartName','?')}
  {C.BOLD}Exécutable  :{C.RESET} {d.get('PathName','?')}""")
    dep, req = get_dependencies(name)
    if req:  info(f"Dépend de      : {', '.join(req)}")
    if dep:  info(f"Utilisé par    : {', '.join(dep)}")

def menu_control():
    sep("Contrôler un service")
    name = input("  Nom du service : ").strip()
    print("  (1) Démarrer  (2) Arrêter  (3) Redémarrer  (4) Modifier démarrage")
    c = input("  Action : ").strip()
    if c=="1":   start_service(name)
    elif c=="2": stop_service(name)
    elif c=="3": restart_service(name)
    elif c=="4":
        print("  (1) Automatique  (2) Manuel  (3) Désactivé  (4) Auto (différé)")
        st = input("  Type [1] : ").strip()
        types = {"1":"auto","2":"manual","3":"disabled","4":"delayed"}
        set_startup_type(name, types.get(st,"auto"))

def menu_scan_risky():
    sep("Détection de services dangereux")
    found = False
    all_svcs = list_services("running")
    running  = {s.get("Name","").lower() for s in all_svcs}

    print(f"\n  {C.BOLD}Services risqués :{C.RESET}")
    for svc, (desc, sev) in RISKY_SERVICES.items():
        status_raw, _ = run_ps(f"(Get-Service '{svc}' -ErrorAction SilentlyContinue).Status")
        if status_raw.strip().lower() == "running":
            color = C.RED if sev=="HIGH" else C.YELLOW
            print(f"  {color}[{sev}] {svc}{C.RESET} — {desc}")
            found = True

    print(f"\n  {C.BOLD}Services inutiles actifs :{C.RESET}")
    for svc, desc in UNNECESSARY_SERVICES.items():
        status_raw, _ = run_ps(f"(Get-Service '{svc}' -ErrorAction SilentlyContinue).Status")
        if status_raw.strip().lower() == "running":
            print(f"  {C.YELLOW}[INFO]{C.RESET} {svc} — {desc}")
            found = True

    if not found:
        ok("Aucun service particulièrement suspect détecté.")

def menu_optimize():
    sep("Désactiver les services inutiles")
    warn("Ces services sont généralement inutiles sur un PC non connecté à un domaine.")
    warn("Certains peuvent affecter des fonctionnalités si désactivés.")
    all_svcs = list_services()
    running_unnecessary = []
    for svc in UNNECESSARY_SERVICES:
        for s in all_svcs:
            if s.get("Name","").lower() == svc.lower() and str(s.get("Status","")) == "Running":
                running_unnecessary.append(svc)
                break

    if not running_unnecessary:
        ok("Aucun service inutile actif."); return

    print(f"\n  Services inutiles actifs ({len(running_unnecessary)}) :")
    for svc in running_unnecessary:
        print(f"    {C.YELLOW}• {svc}{C.RESET} — {UNNECESSARY_SERVICES[svc]}")
    confirm = input(f"\n  {C.YELLOW}Désactiver tous ces services ? (oui/N) :{C.RESET} ").strip().lower()
    if confirm == "oui":
        for svc in running_unnecessary:
            set_startup_type(svc, "manual")
            stop_service(svc)

def menu_export():
    sep("Exporter la liste des services")
    svcs = list_services()
    ts   = datetime.now().strftime('%Y%m%d_%H%M%S')
    pj   = APP_DIR / f"services_{ts}.json"
    pj.write_text(json.dumps(svcs, ensure_ascii=False, indent=2), encoding="utf-8")
    ok(f"Export JSON : {pj}")
    logger.info(f"Export services: {pj}")

def print_banner():
    print(f"""{C.CYAN}{C.BOLD}
╔══════════════════════════════════════════════════════════════╗
║        ⚙️  Gestionnaire de Services Windows v1.0             ║
║   Lister · Contrôler · Analyser · Optimiser · Planifier      ║
╚══════════════════════════════════════════════════════════════╝{C.RESET}""")

def main():
    os.system("cls" if os.name=="nt" else "clear")
    print_banner()
    if not is_admin():
        warn("Certaines opérations nécessitent des droits administrateur.")
        warn("Relancez en tant qu'administrateur pour un contrôle complet.\n")
    while True:
        print(f"""\n{C.BOLD}─── MENU ────────────────────────────────────{C.RESET}
  {C.CYAN}1.{C.RESET} Lister les services
  {C.CYAN}2.{C.RESET} Détails et dépendances d'un service
  {C.CYAN}3.{C.RESET} Démarrer / Arrêter / Redémarrer / Modifier
  {C.CYAN}4.{C.RESET} Détecter services dangereux / inutiles
  {C.CYAN}5.{C.RESET} Désactiver les services inutiles
  {C.CYAN}6.{C.RESET} Exporter la liste (JSON)
  {C.CYAN}0.{C.RESET} Quitter\n""")
        c = input(f"{C.BOLD}Choix >{C.RESET} ").strip()
        if c=="0": break
        elif c=="1": menu_list()
        elif c=="2": menu_details()
        elif c=="3": menu_control()
        elif c=="4": menu_scan_risky()
        elif c=="5": menu_optimize()
        elif c=="6": menu_export()

if __name__ == "__main__":
    main()