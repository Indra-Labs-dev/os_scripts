"""
Gestionnaire de Démarrage Windows - Version 1.0
Registre + dossiers Startup + Task Scheduler, délai de démarrage, impact, score
Auteur: Indra-Labs-dev
"""

import os, sys, json, subprocess, winreg if os.name=="nt" else None, logging
from datetime import datetime
from pathlib import Path

APP_DIR  = Path(os.environ.get("APPDATA", Path.home())) / "StartupManager"
LOG_FILE = APP_DIR / "startup.log"
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

# ── Registre Windows ───────────────────────────────────────────────────────────

REGISTRY_KEYS = [
    (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",      "HKCU", "Utilisateur (Run)"),
    (r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",  "HKCU", "Utilisateur (RunOnce)"),
    (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",      "HKLM", "Système (Run)"),
    (r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",  "HKLM", "Système (RunOnce)"),
    (r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "HKLM", "Système 32bit (Run)"),
]

# ── Applications connues (impact estimé) ──────────────────────────────────────

HIGH_IMPACT = {"teams","discord","slack","spotify","dropbox","onedrive","googledrivefs",
               "steam","epic games","uplay","origin","zoom","skype","webex"}
MED_IMPACT  = {"itunes","adobe","creative cloud","acrobat","nordvpn","expressvpn",
               "malwarebytes","avast","avg","bitdefender"}
SAFE_SYSTEM = {"windows security","windows defender","realtek","nvidia","amd","intel",
               "cortana","windows update"}

def estimate_impact(name: str, path: str) -> tuple[str, str]:
    n = name.lower()
    if any(h in n for h in HIGH_IMPACT): return "ÉLEVÉ",   C.RED
    if any(m in n for m in MED_IMPACT):  return "MOYEN",   C.YELLOW
    if any(s in n for s in SAFE_SYSTEM): return "SYSTÈME", C.GREY
    return "FAIBLE", C.GREEN

def get_registry_startups() -> list[dict]:
    items = []
    if os.name != "nt": return items
    import winreg
    hive_map = {"HKCU": winreg.HKEY_CURRENT_USER, "HKLM": winreg.HKEY_LOCAL_MACHINE}
    for subkey, hive_s, label in REGISTRY_KEYS:
        hive = hive_map[hive_s]
        try:
            key = winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ)
            i = 0
            while True:
                try:
                    name, data, _ = winreg.EnumValue(key, i)
                    impact, color = estimate_impact(name, str(data))
                    items.append({
                        "source": label, "name": name, "command": str(data),
                        "enabled": True, "impact": impact,
                        "hive": hive_s, "subkey": subkey,
                    })
                    i += 1
                except OSError: break
            winreg.CloseKey(key)
        except: pass
    return items

def get_folder_startups() -> list[dict]:
    """Dossiers Startup utilisateur et système."""
    items = []
    folders = [
        (Path(os.environ.get("APPDATA","")) / r"Microsoft\Windows\Start Menu\Programs\Startup", "Startup Utilisateur"),
        (Path(r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"), "Startup Système"),
    ]
    for folder, label in folders:
        if folder.exists():
            for f in folder.iterdir():
                if f.suffix.lower() in (".lnk",".bat",".cmd",".exe",".vbs"):
                    impact, _ = estimate_impact(f.stem, str(f))
                    items.append({
                        "source": label, "name": f.stem, "command": str(f),
                        "enabled": True, "impact": impact, "path": str(f),
                    })
    return items

def get_scheduled_task_startups() -> list[dict]:
    """Tâches planifiées avec déclencheur au démarrage."""
    ps = """
Get-ScheduledTask | Where-Object {
    $_.Triggers | Where-Object {$_ -is [Microsoft.Management.Infrastructure.CimInstance] -and
      ($_.CimClass.CimClassName -like '*LogonTrigger*' -or $_.CimClass.CimClassName -like '*BootTrigger*')}
} | Select-Object TaskName, TaskPath, State | ConvertTo-Json
"""
    raw, _ = run_ps(ps, timeout=15)
    try:
        tasks = json.loads(raw) if raw.startswith("[") else [json.loads(raw)]
        return [{"source":"Tâche planifiée","name":t.get("TaskName","?"),
                 "command":t.get("TaskPath","?"),"enabled":str(t.get("State",""))=="Ready",
                 "impact":"?","path":t.get("TaskPath","?")} for t in tasks]
    except: return []

def get_all_startups() -> list[dict]:
    items = get_registry_startups() + get_folder_startups()
    try: items += get_scheduled_task_startups()
    except: pass
    return items

def disable_registry_startup(name: str, hive_s: str, subkey: str) -> bool:
    if os.name != "nt": return False
    import winreg
    hive_map = {"HKCU": winreg.HKEY_CURRENT_USER, "HKLM": winreg.HKEY_LOCAL_MACHINE}
    try:
        key = winreg.OpenKey(hive_map[hive_s], subkey, 0, winreg.KEY_SET_VALUE)
        # Renommer avec préfixe pour désactiver sans supprimer
        val, _ = winreg.QueryValueEx(key, name)
        winreg.SetValueEx(key, f"[Disabled]{name}", 0, winreg.REG_SZ, val)
        winreg.DeleteValue(key, name)
        winreg.CloseKey(key)
        logger.info(f"Startup désactivé (registre) : {name}")
        return True
    except Exception as e:
        logger.error(f"Erreur désactivation {name}: {e}"); return False

def enable_registry_startup(name: str, hive_s: str, subkey: str) -> bool:
    if os.name != "nt": return False
    import winreg
    hive_map = {"HKCU": winreg.HKEY_CURRENT_USER, "HKLM": winreg.HKEY_LOCAL_MACHINE}
    disabled_name = f"[Disabled]{name}"
    try:
        key = winreg.OpenKey(hive_map[hive_s], subkey, 0, winreg.KEY_SET_VALUE | winreg.KEY_READ)
        val, _ = winreg.QueryValueEx(key, disabled_name)
        winreg.SetValueEx(key, name, 0, winreg.REG_SZ, val)
        winreg.DeleteValue(key, disabled_name)
        winreg.CloseKey(key)
        logger.info(f"Startup réactivé (registre) : {name}")
        return True
    except Exception as e:
        logger.error(f"Erreur réactivation {name}: {e}"); return False

def add_startup(name: str, command: str) -> bool:
    if os.name != "nt": return False
    import winreg
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
              r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, name, 0, winreg.REG_SZ, command)
        winreg.CloseKey(key)
        logger.info(f"Startup ajouté : {name} → {command}")
        return True
    except Exception as e:
        logger.error(f"Erreur ajout startup {name}: {e}"); return False

# ── Interface ──────────────────────────────────────────────────────────────────

def menu_list():
    sep("Applications au démarrage")
    items = get_all_startups()
    if not items:
        info("Aucune application au démarrage détectée."); return items

    by_source = {}
    for it in items:
        by_source.setdefault(it["source"],[]).append(it)

    high = [i for i in items if i.get("impact")=="ÉLEVÉ"]
    info(f"Total : {len(items)} entrée(s) — {C.RED}{len(high)} à impact élevé{C.RESET}")

    for source, its in by_source.items():
        print(f"\n  {C.BOLD}{source}{C.RESET}")
        for i, it in enumerate(its, 1):
            _, color = estimate_impact(it["name"], it.get("command",""))
            status = f"{C.GREEN}✓{C.RESET}" if it.get("enabled",True) else f"{C.GREY}✗{C.RESET}"
            print(f"    {status} {color}{it['name']:<30}{C.RESET} {C.GREY}{it.get('command','')[:50]}{C.RESET}")
    return items

def menu_toggle():
    sep("Activer / Désactiver")
    items = get_registry_startups()
    for i, it in enumerate(items, 1):
        _, color = estimate_impact(it["name"], it.get("command",""))
        print(f"  {C.CYAN}{i}.{C.RESET} {color}{it['name']}{C.RESET}")
    try:
        idx = int(input("  Numéro : ").strip()) - 1
        if 0 <= idx < len(items):
            it = items[idx]
            print(f"  (1) Désactiver  (2) Activer")
            action = input("  Action : ").strip()
            if action == "1":
                if disable_registry_startup(it["name"], it["hive"], it["subkey"]):
                    ok(f"'{it['name']}' désactivé du démarrage.")
            elif action == "2":
                if enable_registry_startup(it["name"], it["hive"], it["subkey"]):
                    ok(f"'{it['name']}' réactivé.")
    except ValueError:
        err("Numéro invalide.")

def menu_add():
    sep("Ajouter au démarrage")
    name = input("  Nom de l'entrée : ").strip()
    cmd  = input("  Commande / Chemin exe : ").strip()
    if name and cmd:
        if add_startup(name, cmd):
            ok(f"'{name}' ajouté au démarrage.")

def menu_impact():
    sep("Analyse de l'impact sur le démarrage")
    items = get_all_startups()
    high = [i for i in items if i.get("impact")=="ÉLEVÉ"]
    med  = [i for i in items if i.get("impact")=="MOYEN"]
    ok(f"Faible impact : {len(items)-len(high)-len(med)}")
    if med:  warn(f"Impact moyen  : {len(med)}")
    if high: err(f"Impact élevé  : {len(high)}")
    if high:
        print(f"\n  {C.RED}{C.BOLD}À désactiver en priorité :{C.RESET}")
        for i in high:
            print(f"    {C.RED}→ {i['name']}{C.RESET}  {C.GREY}({i.get('command','')[:50]}){C.RESET}")

def menu_export():
    items = get_all_startups()
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    pj = APP_DIR / f"startup_{ts}.json"
    pj.write_text(json.dumps(items, ensure_ascii=False, indent=2), encoding="utf-8")
    ok(f"Export : {pj}")

def print_banner():
    print(f"""{C.CYAN}{C.BOLD}
╔══════════════════════════════════════════════════════════════╗
║        🚀  Gestionnaire de Démarrage Windows v1.0            ║
║   Registre · Dossiers · Tâches · Impact · Optimisation       ║
╚══════════════════════════════════════════════════════════════╝{C.RESET}""")

def main():
    os.system("cls" if os.name=="nt" else "clear")
    print_banner()
    while True:
        print(f"""\n{C.BOLD}─── MENU ────────────────────────────────────{C.RESET}
  {C.CYAN}1.{C.RESET} Lister les applications au démarrage
  {C.CYAN}2.{C.RESET} Activer / Désactiver une entrée
  {C.CYAN}3.{C.RESET} Ajouter un programme au démarrage
  {C.CYAN}4.{C.RESET} Analyser l'impact sur les performances
  {C.CYAN}5.{C.RESET} Exporter (JSON)
  {C.CYAN}0.{C.RESET} Quitter\n""")
        c = input(f"{C.BOLD}Choix >{C.RESET} ").strip()
        if c=="0": break
        elif c=="1": menu_list()
        elif c=="2": menu_toggle()
        elif c=="3": menu_add()
        elif c=="4": menu_impact()
        elif c=="5": menu_export()

if __name__ == "__main__":
    main()