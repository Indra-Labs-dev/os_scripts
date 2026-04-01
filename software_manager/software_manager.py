"""
Gestionnaire de Logiciels - Version 1.0
Winget étendu : liste, install, désinstall, MàJ, export, recherche, batch install
Auteur: Indra-Labs-dev
"""

import os, sys, json, subprocess, logging
from datetime import datetime
from pathlib import Path

APP_DIR  = Path(os.environ.get("APPDATA", Path.home())) / "SoftwareManager"
LOG_FILE = APP_DIR / "software.log"
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

def run_winget(args: list[str], timeout: int = 60, stream: bool = False) -> tuple[str, int]:
    cmd = ["winget"] + args + ["--accept-source-agreements"]
    try:
        if stream:
            r = subprocess.run(cmd, timeout=timeout)
            return "", r.returncode
        else:
            r = subprocess.run(cmd, capture_output=True, text=True,
                               encoding="utf-8", errors="replace", timeout=timeout)
            return r.stdout.strip(), r.returncode
    except FileNotFoundError:
        return "WINGET_NOT_FOUND", -1
    except subprocess.TimeoutExpired:
        return "TIMEOUT", -1
    except Exception as e:
        return str(e), -1

def check_winget() -> bool:
    out, rc = run_winget(["--version"])
    if rc == 0:
        ok(f"Winget {out} disponible."); return True
    err("Winget non disponible. Installez 'App Installer' depuis le Microsoft Store.")
    return False

# ── Profils d'installation ─────────────────────────────────────────────────────

BUNDLES = {
    "dev": {
        "label": "Pack Développeur",
        "packages": [
            ("Git.Git",          "Git"),
            ("Python.Python.3",  "Python 3"),
            ("Microsoft.VisualStudioCode", "VS Code"),
            ("OpenJS.NodeJS",    "Node.js"),
            ("Docker.DockerDesktop", "Docker Desktop"),
            ("Postman.Postman",  "Postman"),
        ]
    },
    "productivity": {
        "label": "Pack Productivité",
        "packages": [
            ("7zip.7zip",              "7-Zip"),
            ("Notepad++.Notepad++",    "Notepad++"),
            ("Mozilla.Firefox",        "Firefox"),
            ("Google.Chrome",          "Chrome"),
            ("VideoLAN.VLC",           "VLC"),
            ("Obsidian.Obsidian",      "Obsidian"),
            ("Bitwarden.Bitwarden",    "Bitwarden"),
        ]
    },
    "security": {
        "label": "Pack Sécurité",
        "packages": [
            ("Wireshark.Wireshark",    "Wireshark"),
            ("Nmap.Nmap",              "Nmap"),
            ("PortSwigger.BurpSuite",  "Burp Suite Community"),
            ("KeePassXCTeam.KeePassXC","KeePassXC"),
            ("Malwarebytes.Malwarebytes","Malwarebytes"),
        ]
    },
    "system": {
        "label": "Pack Outils Système",
        "packages": [
            ("Sysinternals.Suite",     "Sysinternals Suite"),
            ("Microsoft.PowerToys",    "PowerToys"),
            ("Greenshot.Greenshot",    "Greenshot"),
            ("ShareX.ShareX",          "ShareX"),
            ("CPU-Z.CPU-Z",            "CPU-Z"),
            ("HWiNFO.HWiNFO",         "HWiNFO"),
        ]
    }
}

# ── Opérations Winget ──────────────────────────────────────────────────────────

def list_installed(filter_str: str = "") -> list[dict]:
    args = ["list"]
    if filter_str: args += ["--name", filter_str]
    out, rc = run_winget(args, timeout=30)
    if rc != 0 or not out: return []

    packages = []
    lines = out.splitlines()
    # Cherche la ligne d'en-tête
    header_idx = next((i for i,l in enumerate(lines) if "Name" in l and "Id" in l), -1)
    if header_idx < 0: return []

    for line in lines[header_idx+2:]:
        if not line.strip() or line.startswith("-"): continue
        parts = line.split()
        if len(parts) >= 2:
            packages.append({"name": parts[0], "id": parts[1] if len(parts)>1 else "",
                              "version": parts[2] if len(parts)>2 else "",
                              "available": parts[3] if len(parts)>3 else ""})
    return packages

def search_package(query: str) -> list[dict]:
    out, rc = run_winget(["search", query, "--limit", "20"], timeout=20)
    if rc != 0: return []
    packages = []
    lines = out.splitlines()
    header_idx = next((i for i,l in enumerate(lines) if "Name" in l and "Id" in l), -1)
    if header_idx < 0: return []
    for line in lines[header_idx+2:]:
        if not line.strip() or line.startswith("-"): continue
        parts = line.split()
        if len(parts) >= 2:
            packages.append({"name": parts[0], "id": parts[1] if len(parts)>1 else "",
                              "version": parts[2] if len(parts)>2 else ""})
    return packages

def install_package(pkg_id: str, silent: bool = False) -> bool:
    args = ["install", "--id", pkg_id, "--exact"]
    if silent: args.append("--silent")
    info(f"Installation de '{pkg_id}'...")
    _, rc = run_winget(args, timeout=180, stream=True)
    if rc == 0:
        ok(f"'{pkg_id}' installé."); logger.info(f"Install: {pkg_id}"); return True
    else:
        err(f"Échec installation '{pkg_id}'."); return False

def uninstall_package(pkg_id: str) -> bool:
    args = ["uninstall", "--id", pkg_id, "--exact", "--silent"]
    info(f"Désinstallation de '{pkg_id}'...")
    _, rc = run_winget(args, timeout=120, stream=True)
    if rc == 0:
        ok(f"'{pkg_id}' désinstallé."); logger.info(f"Uninstall: {pkg_id}"); return True
    else:
        err(f"Échec désinstallation '{pkg_id}'."); return False

def upgrade_all() -> bool:
    info("Mise à jour de tous les logiciels...")
    _, rc = run_winget(["upgrade","--all","--silent"], timeout=600, stream=True)
    if rc == 0: ok("Tous les logiciels mis à jour."); return True
    else:       warn("Des erreurs sont survenues lors des mises à jour."); return False

def check_updates() -> list[dict]:
    out, rc = run_winget(["upgrade","--list"], timeout=30)
    if rc != 0: return []
    packages = []
    lines = out.splitlines()
    header_idx = next((i for i,l in enumerate(lines) if "Name" in l and "Id" in l), -1)
    if header_idx < 0: return []
    for line in lines[header_idx+2:]:
        if not line.strip() or line.startswith("-"): continue
        parts = line.split()
        if len(parts) >= 3:
            packages.append({"name":parts[0],"id":parts[1] if len(parts)>1 else "",
                              "current":parts[2] if len(parts)>2 else "",
                              "available":parts[3] if len(parts)>3 else ""})
    return packages

def export_installed() -> Path:
    ts   = datetime.now().strftime('%Y%m%d_%H%M%S')
    path = APP_DIR / f"installed_{ts}.json"
    out, rc = run_winget(["export","--output",str(path)], timeout=30)
    if rc == 0 or path.exists():
        ok(f"Export winget : {path}")
    else:
        # Fallback JSON manuel
        pkgs = list_installed()
        path.write_text(json.dumps(pkgs, ensure_ascii=False, indent=2), encoding="utf-8")
        ok(f"Export JSON : {path}")
    return path

def install_bundle(bundle_key: str):
    bundle = BUNDLES.get(bundle_key)
    if not bundle: err(f"Bundle '{bundle_key}' inconnu."); return
    sep(f"Installation : {bundle['label']}")
    packages = bundle["packages"]
    info(f"{len(packages)} logiciels à installer :")
    for pid, label in packages:
        print(f"  {C.CYAN}•{C.RESET} {label} ({pid})")
    confirm = input(f"\n  Confirmer l'installation ? (oui/N) : ").strip().lower()
    if confirm != "oui": return
    ok_count = err_count = 0
    for pid, label in packages:
        print(f"\n  {C.CYAN}→ {label}{C.RESET}")
        if install_package(pid, silent=True): ok_count += 1
        else:                                 err_count += 1
    sep("Résultat")
    ok(f"{ok_count}/{len(packages)} logiciels installés.")
    if err_count: warn(f"{err_count} échec(s).")

# ── Interface ──────────────────────────────────────────────────────────────────

def menu_list():
    sep("Logiciels installés")
    q = input("  Filtrer par nom (Entrée = tous) : ").strip()
    pkgs = list_installed(q)
    if not pkgs: warn("Aucun résultat."); return
    print(f"\n  {C.BOLD}{'NOM':<30} {'VERSION':<15} {'MÀJ DISPO'}{C.RESET}")
    print(f"  {'─'*60}")
    for p in pkgs[:50]:
        upd_color = C.YELLOW if p.get("available") else C.RESET
        print(f"  {p['name']:<30} {p.get('version','?'):<15} {upd_color}{p.get('available','')}{C.RESET}")
    if len(pkgs) > 50: info(f"... et {len(pkgs)-50} autres")
    info(f"Total : {len(pkgs)} logiciel(s)")

def menu_search():
    sep("Rechercher un logiciel")
    q    = input("  Recherche : ").strip()
    pkgs = search_package(q)
    if not pkgs: warn("Aucun résultat."); return
    print(f"\n  {C.BOLD}{'NOM':<30} {'ID WINGET':<35} {'VERSION'}{C.RESET}")
    print(f"  {'─'*75}")
    for i, p in enumerate(pkgs, 1):
        print(f"  {C.CYAN}{i:>2}.{C.RESET} {p['name']:<28} {p['id']:<35} {p.get('version','?')}")
    choice = input("\n  Installer le numéro (Entrée=annuler) : ").strip()
    if choice.isdigit():
        idx = int(choice)-1
        if 0 <= idx < len(pkgs):
            install_package(pkgs[idx]["id"])

def menu_updates():
    sep("Vérification des mises à jour")
    info("Récupération des mises à jour disponibles...")
    pkgs = check_updates()
    if not pkgs:
        ok("Tous vos logiciels sont à jour !"); return
    warn(f"{len(pkgs)} mise(s) à jour disponible(s) :")
    print(f"\n  {C.BOLD}{'NOM':<30} {'ACTUEL':<15} {'DISPONIBLE'}{C.RESET}")
    for p in pkgs:
        print(f"  {p['name']:<30} {p.get('current','?'):<15} {C.GREEN}{p.get('available','?')}{C.RESET}")
    update = input(f"\n  Tout mettre à jour ? (oui/N) : ").strip().lower()
    if update == "oui":
        upgrade_all()

def menu_bundles():
    sep("Installation par bundle")
    for key, b in BUNDLES.items():
        pkgs_str = ", ".join(l for _,l in b["packages"][:4])
        print(f"  {C.CYAN}{key:<15}{C.RESET} {b['label']}  {C.GREY}({pkgs_str}...){C.RESET}")
    choice = input("\n  Bundle à installer (ex: dev) : ").strip().lower()
    install_bundle(choice)

def print_banner():
    print(f"""{C.CYAN}{C.BOLD}
╔══════════════════════════════════════════════════════════════╗
║        📦  Gestionnaire de Logiciels v1.0                    ║
║    Winget · Recherche · MàJ · Bundles · Export               ║
╚══════════════════════════════════════════════════════════════╝{C.RESET}""")

def main():
    os.system("cls" if os.name=="nt" else "clear")
    print_banner()
    if not check_winget(): sys.exit(1)
    while True:
        print(f"""\n{C.BOLD}─── MENU ────────────────────────────────────{C.RESET}
  {C.CYAN}1.{C.RESET} Lister les logiciels installés
  {C.CYAN}2.{C.RESET} Rechercher et installer un logiciel
  {C.CYAN}3.{C.RESET} Désinstaller un logiciel
  {C.CYAN}4.{C.RESET} Vérifier les mises à jour
  {C.CYAN}5.{C.RESET} Installer un pack (Dev / Productivité / Sécurité / Système)
  {C.CYAN}6.{C.RESET} Exporter la liste (JSON Winget)
  {C.CYAN}0.{C.RESET} Quitter\n""")
        c = input(f"{C.BOLD}Choix >{C.RESET} ").strip()
        if c=="0": break
        elif c=="1": menu_list()
        elif c=="2": menu_search()
        elif c=="3":
            pkg = input("  ID Winget du logiciel à désinstaller : ").strip()
            if pkg: uninstall_package(pkg)
        elif c=="4": menu_updates()
        elif c=="5": menu_bundles()
        elif c=="6": export_installed()

if __name__ == "__main__":
    main()