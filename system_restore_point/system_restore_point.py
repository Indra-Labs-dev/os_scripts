"""
╔══════════════════════════════════════════════════════════════╗
║        Gestionnaire de Points de Restauration Windows        ║
║                     Version 1.1 (PowerShell)                 ║
╚══════════════════════════════════════════════════════════════╝

Toutes les opérations utilisent PowerShell (WMIC est déprécié
et supprimé sur Windows 11 récent).

Fonctionnalités :
  - Créer, lister, supprimer des points de restauration
  - Restaurer le système à un point donné (rstrui.exe)
  - Activer/désactiver la protection système par lecteur
  - Exporter la liste en JSON ou CSV
  - Journalisation complète des opérations
  - Interface CLI colorée avec menu en boucle
"""

import os
import sys
import ctypes
import subprocess
import json
import csv
import logging
import re
import socket
import platform
from datetime import datetime
from pathlib import Path


# ─────────────────────────────────────────────
#  Journal
# ─────────────────────────────────────────────

LOG_DIR = Path(os.getenv("APPDATA", ".")) / "RestoreManager"
LOG_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE = LOG_DIR / "restore_manager.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
    ],
)
logger = logging.getLogger("RestoreManager")


# ─────────────────────────────────────────────
#  Couleurs ANSI
# ─────────────────────────────────────────────

class C:
    RESET = "\033[0m"
    BOLD  = "\033[1m"
    RED   = "\033[91m"
    GREEN = "\033[92m"
    YEL   = "\033[93m"
    CYAN  = "\033[96m"
    WHITE = "\033[97m"
    GREY  = "\033[90m"

def ok(m):   print(f"{C.GREEN}  [OK]  {m}{C.RESET}")
def err(m):  print(f"{C.RED}  [ERR] {m}{C.RESET}")
def info(m): print(f"{C.CYAN}  [i]   {m}{C.RESET}")
def warn(m): print(f"{C.YEL}  [!]   {m}{C.RESET}")
def titre(m):print(f"\n{C.BOLD}{C.WHITE}{m}{C.RESET}\n")


# ─────────────────────────────────────────────
#  Droits administrateur
# ─────────────────────────────────────────────

def est_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relancer_en_admin() -> None:
    if not est_admin():
        info("Elevation des privileges requise — relancement en Administrateur...")
        params = " ".join(f'"{a}"' for a in sys.argv)
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, params, None, 1
        )
        sys.exit(0)


# ─────────────────────────────────────────────
#  Exécution PowerShell — fonction centrale
# ─────────────────────────────────────────────

def _ps(script: str, timeout: int = 30) -> tuple:
    """
    Exécute un bloc de script PowerShell et retourne (returncode, stdout, stderr).
    Utilise -NonInteractive et -NoProfile pour éviter tout popup.
    """
    cmd = [
        "powershell.exe",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy", "Bypass",
        "-Command", script,
    ]
    try:
        res = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            # Encodage UTF-8 pour lire correctement les caractères accentués
            encoding="utf-8",
            errors="replace",
        )
        return res.returncode, res.stdout.strip(), res.stderr.strip()
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"PowerShell timeout apres {timeout} s.")
    except FileNotFoundError:
        raise RuntimeError("powershell.exe introuvable — Windows requis.")
    except Exception as exc:
        raise RuntimeError(f"Erreur subprocess : {exc}") from exc


# ─────────────────────────────────────────────
#  Génération automatique de description
# ─────────────────────────────────────────────

# Contextes détectés automatiquement selon l'heure et le jour
_CONTEXTES_HEURE = [
    (6,  9,  "Demarrage matinal"),
    (9,  12, "Matinee de travail"),
    (12, 14, "Pause dejeuner"),
    (14, 18, "Session apres-midi"),
    (18, 21, "Soiree"),
    (21, 24, "Travail nocturne"),
    (0,  6,  "Session de nuit"),
]

_JOURS_FR = ["Lundi", "Mardi", "Mercredi", "Jeudi", "Vendredi", "Samedi", "Dimanche"]


def _contexte_heure(heure: int) -> str:
    for debut, fin, label in _CONTEXTES_HEURE:
        if debut <= heure < fin:
            return label
    return "Session"


def _infos_systeme() -> dict:
    """Collecte les infos système disponibles sans appel réseau."""
    infos = {}

    # Nom de la machine
    try:
        infos["machine"] = socket.gethostname()
    except Exception:
        infos["machine"] = "PC"

    # Utilisateur courant
    infos["utilisateur"] = os.getenv("USERNAME") or os.getenv("USER") or "Utilisateur"

    # Version Windows via platform
    try:
        infos["os"] = platform.version()          # ex : "10.0.22631"
        infos["os_nom"] = platform.win32_ver()[0] # ex : "10"
    except Exception:
        infos["os"] = ""
        infos["os_nom"] = "Windows"

    # Espace disque libre sur C:
    try:
        usage = os.statvfs("C:\\") if hasattr(os, "statvfs") else None
        if usage:
            libre_go = (usage.f_bavail * usage.f_frsize) / (1024 ** 3)
            infos["disque_libre"] = f"{libre_go:.1f} Go libres"
        else:
            # Windows : utiliser shutil
            import shutil
            total, used, free = shutil.disk_usage("C:\\")
            infos["disque_libre"] = f"{free / (1024**3):.1f} Go libres"
    except Exception:
        infos["disque_libre"] = ""

    return infos


def generer_description() -> str:
    """
    Génère automatiquement une description structurée pour le point de restauration.

    Format :
      [Contexte] — Machine | Utilisateur | JJ/MM/AAAA HH:MM | Espace disque
    Exemple :
      Matinee de travail — DESKTOP-ABC / Jean / 01/04/2026 09:32 | C: 128.4 Go libres
    """
    now        = datetime.now()
    jour_sem   = _JOURS_FR[now.weekday()]
    contexte   = _contexte_heure(now.hour)
    date_str   = now.strftime("%d/%m/%Y %H:%M")
    infos      = _infos_systeme()

    machine    = infos.get("machine", "PC")
    user       = infos.get("utilisateur", "User")
    disque     = infos.get("disque_libre", "")

    # Construction de la description (max 256 caractères)
    parties = [f"[{contexte} - {jour_sem}]", f"{machine}/{user}", date_str]
    if disque:
        parties.append(f"C: {disque}")

    description = "  |  ".join(parties)
    return description[:256]


# ─────────────────────────────────────────────
#  Création d'un point de restauration
# ─────────────────────────────────────────────

def creer_point(description: str = "Point de restauration Python") -> bool:
    description = (description.strip()[:256] or "Point de restauration Python")
    desc_ps = description.replace("'", "''")

    # ── Patch fréquence (force Windows à ignorer le délai 24h) ──────────
    script_freq = (
        "Set-ItemProperty "
        "-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SystemRestore' "
        "-Name 'SystemRestorePointCreationFrequency' "
        "-Value 0 -Type DWord -Force"
    )
    _ps(script_freq)

    # ── Snapshot AVANT ───────────────────────────────────────────────────
    points_avant = {p["SequenceNumber"] for p in lister_points()}

    # ── Création avec -ErrorAction Stop pour forcer la remontée d'erreur ─
    script = (
        f"try {{"
        f"  Checkpoint-Computer "
        f"  -Description '{desc_ps}' "
        f"  -RestorePointType 'MODIFY_SETTINGS' "
        f"  -ErrorAction Stop; "
        f'  Write-Output "CHECKPOINT_OK"'
        f"}} catch {{"
        f'  Write-Output "CHECKPOINT_ERR:$($_.Exception.Message)"'
        f"}}"
    )

    try:
        code, stdout, stderr = _ps(script, timeout=60)

        # Diagnostic brut — affiché dans tous les cas
        info(f"[DEBUG] code={code}")
        info(f"[DEBUG] stdout={stdout[:300] if stdout else '(vide)'}")
        info(f"[DEBUG] stderr={stderr[:300] if stderr else '(vide)'}")

        # ── Vérification réelle ──────────────────────────────────────────
        points_apres = {p["SequenceNumber"] for p in lister_points()}
        nouveaux     = points_apres - points_avant

        if nouveaux:
            seq = list(nouveaux)[0]
            ok(f"Point cree avec succes (n°{seq}) : \"{description}\"")
            logger.info("Creation verifiee : n°%s — %s", seq, description)
            return True

        # ── Diagnostic selon ce que PowerShell a retourné ────────────────
        combined = (stdout + stderr).lower()

        if "checkpoint_err:" in stdout.lower():
            msg = stdout.split("CHECKPOINT_ERR:", 1)[-1].strip()
            err(f"Erreur PowerShell : {msg}")
            
            if "frequency" in msg.lower() or "already" in msg.lower():
                warn("Limite 24h active malgre le patch — redemarrez le script en admin pur.")
            elif "access" in msg.lower() or "privilege" in msg.lower():
                err("Privileges insuffisants malgre UAC — lancez en 'Executer en tant qu administrateur'.")
            elif "disabled" in msg.lower() or "not enabled" in msg.lower():
                err("La protection systeme est desactivee — utilisez l'option 5 puis reessayez.")
        elif "checkpoint_ok" in stdout.lower():
            err("PowerShell confirme OK mais aucun point trouve dans Get-ComputerRestorePoint.")
            err("Cause probable : VSS (Volume Shadow Copy) ne repond pas.")
            warn("Solution : net start vss  dans un terminal admin.")
        else:
            err("Reponse PowerShell inattendue — voir DEBUG ci-dessus.")

        logger.warning("Creation non verifiee (code=%d) stdout=%s stderr=%s",
                       code, stdout[:200], stderr[:200])
        return False

    except RuntimeError as exc:
        err(str(exc))
        logger.error("Creation — %s", exc)
        return False


# ─────────────────────────────────────────────
#  Liste des points de restauration
# ─────────────────────────────────────────────

def lister_points() -> list:
    """
    Récupère tous les points via Get-ComputerRestorePoint et retourne
    une liste de dicts avec les clés :
      SequenceNumber, Description, CreationTime (str lisible), CreationTimeRaw
    """
    # On sérialise en JSON côté PowerShell pour un parsing fiable
    script = (
        "Get-ComputerRestorePoint | "
        "Select-Object SequenceNumber, Description, CreationTime | "
        "ConvertTo-Json -Depth 2"
    )
    try:
        code, stdout, stderr = _ps(script)
        if code != 0 or not stdout:
            logger.warning("lister_points : code=%d stderr=%s", code, stderr)
            return []

        raw = json.loads(stdout)
        # Si un seul point, PowerShell renvoie un dict au lieu d'une liste
        if isinstance(raw, dict):
            raw = [raw]

        points = []
        for item in raw:
            ct_raw = str(item.get("CreationTime", ""))
            ct_lisible = _formater_date_ps(ct_raw)
            points.append({
                "SequenceNumber": str(item.get("SequenceNumber", "?")),
                "Description":    str(item.get("Description", "(sans nom)")),
                "CreationTime":   ct_lisible,
                "CreationTimeRaw": ct_raw,
            })
        return points

    except json.JSONDecodeError as exc:
        err(f"Impossible de decoder la reponse PowerShell : {exc}")
        logger.error("lister_points JSON : %s | sortie brute : %s", exc, stdout[:200])
        return []
    except RuntimeError as exc:
        err(str(exc))
        logger.error("lister_points — %s", exc)
        return []


def _formater_date_ps(ct_raw: str) -> str:
    """
    Convertit la date renvoyée par PowerShell.
    Formats possibles :
      - Timestamp Unix en millisecondes : /Date(1700000000000)/
      - Chaîne ISO / localisée
    """
    # Format /Date(milliseconds)/
    m = re.search(r'/Date\((-?\d+)\)/', ct_raw)
    if m:
        try:
            ts = int(m.group(1)) / 1000
            return datetime.fromtimestamp(ts).strftime("%d/%m/%Y %H:%M:%S")
        except Exception:
            pass

    # Essai direct de parsing
    for fmt in ("%d/%m/%Y %H:%M:%S", "%m/%d/%Y %H:%M:%S",
                "%Y-%m-%dT%H:%M:%S", "%Y%m%d%H%M%S"):
        try:
            return datetime.strptime(ct_raw[:19], fmt).strftime("%d/%m/%Y %H:%M:%S")
        except Exception:
            continue

    return ct_raw or "—"


def afficher_points() -> list:
    """Affiche un tableau formaté et retourne la liste."""
    points = lister_points()
    if not points:
        warn("Aucun point de restauration trouve (ou protection systeme desactivee).")
        return []

    titre(f"{'N°':<6}  {'Date / Heure':<22}  Description")
    print(f"{C.GREY}{'─'*72}{C.RESET}")
    for p in points:
        print(
            f"{C.YEL}{p['SequenceNumber']:<6}{C.RESET}  "
            f"{p['CreationTime']:<22}  "
            f"{p['Description']}"
        )
    print(f"{C.GREY}{'─'*72}{C.RESET}")
    info(f"{len(points)} point(s) trouve(s).")
    return points


# ─────────────────────────────────────────────
#  Suppression d'un point
# ─────────────────────────────────────────────

def supprimer_point(numero_sequence: int) -> bool:
    """
    Supprime un point via l'API WMI appelée depuis PowerShell
    (Get-WmiObject + Delete, fonctionne même sans WMIC.exe).
    """
    script = (
        f"$rp = Get-WmiObject -Namespace 'root\\default' -Class SystemRestore "
        f"| Where-Object {{ $_.SequenceNumber -eq {numero_sequence} }}; "
        f"if ($rp) {{ $rp.Delete(); exit 0 }} else {{ Write-Error 'Point introuvable'; exit 1 }}"
    )
    try:
        code, stdout, stderr = _ps(script)
        if code == 0:
            ok(f"Point n°{numero_sequence} supprime avec succes.")
            logger.info("Suppression reussie : n°%d", numero_sequence)
            return True
        else:
            err(f"Echec de suppression (code {code}) : {stderr or stdout}")
            logger.warning("Suppression echouee n°%d : %s", numero_sequence, stderr)
            return False
    except RuntimeError as exc:
        err(str(exc))
        logger.error("Suppression — %s", exc)
        return False


# ─────────────────────────────────────────────
#  Restauration du système
# ─────────────────────────────────────────────

def restaurer_systeme(numero_sequence: int) -> bool:
    """Lance rstrui.exe avec le point sélectionné après confirmation."""
    warn("ATTENTION : le systeme va redemarrer apres la restauration !")
    conf = input(
        f"  Confirmer la restauration vers le point n°{numero_sequence} ? [oui/non] : "
    ).strip().lower()
    if conf not in ("oui", "o", "yes", "y"):
        info("Restauration annulee.")
        return False

    try:
        subprocess.Popen(
            ["rstrui.exe", f"/restorepoint:{numero_sequence}"],
            shell=False,
        )
        ok("Interface de restauration Windows lancee.")
        logger.info("Restauration lancee : n°%d", numero_sequence)
        return True
    except FileNotFoundError:
        err("rstrui.exe introuvable — Windows requis.")
        return False
    except Exception as exc:
        err(f"Impossible de lancer rstrui.exe : {exc}")
        logger.error("Restauration — %s", exc)
        return False


# ─────────────────────────────────────────────
#  Protection système (activation / désactivation)
# ─────────────────────────────────────────────

def activer_protection(lecteur: str = "C:") -> bool:
    script = f"Enable-ComputerRestore -Drive '{lecteur}\\'"
    try:
        code, _, stderr = _ps(script)
        if code == 0:
            ok(f"Protection systeme activee pour {lecteur}.")
            logger.info("Protection activee : %s", lecteur)
            return True
        else:
            err(f"Echec activation (code {code}) : {stderr}")
            return False
    except RuntimeError as exc:
        err(str(exc)); return False


def desactiver_protection(lecteur: str = "C:") -> bool:
    warn(f"Desactiver la protection sur {lecteur} supprimera tous les points existants !")
    conf = input("  Confirmer ? [oui/non] : ").strip().lower()
    if conf not in ("oui", "o", "yes", "y"):
        info("Operation annulee."); return False

    script = f"Disable-ComputerRestore -Drive '{lecteur}\\'"
    try:
        code, _, stderr = _ps(script)
        if code == 0:
            ok(f"Protection systeme desactivee pour {lecteur}.")
            logger.info("Protection desactivee : %s", lecteur)
            return True
        else:
            err(f"Echec desactivation (code {code}) : {stderr}")
            return False
    except RuntimeError as exc:
        err(str(exc)); return False


# ─────────────────────────────────────────────
#  Export JSON / CSV
# ─────────────────────────────────────────────

def exporter_points(format_export: str = "json") -> bool:
    points = lister_points()
    if not points:
        warn("Aucune donnee a exporter."); return False

    horodatage = datetime.now().strftime("%Y%m%d_%H%M%S")
    chemin = LOG_DIR / f"restore_points_{horodatage}.{format_export}"

    try:
        if format_export == "json":
            with open(chemin, "w", encoding="utf-8") as f:
                json.dump(points, f, ensure_ascii=False, indent=2)
        elif format_export == "csv":
            with open(chemin, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=points[0].keys())
                writer.writeheader()
                writer.writerows(points)
        else:
            err(f"Format inconnu : {format_export}"); return False

        ok(f"Export reussi -> {chemin}")
        logger.info("Export %s : %s", format_export.upper(), chemin)
        return True
    except OSError as exc:
        err(f"Ecriture impossible : {exc}")
        logger.error("Export — %s", exc)
        return False


# ─────────────────────────────────────────────
#  Utilitaires de saisie
# ─────────────────────────────────────────────

def _saisir_entier(prompt: str):
    try:
        v = int(input(prompt).strip())
        if v <= 0: raise ValueError
        return v
    except ValueError:
        err("Entrez un nombre entier positif."); return None


def _saisir_lecteur() -> str:
    s = input("  Lettre du lecteur [C] : ").strip().upper()
    return (s + ":") if re.match(r'^[A-Z]$', s) else "C:"


# ─────────────────────────────────────────────
#  Menu principal
# ─────────────────────────────────────────────

def afficher_menu() -> None:
    sep = f"{C.GREY}{'─'*54}{C.RESET}"
    print(f"""
{C.BOLD}{C.WHITE}  Gestionnaire de Points de Restauration v1.1{C.RESET}
{sep}
  {C.YEL}1{C.RESET}  Creer un point de restauration (description auto ou manuelle)
  {C.YEL}2{C.RESET}  Lister les points de restauration
  {C.YEL}3{C.RESET}  Supprimer un point de restauration
  {C.YEL}4{C.RESET}  Restaurer le systeme vers un point
  {C.YEL}5{C.RESET}  Activer la protection systeme
  {C.YEL}6{C.RESET}  Desactiver la protection systeme
  {C.YEL}7{C.RESET}  Exporter la liste (JSON)
  {C.YEL}8{C.RESET}  Exporter la liste (CSV)
  {C.YEL}9{C.RESET}  Afficher le fichier journal
  {C.YEL}0{C.RESET}  Quitter
{sep}""")


def afficher_journal() -> None:
    try:
        lignes = LOG_FILE.read_text(encoding="utf-8").splitlines()
        titre(f"Journal — {LOG_FILE}")
        for ligne in lignes[-50:]:
            print(f"  {C.GREY}{ligne}{C.RESET}")
    except FileNotFoundError:
        warn("Fichier journal introuvable.")


def main() -> None:
    os.system("")           # Active les séquences ANSI sur Windows 10+
    relancer_en_admin()
    logger.info("=== Demarrage Gestionnaire Restauration v1.1 ===")

    while True:
        afficher_menu()
        choix = input(f"{C.CYAN}  Votre choix : {C.RESET}").strip()

        if choix == "1":
            desc_auto = generer_description()
            info(f"Description generee : {desc_auto}")
            saisie = input(
                "  Appuyez sur Entree pour l'utiliser, ou tapez votre propre description : "
            ).strip()
            creer_point(saisie if saisie else desc_auto)

        elif choix == "2":
            afficher_points()

        elif choix == "3":
            afficher_points()
            seq = _saisir_entier("  SequenceNumber a supprimer : ")
            if seq:
                supprimer_point(seq)

        elif choix == "4":
            afficher_points()
            seq = _saisir_entier("  SequenceNumber vers lequel restaurer : ")
            if seq:
                restaurer_systeme(seq)

        elif choix == "5":
            activer_protection(_saisir_lecteur())

        elif choix == "6":
            desactiver_protection(_saisir_lecteur())

        elif choix == "7":
            exporter_points("json")

        elif choix == "8":
            exporter_points("csv")

        elif choix == "9":
            afficher_journal()

        elif choix == "0":
            info("Au revoir !")
            logger.info("=== Fermeture ===")
            sys.exit(0)

        else:
            warn(f'Option "{choix}" non reconnue. Choisissez entre 0 et 9.')

        input(f"\n{C.GREY}  Appuyez sur Entree pour continuer...{C.RESET}")


if __name__ == "__main__":
    main()