"""
Gestionnaire de Sauvegarde Intelligente - Version 1.0
Backup incrémental, versioning, compression, planification Windows Task Scheduler
Auteur: Indra-Labs-dev
"""

import os, sys, json, shutil, hashlib, zipfile, subprocess, logging, fnmatch
from datetime import datetime, timedelta
from pathlib import Path

APP_DIR     = Path(os.environ.get("APPDATA", Path.home())) / "BackupManager"
CONFIG_FILE = APP_DIR / "config.json"
LOG_FILE    = APP_DIR / "backup.log"
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

def fmt_size(size: int) -> str:
    for unit in ["B","KB","MB","GB","TB"]:
        if size < 1024: return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} PB"

# ── Configuration ──────────────────────────────────────────────────────────────

DEFAULT_CONFIG = {
    "destinations": [],
    "profiles": {},
    "max_versions": 5,
    "exclude_patterns": ["*.tmp","*.log","thumbs.db","desktop.ini","~*",".git"],
    "compression_level": 6,
}

def load_config() -> dict:
    if CONFIG_FILE.exists():
        try:
            return json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
        except: pass
    return dict(DEFAULT_CONFIG)

def save_config(cfg: dict):
    CONFIG_FILE.write_text(json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8")

# ── Hashing incrémental ────────────────────────────────────────────────────────

def file_hash(path: Path) -> str:
    h = hashlib.md5()
    try:
        with open(path,"rb") as f:
            for chunk in iter(lambda: f.read(65536), b""): h.update(chunk)
        return h.hexdigest()
    except:
        return ""

def load_snapshot(snapshot_file: Path) -> dict:
    if snapshot_file.exists():
        try: return json.loads(snapshot_file.read_text(encoding="utf-8"))
        except: pass
    return {}

def save_snapshot(snapshot_file: Path, snapshot: dict):
    snapshot_file.write_text(json.dumps(snapshot, ensure_ascii=False), encoding="utf-8")

# ── Moteur de sauvegarde ───────────────────────────────────────────────────────

class BackupEngine:
    def __init__(self, cfg: dict):
        self.cfg = cfg

    def should_exclude(self, path: Path) -> bool:
        name = path.name.lower()
        for pat in self.cfg.get("exclude_patterns", []):
            if fnmatch.fnmatch(name, pat.lower()):
                return True
        return False

    def _collect_files(self, source: Path) -> list[Path]:
        files = []
        for p in source.rglob("*"):
            if p.is_file() and not self.should_exclude(p):
                files.append(p)
        return files

    def backup_full(self, source: Path, dest_root: Path, profile_name: str) -> dict:
        """Sauvegarde complète avec compression ZIP."""
        ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
        zip_name = f"{profile_name}_{ts}_full.zip"
        zip_path = dest_root / zip_name
        snap_file= dest_root / f"{profile_name}_snapshot.json"

        files    = self._collect_files(source)
        snapshot = {}
        ok_count = err_count = 0
        total_size = 0

        info(f"Sauvegarde complète : {len(files)} fichier(s)...")
        with zipfile.ZipFile(zip_path, "w",
                             compression=zipfile.ZIP_DEFLATED,
                             compresslevel=self.cfg.get("compression_level", 6)) as zf:
            for f in files:
                try:
                    arcname = f.relative_to(source)
                    zf.write(f, arcname)
                    h = file_hash(f)
                    snapshot[str(arcname)] = {"hash":h, "size":f.stat().st_size,
                                               "mtime":f.stat().st_mtime}
                    total_size += f.stat().st_size
                    ok_count += 1
                except Exception as e:
                    logger.warning(f"Fichier ignoré {f}: {e}")
                    err_count += 1

        save_snapshot(snap_file, snapshot)
        zip_size = zip_path.stat().st_size
        ratio    = (1 - zip_size/total_size)*100 if total_size else 0

        result = {"type":"full", "archive":str(zip_path), "files_ok":ok_count,
                  "files_err":err_count, "size_original":total_size, "size_zip":zip_size,
                  "compression_ratio":round(ratio,1), "timestamp":ts}
        logger.info(f"Backup full {profile_name}: {ok_count} fichiers, {fmt_size(zip_size)}")
        return result

    def backup_incremental(self, source: Path, dest_root: Path, profile_name: str) -> dict:
        """Sauvegarde incrémentale (seuls les fichiers modifiés)."""
        snap_file = dest_root / f"{profile_name}_snapshot.json"
        old_snap  = load_snapshot(snap_file)

        if not old_snap:
            info("Pas de snapshot précédent — sauvegarde complète.")
            return self.backup_full(source, dest_root, profile_name)

        ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
        zip_name = f"{profile_name}_{ts}_incr.zip"
        zip_path = dest_root / zip_name

        files       = self._collect_files(source)
        new_snap    = {}
        changed     = []
        deleted     = []

        for f in files:
            arcname = str(f.relative_to(source))
            h = file_hash(f)
            new_snap[arcname] = {"hash":h,"size":f.stat().st_size,"mtime":f.stat().st_mtime}
            if arcname not in old_snap or old_snap[arcname]["hash"] != h:
                changed.append(f)

        for arc in old_snap:
            if arc not in new_snap:
                deleted.append(arc)

        if not changed and not deleted:
            ok("Aucun changement détecté — sauvegarde incrémentale ignorée.")
            return {"type":"incremental","files_changed":0,"files_deleted":0}

        info(f"{len(changed)} fichier(s) modifié(s), {len(deleted)} supprimé(s)")
        total_size = 0
        with zipfile.ZipFile(zip_path,"w",compression=zipfile.ZIP_DEFLATED,
                             compresslevel=self.cfg.get("compression_level",6)) as zf:
            for f in changed:
                arcname = f.relative_to(source)
                zf.write(f, arcname)
                total_size += f.stat().st_size
            # Fichiers supprimés = manifeste
            if deleted:
                zf.writestr("_deleted.txt", "\n".join(deleted))

        save_snapshot(snap_file, new_snap)
        zip_size = zip_path.stat().st_size
        result = {"type":"incremental","archive":str(zip_path),"files_changed":len(changed),
                  "files_deleted":len(deleted),"size_zip":zip_size,"timestamp":ts}
        logger.info(f"Backup incr {profile_name}: {len(changed)} modifiés")
        return result

    def rotate_versions(self, dest_root: Path, profile_name: str):
        """Conserve uniquement les N dernières versions."""
        max_v  = self.cfg.get("max_versions", 5)
        zips   = sorted(dest_root.glob(f"{profile_name}_*.zip"))
        to_del = zips[:-max_v] if len(zips) > max_v else []
        for z in to_del:
            z.unlink()
            logger.info(f"Version supprimée : {z.name}")
        if to_del:
            warn(f"{len(to_del)} ancienne(s) version(s) supprimée(s) (rotation).")

    def list_versions(self, dest_root: Path, profile_name: str) -> list[Path]:
        return sorted(dest_root.glob(f"{profile_name}_*.zip"), reverse=True)

    def restore(self, zip_path: Path, restore_dest: Path) -> bool:
        """Restaure une archive ZIP vers un dossier."""
        if not zip_path.exists():
            err(f"Archive introuvable : {zip_path}"); return False
        restore_dest.mkdir(parents=True, exist_ok=True)
        try:
            with zipfile.ZipFile(zip_path,"r") as zf:
                zf.extractall(restore_dest)
            ok(f"Restauré dans : {restore_dest}")
            logger.info(f"Restauration {zip_path} → {restore_dest}")
            return True
        except Exception as e:
            err(f"Erreur de restauration : {e}"); return False

# ── Planification (Windows Task Scheduler) ─────────────────────────────────────

def schedule_task(profile_name: str, frequency: str, time_str: str, script_path: str):
    """Crée une tâche planifiée Windows pour la sauvegarde automatique."""
    python_exe = sys.executable
    task_name  = f"BackupManager_{profile_name}"
    trigger    = {"daily":"/SC DAILY","weekly":"/SC WEEKLY","hourly":"/SC HOURLY"}.get(frequency,"/SC DAILY")

    cmd = (f'schtasks /Create /TN "{task_name}" {trigger} /ST {time_str} '
           f'/TR "\\"{python_exe}\\" \\"{script_path}\\" --auto {profile_name}" '
           f'/F /RL HIGHEST')
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if r.returncode == 0:
            ok(f"Tâche planifiée créée : {task_name} ({frequency} à {time_str})")
            logger.info(f"Tâche planifiée : {task_name}")
        else:
            err(f"Erreur planification : {r.stderr.strip()}")
    except Exception as e:
        err(f"Erreur : {e}")

def remove_scheduled_task(profile_name: str):
    task_name = f"BackupManager_{profile_name}"
    r = subprocess.run(f'schtasks /Delete /TN "{task_name}" /F', shell=True,
                       capture_output=True, text=True)
    if r.returncode == 0: ok(f"Tâche supprimée : {task_name}")
    else: warn(f"Tâche introuvable ou erreur : {r.stderr.strip()}")

# ── Interface ──────────────────────────────────────────────────────────────────

def print_banner():
    print(f"""{C.CYAN}{C.BOLD}
╔══════════════════════════════════════════════════════════════╗
║          💾  Gestionnaire de Sauvegarde v1.0                 ║
║   Incrémental · Versioning · Compression · Planification     ║
╚══════════════════════════════════════════════════════════════╝{C.RESET}""")

def menu_new_profile(cfg: dict):
    sep("Nouveau profil de sauvegarde")
    name   = input("  Nom du profil : ").strip()
    source = input("  Dossier source : ").strip()
    dest   = input("  Dossier de destination : ").strip()
    if not Path(source).exists():
        err("Dossier source introuvable."); return
    Path(dest).mkdir(parents=True, exist_ok=True)
    cfg["profiles"][name] = {"source":source,"destination":dest,"last_backup":None}
    save_config(cfg)
    ok(f"Profil '{name}' créé.")

def menu_run_backup(cfg: dict):
    if not cfg["profiles"]:
        warn("Aucun profil configuré. Créez-en un d'abord (option 1)."); return
    sep("Lancer une sauvegarde")
    for i,(n,p) in enumerate(cfg["profiles"].items(),1):
        lb = p.get("last_backup","jamais") or "jamais"
        print(f"  {C.CYAN}{i}.{C.RESET} {n}  {C.GREY}(source: {p['source']}) — dernier backup: {lb}{C.RESET}")
    name = input("  Nom du profil : ").strip()
    if name not in cfg["profiles"]:
        err("Profil introuvable."); return
    p    = cfg["profiles"][name]
    mode = input("  Type : (1) Complet  (2) Incrémental [2] : ").strip()
    engine = BackupEngine(cfg)
    source = Path(p["source"]); dest = Path(p["destination"])
    if mode == "1":
        res = engine.backup_full(source, dest, name)
    else:
        res = engine.backup_incremental(source, dest, name)
    engine.rotate_versions(dest, name)
    cfg["profiles"][name]["last_backup"] = str(datetime.now())
    save_config(cfg)
    sep("Résultat")
    for k,v in res.items():
        if k != "type":
            val = fmt_size(v) if "size" in k else v
            print(f"  {C.BOLD}{k:<20}{C.RESET} {val}")

def menu_list_versions(cfg: dict):
    sep("Versions disponibles")
    engine = BackupEngine(cfg)
    for name, p in cfg["profiles"].items():
        dest  = Path(p["destination"])
        vzips = engine.list_versions(dest, name)
        print(f"\n  {C.BOLD}{name}{C.RESET} ({len(vzips)} version(s)) :")
        for z in vzips[:10]:
            size = fmt_size(z.stat().st_size)
            print(f"    {C.CYAN}{z.name}{C.RESET}  {C.GREY}{size}{C.RESET}")

def menu_restore(cfg: dict):
    sep("Restaurer une sauvegarde")
    zip_path = input("  Chemin de l'archive ZIP : ").strip()
    dest     = input("  Dossier de restauration : ").strip()
    BackupEngine(cfg).restore(Path(zip_path), Path(dest))

def menu_schedule(cfg: dict):
    sep("Planification automatique")
    if not cfg["profiles"]:
        warn("Créez d'abord un profil."); return
    for n in cfg["profiles"]: print(f"  {C.CYAN}•{C.RESET} {n}")
    name = input("  Nom du profil : ").strip()
    if name not in cfg["profiles"]:
        err("Profil introuvable."); return
    print("  Fréquence : (1) Quotidien  (2) Hebdomadaire  (3) Horaire")
    fc = input("  Choix [1] : ").strip()
    freq = {"1":"daily","2":"weekly","3":"hourly"}.get(fc,"daily")
    time_str = input("  Heure (HH:MM) [02:00] : ").strip() or "02:00"
    script   = str(Path(__file__).resolve())
    schedule_task(name, freq, time_str, script)

def menu_settings(cfg: dict):
    sep("Paramètres")
    print(f"  Versions max        : {cfg.get('max_versions',5)}")
    print(f"  Niveau compression  : {cfg.get('compression_level',6)}/9")
    print(f"  Exclusions          : {', '.join(cfg.get('exclude_patterns',[]))}")
    print()
    mv = input("  Versions max [Entrée=conserver] : ").strip()
    if mv.isdigit(): cfg["max_versions"] = int(mv)
    cl = input("  Niveau compression 1-9 [Entrée=conserver] : ").strip()
    if cl.isdigit() and 1<=int(cl)<=9: cfg["compression_level"] = int(cl)
    save_config(cfg); ok("Paramètres sauvegardés.")

def main():
    os.system("cls" if os.name=="nt" else "clear")
    print_banner()
    cfg = load_config()

    # Mode automatique (depuis tâche planifiée)
    if len(sys.argv) >= 3 and sys.argv[1] == "--auto":
        profile = sys.argv[2]
        if profile in cfg.get("profiles",{}):
            p = cfg["profiles"][profile]
            engine = BackupEngine(cfg)
            engine.backup_incremental(Path(p["source"]), Path(p["destination"]), profile)
            engine.rotate_versions(Path(p["destination"]), profile)
            cfg["profiles"][profile]["last_backup"] = str(datetime.now())
            save_config(cfg)
        sys.exit(0)

    while True:
        print(f"""\n{C.BOLD}─── MENU ────────────────────────────────────{C.RESET}
  {C.CYAN}1.{C.RESET} Nouveau profil de sauvegarde
  {C.CYAN}2.{C.RESET} Lancer une sauvegarde
  {C.CYAN}3.{C.RESET} Lister les versions disponibles
  {C.CYAN}4.{C.RESET} Restaurer une sauvegarde
  {C.CYAN}5.{C.RESET} Planification automatique (Task Scheduler)
  {C.CYAN}6.{C.RESET} Paramètres
  {C.CYAN}0.{C.RESET} Quitter\n""")
        c = input(f"{C.BOLD}Choix >{C.RESET} ").strip()
        if c=="0": break
        elif c=="1": menu_new_profile(cfg)
        elif c=="2": menu_run_backup(cfg)
        elif c=="3": menu_list_versions(cfg)
        elif c=="4": menu_restore(cfg)
        elif c=="5": menu_schedule(cfg)
        elif c=="6": menu_settings(cfg)

if __name__ == "__main__":
    main()