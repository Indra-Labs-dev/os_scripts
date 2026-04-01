"""
Moniteur de Processus - Version 2.0
Mode live (top-like), CPU/RAM, processus suspects, kill, analyse réseau par processus
Auteur: Indra-Labs-dev
"""

import os, sys, json, subprocess, time, threading
from datetime import datetime
from pathlib import Path

APP_DIR = Path(os.environ.get("APPDATA", Path.home())) / "ProcessMonitor"
APP_DIR.mkdir(parents=True, exist_ok=True)

try:
    import psutil
    PSUTIL = True
except ImportError:
    PSUTIL = False

class C:
    RESET="\033[0m";BOLD="\033[1m";RED="\033[91m";GREEN="\033[92m"
    YELLOW="\033[93m";CYAN="\033[96m";GREY="\033[90m";BLUE="\033[94m"

def ok(m):   print(f"  {C.GREEN}[✓]{C.RESET} {m}")
def err(m):  print(f"  {C.RED}[✗]{C.RESET} {m}")
def warn(m): print(f"  {C.YELLOW}[!]{C.RESET} {m}")
def info(m): print(f"  {C.CYAN}[i]{C.RESET} {m}")
def sep(t=""): print(f"\n{C.BOLD}{C.BLUE}── {t} {'─'*(50-len(t))}{C.RESET}")

def fmt_mem(bytes_val: int) -> str:
    for u in ["B","KB","MB","GB"]:
        if bytes_val < 1024: return f"{bytes_val:.0f}{u}"
        bytes_val /= 1024
    return f"{bytes_val:.1f}TB"

def run_ps(cmd, timeout=10):
    try:
        r = subprocess.run(["powershell","-NoProfile","-NonInteractive","-Command",cmd],
            capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip()
    except: return ""

# ── Noms de processus suspects ─────────────────────────────────────────────────

SUSPICIOUS_NAMES = {
    # Outils offensifs connus
    "mimikatz","meterpreter","cobaltstrike","empire","powersploit","metasploit",
    "nc","ncat","netcat","psexec","wce","fgdump","pwdump","getsystem",
    # Shells suspects
    "cmd.exe","powershell.exe","wscript.exe","cscript.exe","mshta.exe",
    "regsvr32.exe","rundll32.exe","certutil.exe",
    # RATs courants
    "njrat","darkcomet","nanocore","remcos","asyncrat","quasar",
    # Mineurs de crypto
    "xmrig","minerd","cpuminer","ethminer",
}

SUSPICIOUS_PATHS = [
    r"c:\users\public", r"c:\temp", r"c:\windows\temp",
    r"appdata\local\temp", r"\downloads\\", r"\desktop\\"
]

# ── Récupération des processus ─────────────────────────────────────────────────

def get_processes_ps() -> list[dict]:
    """Récupère les processus via PowerShell si psutil absent."""
    ps = """
Get-Process | Select-Object Id, Name, CPU, WorkingSet64,
  @{N='Path';E={$_.MainModule.FileName}},
  @{N='User';E={(Get-WmiObject Win32_Process -Filter "ProcessId=$($_.Id)" -EA SilentlyContinue).GetOwner().User}} |
  Sort-Object CPU -Descending | ConvertTo-Json
"""
    raw = run_ps(ps, timeout=20)
    try:
        procs = json.loads(raw) if raw.startswith("[") else [json.loads(raw)]
        return [{
            "pid":   p.get("Id",0),
            "name":  p.get("Name","?"),
            "cpu":   round(float(p.get("CPU",0) or 0),1),
            "mem":   int(p.get("WorkingSet64",0) or 0),
            "path":  p.get("Path",""),
            "user":  p.get("User",""),
        } for p in procs]
    except:
        return []

def get_processes() -> list[dict]:
    if PSUTIL:
        procs = []
        for p in psutil.process_iter(["pid","name","cpu_percent","memory_info","exe","username","status"]):
            try:
                info_dict = p.info
                procs.append({
                    "pid":  info_dict["pid"],
                    "name": info_dict["name"] or "?",
                    "cpu":  round(info_dict.get("cpu_percent",0) or 0, 1),
                    "mem":  info_dict["memory_info"].rss if info_dict.get("memory_info") else 0,
                    "path": info_dict.get("exe","") or "",
                    "user": info_dict.get("username","") or "",
                    "status": info_dict.get("status",""),
                })
            except: pass
        return sorted(procs, key=lambda x: x["cpu"], reverse=True)
    else:
        return get_processes_ps()

def get_system_stats() -> dict:
    if PSUTIL:
        cpu  = psutil.cpu_percent(interval=0.5)
        mem  = psutil.virtual_memory()
        disk = psutil.disk_usage("C:\\")
        return {
            "cpu_pct":  cpu,
            "mem_used": mem.used, "mem_total": mem.total, "mem_pct": mem.percent,
            "disk_used": disk.used, "disk_total": disk.total, "disk_pct": disk.percent,
        }
    else:
        cpu  = run_ps("(Get-WmiObject Win32_Processor).LoadPercentage")
        mem_raw = run_ps("Get-WmiObject Win32_OperatingSystem | Select-Object FreePhysicalMemory,TotalVisibleMemorySize | ConvertTo-Json")
        try:
            md = json.loads(mem_raw)
            total = int(md.get("TotalVisibleMemorySize",0))*1024
            free  = int(md.get("FreePhysicalMemory",0))*1024
            used  = total - free
            pct   = round(used/total*100,1) if total else 0
            return {"cpu_pct":int(cpu) if cpu.isdigit() else 0,
                    "mem_used":used,"mem_total":total,"mem_pct":pct,
                    "disk_used":0,"disk_total":0,"disk_pct":0}
        except:
            return {"cpu_pct":0,"mem_used":0,"mem_total":0,"mem_pct":0,"disk_used":0,"disk_total":0,"disk_pct":0}

def is_suspicious(proc: dict) -> list[str]:
    reasons = []
    name_l  = proc["name"].lower().replace(".exe","")
    path_l  = proc.get("path","").lower()

    if name_l in SUSPICIOUS_NAMES:
        reasons.append(f"Nom suspect : {proc['name']}")
    if any(sp in path_l for sp in SUSPICIOUS_PATHS) and path_l:
        reasons.append(f"Emplacement inhabituel : {proc['path'][:60]}")
    if proc["cpu"] > 80:
        reasons.append(f"CPU élevé : {proc['cpu']}%")
    if proc["mem"] > 1.5*1024**3:
        reasons.append(f"RAM élevée : {fmt_mem(proc['mem'])}")
    # Processus système dans mauvais chemin
    SYSTEM_PROCS = {"svchost","lsass","csrss","winlogon","services","smss","wininit"}
    if name_l in SYSTEM_PROCS and path_l and r"system32" not in path_l.lower():
        reasons.append(f"Processus système hors System32 : {proc['path']}")
    return reasons

# ── Affichage ──────────────────────────────────────────────────────────────────

def bar(pct: float, width: int = 20) -> str:
    filled = int(width * pct / 100)
    color  = C.GREEN if pct < 60 else (C.YELLOW if pct < 85 else C.RED)
    return f"{color}{'█'*filled}{'░'*(width-filled)}{C.RESET}"

def live_mode(interval: int = 2, top_n: int = 20):
    """Mode live — rafraîchissement automatique."""
    info(f"Mode live — rafraîchissement toutes les {interval}s. [Ctrl+C pour quitter]")
    time.sleep(1)
    try:
        while True:
            os.system("cls" if os.name=="nt" else "clear")
            stats = get_system_stats()
            procs = get_processes()[:top_n]
            ts    = datetime.now().strftime("%H:%M:%S")

            print(f"{C.BOLD}{C.CYAN}Process Monitor v2.0{C.RESET}  {C.GREY}{ts}{C.RESET}")
            print(f"\n  CPU  [{bar(stats['cpu_pct'])}] {stats['cpu_pct']:.1f}%")
            mem_pct = stats['mem_pct']
            print(f"  RAM  [{bar(mem_pct)}] {mem_pct:.1f}%  ({fmt_mem(stats['mem_used'])} / {fmt_mem(stats['mem_total'])})")
            if stats['disk_total']:
                print(f"  Disk [{bar(stats['disk_pct'])}] {stats['disk_pct']:.1f}%")

            print(f"\n  {C.BOLD}{'PID':>6}  {'NOM':<22} {'CPU':>6}  {'RAM':>8}  {'UTILISATEUR':<20}{C.RESET}")
            print(f"  {'─'*70}")
            for p in procs:
                cpu_color = C.RED if p['cpu']>50 else (C.YELLOW if p['cpu']>20 else C.RESET)
                sus = is_suspicious(p)
                flag = f" {C.RED}⚠{C.RESET}" if sus else ""
                print(f"  {p['pid']:>6}  {p['name']:<22} {cpu_color}{p['cpu']:>5.1f}%{C.RESET}  {fmt_mem(p['mem']):>8}  {p['user']:<20}{flag}")

            print(f"\n  {C.GREY}[Ctrl+C] Quitter{C.RESET}")
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n")

def menu_list_processes():
    sep("Processus actifs")
    procs = get_processes()
    print(f"\n  {C.BOLD}{'PID':>6}  {'NOM':<25} {'CPU':>7}  {'RAM':>9}{C.RESET}")
    print(f"  {'─'*55}")
    for p in procs[:30]:
        sus = "⚠" if is_suspicious(p) else ""
        cpu_color = C.RED if p['cpu']>50 else (C.YELLOW if p['cpu']>20 else C.RESET)
        print(f"  {p['pid']:>6}  {p['name']:<25} {cpu_color}{p['cpu']:>6.1f}%{C.RESET}  {fmt_mem(p['mem']):>9}  {sus}")
    info(f"Total : {len(procs)} processus")

def menu_kill():
    sep("Tuer un processus")
    pid_s = input("  PID ou nom du processus : ").strip()
    if PSUTIL:
        try:
            if pid_s.isdigit():
                p = psutil.Process(int(pid_s))
                name = p.name()
                confirm = input(f"  Tuer '{name}' (PID {pid_s}) ? (oui/N) : ").strip().lower()
                if confirm == "oui":
                    p.kill(); ok(f"Processus {pid_s} ({name}) tué.")
            else:
                killed = 0
                for p in psutil.process_iter(["pid","name"]):
                    if p.info["name"].lower() == pid_s.lower():
                        p.kill(); killed += 1
                if killed: ok(f"{killed} processus '{pid_s}' tué(s).")
                else:      err(f"Aucun processus '{pid_s}' trouvé.")
        except Exception as e:
            err(f"Erreur : {e}")
    else:
        run_ps(f"Stop-Process -Name '{pid_s}' -Force -ErrorAction SilentlyContinue")
        ok(f"Commande envoyée pour '{pid_s}'.")

def menu_scan_suspicious():
    sep("Détection de processus suspects")
    procs  = get_processes()
    alerts = []
    for p in procs:
        reasons = is_suspicious(p)
        if reasons:
            alerts.append((p, reasons))

    if not alerts:
        ok("Aucun processus suspect détecté.")
        return

    warn(f"{len(alerts)} processus suspect(s) :")
    for p, reasons in alerts:
        print(f"\n  {C.RED}{C.BOLD}{p['name']}{C.RESET} (PID {p['pid']})")
        for r in reasons:
            print(f"    {C.YELLOW}→{C.RESET} {r}")
        if p.get("path"):
            print(f"    {C.GREY}Chemin : {p['path']}{C.RESET}")

def menu_connections():
    """Affiche les connexions réseau par processus."""
    sep("Connexions réseau actives")
    if PSUTIL:
        conns = psutil.net_connections(kind="inet")
        by_pid = {}
        for c in conns:
            if c.pid and c.status == "ESTABLISHED":
                by_pid.setdefault(c.pid, []).append(c)
        for pid, conlist in sorted(by_pid.items())[:20]:
            try:
                name = psutil.Process(pid).name()
            except:
                name = f"PID {pid}"
            print(f"\n  {C.CYAN}{name}{C.RESET} (PID {pid})")
            for c in conlist[:5]:
                laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "?"
                raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "?"
                print(f"    {laddr} → {raddr}")
    else:
        raw = run_ps("Get-NetTCPConnection -State Established | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess | ConvertTo-Json")
        try:
            conns = json.loads(raw) if raw.startswith("[") else [json.loads(raw)]
            for c in conns[:30]:
                print(f"  {c.get('LocalAddress')}:{c.get('LocalPort')} → {c.get('RemoteAddress')}:{c.get('RemotePort')}  (PID {c.get('OwningProcess')})")
        except: warn("Impossible de lire les connexions.")

def menu_export():
    procs = get_processes()
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    pj = APP_DIR / f"processes_{ts}.json"
    pj.write_text(json.dumps(procs, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    ok(f"Export : {pj}")

def print_banner():
    print(f"""{C.CYAN}{C.BOLD}
╔══════════════════════════════════════════════════════════════╗
║         📈  Moniteur de Processus v2.0                       ║
║   Live · CPU/RAM · Suspects · Réseau · Kill                  ║
╚══════════════════════════════════════════════════════════════╝{C.RESET}""")

def main():
    os.system("cls" if os.name=="nt" else "clear")
    print_banner()
    if not PSUTIL:
        warn("psutil non installé — fonctionnalités réduites. Installez avec : pip install psutil")
    while True:
        print(f"""\n{C.BOLD}─── MENU ────────────────────────────────────{C.RESET}
  {C.CYAN}1.{C.RESET} Mode live (rafraîchissement automatique)
  {C.CYAN}2.{C.RESET} Lister les processus (top CPU)
  {C.CYAN}3.{C.RESET} Détecter les processus suspects
  {C.CYAN}4.{C.RESET} Tuer un processus
  {C.CYAN}5.{C.RESET} Connexions réseau par processus
  {C.CYAN}6.{C.RESET} Exporter (JSON)
  {C.CYAN}0.{C.RESET} Quitter\n""")
        c = input(f"{C.BOLD}Choix >{C.RESET} ").strip()
        if c=="0": break
        elif c=="1":
            try:
                n = int(input("  Rafraîchir toutes les N secondes [2] : ").strip() or "2")
            except: n=2
            live_mode(n)
        elif c=="2": menu_list_processes()
        elif c=="3": menu_scan_suspicious()
        elif c=="4": menu_kill()
        elif c=="5": menu_connections()
        elif c=="6": menu_export()

if __name__ == "__main__":
    main()