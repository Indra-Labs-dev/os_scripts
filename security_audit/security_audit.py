"""
Audit de Sécurité Windows - Version 2.0
Analyse complète : pare-feu, Defender, ports, comptes, UAC, BitLocker, RDP, politique MdP
Auteur: Indra-Labs-dev
"""

import os, sys, json, subprocess, logging, socket
from datetime import datetime
from pathlib import Path

APP_DIR  = Path(os.environ.get("APPDATA", Path.home())) / "SecurityAudit"
LOG_FILE = APP_DIR / "security_audit.log"
APP_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(filename=LOG_FILE, level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
logger = logging.getLogger(__name__)

class C:
    RESET="\033[0m";BOLD="\033[1m";RED="\033[91m";GREEN="\033[92m"
    YELLOW="\033[93m";CYAN="\033[96m";WHITE="\033[97m";GREY="\033[90m";BLUE="\033[94m"

def ok(m):   print(f"  {C.GREEN}[✓]{C.RESET} {m}")
def err(m):  print(f"  {C.RED}[✗]{C.RESET} {m}")
def warn(m): print(f"  {C.YELLOW}[!]{C.RESET} {m}")
def info(m): print(f"  {C.CYAN}[i]{C.RESET} {m}")
def sep(t=""): print(f"\n{C.BOLD}{C.BLUE}── {t} {'─'*(50-len(t))}{C.RESET}")

def run_ps(cmd, timeout=15):
    try:
        r = subprocess.run(["powershell","-NoProfile","-NonInteractive","-Command",cmd],
            capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip()
    except:
        return ""

def is_admin():
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False

class SecurityAudit:
    def __init__(self):
        self.results = []
        self.score = 0
        self.max_score = 0

    def _add(self, cat, check, status, detail="", weight=5):
        self.max_score += weight
        if status == "OK": self.score += weight
        elif status == "WARN": self.score += weight // 2
        self.results.append({"category":cat,"check":check,"status":status,"detail":detail,"weight":weight})

    def check_firewall(self):
        sep("Pare-feu Windows")
        raw = run_ps("Get-NetFirewallProfile | Select-Object Name,Enabled | ConvertTo-Json")
        try:
            profiles = json.loads(raw) if raw.startswith("[") else [json.loads(raw)]
            for p in profiles:
                name = p.get("Name","?"); enabled = p.get("Enabled",False)
                if enabled:
                    ok(f"Pare-feu {name} : ACTIF")
                    self._add("Pare-feu", f"Profil {name}", "OK", weight=5)
                else:
                    err(f"Pare-feu {name} : DÉSACTIVÉ")
                    self._add("Pare-feu", f"Profil {name}", "FAIL", f"Profil {name} désactivé", weight=5)
        except:
            warn("Impossible de lire l'état du pare-feu.")

    def check_defender(self):
        sep("Windows Defender / Antivirus")
        rt = run_ps("(Get-MpComputerStatus).RealTimeProtectionEnabled")
        if rt.lower() == "true":
            ok("Protection temps réel : ACTIVE"); self._add("Antivirus","Temps réel","OK",weight=8)
        else:
            err("Protection temps réel : DÉSACTIVÉE"); self._add("Antivirus","Temps réel","FAIL","Activez la protection temps réel",weight=8)

        sig = run_ps("(Get-MpComputerStatus).AntivirusSignatureAge")
        try:
            d = int(sig)
            if d <= 1:   ok(f"Définitions : à jour ({d}j)"); self._add("Antivirus","Définitions","OK",weight=5)
            elif d <= 7: warn(f"Définitions : {d}j"); self._add("Antivirus","Définitions","WARN",f"{d} jours",weight=5)
            else:        err(f"Définitions : {d}j — OBSOLÈTES"); self._add("Antivirus","Définitions","FAIL",f"{d} jours",weight=5)
        except: pass

        threats = run_ps("(Get-MpThreat | Where-Object {$_.IsActive -eq $true}).Count")
        try:
            c = int(threats) if threats else 0
            if c == 0: ok("Menaces actives : aucune"); self._add("Antivirus","Menaces","OK",weight=10)
            else:      err(f"Menaces actives : {c} !"); self._add("Antivirus","Menaces","FAIL",f"{c} menace(s)",weight=10)
        except: pass

    def check_uac(self):
        sep("Contrôle de Compte Utilisateur (UAC)")
        val = run_ps(r"(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System').EnableLUA")
        if val.strip() == "1":
            ok("UAC : ACTIVÉ"); self._add("UAC","État","OK",weight=7)
        else:
            err("UAC : DÉSACTIVÉ — risque élevé !"); self._add("UAC","État","FAIL","UAC désactivé",weight=7)

    def check_bitlocker(self):
        sep("Chiffrement de disque (BitLocker)")
        raw = run_ps("Get-BitLockerVolume | Select-Object MountPoint,ProtectionStatus | ConvertTo-Json")
        if not raw: warn("BitLocker : impossible de lire l'état (droits admin requis)."); return
        try:
            vols = json.loads(raw) if raw.startswith("[") else [json.loads(raw)]
            for v in vols:
                mp = v.get("MountPoint","?"); st = v.get("ProtectionStatus",0)
                if st == 1: ok(f"BitLocker {mp} : ACTIVÉ"); self._add("BitLocker",f"Volume {mp}","OK",weight=6)
                else:       warn(f"BitLocker {mp} : DÉSACTIVÉ"); self._add("BitLocker",f"Volume {mp}","WARN","Données non chiffrées",weight=6)
        except: warn("Impossible de parser les volumes BitLocker.")

    def check_accounts(self):
        sep("Comptes Utilisateurs")
        admin_e = run_ps("(Get-LocalUser -Name 'Administrator').Enabled")
        if admin_e.lower() == "true":
            warn("Compte 'Administrator' local ACTIVÉ"); self._add("Comptes","Compte Administrator","WARN","Désactivez ce compte",weight=5)
        else:
            ok("Compte 'Administrator' désactivé"); self._add("Comptes","Compte Administrator","OK",weight=5)

        guest = run_ps("(Get-LocalUser -Name 'Guest').Enabled")
        if guest.lower() == "true":
            err("Compte 'Guest' ACTIVÉ !"); self._add("Comptes","Compte Guest","FAIL","Désactivez Guest",weight=5)
        else:
            ok("Compte 'Guest' désactivé"); self._add("Comptes","Compte Guest","OK",weight=5)

        no_pwd = run_ps("Get-LocalUser | Where-Object {$_.PasswordRequired -eq $false -and $_.Enabled -eq $true} | Select-Object -ExpandProperty Name")
        if no_pwd.strip():
            err(f"Comptes sans mot de passe : {no_pwd.strip()}"); self._add("Comptes","Sans MdP","FAIL",no_pwd.strip(),weight=8)
        else:
            ok("Tous les comptes actifs ont un mot de passe."); self._add("Comptes","Sans MdP","OK",weight=8)

    def check_ports(self):
        sep("Ports réseau exposés")
        RISKY = {21:"FTP",23:"Telnet",135:"RPC",139:"NetBIOS",445:"SMB/WannaCry",1433:"SQL Server",3389:"RDP",5900:"VNC"}
        raw = run_ps("Get-NetTCPConnection -State Listen | Select-Object LocalPort | Sort-Object LocalPort -Unique | ConvertTo-Json")
        try:
            conns = json.loads(raw) if raw.startswith("[") else [json.loads(raw)]
            open_p = {c.get("LocalPort",0) for c in conns}
            risky = {p:d for p,d in RISKY.items() if p in open_p}
            if risky:
                for p,d in risky.items(): warn(f"Port {p} ouvert : {d}")
                self._add("Réseau","Ports dangereux","WARN",str(list(risky.keys())),weight=6)
            else:
                ok("Aucun port particulièrement dangereux."); self._add("Réseau","Ports dangereux","OK",weight=6)
            info(f"Total ports en écoute : {len(open_p)}")
        except: warn("Impossible de lire les ports.")

    def check_rdp(self):
        sep("Bureau à Distance (RDP)")
        val = run_ps(r"(Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server').fDenyTSConnections")
        if val.strip() == "0":
            warn("RDP ACTIVÉ — vérifiez si intentionnel"); self._add("RDP","État","WARN","RDP exposé",weight=6)
            nla = run_ps(r"(Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp').UserAuthentication")
            if nla.strip() == "1": ok("NLA (Network Level Authentication) : ACTIVÉ"); self._add("RDP","NLA","OK",weight=4)
            else:                  err("NLA : DÉSACTIVÉ"); self._add("RDP","NLA","FAIL",weight=4)
        else:
            ok("RDP : DÉSACTIVÉ"); self._add("RDP","État","OK",weight=6)

    def check_services(self):
        sep("Services potentiellement dangereux")
        RISKY = {"RemoteRegistry":"Registre à distance","Telnet":"Telnet","SNMP":"SNMP v1/v2","TlntSvr":"Serveur Telnet"}
        found = False
        for svc, label in RISKY.items():
            st = run_ps(f"(Get-Service '{svc}' -ErrorAction SilentlyContinue).Status")
            if st.strip().lower() == "running":
                err(f"Service risqué actif : {svc} ({label})")
                self._add("Services",svc,"FAIL",f"{label} en cours",weight=5); found=True
        if not found:
            ok("Aucun service particulièrement dangereux actif."); self._add("Services","Services risqués","OK",weight=5)

    def run_all(self):
        for fn in [self.check_firewall, self.check_defender, self.check_uac,
                   self.check_bitlocker, self.check_accounts, self.check_ports,
                   self.check_rdp, self.check_services]:
            try: fn()
            except Exception as e: logger.error(f"{fn.__name__}: {e}")

    def print_score(self):
        pct = int((self.score/self.max_score)*100) if self.max_score else 0
        bar = "█"*int(40*pct/100) + "░"*(40-int(40*pct/100))
        color = C.GREEN if pct>=80 else (C.YELLOW if pct>=60 else C.RED)
        sep("Score de Sécurité")
        print(f"\n  {color}[{bar}] {pct}%{C.RESET}")
        print(f"  Score : {self.score}/{self.max_score}\n")
        fails = [r for r in self.results if r["status"]=="FAIL"]
        warns = [r for r in self.results if r["status"]=="WARN"]
        oks   = [r for r in self.results if r["status"]=="OK"]
        ok(f"{len(oks)} vérification(s) réussie(s)")
        if warns: warn(f"{len(warns)} avertissement(s)")
        if fails:
            err(f"{len(fails)} échec(s) critique(s)")
            print(f"\n  {C.RED}{C.BOLD}Points critiques :{C.RESET}")
            for f in fails: print(f"    {C.RED}→{C.RESET} [{f['category']}] {f['check']} : {f['detail']}")

    def export(self):
        out = {"timestamp":str(datetime.now()),"score":self.score,"max_score":self.max_score,
               "percent":int((self.score/self.max_score)*100) if self.max_score else 0,"results":self.results}
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        pj = APP_DIR / f"audit_{ts}.json"
        pt = APP_DIR / f"audit_{ts}.txt"
        pj.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
        lines = [f"AUDIT SECURITE WINDOWS — {datetime.now().strftime('%d/%m/%Y %H:%M')}",
                 f"Score : {self.score}/{self.max_score}", "="*60]
        for r in self.results:
            icon = {"OK":"[OK]","WARN":"[!!]","FAIL":"[KO]"}.get(r["status"],"[??]")
            lines.append(f"{icon} [{r['category']}] {r['check']}")
            if r["detail"]: lines.append(f"     → {r['detail']}")
        pt.write_text("\n".join(lines), encoding="utf-8")
        ok(f"JSON : {pj}"); ok(f"TXT  : {pt}")

def print_banner():
    print(f"""{C.CYAN}{C.BOLD}
╔══════════════════════════════════════════════════════════════╗
║            🛡️  Audit de Sécurité Windows v2.0               ║
║       Pare-feu · Defender · BitLocker · UAC · RDP           ║
╚══════════════════════════════════════════════════════════════╝{C.RESET}""")

def main():
    os.system("cls" if os.name=="nt" else "clear")
    print_banner()
    if not is_admin(): warn("Relancez en tant qu'administrateur pour un audit complet.\n")
    audit = SecurityAudit()
    while True:
        print(f"""\n{C.BOLD}─── MENU ────────────────────────────────────{C.RESET}
  {C.CYAN}1.{C.RESET} Audit complet
  {C.CYAN}2.{C.RESET} Pare-feu uniquement
  {C.CYAN}3.{C.RESET} Windows Defender
  {C.CYAN}4.{C.RESET} Comptes utilisateurs
  {C.CYAN}5.{C.RESET} Ports réseau
  {C.CYAN}6.{C.RESET} Exporter rapport (JSON + TXT)
  {C.CYAN}0.{C.RESET} Quitter\n""")
        c = input(f"{C.BOLD}Choix >{C.RESET} ").strip()
        if c=="0": break
        elif c=="1": audit=SecurityAudit(); audit.run_all(); audit.print_score()
        elif c=="2": SecurityAudit().check_firewall()
        elif c=="3": SecurityAudit().check_defender()
        elif c=="4": SecurityAudit().check_accounts()
        elif c=="5": SecurityAudit().check_ports()
        elif c=="6":
            if audit.results: audit.export()
            else: warn("Lancez d'abord un audit (option 1).")

if __name__ == "__main__":
    main()