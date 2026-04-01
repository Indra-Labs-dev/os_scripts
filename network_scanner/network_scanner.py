"""
Scanner Réseau - Version 1.0
Scan ARP, détection OS (TTL), ports, services, vulnérabilités basiques, export
Auteur: Indra-Labs-dev
"""

import os, sys, json, subprocess, socket, struct, threading, time, ipaddress
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

APP_DIR  = Path(os.environ.get("APPDATA", Path.home())) / "NetworkScanner"
APP_DIR.mkdir(parents=True, exist_ok=True)

class C:
    RESET="\033[0m";BOLD="\033[1m";RED="\033[91m";GREEN="\033[92m"
    YELLOW="\033[93m";CYAN="\033[96m";GREY="\033[90m";BLUE="\033[94m";MAGENTA="\033[95m"

def ok(m):   print(f"  {C.GREEN}[✓]{C.RESET} {m}")
def err(m):  print(f"  {C.RED}[✗]{C.RESET} {m}")
def warn(m): print(f"  {C.YELLOW}[!]{C.RESET} {m}")
def info(m): print(f"  {C.CYAN}[i]{C.RESET} {m}")
def sep(t=""): print(f"\n{C.BOLD}{C.BLUE}── {t} {'─'*(50-len(t))}{C.RESET}")

# ── Utilitaires réseau ─────────────────────────────────────────────────────────

def get_local_network() -> tuple[str, str]:
    """Retourne (IP locale, réseau CIDR)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]; s.close()
        parts = ip.split(".")
        network = ".".join(parts[:3]) + ".0/24"
        return ip, network
    except:
        return "127.0.0.1", "127.0.0.1/32"

def resolve_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return ""

def ping(ip: str, timeout: int = 1) -> tuple[bool, int]:
    """Ping un hôte, retourne (up, ttl)."""
    try:
        if os.name == "nt":
            r = subprocess.run(["ping","-n","1","-w",str(timeout*1000),ip],
                capture_output=True, text=True, timeout=timeout+2)
            if r.returncode == 0:
                for line in r.stdout.splitlines():
                    if "TTL=" in line or "ttl=" in line:
                        ttl_str = line.upper().split("TTL=")[-1].split()[0].rstrip(".")
                        return True, int(ttl_str)
                return True, 0
        return False, 0
    except:
        return False, 0

def guess_os_from_ttl(ttl: int) -> str:
    """Estimation grossière de l'OS depuis le TTL."""
    if ttl == 0: return "?"
    if ttl <= 64:  return "Linux/macOS/Android"
    if ttl <= 128: return "Windows"
    if ttl <= 255: return "Cisco/Network device"
    return "?"

def get_mac_from_arp(ip: str) -> str:
    """Récupère la MAC via la table ARP."""
    try:
        r = subprocess.run(["arp","-a",ip], capture_output=True, text=True, timeout=3)
        for line in r.stdout.splitlines():
            if ip in line:
                parts = line.split()
                for p in parts:
                    if "-" in p and len(p) == 17:
                        return p.upper()
                    if ":" in p and len(p) == 17:
                        return p.upper()
    except: pass
    return ""

PORT_SERVICES = {
    21:"FTP", 22:"SSH", 23:"Telnet", 25:"SMTP", 53:"DNS", 80:"HTTP",
    110:"POP3", 135:"RPC", 139:"NetBIOS", 143:"IMAP", 443:"HTTPS",
    445:"SMB", 3306:"MySQL", 3389:"RDP", 5432:"PostgreSQL", 5900:"VNC",
    6379:"Redis", 8080:"HTTP-Alt", 8443:"HTTPS-Alt", 27017:"MongoDB",
}

VULNERABLE_COMBOS = {
    21:  ("FTP sans chiffrement", "MEDIUM"),
    23:  ("Telnet — protocole non chiffré", "HIGH"),
    139: ("NetBIOS — vecteur d'attaque classique", "MEDIUM"),
    445: ("SMB — risque WannaCry/EternalBlue si non patché", "HIGH"),
    3389:("RDP exposé — risque brute force", "MEDIUM"),
    5900:("VNC exposé", "MEDIUM"),
    6379:("Redis souvent non authentifié", "HIGH"),
    27017:("MongoDB souvent non authentifié", "HIGH"),
}

def scan_port(ip: str, port: int, timeout: float = 0.5) -> bool:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        r = s.connect_ex((ip, port))
        s.close()
        return r == 0
    except:
        return False

def grab_banner(ip: str, port: int, timeout: float = 2.0) -> str:
    """Grab de bannière pour identifier le service."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        if port in (80, 8080, 8443, 443):
            s.send(b"HEAD / HTTP/1.0\r\n\r\n")
        else:
            pass  # On attend la bannière spontanée
        banner = s.recv(256).decode("utf-8", errors="replace").strip()
        s.close()
        return banner[:80]
    except:
        return ""

# ── Classe principale ──────────────────────────────────────────────────────────

class NetworkScanner:
    def __init__(self):
        self.discovered: list[dict] = []
        self.local_ip, self.network = get_local_network()

    def scan_host(self, ip: str, ports: list[int] = None) -> dict | None:
        up, ttl = ping(ip)
        if not up: return None

        hostname = resolve_hostname(ip)
        mac      = get_mac_from_arp(ip)
        os_guess = guess_os_from_ttl(ttl)

        host = {
            "ip": ip, "hostname": hostname, "mac": mac,
            "ttl": ttl, "os_guess": os_guess,
            "open_ports": [], "vulnerabilities": [],
        }

        if ports:
            with ThreadPoolExecutor(max_workers=50) as ex:
                futures = {ex.submit(scan_port, ip, p): p for p in ports}
                for f in as_completed(futures):
                    p = futures[f]
                    if f.result():
                        service = PORT_SERVICES.get(p, "?")
                        banner  = grab_banner(ip, p) if p in (21,22,80,8080,3389,5900) else ""
                        host["open_ports"].append({"port":p,"service":service,"banner":banner})
                        if p in VULNERABLE_COMBOS:
                            msg, sev = VULNERABLE_COMBOS[p]
                            host["vulnerabilities"].append({"port":p,"issue":msg,"severity":sev})

        return host

    def ping_sweep(self, network: str = None, max_workers: int = 100) -> list[str]:
        net = network or self.network
        sep(f"Ping Sweep — {net}")
        try:
            net_obj = ipaddress.ip_network(net, strict=False)
            hosts   = list(net_obj.hosts())
        except:
            err("Réseau invalide."); return []

        info(f"Scan de {len(hosts)} hôtes potentiels...")
        alive = []
        lock  = threading.Lock()

        def _ping(h):
            ip = str(h)
            up, _ = ping(ip)
            if up:
                with lock: alive.append(ip)

        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futures = [ex.submit(_ping, h) for h in hosts]
            done = 0
            for f in as_completed(futures):
                done += 1
                print(f"\r  Progression : {done}/{len(hosts)}", end="", flush=True)
        print()
        ok(f"{len(alive)} hôte(s) actif(s) trouvé(s)")
        return sorted(alive)

    def full_scan(self, ips: list[str], ports: list[int] = None):
        """Scan complet d'une liste d'IPs."""
        ports = ports or list(PORT_SERVICES.keys())
        sep(f"Scan complet — {len(ips)} hôte(s)")
        self.discovered = []
        for i, ip in enumerate(ips, 1):
            print(f"\r  [{i}/{len(ips)}] Scan {ip}...", end="", flush=True)
            h = self.scan_host(ip, ports)
            if h:
                self.discovered.append(h)
        print()
        return self.discovered

    def print_results(self):
        if not self.discovered:
            info("Aucun hôte dans les résultats."); return
        sep(f"Résultats — {len(self.discovered)} hôte(s)")
        for h in self.discovered:
            color = C.GREEN if h["open_ports"] else C.GREY
            print(f"\n  {color}{C.BOLD}{h['ip']}{C.RESET}", end="")
            if h["hostname"]: print(f"  ({h['hostname']})", end="")
            print(f"  {C.GREY}TTL:{h['ttl']} OS:{h['os_guess']} MAC:{h['mac']}{C.RESET}")
            for p in h["open_ports"]:
                print(f"    {C.CYAN}:{p['port']}{C.RESET} {p['service']}", end="")
                if p["banner"]: print(f"  {C.GREY}[{p['banner'][:60]}]{C.RESET}", end="")
                print()
            for v in h["vulnerabilities"]:
                color_v = C.RED if v["severity"]=="HIGH" else C.YELLOW
                print(f"    {color_v}⚠ Port {v['port']} — {v['issue']}{C.RESET}")

    def print_vulnerabilities_summary(self):
        sep("Résumé des vulnérabilités")
        all_vulns = [(h["ip"], v) for h in self.discovered for v in h["vulnerabilities"]]
        if not all_vulns:
            ok("Aucune vulnérabilité évidente détectée."); return
        high   = [(ip,v) for ip,v in all_vulns if v["severity"]=="HIGH"]
        medium = [(ip,v) for ip,v in all_vulns if v["severity"]=="MEDIUM"]
        if high:
            print(f"\n  {C.RED}{C.BOLD}HIGH :{C.RESET}")
            for ip,v in high: print(f"    {C.RED}{ip}:{v['port']} — {v['issue']}{C.RESET}")
        if medium:
            print(f"\n  {C.YELLOW}MEDIUM :{C.RESET}")
            for ip,v in medium: print(f"    {C.YELLOW}{ip}:{v['port']} — {v['issue']}{C.RESET}")

    def export(self):
        ts  = datetime.now().strftime('%Y%m%d_%H%M%S')
        pj  = APP_DIR / f"scan_{ts}.json"
        out = {"timestamp":str(datetime.now()),"network":self.network,
               "hosts_found":len(self.discovered),"hosts":self.discovered}
        pj.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
        ok(f"Rapport JSON : {pj}")

        # CSV simple
        pc = APP_DIR / f"scan_{ts}.csv"
        lines = ["IP,Hostname,MAC,OS,Ports ouverts,Vulnérabilités"]
        for h in self.discovered:
            ports = " ".join(str(p["port"]) for p in h["open_ports"])
            vulns = " ".join(v["issue"] for v in h["vulnerabilities"])
            lines.append(f"{h['ip']},{h['hostname']},{h['mac']},{h['os_guess']},{ports},{vulns}")
        pc.write_text("\n".join(lines), encoding="utf-8")
        ok(f"CSV         : {pc}")

def print_banner():
    print(f"""{C.CYAN}{C.BOLD}
╔══════════════════════════════════════════════════════════════╗
║            🌐  Scanner Réseau v1.0                           ║
║    Ping Sweep · Ports · Détection OS · Vulnérabilités        ║
╚══════════════════════════════════════════════════════════════╝{C.RESET}""")

COMMON_PORTS = [21,22,23,25,53,80,110,135,139,143,443,445,3306,3389,5432,5900,6379,8080,8443,27017]
TOP_PORTS    = list(range(1,1025)) + [3306,3389,5432,5900,6379,8080,8443,27017]

def main():
    os.system("cls" if os.name=="nt" else "clear")
    print_banner()
    scanner = NetworkScanner()
    info(f"IP locale : {scanner.local_ip}  |  Réseau : {scanner.network}")

    while True:
        print(f"""\n{C.BOLD}─── MENU ────────────────────────────────────{C.RESET}
  {C.CYAN}1.{C.RESET} Ping sweep (réseau local)
  {C.CYAN}2.{C.RESET} Scan complet réseau local (ports + OS + vulnérabilités)
  {C.CYAN}3.{C.RESET} Scanner une IP spécifique
  {C.CYAN}4.{C.RESET} Scanner un réseau personnalisé (ex: 192.168.1.0/24)
  {C.CYAN}5.{C.RESET} Afficher les résultats
  {C.CYAN}6.{C.RESET} Résumé des vulnérabilités
  {C.CYAN}7.{C.RESET} Exporter (JSON + CSV)
  {C.CYAN}0.{C.RESET} Quitter\n""")
        c = input(f"{C.BOLD}Choix >{C.RESET} ").strip()
        if c=="0": break
        elif c=="1":
            ips = scanner.ping_sweep()
            if ips:
                print(f"\n  Hôtes actifs : {', '.join(ips)}")
        elif c=="2":
            ips = scanner.ping_sweep()
            if ips:
                choice_p = input(f"  Ports : (1) Courants  (2) Top 1024 [1] : ").strip()
                ports = TOP_PORTS if choice_p=="2" else COMMON_PORTS
                scanner.full_scan(ips, ports)
                scanner.print_results()
                scanner.print_vulnerabilities_summary()
        elif c=="3":
            ip = input("  IP à scanner : ").strip()
            choice_p = input(f"  Ports : (1) Courants  (2) Top 1024 [1] : ").strip()
            ports = TOP_PORTS if choice_p=="2" else COMMON_PORTS
            sep(f"Scan {ip}")
            h = scanner.scan_host(ip, ports)
            if h:
                scanner.discovered = [h]
                scanner.print_results()
            else:
                err(f"{ip} ne répond pas au ping.")
        elif c=="4":
            net = input("  Réseau CIDR (ex: 10.0.0.0/24) : ").strip()
            ips = scanner.ping_sweep(net)
            if ips:
                scanner.full_scan(ips, COMMON_PORTS)
                scanner.print_results()
        elif c=="5": scanner.print_results()
        elif c=="6": scanner.print_vulnerabilities_summary()
        elif c=="7":
            if scanner.discovered: scanner.export()
            else: warn("Aucune donnée à exporter.")

if __name__ == "__main__":
    main()