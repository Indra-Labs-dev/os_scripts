import subprocess
import socket
import ipaddress

def run_powershell(command):
    result = subprocess.run(["powershell", "-Command", command], capture_output=True, text=True)
    return result.stdout.strip(), result.stderr.strip(), result.returncode

def scan_local_ips():
    stdout, stderr, code = run_powershell("Get-NetIPAddress | Where-Object {$_.AddressFamily -eq 'IPv4'} | Select-Object -Property IPAddress")
    if code == 0:
        return stdout
    else:
        return "Erreur: " + stderr

def detect_connected_devices():
    stdout, stderr, code = run_powershell("Get-NetNeighbor | Select-Object -Property IPAddress,LinkLayerAddress")
    if code == 0:
        return stdout
    else:
        return "Erreur: " + stderr

def ping_sweep(network):
    # Placeholder for ping sweep
    stdout, stderr, code = run_powershell(f"1..10 | ForEach-Object {{ Test-Connection -ComputerName {network}.$_ -Count 1 -Quiet }}")
    if code == 0:
        return stdout
    else:
        return "Erreur: " + stderr

def detect_open_ports(ip):
    open_ports = []
    for port in [80, 443, 22, 3389]:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        if result == 0:
            open_ports.append(str(port))
        sock.close()
    return ', '.join(open_ports) if open_ports else "Aucun port ouvert détecté"

def resolve_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "Inconnu"

def main():
    while True:
        print("\n=== Scanner Réseau ===")
        print("1. Scanner IPs locales")
        print("2. Détecter appareils connectés")
        print("3. Ping sweep")
        print("4. Détecter ports ouverts")
        print("5. Résoudre hostname")
        print("6. Quitter")
        choice = input("Choix: ")
        if choice == '1':
            print(scan_local_ips())
        elif choice == '2':
            print(detect_connected_devices())
        elif choice == '3':
            network = input("Entrez le réseau (ex: 192.168.1): ")
            print(ping_sweep(network))
        elif choice == '4':
            ip = input("Entrez l'IP: ")
            print(detect_open_ports(ip))
        elif choice == '5':
            ip = input("Entrez l'IP: ")
            print(resolve_hostname(ip))
        elif choice == '6':
            break
        else:
            print("Choix invalide")

if __name__ == "__main__":
    main()