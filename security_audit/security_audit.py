import subprocess
import json
from pathlib import Path

def run_powershell(command):
    result = subprocess.run(["powershell", "-Command", command], capture_output=True, text=True)
    return result.stdout.strip(), result.stderr.strip(), result.returncode

def check_firewall():
    stdout, stderr, code = run_powershell("Get-NetFirewallProfile | Select-Object -Property Name,Enabled")
    if code == 0:
        return stdout
    else:
        return "Erreur: " + stderr

def check_defender():
    stdout, stderr, code = run_powershell("Get-MpComputerStatus | Select-Object -Property AntivirusEnabled,RealTimeProtectionEnabled")
    if code == 0:
        return stdout
    else:
        return "Erreur: " + stderr

def list_open_ports():
    stdout, stderr, code = run_powershell("Get-NetTCPConnection | Where-Object {$_.State -eq 'Listen'} | Select-Object -Property LocalAddress,LocalPort -First 10")
    if code == 0:
        return stdout
    else:
        return "Erreur: " + stderr

def detect_dangerous_services():
    stdout, stderr, code = run_powershell("Get-Service | Where-Object {$_.Status -eq 'Running' -and ($_.Name -like '*hack*' -or $_.Name -like '*trojan*')}")
    if code == 0:
        return stdout
    else:
        return "Erreur: " + stderr

def check_updates():
    stdout, stderr, code = run_powershell("(New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher().Search('IsInstalled=0').Updates.Count")
    if code == 0:
        return f"Mises à jour disponibles: {stdout}"
    else:
        return "Erreur: " + stderr

def scan_admin_accounts():
    stdout, stderr, code = run_powershell("Get-LocalUser | Where-Object {$_.Enabled -eq $true -and $_.Description -like '*admin*'} | Select-Object -Property Name")
    if code == 0:
        return stdout
    else:
        return "Erreur: " + stderr

def calculate_security_score():
    score = 0
    if "True" in check_firewall():
        score += 20
    if "True" in check_defender():
        score += 20
    if list_open_ports():
        score += 10
    if not detect_dangerous_services():
        score += 20
    if "0" in check_updates():
        score += 20
    if not scan_admin_accounts():
        score += 10
    return score

def export_report():
    report = {
        "firewall": check_firewall(),
        "defender": check_defender(),
        "open_ports": list_open_ports(),
        "dangerous_services": detect_dangerous_services(),
        "updates": check_updates(),
        "admin_accounts": scan_admin_accounts(),
        "security_score": calculate_security_score()
    }
    path = Path.home() / "security_audit_report.json"
    with open(path, 'w') as f:
        json.dump(report, f, indent=4)
    return f"Rapport exporté vers {path}"

def main():
    while True:
        print("\n=== Audit de Sécurité Windows ===")
        print("1. Vérifier pare-feu")
        print("2. Vérifier Windows Defender")
        print("3. Lister ports ouverts")
        print("4. Détecter services dangereux")
        print("5. Vérifier mises à jour")
        print("6. Scanner comptes admin")
        print("7. Calculer score de sécurité")
        print("8. Exporter rapport")
        print("9. Quitter")
        choice = input("Choix: ")
        if choice == '1':
            print(check_firewall())
        elif choice == '2':
            print(check_defender())
        elif choice == '3':
            print(list_open_ports())
        elif choice == '4':
            print(detect_dangerous_services())
        elif choice == '5':
            print(check_updates())
        elif choice == '6':
            print(scan_admin_accounts())
        elif choice == '7':
            print(f"Score de sécurité: {calculate_security_score()}/100")
        elif choice == '8':
            print(export_report())
        elif choice == '9':
            break
        else:
            print("Choix invalide")

if __name__ == "__main__":
    main()