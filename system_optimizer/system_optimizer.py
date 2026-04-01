import subprocess

def run_powershell(command):
    result = subprocess.run(["powershell", "-Command", command], capture_output=True, text=True)
    return result.stdout.strip(), result.stderr.strip(), result.returncode

def clean_temp():
    stdout, stderr, code = run_powershell("Remove-Item -Path $env:TEMP\\* -Recurse -Force -ErrorAction SilentlyContinue")
    return "Fichiers temporaires nettoyés" if code == 0 else "Erreur: " + stderr

def flush_dns():
    stdout, stderr, code = run_powershell("Clear-DnsClientCache")
    return "Cache DNS vidé" if code == 0 else "Erreur: " + stderr

def disable_services():
    services = ["SysMain", "Superfetch"]
    for svc in services:
        run_powershell(f"Stop-Service -Name {svc} -ErrorAction SilentlyContinue; Set-Service -Name {svc} -StartupType Disabled -ErrorAction SilentlyContinue")
    return "Services inutiles désactivés"

def optimize_startup():
    return "Démarrage optimisé (placeholder)"

def free_ram():
    return "RAM libérée (placeholder)"

def main():
    while True:
        print("\n=== Optimiseur Système ===")
        print("1. Nettoyer fichiers temporaires")
        print("2. Vider cache DNS")
        print("3. Désactiver services inutiles")
        print("4. Optimiser démarrage")
        print("5. Libérer RAM")
        print("6. Quitter")
        choice = input("Choix: ")
        if choice == '1':
            print(clean_temp())
        elif choice == '2':
            print(flush_dns())
        elif choice == '3':
            print(disable_services())
        elif choice == '4':
            print(optimize_startup())
        elif choice == '5':
            print(free_ram())
        elif choice == '6':
            break
        else:
            print("Choix invalide")

if __name__ == "__main__":
    main()