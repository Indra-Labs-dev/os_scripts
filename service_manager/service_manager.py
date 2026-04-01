import subprocess

def run_powershell(command):
    result = subprocess.run(["powershell", "-Command", command], capture_output=True, text=True)
    return result.stdout.strip(), result.stderr.strip(), result.returncode

def list_services():
    stdout, stderr, code = run_powershell("Get-Service | Select-Object -Property Name,Status,StartType")
    return stdout if code == 0 else "Erreur: " + stderr

def start_stop_service(name, action):
    stdout, stderr, code = run_powershell(f"{action}-Service -Name {name}")
    return f"Service {action}é" if code == 0 else "Erreur: " + stderr

def change_startup(name, startup_type):
    stdout, stderr, code = run_powershell(f"Set-Service -Name {name} -StartupType {startup_type}")
    return "Modifié" if code == 0 else "Erreur: " + stderr

def detect_suspicious():
    # Placeholder
    stdout, stderr, code = run_powershell("Get-Service | Where-Object {$_.Status -eq 'Running' -and $_.Name -like '*unknown*'}")
    return stdout if code == 0 else "Aucun service suspect"

def main():
    while True:
        print("\n=== Gestionnaire de Services Windows ===")
        print("1. Lister services")
        print("2. Démarrer/Arrêter service")
        print("3. Modifier type de démarrage")
        print("4. Détecter services suspects")
        print("5. Quitter")
        choice = input("Choix: ")
        if choice == '1':
            print(list_services())
        elif choice == '2':
            name = input("Nom du service: ")
            action = input("Démarrer (start) ou Arrêter (stop): ")
            print(start_stop_service(name, action))
        elif choice == '3':
            name = input("Nom du service: ")
            stype = input("Type (Automatic/Manual/Disabled): ")
            print(change_startup(name, stype))
        elif choice == '4':
            print(detect_suspicious())
        elif choice == '5':
            break
        else:
            print("Choix invalide")

if __name__ == "__main__":
    main()