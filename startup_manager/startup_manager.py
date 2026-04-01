import subprocess

def run_powershell(command):
    result = subprocess.run(["powershell", "-Command", command], capture_output=True, text=True)
    return result.stdout.strip(), result.stderr.strip(), result.returncode

def list_startup():
    stdout, stderr, code = run_powershell("Get-CimInstance Win32_StartupCommand | Select-Object -Property Name,Command,Location")
    return stdout if code == 0 else "Erreur: " + stderr

def enable_disable(name, enable):
    # Placeholder
    return "Fonction non implémentée"

def add_program():
    # Placeholder
    return "Fonction non implémentée"

def main():
    while True:
        print("\n=== Gestionnaire de Démarrage ===")
        print("1. Lister apps au démarrage")
        print("2. Activer/Désactiver")
        print("3. Ajouter programme")
        print("4. Quitter")
        choice = input("Choix: ")
        if choice == '1':
            print(list_startup())
        elif choice == '2':
            name = input("Nom: ")
            en = input("Activer (y/n): ")
            print(enable_disable(name, en == 'y'))
        elif choice == '3':
            print(add_program())
        elif choice == '4':
            break
        else:
            print("Choix invalide")

if __name__ == "__main__":
    main()