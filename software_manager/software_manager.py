import subprocess

def run_powershell(command):
    result = subprocess.run(["powershell", "-Command", command], capture_output=True, text=True)
    return result.stdout.strip(), result.stderr.strip(), result.returncode

def list_installed():
    stdout, stderr, code = run_powershell("winget list")
    return stdout if code == 0 else "Erreur: " + stderr

def uninstall(program):
    stdout, stderr, code = run_powershell(f"winget uninstall {program}")
    return "Désinstallé" if code == 0 else "Erreur: " + stderr

def install(program):
    stdout, stderr, code = run_powershell(f"winget install {program}")
    return "Installé" if code == 0 else "Erreur: " + stderr

def check_updates():
    stdout, stderr, code = run_powershell("winget upgrade --all")
    return stdout if code == 0 else "Erreur: " + stderr

def main():
    while True:
        print("\n=== Gestionnaire de Logiciels ===")
        print("1. Lister programmes installés")
        print("2. Désinstaller un programme")
        print("3. Installer un programme")
        print("4. Vérifier mises à jour")
        print("5. Quitter")
        choice = input("Choix: ")
        if choice == '1':
            print(list_installed())
        elif choice == '2':
            prog = input("Nom du programme: ")
            print(uninstall(prog))
        elif choice == '3':
            prog = input("Nom du programme: ")
            print(install(prog))
        elif choice == '4':
            print(check_updates())
        elif choice == '5':
            break
        else:
            print("Choix invalide")

if __name__ == "__main__":
    main()