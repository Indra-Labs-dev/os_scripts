import subprocess
from pathlib import Path

def run_powershell(command):
    result = subprocess.run(["powershell", "-Command", command], capture_output=True, text=True)
    return result.stdout.strip(), result.stderr.strip(), result.returncode

def backup_folder(src, dst):
    stdout, stderr, code = run_powershell(f"Copy-Item -Path '{src}' -Destination '{dst}' -Recurse")
    return "Sauvegardé" if code == 0 else "Erreur: " + stderr

def compress_folder(src, dst):
    stdout, stderr, code = run_powershell(f"Compress-Archive -Path '{src}' -DestinationPath '{dst}'")
    return "Compressé" if code == 0 else "Erreur: " + stderr

def schedule_backup(src, dst, time):
    # Placeholder for scheduling
    return "Planifié (placeholder)"

def main():
    while True:
        print("\n=== Gestionnaire de Sauvegarde ===")
        print("1. Sauvegarder dossier")
        print("2. Compresser dossier")
        print("3. Planifier sauvegarde")
        print("4. Quitter")
        choice = input("Choix: ")
        if choice == '1':
            src = input("Source: ")
            dst = input("Destination: ")
            print(backup_folder(src, dst))
        elif choice == '2':
            src = input("Source: ")
            dst = input("Destination (zip): ")
            print(compress_folder(src, dst))
        elif choice == '3':
            src = input("Source: ")
            dst = input("Destination: ")
            time = input("Heure (HH:MM): ")
            print(schedule_backup(src, dst, time))
        elif choice == '4':
            break
        else:
            print("Choix invalide")

if __name__ == "__main__":
    main()