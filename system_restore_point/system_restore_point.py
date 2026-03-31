import os
import ctypes
import sys
import subprocess
import logging
from datetime import datetime

# =========================
# CONFIGURATION LOGS
# =========================
logging.basicConfig(
    filename="restore_manager.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# =========================
# ADMIN
# =========================
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False


def run_as_admin():
    if not is_admin():
        logging.warning("Relancement du script en mode administrateur")
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, " ".join(sys.argv), None, 1
        )
        sys.exit()


# =========================
# UTILITAIRE EXECUTION CMD
# =========================
def run_command(cmd):
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True
        )
        logging.info(f"Commande exécutée : {cmd}")
        logging.info(f"Sortie : {result.stdout}")
        logging.error(f"Erreur : {result.stderr}")
        return result
    except Exception as e:
        logging.exception("Erreur lors de l'exécution de la commande")
        print(f"Erreur système : {e}")


# =========================
# VERIFICATION SYSTEM RESTORE
# =========================
def check_system_restore():
    cmd = "sc query srservice"
    result = run_command(cmd)

    if "RUNNING" in result.stdout:
        print("✔ Service de restauration actif")
        return True
    else:
        print("⚠ Le service de restauration système semble désactivé")
        return False


# =========================
# CREATION POINT
# =========================
def create_restore_point(description=None):
    description = description or f"RestorePoint_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

    print("Création du point de restauration...")
    logging.info(f"Création du point : {description}")

    # PowerShell (recommandé)
    cmd = f'powershell -Command "Checkpoint-Computer -Description \\"{description}\\" -RestorePointType MODIFY_SETTINGS"'
    
    result = run_command(cmd)

    if result.returncode == 0:
        print("✔ Point de restauration créé avec succès")
    else:
        print("❌ Échec de création")
        print(result.stderr)


# =========================
# LISTE
# =========================
def list_restore_points():
    print("\nListe des points de restauration :\n")

    cmd = 'powershell -Command "Get-ComputerRestorePoint | Select-Object SequenceNumber, Description, CreationTime"'
    result = run_command(cmd)

    print(result.stdout)


# =========================
# SUPPRESSION
# =========================
def delete_restore_point(sequence_number):
    print(f"Suppression du point {sequence_number}...")
    logging.info(f"Suppression du point : {sequence_number}")

    cmd = f'powershell -Command "Get-ComputerRestorePoint | Where-Object {{$_.SequenceNumber -eq {sequence_number}}} | Remove-ComputerRestorePoint"'
    
    result = run_command(cmd)

    if result.returncode == 0:
        print("✔ Suppression réussie")
    else:
        print("❌ Échec de suppression")
        print(result.stderr)


# =========================
# MENU
# =========================
def show_menu():
    print("\n===== RESTORE POINT MANAGER =====")
    print("1. Créer un point de restauration")
    print("2. Lister les points")
    print("3. Supprimer un point")
    print("4. Vérifier service restauration")
    print("5. Quitter")


def main():
    run_as_admin()

    while True:
        show_menu()
        choix = input("Choix : ").strip()

        if choix == "1":
            desc = input("Description (optionnel) : ")
            create_restore_point(desc)

        elif choix == "2":
            list_restore_points()

        elif choix == "3":
            list_restore_points()
            seq = input("SequenceNumber à supprimer : ")
            if seq.isdigit():
                delete_restore_point(seq)
            else:
                print("❌ Valeur invalide")

        elif choix == "4":
            check_system_restore()

        elif choix == "5":
            print("Bye 👋")
            sys.exit()

        else:
            print("❌ Option invalide")


if __name__ == "__main__":
    main()