#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OS Scripts - Lanceur Principal
Collection de scripts utilitaires pour Windows
Auteur: Indra-Labs-dev
"""

import os
import subprocess
import sys
from colorama import init, Fore, Back, Style

# Initialisation colorama
init(autoreset=True)

def afficher_titre():
    """Affiche le titre du programme"""
    print(Fore.CYAN + Style.BRIGHT + """
╔══════════════════════════════════════════════════════════════╗
║                     OS Scripts Collection                    ║
║                Outils Système Windows - v1.0                 ║
╚══════════════════════════════════════════════════════════════╝
""" + Style.RESET_ALL)

def afficher_menu():
    """Affiche le menu principal"""
    print(Fore.YELLOW + "\n📋 MENU PRINCIPAL" + Style.RESET_ALL)
    print(Fore.WHITE + "=" * 60)
    print("1. 🛡️  Audit de Sécurité Windows")
    print("2. 🚀 Optimiseur Système")
    print("3. 🔍 Moniteur de Processus")
    print("4. 🌐 Scanner Réseau")
    print("5. 🔐 Gestionnaire de Mots de Passe")
    print("6. 📦 Gestionnaire de Logiciels")
    print("7. 🧠 Analyseur de Logs Windows")
    print("8. ⚡ Boost Démarrage Windows")
    print("9. 📁 Sauvegarde Intelligente")
    print("10. 🔄 Gestionnaire de Services Windows")
    print("11. 🔄 Gestionnaire de Points de Restauration")
    print(Fore.RED + "0. ❌ Quitter" + Style.RESET_ALL)
    print(Fore.WHITE + "=" * 60)

def lancer_script(script_path):
    """Lance un script Python"""
    try:
        print(Fore.GREEN + f"\n▶️  Lancement de {script_path}..." + Style.RESET_ALL)
        subprocess.run([sys.executable, script_path], check=True)
    except subprocess.CalledProcessError as e:
        print(Fore.RED + f"❌ Erreur lors de l'exécution de {script_path}: {e}" + Style.RESET_ALL)
    except FileNotFoundError:
        print(Fore.RED + f"❌ Fichier non trouvé: {script_path}" + Style.RESET_ALL)
    except KeyboardInterrupt:
        print(Fore.YELLOW + "\n⚠️  Interruption par l'utilisateur" + Style.RESET_ALL)

def main():
    """Fonction principale"""
    afficher_titre()

    while True:
        afficher_menu()

        try:
            choix = input(Fore.CYAN + "Choix (0-11) : " + Style.RESET_ALL).strip()

            if choix == "1":
                lancer_script("security_audit/security_audit.py")
            elif choix == "2":
                lancer_script("system_optimizer/system_optimizer.py")
            elif choix == "3":
                lancer_script("process_monitor/process_monitor.py")
            elif choix == "4":
                lancer_script("network_scanner/network_scanner.py")
            elif choix == "5":
                lancer_script("password_manager/password_manager.py")
            elif choix == "6":
                lancer_script("software_manager/software_manager.py")
            elif choix == "7":
                lancer_script("log_analyzer/log_analyzer.py")
            elif choix == "8":
                lancer_script("startup_manager/startup_manager.py")
            elif choix == "9":
                lancer_script("backup_manager/backup_manager.py")
            elif choix == "10":
                lancer_script("service_manager/service_manager.py")
            elif choix == "11":
                lancer_script("system_restore_point/system_restore_point.py")
            elif choix == "0":
                print(Fore.GREEN + "\n👋 Au revoir !" + Style.RESET_ALL)
                break
            else:
                print(Fore.RED + "❌ Choix invalide. Veuillez entrer un nombre entre 0 et 11." + Style.RESET_ALL)

        except KeyboardInterrupt:
            print(Fore.YELLOW + "\n⚠️  Interruption par l'utilisateur" + Style.RESET_ALL)
            break
        except Exception as e:
            print(Fore.RED + f"❌ Erreur inattendue: {e}" + Style.RESET_ALL)

        # Pause avant de revenir au menu
        input(Fore.CYAN + "\n🔄 Appuyez sur Entrée pour continuer..." + Style.RESET_ALL)

if __name__ == "__main__":
    main()
