import subprocess
import time

def run_powershell(command):
    result = subprocess.run(["powershell", "-Command", command], capture_output=True, text=True)
    return result.stdout.strip(), result.stderr.strip(), result.returncode

def list_processes():
    stdout, stderr, code = run_powershell("Get-Process | Select-Object -Property Name,Id,CPU,WorkingSet -First 20")
    return stdout if code == 0 else "Erreur: " + stderr

def show_usage():
    return list_processes()

def detect_suspicious():
    stdout, stderr, code = run_powershell("Get-Process | Where-Object {$_.CPU -gt 50 -or $_.WorkingSet -gt 100MB} | Select-Object -Property Name,Id,CPU,WorkingSet")
    return stdout if code == 0 else "Erreur: " + stderr

def kill_process(pid):
    stdout, stderr, code = run_powershell(f"Stop-Process -Id {pid} -Force")
    return "Processus tué" if code == 0 else "Erreur: " + stderr

def live_mode():
    print("Mode live (appuyez Ctrl+C pour arrêter)")
    try:
        while True:
            print(list_processes())
            time.sleep(5)
    except KeyboardInterrupt:
        pass

def main():
    while True:
        print("\n=== Moniteur de Processus ===")
        print("1. Lister processus")
        print("2. Afficher usage CPU/RAM")
        print("3. Détecter processus suspects")
        print("4. Tuer un processus")
        print("5. Mode live")
        print("6. Quitter")
        choice = input("Choix: ")
        if choice == '1':
            print(list_processes())
        elif choice == '2':
            print(show_usage())
        elif choice == '3':
            print(detect_suspicious())
        elif choice == '4':
            pid = input("PID: ")
            print(kill_process(pid))
        elif choice == '5':
            live_mode()
        elif choice == '6':
            break
        else:
            print("Choix invalide")

if __name__ == "__main__":
    main()