import subprocess
import json
from pathlib import Path

def run_powershell(command):
    result = subprocess.run(["powershell", "-Command", command], capture_output=True, text=True)
    return result.stdout.strip(), result.stderr.strip(), result.returncode

def read_logs():
    stdout, stderr, code = run_powershell("Get-EventLog -LogName System -Newest 10 | Select-Object -Property TimeGenerated,EntryType,Message")
    return stdout if code == 0 else "Erreur: " + stderr

def filter_errors():
    stdout, stderr, code = run_powershell("Get-EventLog -LogName System | Where-Object {$_.EntryType -eq 'Error'} -Newest 10 | Select-Object -Property TimeGenerated,Message")
    return stdout if code == 0 else "Erreur: " + stderr

def detect_brute_force():
    stdout, stderr, code = run_powershell("Get-EventLog -LogName Security -InstanceId 4625 -Newest 10 | Select-Object -Property TimeGenerated,Message")
    return stdout if code == 0 else "Erreur: " + stderr

def export_report():
    report = {
        "logs": read_logs(),
        "errors": filter_errors(),
        "brute_force": detect_brute_force()
    }
    path = Path.home() / "log_report.json"
    with open(path, 'w') as f:
        json.dump(report, f, indent=4)
    return f"Rapport exporté vers {path}"

def main():
    while True:
        print("\n=== Analyseur de Logs Windows ===")
        print("1. Lire logs système")
        print("2. Filtrer erreurs critiques")
        print("3. Détecter brute force")
        print("4. Exporter rapport")
        print("5. Quitter")
        choice = input("Choix: ")
        if choice == '1':
            print(read_logs())
        elif choice == '2':
            print(filter_errors())
        elif choice == '3':
            print(detect_brute_force())
        elif choice == '4':
            print(export_report())
        elif choice == '5':
            break
        else:
            print("Choix invalide")

if __name__ == "__main__":
    main()