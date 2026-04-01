import hashlib
import json
import getpass
from pathlib import Path

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def load_data():
    path = Path.home() / "passwords.json"
    if path.exists():
        with open(path, 'r') as f:
            return json.load(f)
    return {}

def save_data(data):
    path = Path.home() / "passwords.json"
    with open(path, 'w') as f:
        json.dump(data, f, indent=4)

def set_master():
    master = getpass.getpass("Mot de passe maître: ")
    data = load_data()
    data['master'] = hash_password(master)
    save_data(data)
    return "Mot de passe maître défini"

def add_password():
    data = load_data()
    if 'master' not in data:
        print("Définissez le mot de passe maître d'abord")
        return
    master = getpass.getpass("Mot de passe maître: ")
    if hash_password(master) != data['master']:
        print("Mot de passe maître incorrect")
        return
    site = input("Site: ")
    user = input("Utilisateur: ")
    pwd = input("Mot de passe: ")
    data[site] = {'user': user, 'pwd': pwd}
    save_data(data)
    print("Mot de passe ajouté")

def get_password():
    data = load_data()
    if 'master' not in data:
        print("Définissez le mot de passe maître d'abord")
        return
    master = getpass.getpass("Mot de passe maître: ")
    if hash_password(master) != data['master']:
        print("Mot de passe maître incorrect")
        return
    site = input("Site: ")
    if site in data:
        print(f"Utilisateur: {data[site]['user']}, Mot de passe: {data[site]['pwd']}")
    else:
        print("Site non trouvé")

def generate_password():
    import random
    chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
    pwd = ''.join(random.choice(chars) for _ in range(12))
    print(f"Mot de passe généré: {pwd}")

def main():
    while True:
        print("\n=== Gestionnaire de Mots de Passe ===")
        print("1. Définir mot de passe maître")
        print("2. Ajouter mot de passe")
        print("3. Récupérer mot de passe")
        print("4. Générer mot de passe")
        print("5. Quitter")
        choice = input("Choix: ")
        if choice == '1':
            print(set_master())
        elif choice == '2':
            add_password()
        elif choice == '3':
            get_password()
        elif choice == '4':
            generate_password()
        elif choice == '5':
            break
        else:
            print("Choix invalide")

if __name__ == "__main__":
    main()