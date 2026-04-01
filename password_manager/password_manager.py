"""
Gestionnaire de Mots de Passe Local - Version 1.0
Chiffrement AES-256 (Fernet) + dérivation de clé Argon2id
Auteur: Indra-Labs-dev
"""

import os
import sys
import json
import secrets
import string
import hashlib
import base64
import getpass
import logging
from datetime import datetime
from pathlib import Path

# Vérification des dépendances
try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    from cryptography.hazmat.backends import default_backend
except ImportError:
    print("[ERREUR] Module 'cryptography' manquant.")
    print("         Installez-le avec : pip install cryptography")
    sys.exit(1)

# ─── Configuration ──────────────────────────────────────────────────────────────

APP_NAME    = "PasswordManager"
APP_DIR     = Path(os.environ.get("APPDATA", Path.home())) / APP_NAME
VAULT_FILE  = APP_DIR / "vault.enc"
LOG_FILE    = APP_DIR / "password_manager.log"
SALT_FILE   = APP_DIR / "salt.bin"

APP_DIR.mkdir(parents=True, exist_ok=True)

# ─── Logging ────────────────────────────────────────────────────────────────────

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger(__name__)

# ─── Couleurs CLI ───────────────────────────────────────────────────────────────

class C:
    RESET  = "\033[0m"
    BOLD   = "\033[1m"
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    WHITE  = "\033[97m"
    GREY   = "\033[90m"

def ok(msg):    print(f"{C.GREEN}[✓]{C.RESET} {msg}")
def err(msg):   print(f"{C.RED}[✗]{C.RESET} {msg}")
def info(msg):  print(f"{C.CYAN}[i]{C.RESET} {msg}")
def warn(msg):  print(f"{C.YELLOW}[!]{C.RESET} {msg}")

# ─── Dérivation de clé (Scrypt) ─────────────────────────────────────────────────

def _get_or_create_salt() -> bytes:
    """Charge ou génère un salt cryptographique persistant."""
    if SALT_FILE.exists():
        return SALT_FILE.read_bytes()
    salt = os.urandom(32)
    SALT_FILE.write_bytes(salt)
    logger.info("Nouveau salt généré.")
    return salt


def derive_key(master_password: str) -> bytes:
    """
    Dérive une clé AES-256 depuis le mot de passe maître via Scrypt.
    Paramètres conformes aux recommandations OWASP 2024.
    """
    salt = _get_or_create_salt()
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**17,     # Facteur de coût CPU/mémoire
        r=8,
        p=1,
        backend=default_backend()
    )
    key_raw = kdf.derive(master_password.encode("utf-8"))
    return base64.urlsafe_b64encode(key_raw)


# ─── Coffre-fort chiffré ────────────────────────────────────────────────────────

class Vault:
    def __init__(self, fernet: Fernet):
        self.fernet = fernet
        self._data: dict = {}

    # ── Chargement / Sauvegarde ──────────────────────────────────────────────────

    def load(self) -> bool:
        if not VAULT_FILE.exists():
            self._data = {"entries": {}, "created": str(datetime.now())}
            return True
        try:
            raw = VAULT_FILE.read_bytes()
            decrypted = self.fernet.decrypt(raw)
            self._data = json.loads(decrypted.decode("utf-8"))
            logger.info("Coffre-fort chargé avec succès.")
            return True
        except Exception:
            logger.error("Échec du déchiffrement — mot de passe incorrect ou fichier corrompu.")
            return False

    def save(self):
        plaintext = json.dumps(self._data, ensure_ascii=False, indent=2).encode("utf-8")
        encrypted = self.fernet.encrypt(plaintext)
        VAULT_FILE.write_bytes(encrypted)
        logger.info("Coffre-fort sauvegardé.")

    # ── Opérations CRUD ─────────────────────────────────────────────────────────

    def add(self, service: str, username: str, password: str, notes: str = "") -> bool:
        key = service.lower()
        if key in self._data["entries"]:
            warn(f"Une entrée existe déjà pour '{service}'. Utilisez 'modifier' pour la mettre à jour.")
            return False
        self._data["entries"][key] = {
            "service":   service,
            "username":  username,
            "password":  password,
            "notes":     notes,
            "created":   str(datetime.now()),
            "modified":  str(datetime.now()),
        }
        self.save()
        logger.info(f"Entrée ajoutée : {service}")
        return True

    def update(self, service: str, username: str = None, password: str = None, notes: str = None) -> bool:
        key = service.lower()
        if key not in self._data["entries"]:
            err(f"Aucune entrée pour '{service}'.")
            return False
        entry = self._data["entries"][key]
        if username: entry["username"] = username
        if password: entry["password"] = password
        if notes is not None: entry["notes"] = notes
        entry["modified"] = str(datetime.now())
        self.save()
        logger.info(f"Entrée modifiée : {service}")
        return True

    def get(self, service: str) -> dict | None:
        return self._data["entries"].get(service.lower())

    def delete(self, service: str) -> bool:
        key = service.lower()
        if key not in self._data["entries"]:
            err(f"Aucune entrée pour '{service}'.")
            return False
        del self._data["entries"][key]
        self.save()
        logger.info(f"Entrée supprimée : {service}")
        return True

    def list_all(self) -> list[dict]:
        return list(self._data["entries"].values())

    def search(self, query: str) -> list[dict]:
        q = query.lower()
        return [
            e for e in self._data["entries"].values()
            if q in e["service"].lower() or q in e["username"].lower()
        ]

    def count(self) -> int:
        return len(self._data["entries"])


# ─── Générateur de mots de passe ────────────────────────────────────────────────

class PasswordGenerator:
    CHARSETS = {
        "letters":    string.ascii_letters,
        "digits":     string.digits,
        "symbols":    "!@#$%^&*()_+-=[]{}|;:,.<>?",
        "ambiguous":  "l1IO0",
    }

    @classmethod
    def generate(cls,
                 length: int = 20,
                 use_digits: bool = True,
                 use_symbols: bool = True,
                 no_ambiguous: bool = True) -> str:
        charset = cls.CHARSETS["letters"]
        if use_digits:   charset += cls.CHARSETS["digits"]
        if use_symbols:  charset += cls.CHARSETS["symbols"]
        if no_ambiguous:
            charset = "".join(c for c in charset if c not in cls.CHARSETS["ambiguous"])

        while True:
            pwd = "".join(secrets.choice(charset) for _ in range(length))
            # Garantit au moins un caractère de chaque catégorie choisie
            has_upper  = any(c in string.ascii_uppercase for c in pwd)
            has_lower  = any(c in string.ascii_lowercase for c in pwd)
            has_digit  = (not use_digits)  or any(c in string.digits for c in pwd)
            has_symbol = (not use_symbols) or any(c in cls.CHARSETS["symbols"] for c in pwd)
            if has_upper and has_lower and has_digit and has_symbol:
                return pwd

    @classmethod
    def strength(cls, pwd: str) -> tuple[str, str]:
        """Retourne (niveau, description) de la force du mot de passe."""
        score = 0
        if len(pwd) >= 12: score += 1
        if len(pwd) >= 16: score += 1
        if len(pwd) >= 20: score += 1
        if any(c in string.ascii_uppercase for c in pwd): score += 1
        if any(c in string.ascii_lowercase for c in pwd): score += 1
        if any(c in string.digits for c in pwd): score += 1
        if any(c in cls.CHARSETS["symbols"] for c in pwd): score += 1

        if score <= 3:   return ("FAIBLE",   C.RED)
        if score <= 5:   return ("MOYEN",    C.YELLOW)
        if score <= 6:   return ("FORT",     C.GREEN)
        return                  ("TRÈS FORT", C.GREEN + C.BOLD)


# ─── Interface CLI ───────────────────────────────────────────────────────────────

def print_banner():
    print(f"""{C.CYAN}{C.BOLD}
╔══════════════════════════════════════════════════════════════╗
║          🔐  Gestionnaire de Mots de Passe Local             ║
║                    Version 1.0 — AES-256                     ║
╚══════════════════════════════════════════════════════════════╝{C.RESET}""")

def print_menu():
    print(f"""
{C.BOLD}─── MENU ────────────────────────────────────{C.RESET}
  {C.CYAN}1.{C.RESET} Ajouter un mot de passe
  {C.CYAN}2.{C.RESET} Afficher / Copier un mot de passe
  {C.CYAN}3.{C.RESET} Lister tous les services
  {C.CYAN}4.{C.RESET} Rechercher
  {C.CYAN}5.{C.RESET} Modifier une entrée
  {C.CYAN}6.{C.RESET} Supprimer une entrée
  {C.CYAN}7.{C.RESET} Générer un mot de passe fort
  {C.CYAN}8.{C.RESET} Analyser la force d'un mot de passe
  {C.CYAN}9.{C.RESET} Exporter (JSON chiffré)
  {C.CYAN}0.{C.RESET} Quitter
{C.BOLD}─────────────────────────────────────────────{C.RESET}""")

def authenticate() -> Vault | None:
    print_banner()
    is_new = not VAULT_FILE.exists()

    if is_new:
        info("Première utilisation — Création du coffre-fort.")
        warn("Choisissez un mot de passe maître FORT. Il ne peut pas être récupéré.")
        pwd1 = getpass.getpass("  Mot de passe maître : ")
        pwd2 = getpass.getpass("  Confirmation        : ")
        if pwd1 != pwd2:
            err("Les mots de passe ne correspondent pas.")
            return None
        if len(pwd1) < 8:
            err("Le mot de passe doit faire au moins 8 caractères.")
            return None
    else:
        pwd1 = getpass.getpass("  Mot de passe maître : ")

    print()
    info("Dérivation de la clé en cours (Scrypt — peut prendre quelques secondes)...")
    key    = derive_key(pwd1)
    fernet = Fernet(key)
    vault  = Vault(fernet)

    if not vault.load():
        err("Mot de passe incorrect ou coffre-fort corrompu.")
        logger.warning("Tentative d'authentification échouée.")
        return None

    ok(f"Coffre-fort ouvert. {vault.count()} entrée(s).")
    logger.info("Authentification réussie.")
    return vault

def display_entry(entry: dict, show_password: bool = False):
    print(f"""
  {C.BOLD}Service  :{C.RESET} {entry['service']}
  {C.BOLD}Login    :{C.RESET} {entry['username']}
  {C.BOLD}Mot passe:{C.RESET} {entry['password'] if show_password else '●●●●●●●●'}
  {C.BOLD}Notes    :{C.RESET} {entry['notes'] or '—'}
  {C.GREY}Créé     : {entry['created']}
  Modifié  : {entry['modified']}{C.RESET}""")

def menu_add(vault: Vault):
    print(f"\n{C.BOLD}── Ajouter une entrée ──{C.RESET}")
    service  = input("  Service (ex: Gmail) : ").strip()
    username = input("  Identifiant/Email   : ").strip()
    gen = input("  Générer un mot de passe ? (o/N) : ").strip().lower()
    if gen == "o":
        password = PasswordGenerator.generate()
        ok(f"Mot de passe généré : {C.YELLOW}{password}{C.RESET}")
    else:
        password = getpass.getpass("  Mot de passe        : ")
        level, color = PasswordGenerator.strength(password)
        print(f"  Force : {color}{level}{C.RESET}")
    notes = input("  Notes (optionnel)   : ").strip()

    if vault.add(service, username, password, notes):
        ok(f"Entrée '{service}' ajoutée.")

def menu_get(vault: Vault):
    print(f"\n{C.BOLD}── Afficher un mot de passe ──{C.RESET}")
    service = input("  Service : ").strip()
    entry = vault.get(service)
    if not entry:
        err(f"Aucune entrée pour '{service}'.")
        return
    display_entry(entry, show_password=False)
    show = input("\n  Afficher le mot de passe ? (o/N) : ").strip().lower()
    if show == "o":
        print(f"  {C.YELLOW}{entry['password']}{C.RESET}")

def menu_list(vault: Vault):
    entries = vault.list_all()
    if not entries:
        info("Le coffre-fort est vide.")
        return
    print(f"\n{C.BOLD}── {len(entries)} entrée(s) ──{C.RESET}")
    for e in sorted(entries, key=lambda x: x["service"].lower()):
        print(f"  {C.CYAN}•{C.RESET} {e['service']:<25} {C.GREY}{e['username']}{C.RESET}")

def menu_search(vault: Vault):
    print(f"\n{C.BOLD}── Rechercher ──{C.RESET}")
    query   = input("  Recherche : ").strip()
    results = vault.search(query)
    if not results:
        info("Aucun résultat.")
        return
    ok(f"{len(results)} résultat(s) :")
    for e in results:
        print(f"  {C.CYAN}•{C.RESET} {e['service']:<25} {C.GREY}{e['username']}{C.RESET}")

def menu_update(vault: Vault):
    print(f"\n{C.BOLD}── Modifier une entrée ──{C.RESET}")
    service = input("  Service à modifier : ").strip()
    entry   = vault.get(service)
    if not entry:
        err(f"Aucune entrée pour '{service}'.")
        return
    display_entry(entry)
    print("\n  Laissez vide pour conserver la valeur actuelle.")
    username = input(f"  Nouvel identifiant [{entry['username']}] : ").strip() or None
    gen = input("  Nouveau mot de passe ? Générer ? (o/N) : ").strip().lower()
    if gen == "o":
        password = PasswordGenerator.generate()
        ok(f"Nouveau mot de passe : {C.YELLOW}{password}{C.RESET}")
    else:
        raw = getpass.getpass("  Nouveau mot de passe (vide=inchangé) : ")
        password = raw if raw else None
    notes = input(f"  Notes [{entry['notes']}] : ").strip() or None

    if vault.update(service, username, password, notes):
        ok("Entrée mise à jour.")

def menu_delete(vault: Vault):
    print(f"\n{C.BOLD}── Supprimer une entrée ──{C.RESET}")
    service = input("  Service à supprimer : ").strip()
    entry   = vault.get(service)
    if not entry:
        err(f"Aucune entrée pour '{service}'.")
        return
    display_entry(entry)
    confirm = input(f"\n  {C.RED}Confirmer la suppression ? (oui/N) :{C.RESET} ").strip().lower()
    if confirm == "oui":
        if vault.delete(service):
            ok("Entrée supprimée.")
    else:
        info("Suppression annulée.")

def menu_generate():
    print(f"\n{C.BOLD}── Générateur de mot de passe ──{C.RESET}")
    try:
        length = int(input("  Longueur [20] : ").strip() or "20")
    except ValueError:
        length = 20
    digits  = input("  Inclure chiffres ? (O/n) : ").strip().lower() != "n"
    symbols = input("  Inclure symboles ? (O/n) : ").strip().lower() != "n"
    ambig   = input("  Exclure caractères ambigus (l,1,O,0) ? (O/n) : ").strip().lower() != "n"

    pwd = PasswordGenerator.generate(length, digits, symbols, ambig)
    level, color = PasswordGenerator.strength(pwd)
    print(f"\n  {C.BOLD}Mot de passe :{C.RESET} {C.YELLOW}{pwd}{C.RESET}")
    print(f"  {C.BOLD}Force        :{C.RESET} {color}{level}{C.RESET}")

def menu_strength():
    print(f"\n{C.BOLD}── Analyser la force ──{C.RESET}")
    pwd = getpass.getpass("  Mot de passe à analyser : ")
    level, color = PasswordGenerator.strength(pwd)
    checks = [
        (len(pwd) >= 8,  "Au moins 8 caractères"),
        (len(pwd) >= 12, "Au moins 12 caractères"),
        (len(pwd) >= 16, "Au moins 16 caractères"),
        (any(c in string.ascii_uppercase for c in pwd), "Contient des majuscules"),
        (any(c in string.ascii_lowercase for c in pwd), "Contient des minuscules"),
        (any(c in string.digits for c in pwd),          "Contient des chiffres"),
        (any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in pwd), "Contient des symboles"),
    ]
    print()
    for passed, label in checks:
        icon = f"{C.GREEN}✓" if passed else f"{C.RED}✗"
        print(f"  {icon}{C.RESET} {label}")
    print(f"\n  Force globale : {color}{level}{C.RESET}")

def menu_export(vault: Vault):
    """Exporte les métadonnées (sans mots de passe) en JSON."""
    print(f"\n{C.BOLD}── Exporter ──{C.RESET}")
    warn("Pour la sécurité, les mots de passe ne sont PAS inclus dans l'export.")
    export_data = []
    for e in vault.list_all():
        export_data.append({
            "service":  e["service"],
            "username": e["username"],
            "notes":    e["notes"],
            "created":  e["created"],
            "modified": e["modified"],
        })
    out_file = APP_DIR / f"export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    out_file.write_text(json.dumps(export_data, ensure_ascii=False, indent=2), encoding="utf-8")
    ok(f"Export (sans mots de passe) : {out_file}")
    logger.info(f"Export effectué : {out_file}")


# ─── Point d'entrée ─────────────────────────────────────────────────────────────

def main():
    os.system("cls" if os.name == "nt" else "clear")

    vault = authenticate()
    if not vault:
        sys.exit(1)

    actions = {
        "1": menu_add,
        "2": menu_get,
        "3": menu_list,
        "4": menu_search,
        "5": menu_update,
        "6": menu_delete,
        "7": lambda _: menu_generate(),
        "8": lambda _: menu_strength(),
        "9": menu_export,
    }

    while True:
        print_menu()
        choice = input(f"{C.BOLD}Choix >{C.RESET} ").strip()
        if choice == "0":
            info("Fermeture du coffre-fort. À bientôt.")
            logger.info("Session terminée.")
            break
        elif choice in actions:
            try:
                if choice in ("7", "8"):
                    actions[choice](None)
                else:
                    actions[choice](vault)
            except KeyboardInterrupt:
                print()
                info("Opération annulée.")
        else:
            warn("Choix invalide.")


if __name__ == "__main__":
    main()