import os
import time
import shutil
import tempfile
import requests
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# === Configuration ===
WATCH_FOLDER = r"\\chemin\vers\dossier\ENVOI"  
PFX_PATH = "certificat.pfx"
PFX_PASSWORD = "mot-de-passe-du-certificat".encode("utf-8")   
ARIBA_URL = "https://url-de-test.ariba.com/http/recevoir"
ARCHIVE_FOLDER = os.path.join(WATCH_FOLDER, "Envoyes")

# === Extraction PFX ===
def extract_cert_key_from_pfx(pfx_path, pfx_password):
    with open(pfx_path, "rb") as f:
        pfx_data = f.read()

    private_key, cert, _ = pkcs12.load_key_and_certificates(
        pfx_data, pfx_password, backend=default_backend()
    )

    cert_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pem")
    key_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pem")

    cert_file.write(cert.public_bytes(serialization.Encoding.PEM))
    cert_file.close()

    key_file.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ))
    key_file.close()

    return cert_file.name, key_file.name

# === Envoi du fichier XML ===
def send_file(filepath, cert_path, key_path):
    with open(filepath, 'rb') as f:
        try:
            response = requests.post(
                ARIBA_URL,
                data=f.read(),
                headers={"Content-Type": "application/xml"},
                cert=(cert_path, key_path),
                verify=False 
            )
            print(f"Code retour : {response.status_code}")
            print(f"Réponse (début) : {response.text[:300]}")

            if response.status_code in (200, 201):
                print(f"{os.path.basename(filepath)} envoyé avec succès.")
                return True
            else:
                print(f"Envoi effectué mais statut {response.status_code}")
                return False

        except requests.exceptions.SSLError as e:
            print("Erreur SSL persistante :", e)
            return False
        except Exception as e:
            print("Erreur inattendue :", e)
            return False

# === Gestion des événements de fichiers ===
class XMLHandler(FileSystemEventHandler):
    def __init__(self, cert_path, key_path):
        self.cert_path = cert_path
        self.key_path = key_path

    def on_created(self, event):
        if not event.is_directory and event.src_path.lower().endswith(".xml"):
            print(f"Nouveau fichier détecté : {event.src_path}")
            time.sleep(1)  # Petit délai pour éviter de lire pendant l'écriture
            success = send_file(event.src_path, self.cert_path, self.key_path)
            if success:
                os.makedirs(ARCHIVE_FOLDER, exist_ok=True)
                shutil.move(event.src_path, os.path.join(ARCHIVE_FOLDER, os.path.basename(event.src_path)))

# === Lancement de la surveillance ===
def start_watching():
    cert_path, key_path = extract_cert_key_from_pfx(PFX_PATH, PFX_PASSWORD)

    event_handler = XMLHandler(cert_path, key_path)
    observer = Observer()
    observer.schedule(event_handler, path=WATCH_FOLDER, recursive=False)
    observer.start()
    print(f"Surveillance du dossier : {WATCH_FOLDER}")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

if __name__ == "__main__":
    start_watching()
