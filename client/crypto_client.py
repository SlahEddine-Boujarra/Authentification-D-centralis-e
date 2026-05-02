from cryptography.fernet import Fernet
import json
import base64
import hashlib

# Clés statiques pour simulation (Simplification académique autorisée)
# Ces clés sont de 32 bytes encodées en base64 url-safe, format exigé par Fernet
CLIENT_KEY = b'Q0xJRU5UX0tFWV8xMjM0NTY3ODkwMTIzNDU2Nzg5MDE=' 
SERVER_KEY = b'U0VSVkVSX0tFWV8xMjM0NTY3ODkwMTIzNDU2Nzg5MDE='

client_cipher = Fernet(CLIENT_KEY)
server_cipher = Fernet(SERVER_KEY)

def encrypt_fragment_A(fragment_list):
    """Chiffre le fragment A avec la clé client"""
    data = json.dumps(fragment_list).encode()
    enc_data = client_cipher.encrypt(data)
    return base64.b64encode(enc_data).decode('utf-8')

def decrypt_fragment_A(b64_enc_data):
    """Déchiffre le fragment A avec la clé client"""
    enc_data = base64.b64decode(b64_enc_data)
    data = client_cipher.decrypt(enc_data)
    return json.loads(data.decode())

def encrypt_fragment_B(fragment_list):
    """Chiffre le fragment B avec la clé serveur (avant envoi)"""
    data = json.dumps(fragment_list).encode()
    enc_data = server_cipher.encrypt(data)
    return base64.b64encode(enc_data).decode('utf-8')

def decrypt_fragment_B(b64_enc_data):
    """Déchiffre le fragment B reçu du serveur"""
    enc_data = base64.b64decode(b64_enc_data)
    data = server_cipher.decrypt(enc_data)
    return json.loads(data.decode())

def hash_template(template):
    """Génère un hash SHA-256 du template pour vérification d'intégrité"""
    data_string = json.dumps(template)
    return hashlib.sha256(data_string.encode()).hexdigest()
