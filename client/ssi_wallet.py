"""
SSI Wallet — Self-Sovereign Identity
Gère : DID (Decentralized Identifier), paires de clés RSA, Verifiable Credentials.
Toutes les données restent LOCALEMENT sur l'appareil de l'utilisateur.
"""
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
import json
import os
import base64
import hashlib
import time


class SSIWallet:
    def __init__(self, wallet_dir="wallet_data"):
        self.wallet_dir = wallet_dir
        os.makedirs(wallet_dir, exist_ok=True)
        self.private_key = None
        self.public_key = None
        self.did = None
        self.credentials = []

    # ==================== IDENTITÉ ====================

    def create_identity(self):
        """Génère un nouveau DID avec sa paire de clés RSA-2048."""
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.public_key = self.private_key.public_key()

        # DID = did:key:<hash du public key>
        pub_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        did_hash = hashlib.sha256(pub_bytes).hexdigest()[:32]
        self.did = f"did:key:{did_hash}"
        return self.did

    def get_public_key_pem(self):
        """Exporte la clé publique au format PEM."""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

    # ==================== SIGNATURE ====================

    def sign(self, data):
        """Signe des données avec la clé privée (RSA-PSS + SHA-256)."""
        if isinstance(data, str):
            data = data.encode('utf-8')
        signature = self.private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode('utf-8')

    # ==================== WALLET PERSISTENCE ====================

    def save_wallet(self, template, randomness, commitment):
        """Sauvegarde le wallet SSI localement (template, r, DID, clé privée)."""
        pk_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        did_short = self.did.split(':')[-1]

        wallet_data = {
            "did": self.did,
            "template": template,
            "randomness": base64.b64encode(randomness).decode('utf-8'),
            "commitment": commitment,
            "credentials": self.credentials,
            "created_at": time.time()
        }
        with open(os.path.join(self.wallet_dir, f"{did_short}.json"), "w") as f:
            json.dump(wallet_data, f, indent=2)
        with open(os.path.join(self.wallet_dir, f"{did_short}_sk.pem"), "wb") as f:
            f.write(pk_pem)

    def load_wallet(self, did):
        """Charge un wallet depuis le stockage local."""
        did_short = did.split(':')[-1]
        wallet_path = os.path.join(self.wallet_dir, f"{did_short}.json")
        key_path = os.path.join(self.wallet_dir, f"{did_short}_sk.pem")

        if not os.path.exists(wallet_path):
            return None

        with open(wallet_path, "r") as f:
            data = json.load(f)
        with open(key_path, "rb") as f:
            self.private_key = serialization.load_pem_private_key(f.read(), password=None)
            self.public_key = self.private_key.public_key()

        self.did = data["did"]
        self.credentials = data.get("credentials", [])
        data["randomness"] = base64.b64decode(data["randomness"])
        return data

    def store_credential(self, vc):
        """Stocke un Verifiable Credential dans le wallet."""
        self.credentials.append(vc)
        # Mettre à jour le fichier wallet
        did_short = self.did.split(':')[-1]
        wallet_path = os.path.join(self.wallet_dir, f"{did_short}.json")
        if os.path.exists(wallet_path):
            with open(wallet_path, "r") as f:
                data = json.load(f)
            data["credentials"] = self.credentials
            with open(wallet_path, "w") as f:
                json.dump(data, f, indent=2)

    def list_identities(self):
        """Liste tous les DIDs dans le wallet local."""
        dids = []
        for fname in os.listdir(self.wallet_dir):
            if fname.endswith(".json"):
                with open(os.path.join(self.wallet_dir, fname), "r") as f:
                    data = json.load(f)
                    dids.append({"did": data["did"], "created": data.get("created_at")})
        return dids
