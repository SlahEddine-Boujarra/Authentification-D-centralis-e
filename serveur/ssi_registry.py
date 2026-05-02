"""
SSI Registry & Verifiable Credentials — Côté Serveur

Gère :
  - Le registre des DID (Decentralized Identifiers)
  - L'émission de Verifiable Credentials (VC) lors de l'enrôlement
  - La vérification des VC lors de l'authentification

En production : utiliser Hyperledger Indy / Aries.
Prototype : registre local JSON + signatures RSA.
"""
import json
import time
import hashlib
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization


class SSIRegistry:
    """Registre SSI simplifié (remplace un ledger blockchain en production)."""

    def __init__(self):
        # Clé privée du serveur (l'émetteur de credentials)
        self._server_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048
        )
        self._server_pub = self._server_key.public_key()
        pub_bytes = self._server_pub.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.server_did = f"did:key:{hashlib.sha256(pub_bytes).hexdigest()[:32]}"

    def get_server_public_key_pem(self):
        return self._server_pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

    # ==================== VERIFIABLE CREDENTIALS ====================

    def issue_credential(self, user_did, commitment, method="facial_recognition"):
        """
        Émet un Verifiable Credential (VC) pour un utilisateur enrôlé.
        Structure basée sur W3C VC Data Model.
        """
        credential = {
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "type": ["VerifiableCredential", "BiometricEnrollmentCredential"],
            "issuer": self.server_did,
            "issuanceDate": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "credentialSubject": {
                "id": user_did,
                "enrollment": {
                    "commitment": commitment,
                    "method": method
                }
            }
        }

        # Signature du VC par le serveur
        cred_json = json.dumps(credential, sort_keys=True)
        signature = self._server_key.sign(
            cred_json.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        credential["proof"] = {
            "type": "RsaSignature2018",
            "created": credential["issuanceDate"],
            "verificationMethod": f"{self.server_did}#key-1",
            "signature": base64.b64encode(signature).decode('utf-8')
        }

        return credential

    def verify_credential(self, vc):
        """
        Vérifie la validité d'un Verifiable Credential.
        Vérifie la signature du serveur émetteur.
        """
        try:
            # Extraire la preuve et recréer le document signé
            vc_copy = {k: v for k, v in vc.items() if k != "proof"}
            vc_json = json.dumps(vc_copy, sort_keys=True)

            sig_bytes = base64.b64decode(vc["proof"]["signature"])

            self._server_pub.verify(
                sig_bytes,
                vc_json.encode('utf-8'),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True, "VC valide"
        except Exception as e:
            return False, f"VC invalide : {str(e)}"
