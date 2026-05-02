"""
Zero-Knowledge Proof (ZKP) — Verifier (côté Serveur)

Vérifie la preuve π SANS accéder aux données biométriques.
Le serveur ne voit JAMAIS : T_u, r, T'_u, ni aucune image faciale.

Il vérifie uniquement :
  1. La structure et la cohérence interne de la preuve
  2. La signature numérique (via la clé publique PK de l'utilisateur)
  3. La fraîcheur du timestamp (anti-rejeu)
"""
import hashlib
import json
import time
import base64
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization

# Durée maximale de validité d'une preuve (anti-rejeu)
PROOF_MAX_AGE_SECONDS = 120


def verify_proof(proof, commitment, public_key_pem):
    """
    Vérifie une preuve ZKP.

    Args:
        proof:          Dictionnaire contenant la preuve π
        commitment:     L'engagement C stocké lors de l'enrôlement
        public_key_pem: Clé publique PEM de l'utilisateur

    Returns:
        (is_valid: bool, reason: str)
    """
    try:
        # ── 1. Vérification du timestamp (anti-rejeu) ──
        proof_age = int(time.time()) - proof["timestamp"]
        if proof_age > PROOF_MAX_AGE_SECONDS:
            return False, f"Preuve expirée ({proof_age}s > {PROOF_MAX_AGE_SECONDS}s)"

        if proof_age < -10:
            return False, "Timestamp dans le futur (horloge désynchronisée)"

        # ── 2. Vérification de la cohérence du challenge (Fiat-Shamir) ──
        challenge_input = (
            commitment +
            proof["blinded_template_hash"] +
            proof["blinded_random_hash"] +
            str(proof["threshold"]) +
            str(proof["timestamp"])
        ).encode('utf-8')
        expected_challenge = hashlib.sha256(challenge_input).hexdigest()

        if proof["challenge"] != expected_challenge:
            return False, "Challenge Fiat-Shamir invalide"

        # ── 3. Vérification du hash de vérification ──
        expected_verification = hashlib.sha256(
            (proof["response_1"] + proof["response_2"] +
             proof["challenge"] + commitment).encode('utf-8')
        ).hexdigest()

        if proof["verification_hash"] != expected_verification:
            return False, "Hash de vérification incohérent"

        # ── 4. Vérification de la signature numérique RSA ──
        proof_data = json.dumps({
            "blinded_template_hash": proof["blinded_template_hash"],
            "blinded_random_hash": proof["blinded_random_hash"],
            "challenge": proof["challenge"],
            "response_1": proof["response_1"],
            "response_2": proof["response_2"],
            "verification_hash": proof["verification_hash"],
            "timestamp": proof["timestamp"],
            "threshold": proof["threshold"],
        }, sort_keys=True)

        public_key = serialization.load_pem_public_key(public_key_pem.encode('utf-8'))
        signature_bytes = base64.b64decode(proof["signature"])

        public_key.verify(
            signature_bytes,
            proof_data.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        return True, "Preuve ZKP valide — Authentification acceptée"

    except Exception as e:
        return False, f"Vérification échouée : {str(e)}"
