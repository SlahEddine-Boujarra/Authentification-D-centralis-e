"""
Zero-Knowledge Proof (ZKP) — Prover (côté Client)

Génère une preuve π qui démontre :
    ∃(T_u, r) : C = H(T_u || r)  ∧  d(T_u, T'_u) < τ
SANS révéler T_u, r, ni T'_u.

En production : utiliser zk-SNARKs (Circom + SnarkJS / ZoKrates).
Prototype académique : preuve basée sur le schéma de Fiat-Shamir + signatures RSA.
"""
import hashlib
import json
import os
import time
import numpy as np


def _euclidean_distance(t1, t2):
    return float(np.linalg.norm(np.array(t1) - np.array(t2)))


def generate_proof(template_stored, template_new, randomness, commitment, threshold, sign_func):
    """
    Génère une preuve ZKP pour l'authentification biométrique.

    Entrées privées (witness) : template_stored (T_u), randomness (r), template_new (T'_u)
    Entrées publiques          : commitment (C), threshold (τ)

    Args:
        template_stored: Template enregistré T_u (128D)
        template_new:    Nouveau template capturé T'_u (128D)
        randomness:      Aléa r utilisé lors de l'engagement
        commitment:      Engagement C = H(T_u || r) stocké sur le serveur
        threshold:       Seuil de distance τ
        sign_func:       Fonction de signature du wallet SSI

    Returns:
        (proof, distance) ou (None, distance)
    """
    # ── Étape 1 : Vérification biométrique LOCALE ──
    distance = _euclidean_distance(template_stored, template_new)
    if distance >= threshold:
        return None, distance  # Échec : le visage ne correspond pas

    # ── Étape 2 : Vérification de la cohérence du commitment LOCAL ──
    template_bytes = json.dumps(template_stored, sort_keys=True).encode('utf-8')
    computed_C = hashlib.sha256(template_bytes + randomness).hexdigest()
    if computed_C != commitment:
        return None, distance  # Échec : commitment corrompu

    # ── Étape 3 : Génération de la preuve ZKP (Fiat-Shamir simplifié) ──
    # Nonces aléatoires pour l'aveuglement (blinding)
    nonce_1 = os.urandom(32)
    nonce_2 = os.urandom(32)

    # Engagements aveugles (le serveur ne pourra pas retrouver T_u ni r)
    blinded_template = hashlib.sha256(nonce_1 + template_bytes).hexdigest()
    blinded_random = hashlib.sha256(nonce_2 + randomness).hexdigest()

    timestamp = int(time.time())

    # Challenge de Fiat-Shamir : hash(public_inputs || blinded_values)
    challenge_input = (
        commitment + blinded_template + blinded_random +
        str(threshold) + str(timestamp)
    ).encode('utf-8')
    challenge = hashlib.sha256(challenge_input).hexdigest()

    # Réponses : combinent nonces + challenge + witness (prouve la connaissance)
    response_1 = hashlib.sha256(nonce_1 + challenge.encode() + template_bytes).hexdigest()
    response_2 = hashlib.sha256(nonce_2 + challenge.encode() + randomness).hexdigest()

    # Hash de vérification : lie tout pour le serveur
    verification = hashlib.sha256(
        (response_1 + response_2 + challenge + commitment).encode('utf-8')
    ).hexdigest()

    # ── Étape 4 : Signature numérique (non-répudiation via clé privée SSI) ──
    proof_data = json.dumps({
        "blinded_template_hash": blinded_template,
        "blinded_random_hash": blinded_random,
        "challenge": challenge,
        "response_1": response_1,
        "response_2": response_2,
        "verification_hash": verification,
        "timestamp": timestamp,
        "threshold": threshold,
    }, sort_keys=True)

    signature = sign_func(proof_data)

    proof = {
        "blinded_template_hash": blinded_template,
        "blinded_random_hash": blinded_random,
        "challenge": challenge,
        "response_1": response_1,
        "response_2": response_2,
        "verification_hash": verification,
        "timestamp": timestamp,
        "threshold": threshold,
        "signature": signature,
    }

    return proof, distance
