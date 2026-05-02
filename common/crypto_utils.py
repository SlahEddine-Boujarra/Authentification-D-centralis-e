"""
Utilitaires cryptographiques partagés pour le système SSI + ZKP.
Implémente le schéma d'engagement (commitment) et les fonctions de hachage.
"""
import hashlib
import json
import os
import numpy as np


def compute_commitment(template, randomness):
    """
    Calcul de l'engagement : C = H(T_u || r)
    Le serveur stocke C, mais ne peut jamais retrouver T_u ni r.
    
    Args:
        template: Vecteur biométrique 128D (liste de floats)
        randomness: Octets aléatoires pour l'aveuglement (blinding)
    Returns:
        Chaîne hexadécimale du commitment SHA-256
    """
    template_bytes = json.dumps(template, sort_keys=True).encode('utf-8')
    data = template_bytes + randomness
    return hashlib.sha256(data).hexdigest()


def generate_randomness():
    """Génère un aléa cryptographique r de 32 octets pour le schéma d'engagement."""
    return os.urandom(32)


def hash_data(*args):
    """SHA-256 de la concaténation de données arbitraires."""
    h = hashlib.sha256()
    for arg in args:
        if isinstance(arg, str):
            h.update(arg.encode('utf-8'))
        elif isinstance(arg, bytes):
            h.update(arg)
        else:
            h.update(json.dumps(arg, sort_keys=True).encode('utf-8'))
    return h.hexdigest()


def euclidean_distance(t1, t2):
    """Distance euclidienne entre deux vecteurs (pour le matching local)."""
    return float(np.linalg.norm(np.array(t1) - np.array(t2)))
