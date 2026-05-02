"""
Serveur d'Authentification — API REST (Flask + HTTPS + JWT)

Endpoints :
  POST /enroll      — Enrôlement (reçoit DID, C, PK → émet un VC)
  POST /authenticate — Authentification (reçoit π, DID, VC → vérifie ZKP)
  POST /token       — Obtenir un token JWT

Le serveur ne reçoit JAMAIS de données biométriques.
Il vérifie uniquement des preuves cryptographiques.
"""
from flask import Flask, request, jsonify
from database import init_db, save_enrollment, get_enrollment, list_enrollments
from zkp_verifier import verify_proof
from ssi_registry import SSIRegistry
import jwt
import datetime
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = 'ssi-zkp-server-secret-key-2026'
API_PASSWORD = "client_secret_password"

# Registre SSI (émetteur de credentials)
registry = SSIRegistry()


# ==================== JWT MIDDLEWARE ====================

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            parts = request.headers['Authorization'].split()
            if len(parts) == 2 and parts[0] == 'Bearer':
                token = parts[1]
        if not token:
            return jsonify({'error': 'Token JWT manquant'}), 401
        try:
            jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token JWT expiré'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Token JWT invalide'}), 401
        return f(*args, **kwargs)
    return decorated


@app.route('/token', methods=['POST'])
def get_token():
    """Génère un token JWT."""
    data = request.json
    if data and data.get('password') == API_PASSWORD:
        exp = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)
        token = jwt.encode({'exp': exp, 'client': 'ssi_client'}, app.config['SECRET_KEY'], algorithm="HS256")
        return jsonify({'token': token})
    return jsonify({'error': 'Mot de passe API invalide'}), 401


# ==================== ENRÔLEMENT ====================

@app.route('/enroll', methods=['POST'])
@token_required
def enroll():
    """
    Enrôlement d'un utilisateur.
    Reçoit : DID, Commitment C = H(T_u || r), Clé publique PK
    Stocke : {DID, C, PK, date}
    Émet  : Verifiable Credential (VC)

    ⚠️ Aucune donnée biométrique n'est reçue ni stockée.
    """
    data = request.json
    did = data.get('did')
    commitment = data.get('commitment')
    public_key_pem = data.get('public_key_pem')

    if not all([did, commitment, public_key_pem]):
        return jsonify({"error": "Paramètres manquants (did, commitment, public_key_pem)"}), 400

    # Vérifier que le DID n'est pas déjà enregistré
    existing = get_enrollment(did)
    if existing:
        return jsonify({"error": "Ce DID est déjà enregistré"}), 409

    # Stocker dans la base (métadonnées uniquement)
    save_enrollment(did, commitment, public_key_pem)

    # Émettre un Verifiable Credential
    vc = registry.issue_credential(did, commitment)

    return jsonify({
        "status": "success",
        "message": "Enrôlement réussi. VC émis.",
        "verifiable_credential": vc,
        "server_did": registry.server_did
    }), 200


# ==================== AUTHENTIFICATION ====================

@app.route('/authenticate', methods=['POST'])
@token_required
def authenticate():
    """
    Authentification par preuve ZKP.
    Reçoit : π (preuve ZKP), DID, VC
    Vérifie :
      1. Le VC (signature, validité)
      2. La preuve ZKP (sans connaître T_u ni r)

    ⚠️ Le serveur ne voit JAMAIS T_u, r, ni aucune image faciale.
    """
    data = request.json
    did = data.get('did')
    proof = data.get('proof')
    vc = data.get('verifiable_credential')

    if not all([did, proof, vc]):
        return jsonify({"error": "Paramètres manquants (did, proof, vc)"}), 400

    # 1. Récupérer l'enrôlement
    enrollment = get_enrollment(did)
    if not enrollment:
        return jsonify({"error": "DID non enregistré", "authenticated": False}), 404

    # 2. Vérifier le Verifiable Credential
    vc_valid, vc_reason = registry.verify_credential(vc)
    if not vc_valid:
        return jsonify({"error": vc_reason, "authenticated": False}), 401

    # 3. Vérifier la preuve ZKP
    zkp_valid, zkp_reason = verify_proof(
        proof,
        enrollment["commitment"],
        enrollment["public_key_pem"]
    )

    return jsonify({
        "authenticated": zkp_valid,
        "reason": zkp_reason,
        "did": did,
        "vc_valid": vc_valid
    }), 200 if zkp_valid else 401


if __name__ == '__main__':
    init_db()
    print("=" * 55)
    print(" SERVEUR SSI + ZKP — Authentification Décentralisée")
    print(" HTTPS activé | JWT activé | Aucune biométrie stockée")
    print("=" * 55)
    app.run(host='127.0.0.1', port=5050, ssl_context='adhoc', debug=True)
