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
import logging
from functools import wraps

# ==================== CONFIGURATION LOGGING ====================

logging.basicConfig(
    level=logging.DEBUG,
    format='%(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('serveur_log.txt', encoding='utf-8')
    ]
)
logger = logging.getLogger('SERVEUR')


def log_header(title):
    """Affiche un en-tête de section de log."""
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    logger.info("")
    logger.info("=" * 65)
    logger.info(f"  {title}")
    logger.info(f"  Horodatage : {now}")
    logger.info("=" * 65)


def log_step(step_num, description):
    """Affiche une étape numérotée."""
    logger.info(f"  [{step_num}] {description}")


def log_data(label, value, indent=6):
    """Affiche une donnée avec label."""
    prefix = " " * indent
    if isinstance(value, str) and len(value) > 64:
        logger.info(f"{prefix}{label} : {value[:64]}...")
    else:
        logger.info(f"{prefix}{label} : {value}")


def log_result(success, message):
    """Affiche le résultat final."""
    if success:
        logger.info(f"  >>> RESULTAT : [OK] {message}")
    else:
        logger.info(f"  >>> RESULTAT : [ECHEC] {message}")
    logger.info("-" * 65)


def log_security_notice():
    """Rappel de sécurité dans les logs."""
    logger.info("  [SECURITE] Le serveur n'a recu AUCUNE donnee biometrique")
    logger.info("  [SECURITE] Pas de template T_u, pas d'alea r, pas d'image")


# ==================== APP FLASK ====================

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
            logger.info("  [JWT] Token manquant dans la requete")
            return jsonify({'error': 'Token JWT manquant'}), 401
        try:
            jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            logger.info("  [JWT] Token valide")
        except jwt.ExpiredSignatureError:
            logger.info("  [JWT] Token expire")
            return jsonify({'error': 'Token JWT expiré'}), 401
        except jwt.InvalidTokenError:
            logger.info("  [JWT] Token invalide")
            return jsonify({'error': 'Token JWT invalide'}), 401
        return f(*args, **kwargs)
    return decorated


@app.route('/token', methods=['POST'])
def get_token():
    """Génère un token JWT."""
    log_header("REQUETE : GENERATION TOKEN JWT")
    data = request.json
    log_step(1, "Verification du mot de passe API")

    if data and data.get('password') == API_PASSWORD:
        exp = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)
        token = jwt.encode({'exp': exp, 'client': 'ssi_client'}, app.config['SECRET_KEY'], algorithm="HS256")
        log_step(2, "Token JWT genere avec succes")
        log_data("Expiration", exp.strftime("%Y-%m-%d %H:%M:%S UTC"))
        log_data("Token (debut)", token[:40])
        log_result(True, "Token JWT emis")
        return jsonify({'token': token})

    log_result(False, "Mot de passe API invalide")
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
    log_header("REQUETE : ENROLEMENT SSI")

    data = request.json
    did = data.get('did')
    commitment = data.get('commitment')
    public_key_pem = data.get('public_key_pem')

    # Log des données reçues
    log_step(1, "Donnees recues du client")
    log_data("DID", did)
    log_data("Commitment C", commitment)
    log_data("Cle publique PK", public_key_pem[:50] if public_key_pem else "None")
    logger.info("")
    log_security_notice()
    logger.info("")

    if not all([did, commitment, public_key_pem]):
        log_result(False, "Parametres manquants")
        return jsonify({"error": "Paramètres manquants (did, commitment, public_key_pem)"}), 400

    # Vérifier que le DID n'est pas déjà enregistré
    log_step(2, "Verification DID dans la base de donnees")
    existing = get_enrollment(did)
    if existing:
        log_data("Statut", "DID deja enregistre")
        log_result(False, f"DID duplique : {did}")
        return jsonify({"error": "Ce DID est déjà enregistré"}), 409
    log_data("Statut", "DID disponible")

    # Stocker dans la base (métadonnées uniquement)
    log_step(3, "Stockage dans SQLite (metadonnees uniquement)")
    save_enrollment(did, commitment, public_key_pem)
    log_data("Table", "enrollments")
    log_data("Colonnes", "did, commitment, public_key_pem, enrolled_at")
    log_data("Biometrie stockee", "AUCUNE (jamais)")

    # Émettre un Verifiable Credential
    log_step(4, "Emission du Verifiable Credential (VC)")
    vc = registry.issue_credential(did, commitment)
    log_data("VC type", vc.get("type", []))
    log_data("VC issuer", vc.get("issuer", ""))
    log_data("VC date", vc.get("issuanceDate", ""))
    log_data("VC signature", vc.get("proof", {}).get("signature", "")[:40])

    log_result(True, f"Enrolement reussi pour {did}")

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
    log_header("REQUETE : AUTHENTIFICATION ZKP")

    data = request.json
    did = data.get('did')
    proof = data.get('proof')
    vc = data.get('verifiable_credential')

    # Log des données reçues
    log_step(1, "Donnees recues du client")
    log_data("DID", did)
    if proof:
        log_data("Preuve ZKP (challenge)", proof.get("challenge", "N/A"))
        log_data("Preuve ZKP (timestamp)", proof.get("timestamp", "N/A"))
        log_data("Preuve ZKP (threshold)", proof.get("threshold", "N/A"))
        log_data("Preuve ZKP (signature)", str(proof.get("signature", ""))[:40])
        log_data("Preuve ZKP (blinded_T)", proof.get("blinded_template_hash", "N/A"))
        log_data("Preuve ZKP (blinded_r)", proof.get("blinded_random_hash", "N/A"))
        log_data("Preuve ZKP (response1)", proof.get("response_1", "N/A"))
        log_data("Preuve ZKP (response2)", proof.get("response_2", "N/A"))
        log_data("Preuve ZKP (verif_hash)", proof.get("verification_hash", "N/A"))
    if vc:
        log_data("VC issuer", vc.get("issuer", "N/A"))
        log_data("VC subject", vc.get("credentialSubject", {}).get("id", "N/A"))
    logger.info("")
    log_security_notice()
    logger.info("")

    if not all([did, proof, vc]):
        log_result(False, "Parametres manquants")
        return jsonify({"error": "Paramètres manquants (did, proof, vc)"}), 400

    # 1. Récupérer l'enrôlement
    log_step(2, "Recherche du DID dans la base de donnees")
    enrollment = get_enrollment(did)
    if not enrollment:
        log_data("Statut", "DID non trouve")
        log_result(False, f"DID inconnu : {did}")
        return jsonify({"error": "DID non enregistré", "authenticated": False}), 404
    log_data("DID trouve", did)
    log_data("Commitment stocke", enrollment["commitment"])
    log_data("Date enrolement", enrollment.get("enrolled_at", "N/A"))

    # 2. Vérifier le Verifiable Credential
    log_step(3, "Verification du Verifiable Credential (VC)")
    vc_valid, vc_reason = registry.verify_credential(vc)
    log_data("VC valide", vc_valid)
    log_data("VC raison", vc_reason)
    if not vc_valid:
        log_result(False, f"VC invalide : {vc_reason}")
        return jsonify({"error": vc_reason, "authenticated": False}), 401

    # 3. Vérifier la preuve ZKP
    log_step(4, "Verification de la preuve ZKP (Zero-Knowledge)")
    logger.info("      Etapes de verification :")
    logger.info("        a) Verification du timestamp (anti-rejeu, max 120s)")
    logger.info("        b) Verification du challenge Fiat-Shamir")
    logger.info("        c) Verification du hash de verification")
    logger.info("        d) Verification de la signature RSA-PSS")

    zkp_valid, zkp_reason = verify_proof(
        proof,
        enrollment["commitment"],
        enrollment["public_key_pem"]
    )

    log_data("ZKP valide", zkp_valid)
    log_data("ZKP raison", zkp_reason)

    if zkp_valid:
        log_result(True, f"Authentification ACCEPTEE pour {did}")
    else:
        log_result(False, f"Authentification REJETEE pour {did} — {zkp_reason}")

    return jsonify({
        "authenticated": zkp_valid,
        "reason": zkp_reason,
        "did": did,
        "vc_valid": vc_valid
    }), 200 if zkp_valid else 401


if __name__ == '__main__':
    init_db()
    logger.info("")
    logger.info("=" * 65)
    logger.info("  SERVEUR SSI + ZKP — Authentification Decentralisee")
    logger.info("  HTTPS active | JWT active | Aucune biometrie stockee")
    logger.info("=" * 65)
    logger.info(f"  DID Serveur  : {registry.server_did}")
    logger.info(f"  Adresse      : https://127.0.0.1:5050")
    logger.info(f"  Base donnees : serveur_db.sqlite")
    logger.info(f"  Fichier log  : serveur_log.txt")
    logger.info("=" * 65)
    logger.info("")
    app.run(host='127.0.0.1', port=5050, ssl_context='adhoc', debug=True)
