"""
Client SSI + ZKP — Application Graphique (Tkinter)

Architecture :
  1. CAPTURE VISAGE  → OpenCV / face_recognition
  2. EXTRACTION      → Template 128D (T_u)
  3. MATCHING LOCAL  → d(T_u, T'_u) < τ (côté client uniquement)
  4. PREUVE ZKP      → π (aucune donnée biométrique révélée)
  5. STOCKAGE LOCAL  → Wallet SSI (T_u, r, SK, DID, VC)

Le serveur ne reçoit JAMAIS de données biométriques.
"""
import os
import sys
import cv2
import tkinter as tk
from tkinter import messagebox
from PIL import Image, ImageTk
import requests
import json
import base64
import urllib3
import logging
import datetime

# Ajouter le dossier parent au path pour importer common
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from biometrics import extract_template
from ssi_wallet import SSIWallet
from zkp_prover import generate_proof
from common.crypto_utils import compute_commitment, generate_randomness

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ==================== CONFIGURATION LOGGING ====================

logging.basicConfig(
    level=logging.DEBUG,
    format='%(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('client_log.txt', encoding='utf-8')
    ]
)
logger = logging.getLogger('CLIENT')


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


def log_privacy_notice(what_sent, what_kept):
    """Affiche ce qui est envoyé vs ce qui reste local."""
    logger.info("")
    logger.info("  [VIE PRIVEE] Donnees ENVOYEES au serveur :")
    for item in what_sent:
        logger.info(f"      --> {item}")
    logger.info("  [VIE PRIVEE] Donnees restees en LOCAL :")
    for item in what_kept:
        logger.info(f"      (local) {item}")
    logger.info("")


# ==================== CONSTANTES ====================

SERVER_URL = "https://127.0.0.1:5050"
API_PASSWORD = "client_secret_password"
THRESHOLD = 0.5  # Seuil de distance pour le matching


class ZKPBiometricsApp:
    def __init__(self):
        self.main_window = tk.Tk()
        self.main_window.geometry("1200x600+250+80")
        self.main_window.title("SSI + ZKP Biometrics — Client Décentralisé")
        self.main_window.configure(bg="#1a1a2e")

        logger.info("")
        logger.info("=" * 65)
        logger.info("  CLIENT SSI + ZKP — Authentification Decentralisee")
        logger.info("  Toutes les donnees biometriques restent en LOCAL")
        logger.info("=" * 65)
        logger.info(f"  Serveur       : {SERVER_URL}")
        logger.info(f"  Seuil (tau)   : {THRESHOLD}")
        logger.info(f"  Fichier log   : client_log.txt")
        logger.info("=" * 65)
        logger.info("")

        self.wallet = SSIWallet(wallet_dir="wallet_data")
        self.jwt_token = None
        self._get_jwt()

        self._build_ui()

        self.cap = cv2.VideoCapture(0)
        self.frame = None
        self._update_camera()

    # ==================== JWT ====================

    def _get_jwt(self):
        log_header("OBTENTION TOKEN JWT")
        try:
            log_step(1, f"Connexion au serveur {SERVER_URL}/token")
            r = requests.post(f"{SERVER_URL}/token",
                              json={"password": API_PASSWORD}, verify=False, timeout=5)
            if r.status_code == 200:
                self.jwt_token = r.json().get("token")
                log_step(2, "Token JWT recu avec succes")
                log_data("Token (debut)", self.jwt_token[:40] if self.jwt_token else "None")
                log_result(True, "Connexion au serveur etablie")
            else:
                log_result(False, f"Erreur serveur : {r.text}")
        except Exception as e:
            log_result(False, f"Serveur injoignable : {e}")

    def _headers(self):
        return {"Authorization": f"Bearer {self.jwt_token}"}

    # ==================== UI ====================

    def _build_ui(self):
        # Titre
        title = tk.Label(self.main_window, text="Authentification Faciale SSI + ZKP",
                         font=("Helvetica", 18, "bold"), fg="#e94560", bg="#1a1a2e")
        title.place(x=10, y=10)

        subtitle = tk.Label(self.main_window,
                            text="Aucune donnée biométrique n'est envoyée au serveur",
                            font=("Helvetica", 10), fg="#aaaaaa", bg="#1a1a2e")
        subtitle.place(x=10, y=45)

        # Caméra
        self.webcam_label = tk.Label(self.main_window, bg="#0f3460")
        self.webcam_label.place(x=10, y=75, width=700, height=500)

        # Boutons
        btn_style = {"height": 2, "width": 25, "font": ("Helvetica", 13, "bold"),
                     "relief": "flat", "cursor": "hand2"}

        self.enroll_btn = tk.Button(self.main_window, text="Enrôlement (SSI)",
                                    bg="#0f3460", fg="white",
                                    command=self.enroll, **btn_style)
        self.enroll_btn.place(x=750, y=120)

        self.auth_btn = tk.Button(self.main_window, text="Authentification (ZKP)",
                                   bg="#e94560", fg="white",
                                   command=self.authenticate, **btn_style)
        self.auth_btn.place(x=750, y=220)

        self.wallet_btn = tk.Button(self.main_window, text="Mon Wallet SSI",
                                     bg="#16213e", fg="white",
                                     command=self.show_wallet, **btn_style)
        self.wallet_btn.place(x=750, y=320)

        # Status
        self.status_label = tk.Label(self.main_window, text="Prêt",
                                      font=("Helvetica", 10), fg="#53ff45", bg="#1a1a2e")
        self.status_label.place(x=750, y=430)

    def _set_status(self, msg, color="#53ff45"):
        self.status_label.config(text=msg, fg=color)
        self.main_window.update()

    # ==================== CAMERA ====================

    def _update_camera(self):
        ret, frame = self.cap.read()
        if ret:
            self.frame = frame
            rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            img = Image.fromarray(rgb)
            imgtk = ImageTk.PhotoImage(image=img)
            self.webcam_label.imgtk = imgtk
            self.webcam_label.configure(image=imgtk)
        self.webcam_label.after(20, self._update_camera)

    # ==================== ENRÔLEMENT ====================

    def enroll(self):
        log_header("ENROLEMENT SSI (Inscription)")
        self._set_status("Enrôlement en cours...", "#ffcc00")

        # 1. Extraction du template (LOCAL)
        log_step(1, "Capture visage + extraction template (LOCAL)")
        template = extract_template(self.frame)
        if template is None:
            log_result(False, "Aucun visage detecte dans l'image")
            messagebox.showerror("Erreur", "Aucun visage détecté.")
            self._set_status("Échec : pas de visage", "#ff4444")
            return
        log_data("Template T_u", f"vecteur {len(template)}D")
        log_data("T_u[0:5]", [round(x, 6) for x in template[:5]])

        # 2. Génération de l'identité SSI (DID + clés)
        log_step(2, "Generation de l'identite SSI")
        did = self.wallet.create_identity()
        pk_pem = self.wallet.get_public_key_pem()
        log_data("DID genere", did)
        log_data("Cle publique PK", pk_pem[:50])
        log_data("Cle privee SK", "(stockee localement, jamais envoyee)")

        # 3. Engagement : C = H(T_u || r)
        log_step(3, "Calcul de l'engagement C = SHA-256(T_u || r)")
        randomness = generate_randomness()
        commitment = compute_commitment(template, randomness)
        log_data("Alea r", f"{len(randomness)} octets (os.urandom)")
        log_data("Commitment C", commitment)

        # 4. Sauvegarde du wallet LOCALEMENT (T_u, r, SK restent sur le client)
        log_step(4, "Sauvegarde du wallet LOCAL")
        self.wallet.save_wallet(template, randomness, commitment)
        log_data("Fichier wallet", f"wallet_data/{did.split(':')[-1]}.json")
        log_data("Fichier cle", f"wallet_data/{did.split(':')[-1]}_sk.pem")

        # 5. Envoi au serveur : UNIQUEMENT {DID, C, PK} — PAS de biométrie
        log_step(5, "Envoi au serveur (AUCUNE biometrie)")
        log_privacy_notice(
            what_sent=["DID (identifiant decentralise)", "Commitment C = H(T_u || r)", "Cle publique PK"],
            what_kept=["Template T_u (128D)", "Alea r (32 octets)", "Cle privee SK"]
        )

        if not self.jwt_token:
            self._get_jwt()
        try:
            log_step(6, f"POST {SERVER_URL}/enroll")
            r = requests.post(f"{SERVER_URL}/enroll", json={
                "did": did,
                "commitment": commitment,
                "public_key_pem": pk_pem
            }, headers=self._headers(), verify=False, timeout=10)

            if r.status_code == 200:
                resp = r.json()
                # Stocker le VC dans le wallet
                vc = resp.get("verifiable_credential")
                if vc:
                    self.wallet.store_credential(vc)
                    log_step(7, "Verifiable Credential (VC) recu et stocke")
                    log_data("VC issuer", vc.get("issuer", "N/A"))
                    log_data("VC type", vc.get("type", []))
                    log_data("VC date", vc.get("issuanceDate", "N/A"))

                log_result(True, f"Enrolement reussi — DID : {did}")

                messagebox.showinfo("Enrôlement Réussi",
                    f"Identité créée !\n\n"
                    f"DID : {did}\n"
                    f"Commitment C : {commitment[:32]}...\n"
                    f"VC reçu et stocké dans le wallet.\n\n"
                    f"Données envoyées au serveur :\n"
                    f"  ✓ DID\n  ✓ Engagement C = H(T_u || r)\n  ✓ Clé publique PK\n\n"
                    f"Données restées en LOCAL :\n"
                    f"  ✓ Template T_u (128D)\n  ✓ Aléa r\n  ✓ Clé privée SK")
                self._set_status(f"Enrôlé : {did[:30]}...", "#53ff45")
            else:
                error_msg = r.json().get("error", r.text)
                log_result(False, f"Erreur serveur : {error_msg}")
                messagebox.showerror("Erreur", error_msg)
                self._set_status("Échec enrôlement", "#ff4444")
        except Exception as e:
            log_result(False, f"Serveur injoignable : {e}")
            messagebox.showerror("Erreur", f"Serveur injoignable :\n{e}")
            self._set_status("Serveur hors ligne", "#ff4444")

    # ==================== AUTHENTIFICATION ====================

    def authenticate(self):
        identities = self.wallet.list_identities()
        if not identities:
            messagebox.showerror("Erreur", "Aucune identité dans le wallet. Enrôlez-vous d'abord.")
            return

        # Fenêtre de sélection du DID
        self.auth_window = tk.Toplevel(self.main_window)
        self.auth_window.geometry("500x200")
        self.auth_window.title("Sélectionner votre identité")
        self.auth_window.configure(bg="#1a1a2e")

        tk.Label(self.auth_window, text="Choisissez votre DID :",
                 font=("Arial", 12), fg="white", bg="#1a1a2e").pack(pady=10)

        self.did_var = tk.StringVar()
        did_list = [i["did"] for i in identities]
        self.did_var.set(did_list[0])

        dropdown = tk.OptionMenu(self.auth_window, self.did_var, *did_list)
        dropdown.config(font=("Arial", 10), width=45)
        dropdown.pack(pady=5)

        tk.Button(self.auth_window, text="Authentifier avec ZKP",
                  bg="#e94560", fg="white", font=("Arial", 12, "bold"),
                  command=self._do_authenticate).pack(pady=20)

    def _do_authenticate(self):
        did = self.did_var.get()
        try:
            self.auth_window.destroy()
        except tk.TclError:
            pass

        log_header("AUTHENTIFICATION ZKP (Login)")
        self._set_status("Authentification ZKP en cours...", "#ffcc00")

        # 1. Nouvelle capture biométrique (LOCAL)
        log_step(1, "Capture nouveau visage + extraction template T'_u (LOCAL)")
        new_template = extract_template(self.frame)
        if new_template is None:
            log_result(False, "Aucun visage detecte dans l'image")
            messagebox.showerror("Erreur", "Aucun visage détecté.")
            self._set_status("Échec : pas de visage", "#ff4444")
            return
        log_data("Nouveau template T'_u", f"vecteur {len(new_template)}D")
        log_data("T'_u[0:5]", [round(x, 6) for x in new_template[:5]])

        # 2. Charger le wallet (T_u, r, SK — tout est LOCAL)
        log_step(2, "Chargement du wallet SSI LOCAL")
        wallet_data = self.wallet.load_wallet(did)
        if wallet_data is None:
            log_result(False, f"Wallet introuvable pour DID : {did}")
            messagebox.showerror("Erreur", "Wallet introuvable pour ce DID.")
            self._set_status("Wallet introuvable", "#ff4444")
            return
        log_data("DID", did)
        log_data("Wallet charge", "OK")

        stored_template = wallet_data["template"]
        randomness = wallet_data["randomness"]
        commitment = wallet_data["commitment"]
        credentials = wallet_data.get("credentials", [])

        log_data("Template stocke T_u", f"vecteur {len(stored_template)}D")
        log_data("Commitment C", commitment)
        log_data("Nombre de VC", len(credentials))

        if not credentials:
            log_result(False, "Aucun Verifiable Credential dans le wallet")
            messagebox.showerror("Erreur", "Aucun Verifiable Credential dans le wallet.")
            return

        # 3. Matching LOCAL : d(T_u, T'_u) < τ
        # 4. Génération de la preuve ZKP π (si le matching local réussit)
        log_step(3, "Matching biometrique LOCAL : d(T_u, T'_u) < tau")
        proof, distance = generate_proof(
            stored_template, new_template, randomness,
            commitment, THRESHOLD, self.wallet.sign
        )

        log_data("Distance euclidienne", f"{distance:.6f}")
        log_data("Seuil (tau)", THRESHOLD)
        log_data("Matching local", "REUSSI" if distance < THRESHOLD else "ECHOUE")

        if proof is None:
            log_result(False, f"Visage ne correspond pas (d={distance:.4f} >= tau={THRESHOLD})")
            logger.info("  [VIE PRIVEE] Aucune donnee envoyee au serveur (echec local)")
            messagebox.showwarning("Échec Local",
                f"Le visage ne correspond pas.\n"
                f"Distance : {distance:.4f} (seuil : {THRESHOLD})\n\n"
                f"Aucune preuve ZKP générée.\n"
                f"Aucune donnée envoyée au serveur.")
            self._set_status(f"Échec local (d={distance:.4f})", "#ff4444")
            return

        log_step(4, "Generation de la preuve ZKP (Fiat-Shamir)")
        log_data("Challenge", proof.get("challenge", "N/A"))
        log_data("Blinded template", proof.get("blinded_template_hash", "N/A"))
        log_data("Blinded random", proof.get("blinded_random_hash", "N/A"))
        log_data("Response 1", proof.get("response_1", "N/A"))
        log_data("Response 2", proof.get("response_2", "N/A"))
        log_data("Verification hash", proof.get("verification_hash", "N/A"))
        log_data("Timestamp", proof.get("timestamp", "N/A"))
        log_data("Signature RSA", str(proof.get("signature", ""))[:50])

        # 5. Envoi au serveur : {π, DID, VC} — PAS de biométrie
        log_step(5, "Envoi au serveur (AUCUNE biometrie)")
        log_privacy_notice(
            what_sent=["Preuve ZKP (pi) — hash aveugles, challenge, reponses, signature",
                        "DID (identifiant)", "Verifiable Credential (VC)"],
            what_kept=["Template T_u (128D)", "Nouveau template T'_u (128D)",
                        "Alea r (32 octets)", "Cle privee SK",
                        "Nonces d'aveuglement (nonce1, nonce2)"]
        )

        if not self.jwt_token:
            self._get_jwt()
        try:
            log_step(6, f"POST {SERVER_URL}/authenticate")
            r = requests.post(f"{SERVER_URL}/authenticate", json={
                "did": did,
                "proof": proof,
                "verifiable_credential": credentials[-1]
            }, headers=self._headers(), verify=False, timeout=10)

            resp = r.json()
            log_step(7, "Reponse du serveur")
            log_data("Authentifie", resp.get("authenticated", False))
            log_data("Raison", resp.get("reason", "N/A"))
            log_data("VC valide", resp.get("vc_valid", False))

            if resp.get("authenticated"):
                log_result(True, f"Authentification ACCEPTEE — DID : {did}")
                messagebox.showinfo("Authentification Réussie",
                    f"Bienvenue !\n\n"
                    f"DID : {did}\n"
                    f"Distance locale : {distance:.4f}\n"
                    f"VC valide : ✓\n"
                    f"Preuve ZKP : ✓ ACCEPTÉE\n\n"
                    f"Le serveur a vérifié votre identité\n"
                    f"SANS voir votre visage ni votre template.")
                self._set_status("Authentifié ✓", "#53ff45")
            else:
                reason = resp.get("reason", "Inconnue")
                log_result(False, f"Authentification REJETEE — {reason}")
                messagebox.showwarning("Rejeté", f"Preuve ZKP rejetée.\nRaison : {reason}")
                self._set_status("Rejeté par le serveur", "#ff4444")
        except Exception as e:
            log_result(False, f"Serveur injoignable : {e}")
            messagebox.showerror("Erreur", f"Serveur injoignable :\n{e}")
            self._set_status("Serveur hors ligne", "#ff4444")

    # ==================== WALLET ====================

    def show_wallet(self):
        log_header("CONSULTATION WALLET SSI")
        identities = self.wallet.list_identities()
        if not identities:
            log_result(False, "Wallet vide")
            messagebox.showinfo("Wallet SSI", "Votre wallet est vide.\nEnrôlez-vous pour créer une identité.")
            return

        log_step(1, f"Nombre d'identites : {len(identities)}")
        info = "=== WALLET SSI LOCAL ===\n\n"
        for idx, identity in enumerate(identities, 1):
            info += f"Identité {idx}:\n"
            info += f"  DID : {identity['did']}\n\n"
            log_data(f"Identite {idx}", identity['did'])
        info += "Données stockées localement :\n"
        info += "  • Template biométrique (T_u)\n"
        info += "  • Aléa cryptographique (r)\n"
        info += "  • Clé privée RSA (SK)\n"
        info += "  • Verifiable Credentials (VC)\n"

        log_result(True, f"{len(identities)} identite(s) dans le wallet")
        messagebox.showinfo("Wallet SSI", info)

    # ==================== RUN ====================

    def run(self):
        self.main_window.mainloop()


if __name__ == "__main__":
    app = ZKPBiometricsApp()
    app.run()
