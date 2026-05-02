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

# Ajouter le dossier parent au path pour importer common
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from biometrics import extract_template
from ssi_wallet import SSIWallet
from zkp_prover import generate_proof
from common.crypto_utils import compute_commitment, generate_randomness

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SERVER_URL = "https://127.0.0.1:5050"
API_PASSWORD = "client_secret_password"
THRESHOLD = 0.5  # Seuil de distance pour le matching


class ZKPBiometricsApp:
    def __init__(self):
        self.main_window = tk.Tk()
        self.main_window.geometry("1200x600+250+80")
        self.main_window.title("SSI + ZKP Biometrics — Client Décentralisé")
        self.main_window.configure(bg="#1a1a2e")

        self.wallet = SSIWallet(wallet_dir="wallet_data")
        self.jwt_token = None
        self._get_jwt()

        self._build_ui()

        self.cap = cv2.VideoCapture(0)
        self.frame = None
        self._update_camera()

    # ==================== JWT ====================

    def _get_jwt(self):
        try:
            r = requests.post(f"{SERVER_URL}/token",
                              json={"password": API_PASSWORD}, verify=False, timeout=5)
            if r.status_code == 200:
                self.jwt_token = r.json().get("token")
                print("[JWT] Token récupéré avec succès.")
            else:
                print("[JWT] Erreur:", r.text)
        except Exception as e:
            print(f"[JWT] Serveur injoignable: {e}")

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
        self._set_status("Enrôlement en cours...", "#ffcc00")

        # 1. Extraction du template (LOCAL)
        template = extract_template(self.frame)
        if template is None:
            messagebox.showerror("Erreur", "Aucun visage détecté.")
            self._set_status("Échec : pas de visage", "#ff4444")
            return

        # 2. Génération de l'identité SSI (DID + clés)
        did = self.wallet.create_identity()
        pk_pem = self.wallet.get_public_key_pem()

        # 3. Engagement : C = H(T_u || r)
        randomness = generate_randomness()
        commitment = compute_commitment(template, randomness)

        # 4. Sauvegarde du wallet LOCALEMENT (T_u, r, SK restent sur le client)
        self.wallet.save_wallet(template, randomness, commitment)

        # 5. Envoi au serveur : UNIQUEMENT {DID, C, PK} — PAS de biométrie
        if not self.jwt_token:
            self._get_jwt()
        try:
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
                messagebox.showerror("Erreur", r.json().get("error", r.text))
                self._set_status("Échec enrôlement", "#ff4444")
        except Exception as e:
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

        self._set_status("Authentification ZKP en cours...", "#ffcc00")

        # 1. Nouvelle capture biométrique (LOCAL)
        new_template = extract_template(self.frame)
        if new_template is None:
            messagebox.showerror("Erreur", "Aucun visage détecté.")
            self._set_status("Échec : pas de visage", "#ff4444")
            return

        # 2. Charger le wallet (T_u, r, SK — tout est LOCAL)
        wallet_data = self.wallet.load_wallet(did)
        if wallet_data is None:
            messagebox.showerror("Erreur", "Wallet introuvable pour ce DID.")
            self._set_status("Wallet introuvable", "#ff4444")
            return

        stored_template = wallet_data["template"]
        randomness = wallet_data["randomness"]
        commitment = wallet_data["commitment"]
        credentials = wallet_data.get("credentials", [])

        if not credentials:
            messagebox.showerror("Erreur", "Aucun Verifiable Credential dans le wallet.")
            return

        # 3. Matching LOCAL : d(T_u, T'_u) < τ
        # 4. Génération de la preuve ZKP π (si le matching local réussit)
        proof, distance = generate_proof(
            stored_template, new_template, randomness,
            commitment, THRESHOLD, self.wallet.sign
        )

        if proof is None:
            messagebox.showwarning("Échec Local",
                f"Le visage ne correspond pas.\n"
                f"Distance : {distance:.4f} (seuil : {THRESHOLD})\n\n"
                f"Aucune preuve ZKP générée.\n"
                f"Aucune donnée envoyée au serveur.")
            self._set_status(f"Échec local (d={distance:.4f})", "#ff4444")
            return

        # 5. Envoi au serveur : {π, DID, VC} — PAS de biométrie
        if not self.jwt_token:
            self._get_jwt()
        try:
            r = requests.post(f"{SERVER_URL}/authenticate", json={
                "did": did,
                "proof": proof,
                "verifiable_credential": credentials[-1]
            }, headers=self._headers(), verify=False, timeout=10)

            resp = r.json()
            if resp.get("authenticated"):
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
                messagebox.showwarning("Rejeté", f"Preuve ZKP rejetée.\nRaison : {reason}")
                self._set_status("Rejeté par le serveur", "#ff4444")
        except Exception as e:
            messagebox.showerror("Erreur", f"Serveur injoignable :\n{e}")
            self._set_status("Serveur hors ligne", "#ff4444")

    # ==================== WALLET ====================

    def show_wallet(self):
        identities = self.wallet.list_identities()
        if not identities:
            messagebox.showinfo("Wallet SSI", "Votre wallet est vide.\nEnrôlez-vous pour créer une identité.")
            return

        info = "=== WALLET SSI LOCAL ===\n\n"
        for idx, identity in enumerate(identities, 1):
            info += f"Identité {idx}:\n"
            info += f"  DID : {identity['did']}\n\n"
        info += "Données stockées localement :\n"
        info += "  • Template biométrique (T_u)\n"
        info += "  • Aléa cryptographique (r)\n"
        info += "  • Clé privée RSA (SK)\n"
        info += "  • Verifiable Credentials (VC)\n"

        messagebox.showinfo("Wallet SSI", info)

    # ==================== RUN ====================

    def run(self):
        self.main_window.mainloop()


if __name__ == "__main__":
    app = ZKPBiometricsApp()
    app.run()
