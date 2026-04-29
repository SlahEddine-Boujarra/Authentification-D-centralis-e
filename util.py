import os
import numpy as np
import tkinter as tk
from tkinter import messagebox
import face_recognition
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Clé de simulation (Étudiant 2 - Simplification académique autorisée)
SECRET_KEY = b'0123456789abcdef0123456789abcdef' # 32 octets pour AES-256
aesgcm = AESGCM(SECRET_KEY)

def get_button(window, text, color, command, fg='white'):
    return tk.Button(window, text=text, fg=fg, bg=color, command=command,
                     height=2, width=20, font=('Helvetica bold', 20))

def get_img_label(window):
    label = tk.Label(window)
    label.grid(row=0, column=0)
    return label

def get_text_label(window, text):
    label = tk.Label(window, text=text)
    label.config(font=("sans-serif", 21), justify="left")
    return label

def get_entry_text(window):
    return tk.Text(window, height=2, width=15, font=("Arial", 32))

def msg_box(title, description):
    messagebox.showinfo(title, description)

# --- NOUVELLES FONCTIONS DE FRAGMENTATION ---

def fragment_and_encrypt(embeddings):
    """Sépare le vecteur 128D en 2 et chiffre chaque partie"""
    template = embeddings.astype(np.float32)
    frag_a = template[:64].tobytes()
    frag_b = template[64:].tobytes()
    
    nonce_a, nonce_b = os.urandom(12), os.urandom(12)
    enc_a = nonce_a + aesgcm.encrypt(nonce_a, frag_a, None)
    enc_b = nonce_b + aesgcm.encrypt(nonce_b, frag_b, None)
    return enc_a, enc_b

def decrypt_and_reconstruct(enc_a, enc_b):
    """Reconstitue le template original à partir des deux fragments"""
    dec_a = aesgcm.decrypt(enc_a[:12], enc_a[12:], None)
    dec_b = aesgcm.decrypt(enc_b[:12], enc_b[12:], None)
    
    vec_a = np.frombuffer(dec_a, dtype=np.float32)
    vec_b = np.frombuffer(dec_b, dtype=np.float32)
    return np.concatenate([vec_a, vec_b])

def recognize(img, db_path, mock_server_db):
    """Reconnaissance Zero-Knowledge : Reconstitue en RAM uniquement"""
    embeddings_unknown = face_recognition.face_encodings(img)
    if len(embeddings_unknown) == 0: return 'no_persons_found'
    
    unknown_vec = embeddings_unknown[0]
    
    # On liste les utilisateurs à partir des fragments locaux (A)
    users_found = [f.replace('_fragA.bin', '') for f in os.listdir(db_path) if f.endswith('_fragA.bin')]

    for user_id in users_found:
        # 1. Lire Fragment A (Local)
        with open(os.path.join(db_path, f"{user_id}_fragA.bin"), 'rb') as f:
            enc_a = f.read()
        
        # 2. Récupérer Fragment B (Simulation Serveur - Étudiant 3)
        enc_b = mock_server_db.get(user_id)
        
        if enc_b:
            # 3. Reconstitution temporaire (Zero-Knowledge)
            try:
                original_template = decrypt_and_reconstruct(enc_a, enc_b)
                match = face_recognition.compare_faces([original_template], unknown_vec, tolerance=0.6)[0]
                if match: return user_id
            except: continue
            
    return 'unknown_person'