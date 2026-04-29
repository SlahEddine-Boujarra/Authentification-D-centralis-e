import numpy as np
import tkinter as tk
from tkinter import messagebox
import os
import face_recognition

# ================= UI HELPERS =================

def get_button(window, text, color, command, fg='white'):
    return tk.Button(
        window, text=text, fg=fg, bg=color,
        command=command, height=2, width=20,
        font=('Helvetica bold', 20)
    )

def get_img_label(window):
    label = tk.Label(window)
    label.grid(row=0, column=0)
    return label

def get_entry_text(window):
    return tk.Text(window, height=2, width=15, font=("Arial", 32))

def msg_box(title, description):
    messagebox.showinfo(title, description)


# ================= RCPD CORE =================

# Secret transformation key (simulate system secret)
KEY = np.random.RandomState(42).randn(128, 128)


def transform_embedding(embedding):
    """Cancelable biometric transformation (RCPD core)"""
    embedding = np.array(embedding, dtype=np.float32)
    return np.dot(embedding, KEY)


def compare_templates(t1, t2):
    """Distance-based matching"""
    return np.linalg.norm(t1 - t2)


def recognize(img, db_dir):
    """RCPD recognition (NO decrypt, NO reconstruction)"""

    encodings = face_recognition.face_encodings(img)
    if len(encodings) == 0:
        return "no_persons_found"

    unknown = transform_embedding(encodings[0])

    for file in os.listdir(db_dir):
        if file.endswith(".npy"):
            stored = np.load(os.path.join(db_dir, file))

            dist = compare_templates(stored, unknown)

            if dist < 5.0:  # threshold (adjustable)
                return file.replace(".npy", "")

    return "unknown_person"