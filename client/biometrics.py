"""
Module Biométrique — Capture & Extraction de Template Facial

Extrait un vecteur de caractéristiques 128D à partir d'une image webcam.
Si face_recognition (dlib) n'est pas disponible, utilise une simulation
avec détection de visage OpenCV (autorisée par le cahier des charges).

Toutes les opérations biométriques restent LOCALEMENT sur le client.
"""
import numpy as np
import cv2

try:
    import face_recognition
    USE_SIMULATION = False
except ImportError:
    USE_SIMULATION = True
    print("[BIOMETRICS] face_recognition non installé → Mode SIMULATION (OpenCV Haar Cascade)")
    face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_frontalface_default.xml')


def extract_template(frame):
    """
    Extrait le template biométrique (128D) d'une image BGR.
    Retourne None si aucun visage n'est détecté.
    """
    if not USE_SIMULATION:
        rgb_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        encodings = face_recognition.face_encodings(rgb_frame)
        if len(encodings) == 0:
            return None
        return encodings[0].tolist()
    else:
        # Détection réelle d'un visage avec Haar Cascade
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        faces = face_cascade.detectMultiScale(gray, scaleFactor=1.1, minNeighbors=4, minSize=(30, 30))
        if len(faces) == 0:
            return None

        # Simulation du vecteur 128D (même base + léger bruit)
        np.random.seed(42)
        base_vector = np.random.rand(128)
        np.random.seed()
        noise = np.random.normal(0, 0.01, 128)
        return (base_vector + noise).tolist()
