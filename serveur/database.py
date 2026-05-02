"""
Base de données du serveur d'authentification.

Stocke UNIQUEMENT des métadonnées (aucune donnée biométrique) :
  - DID de l'utilisateur
  - Engagement C = H(T_u || r)
  - Clé publique PK
  - Date d'enrôlement
"""
import sqlite3
import time

DB_PATH = 'serveur_db.sqlite'


def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS enrollments (
            did TEXT PRIMARY KEY,
            commitment TEXT NOT NULL,
            public_key_pem TEXT NOT NULL,
            enrolled_at TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()


def save_enrollment(did, commitment, public_key_pem):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        'REPLACE INTO enrollments (did, commitment, public_key_pem, enrolled_at) VALUES (?, ?, ?, ?)',
        (did, commitment, public_key_pem, time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    )
    conn.commit()
    conn.close()


def get_enrollment(did):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT did, commitment, public_key_pem, enrolled_at FROM enrollments WHERE did = ?', (did,))
    row = c.fetchone()
    conn.close()
    if row:
        return {
            "did": row[0],
            "commitment": row[1],
            "public_key_pem": row[2],
            "enrolled_at": row[3]
        }
    return None


def list_enrollments():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT did, enrolled_at FROM enrollments')
    rows = c.fetchall()
    conn.close()
    return [{"did": r[0], "enrolled_at": r[1]} for r in rows]
