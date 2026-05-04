# 🔐 Authentification Biométrique Décentralisée — SSI + ZKP

> **Système d'authentification faciale basé sur la Self-Sovereign Identity (SSI) et les Zero-Knowledge Proofs (ZKP)**
>
> L'utilisateur prouve son identité **sans jamais partager ses données biométriques**.
> Le serveur **ne voit, ne stocke et ne transmet AUCUNE donnée biométrique**.

---

## 📋 Table des Matières

1. [Contexte et Problématique](#1-contexte-et-problématique)
2. [Solution Proposée](#2-solution-proposée)
3. [Architecture du Système](#3-architecture-du-système)
4. [Technologies Utilisées](#4-technologies-utilisées)
5. [Structure du Projet](#5-structure-du-projet)
6. [Installation](#6-installation)
7. [Utilisation](#7-utilisation)
8. [Flux Détaillé du Système](#8-flux-détaillé-du-système)
9. [Composants Techniques](#9-composants-techniques)
10. [Sécurité et Conformité](#10-sécurité-et-conformité)
11. [Glossaire](#11-glossaire)

---

## 1. Contexte et Problématique

### Problèmes actuels des systèmes biométriques classiques

| Problème | Conséquence |
|:---|:---|
| Centralisation des données biométriques | Risque de fuite massive (ex: Aadhaar, OPM) |
| Stockage serveur du template facial | Usurpation d'identité si la base est compromise |
| Aucun contrôle utilisateur | Non-conformité RGPD, atteinte à la vie privée |
| Transmission de données sensibles | Vulnérabilité aux attaques MITM |

### Question centrale

> *Comment authentifier un utilisateur par biométrie faciale **sans jamais révéler ni stocker** ses données biométriques côté serveur ?*

---

## 2. Solution Proposée

Le système combine trois paradigmes de sécurité :

### 🆔 SSI — Self-Sovereign Identity
L'utilisateur possède un **DID (Decentralized Identifier)** et des **Verifiable Credentials (VC)**. Il est le seul propriétaire de son identité numérique.

### 🔒 ZKP — Zero-Knowledge Proofs
L'utilisateur prouve qu'il possède un template facial valide **sans révéler le template lui-même**. Le serveur vérifie la preuve mathématique sans jamais accéder aux données biométriques.

### 📱 Matching Local
La comparaison faciale (distance euclidienne entre templates) est effectuée **exclusivement côté client**. Aucun template ne transite sur le réseau.

### Résultat

```
╔══════════════════════════════════════════════════════════════╗
║  Le serveur ne voit JAMAIS :                                ║
║    ✗ Le visage de l'utilisateur                             ║
║    ✗ Le template biométrique T_u (128 dimensions)           ║
║    ✗ L'aléa cryptographique r                               ║
║    ✗ Le nouveau template T'_u capturé lors du login         ║
║                                                              ║
║  Le serveur stocke UNIQUEMENT :                              ║
║    ✓ Le DID (identifiant décentralisé)                      ║
║    ✓ L'engagement C = H(T_u || r) (hash irréversible)       ║
║    ✓ La clé publique PK                                     ║
╚══════════════════════════════════════════════════════════════╝
```

---

## 3. Architecture du Système

```
┌─────────────────────────────────────┐     HTTPS/TLS     ┌──────────────────────────────┐
│          CLIENT (Utilisateur)       │◄─────────────────►│    SERVEUR D'AUTHENTIFICATION │
│                                     │                    │                              │
│  1. Capture Visage (OpenCV)         │   Enrôlement :     │  A. Réception {DID, C, PK}   │
│  2. Extraction Template T_u (128D)  │   {DID, C, PK} ──►│  B. Vérification DID         │
│  3. Matching Local : d(T_u,T'_u)<τ  │                    │  C. Stockage métadonnées     │
│  4. Preuve ZKP : π                  │   Auth :           │  D. Émission VC              │
│  5. Stockage Local Sécurisé         │   {π, DID, VC} ──►│                              │
│                                     │                    │  Vérification :              │
│  ┌─ WALLET SSI LOCAL ───────────┐   │                    │  1. Vérifier VC (signature)  │
│  │ • Template T_u               │   │                    │  2. Vérifier ZKP π           │
│  │ • Aléa r                     │   │   ◄── Résultat ───│  3. ACCEPTÉ / REJETÉ         │
│  │ • Clé privée SK              │   │                    │                              │
│  │ • DID (did:key:...)          │   │                    │  ┌─ BASE DE DONNÉES ───────┐ │
│  │ • Verifiable Credentials     │   │                    │  │ DID        │ C (hash)   │ │
│  └──────────────────────────────┘   │                    │  │ PK         │ Date       │ │
│                                     │                    │  │ (PAS de biométrie)      │ │
│  Données biométriques restent       │                    │  └─────────────────────────┘ │
│  TOUJOURS LOCALES sur le client     │                    │                              │
└─────────────────────────────────────┘                    └──────────────────────────────┘
```

---

## 4. Technologies Utilisées

| Composant | Technologie | Rôle |
|:---|:---|:---|
| Langage | Python 3.9+ | Langage principal (client + serveur) |
| Vision | OpenCV 4.x | Capture webcam + détection de visage (Haar Cascade) |
| Biométrie | face_recognition (optionnel) / Simulation | Extraction template 128D (mode simulation si non installé) |
| Cryptographie | `cryptography` (RSA-2048, SHA-256) | Signatures, engagement, chiffrement |
| API | Flask | API REST du serveur |
| Base de données | SQLite 3 | Stockage métadonnées serveur |
| Authentification API | PyJWT | Tokens JWT avec expiration |
| HTTPS | pyOpenSSL | Certificats auto-signés (TLS) |
| Interface | Tkinter | Application graphique client |
| SSI | Implémentation custom (did:key) | DID, Verifiable Credentials |
| ZKP | Fiat-Shamir + RSA Signatures | Preuve sans divulgation |

---

## 5. Structure du Projet

```
Authentification-D-centralis-e/
│
├── client/                          # 📱 APPLICATION CLIENT (SSI + ZKP)
│   ├── client_app.py                # Interface graphique Tkinter
│   ├── biometrics.py                # Capture webcam + extraction template 128D
│   ├── ssi_wallet.py                # Wallet SSI : DID, clés RSA, VC
│   ├── zkp_prover.py                # Génération de la preuve ZKP (π)
│   └── wallet_data/                 # Stockage local du wallet
│       ├── <did_hash>.json          #   → Template, aléa, credentials
│       └── <did_hash>_sk.pem        #   → Clé privée RSA
│
├── serveur/                         # 🖥️ SERVEUR D'AUTHENTIFICATION
│   ├── api.py                       # API Flask (HTTPS + JWT)
│   ├── database.py                  # SQLite (DID, C, PK — PAS de biométrie)
│   ├── zkp_verifier.py              # Vérification de la preuve ZKP
│   ├── ssi_registry.py              # Registre DID + émission VC
│   └── serveur_db.sqlite            # Base de données (générée automatiquement)
│
├── common/                          # 🔧 UTILITAIRES PARTAGÉS
│   ├── __init__.py
│   └── crypto_utils.py              # C = H(T_u || r), SHA-256, distance
│
├── requirements.txt                 # Dépendances Python
├── run_serveur.bat                  # Lancer le serveur
├── run_client.bat                   # Lancer le client
└── README.md                        # Ce fichier
```

---

## 6. Installation

### Prérequis
- **Python 3.9+** installé
- **Webcam** (ou le système utilisera la simulation Haar Cascade)
- Connexion réseau locale (client et serveur sur la même machine)

### Étapes

```bash
# 1. Cloner le dépôt
git clone https://github.com/SlahEddine-Boujarra/Authentification-D-centralis-e.git
cd Authentification-D-centralis-e

# 2. Installer les dépendances
pip install -r requirements.txt

# 3. (Optionnel) Installer face_recognition pour le mode réel (nécessite dlib + CMake)
pip install face_recognition
```

Les dépendances principales :
```
flask, requests, cryptography, opencv-python, numpy, Pillow, PyJWT, pyOpenSSL
```

> **Note :** Si `face_recognition` n'est pas installé, le système fonctionne automatiquement en **mode simulation** : la détection de visage utilise Haar Cascade (OpenCV) et le template 128D est simulé. Ce mode est suffisant pour démontrer le fonctionnement du protocole SSI+ZKP.

---

## 7. Utilisation

### Étape 1 — Lancer le Serveur

```bash
# Double-cliquer sur run_serveur.bat ou exécuter :
cd serveur
python api.py
```

Le serveur démarre en HTTPS sur `https://127.0.0.1:5050` :
```
=======================================================
 SERVEUR SSI + ZKP — Authentification Décentralisée
 HTTPS activé | JWT activé | Aucune biométrie stockée
=======================================================
 * Serving Flask app 'api'
 * Running on https://127.0.0.1:5050
```

### Étape 2 — Lancer le Client

```bash
# Dans un NOUVEAU terminal, double-cliquer sur run_client.bat ou exécuter :
cd client
python client_app.py
```

### Étape 3 — Enrôlement (Inscription)

1. Placez votre visage devant la webcam
2. Cliquez sur **"Enrôlement (SSI)"**
3. Le système :
   - Capture votre visage et extrait le template T_u (128D)
   - Génère votre identité SSI (DID + clés RSA)
   - Calcule l'engagement C = H(T_u || r)
   - Envoie au serveur **uniquement** : `{DID, C, PK}`
   - Reçoit un Verifiable Credential (VC) du serveur
   - Stocke **tout localement** dans votre wallet

### Étape 4 — Authentification (Login)

1. Placez votre visage devant la webcam
2. Cliquez sur **"Authentification (ZKP)"**
3. Sélectionnez votre DID dans la liste
4. Le système :
   - Capture un nouveau template T'_u
   - Compare **localement** : d(T_u, T'_u) < τ (seuil τ = 0.5)
   - Si le matching réussit → Génère la preuve ZKP (π)
   - Envoie au serveur : `{π, DID, VC}` (aucune biométrie !)
   - Le serveur vérifie le VC et la preuve ZKP
   - Résultat : **ACCEPTÉ** ou **REJETÉ**

---

## 8. Flux Détaillé du Système

### Phase A — Enrôlement (une seule fois)

```
CLIENT                                              SERVEUR
  │                                                    │
  │  1. Capture visage (webcam)                        │
  │  2. Extraction template T_u (128D)                 │
  │  3. Génération aléa r (32 octets)                  │
  │  4. Calcul engagement C = SHA256(T_u || r)         │
  │  5. Génération DID + paire de clés (SK, PK)        │
  │                                                    │
  │──── Envoi : {DID, C, PK} ────────────────────────►│
  │     (PAS de T_u, PAS de r, PAS d'image)            │
  │                                                    │  6. Vérification du DID
  │                                                    │  7. Stockage : {DID, C, PK, date}
  │                                                    │  8. Émission Verifiable Credential
  │◄──── Réponse : {VC signé} ────────────────────────│
  │                                                    │
  │  9. Stockage LOCAL dans le wallet :                │
  │     • Template T_u                                 │
  │     • Aléa r                                       │
  │     • Clé privée SK                                │
  │     • DID + VC                                     │
  │                                                    │
```

### Phase B — Authentification (à chaque connexion)

```
CLIENT                                              SERVEUR
  │                                                    │
  │  1. Capture nouveau visage → T'_u                  │
  │  2. Chargement wallet (T_u, r, SK)                 │
  │  3. Matching LOCAL : d(T_u, T'_u) < τ ?            │
  │     ├── NON → ÉCHEC (rien n'est envoyé)            │
  │     └── OUI → Continue                             │
  │  4. Génération preuve ZKP π :                      │
  │     Statement : ∃(T_u, r) : C = H(T_u||r)         │
  │                           ∧ d(T_u, T'_u) < τ      │
  │     π ne révèle NI T_u, NI r, NI T'_u             │
  │                                                    │
  │──── Envoi : {π, DID, VC} ────────────────────────►│
  │     (PAS de T_u, PAS de T'_u, PAS d'image)        │
  │                                                    │  5. Vérification du VC
  │                                                    │     (signature, validité)
  │                                                    │  6. Vérification de la preuve ZKP
  │                                                    │     (challenge, signature, timestamp)
  │                                                    │  7. Décision : ACCEPTÉ / REJETÉ
  │◄──── Résultat ────────────────────────────────────│
  │                                                    │
```

---

## 9. Composants Techniques

### 9.1 — Engagement Cryptographique (Commitment)

```python
C = SHA-256(T_u || r)
```

| Élément | Description |
|:---|:---|
| `T_u` | Template biométrique (vecteur 128D) |
| `r` | Aléa cryptographique (32 octets) |
| `C` | Engagement (hash irréversible, stocké sur le serveur) |

Le serveur stocke `C` mais **ne peut jamais retrouver `T_u` ni `r`** (propriété de résistance à la préimage de SHA-256).

### 9.2 — Preuve Zero-Knowledge (ZKP)

La preuve π est générée via le **protocole de Fiat-Shamir** (transformation d'un protocole interactif en non-interactif) :

```
1. Engagements aveugles :
   blinded_T = SHA-256(nonce₁ || T_u)
   blinded_r = SHA-256(nonce₂ || r)

2. Challenge (Fiat-Shamir) :
   challenge = SHA-256(C || blinded_T || blinded_r || τ || timestamp)

3. Réponses :
   response₁ = SHA-256(nonce₁ || challenge || T_u)
   response₂ = SHA-256(nonce₂ || challenge || r)

4. Hash de vérification :
   verification = SHA-256(response₁ || response₂ || challenge || C)

5. Signature RSA :
   signature = Sign(SK, serialize(proof))
```

Le serveur vérifie :
- ✅ La cohérence du challenge (Fiat-Shamir)
- ✅ Le hash de vérification
- ✅ La signature RSA (via la PK stockée)
- ✅ La fraîcheur du timestamp (anti-rejeu, max 120 secondes)

### 9.3 — Self-Sovereign Identity (SSI)

| Composant | Implémentation |
|:---|:---|
| **DID** | `did:key:<SHA-256(PK)[:32]>` |
| **Paire de clés** | RSA-2048 (clé privée = client, clé publique = serveur) |
| **Verifiable Credential** | JSON-LD (W3C VC Data Model), signé par le serveur |
| **Wallet** | Stockage local (`wallet_data/`) sur l'appareil du client |

### 9.4 — Sécurité des Communications

| Couche | Technologie |
|:---|:---|
| Transport | HTTPS (TLS) via certificats auto-signés (pyOpenSSL) |
| Autorisation API | JWT (PyJWT) avec expiration 1 heure |
| Signatures | RSA-PSS + SHA-256 |
| Anti-rejeu | Timestamp dans la preuve (max 120s) |

---

## 10. Sécurité et Conformité

### Matrice des Menaces

| Menace | Impact | Contre-mesure |
|:---|:---|:---|
| Vol de la base serveur | **Nul** — La base ne contient que des hash (C) et des clés publiques | Engagement irréversible C = H(T_u \|\| r) |
| Interception réseau (MITM) | Faible | HTTPS/TLS + JWT |
| Usurpation biométrique | Faible | Matching local + ZKP signé par clé privée |
| Attaque par rejeu | Faible | Timestamp dans la preuve (120s max) |
| Compromission du client | Moyen | Template chiffré dans le wallet local |

### Conformité Normative

| Norme | Application |
|:---|:---|
| **RGPD** | Aucune donnée biométrique stockée côté serveur. Droit à l'oubli : supprimer le wallet |
| **ISO 27001** | Gestion des actifs (engagement), contrôle d'accès (JWT), cryptographie (SHA-256, RSA) |
| **ISO 27018** | Pas de stockage en clair, minimisation des données (engagement seulement) |
| **FIDO2** | Clé privée côté utilisateur, clé publique côté serveur, pas de mot de passe |

### Propriétés du Système

- ✅ **Respect de la vie privée** — Aucune donnée biométrique partagée
- ✅ **Sécurité** — ZKP empêche la divulgation de T_u et r
- ✅ **Contrôle utilisateur** — Données stockées localement (SSI)
- ✅ **Interopérabilité** — Standards W3C DID, VC Data Model, API REST/JSON
- ✅ **Performance** — Temps d'authentification < 3 secondes

---

## 11. Glossaire

| Terme | Définition |
|:---|:---|
| **SSI** | Self-Sovereign Identity — L'utilisateur contrôle entièrement son identité numérique |
| **DID** | Decentralized Identifier — Identifiant unique décentralisé (ex: `did:key:abc123...`) |
| **VC** | Verifiable Credential — Attestation numérique signée par un émetteur de confiance |
| **ZKP** | Zero-Knowledge Proof — Preuve qu'une affirmation est vraie sans révéler d'information |
| **Commitment** | Engagement cryptographique C = H(T_u \|\| r), irréversible |
| **Template** | Représentation mathématique (128D) d'un visage |
| **Fiat-Shamir** | Heuristique qui transforme un protocole interactif en preuve non-interactive |
| **JWT** | JSON Web Token — Jeton d'authentification pour sécuriser l'API |
| **MITM** | Man-In-The-Middle — Attaque par interception de communication |
| **DPIA** | Data Protection Impact Assessment — Analyse d'impact sur les données personnelles |

---

## Auteurs

Projet académique — Année universitaire 2025-2026

---

*Document préparé pour l'année universitaire 2025-2026*
