"""
crypto_utils.py
----------------
Funzioni di utilita' crittografiche condivise dal sistema di voto.

Implementa i primitivi descritti nel WP2:
- RSA-OAEP per la cifratura probabilistica dei voti;
- RSA-PSS per le firme digitali (autenticita' e non-ripudio);
- SHA-256 per impronte, ReceiptID e nodi del Merkle Tree;
- CSPRNG per token, challenge, nonce e seed.

Tutte le funzioni qui contenute si basano sulla libreria 'cryptography',
che internamente utilizza un CSPRNG fornito dal sistema operativo per
la generazione di chiavi, padding OAEP/PSS e numeri casuali.
"""

import os
import secrets
import hashlib
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization


# ---------------------------------------------------------------------------
# Generazione chiavi RSA
# ---------------------------------------------------------------------------

def genera_coppia_rsa(bit_size: int) -> rsa.RSAPrivateKey:
    """
    Genera una coppia di chiavi RSA (privata/pubblica) della dimensione
    richiesta. L'esponente pubblico e' fissato a 65537, valore standard
    raccomandato per RSA.

    Corrisponde, nel protocollo, a:
        (PK, SK) <- RSA_KeyGen(bit_size)
    """
    chiave_privata = rsa.generate_private_key(
        public_exponent=65537,
        key_size=bit_size,
    )
    return chiave_privata


# ---------------------------------------------------------------------------
# Cifratura / decifratura RSA-OAEP (per i voti)
# ---------------------------------------------------------------------------

def rsa_oaep_encrypt(public_key: rsa.RSAPublicKey, plaintext: bytes) -> bytes:
    """
    Cifra 'plaintext' con RSA-OAEP usando la chiave pubblica fornita.
    OAEP introduce un padding randomizzato: a parita' di messaggio in
    chiaro, il ciphertext prodotto e' (con probabilita' overwhelming)
    sempre diverso ad ogni chiamata. Questo realizza la cifratura
    probabilistica richiesta per la cifratura del voto.
    """
    return public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def rsa_oaep_decrypt(private_key: rsa.RSAPrivateKey, ciphertext: bytes) -> bytes:
    """
    Decifra un ciphertext RSA-OAEP usando la chiave privata.
    Operazione riservata all'Autorita' Elettorale in fase di scrutinio.
    """
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


# ---------------------------------------------------------------------------
# Firme digitali RSA-PSS
# ---------------------------------------------------------------------------

def rsa_pss_sign(private_key: rsa.RSAPrivateKey, message: bytes) -> bytes:
    """
    Firma 'message' con RSA-PSS, usato per garantire autenticita' e
    non-ripudio (es. AS che firma il token, Urna che firma le ricevute
    e le Merkle Root, AE che firma il verbale finale).
    """
    return private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )


def rsa_pss_verify(public_key: rsa.RSAPublicKey, message: bytes, signature: bytes) -> bool:
    """
    Verifica una firma RSA-PSS. Ritorna True se valida, False altrimenti
    (non solleva eccezioni verso il chiamante, per comodita' d'uso nella CLI).
    """
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Hashing SHA-256
# ---------------------------------------------------------------------------

def sha256(data: bytes) -> bytes:
    """Calcola l'impronta SHA-256 di 'data' e ritorna i byte digest."""
    return hashlib.sha256(data).digest()


def sha256_hex(data: bytes) -> str:
    """Come sha256(), ma ritorna la rappresentazione esadecimale (stringa)."""
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# CSPRNG: token, challenge, nonce, seed
# ---------------------------------------------------------------------------

def genera_valore_casuale(n_bytes: int = 32) -> bytes:
    """
    Genera 'n_bytes' casuali tramite CSPRNG (generatore pseudocasuale
    crittograficamente sicuro). Utilizzato per token pseudonimi,
    challenge FIDO2, nonce e seed di cifratura.

    Si appoggia a 'secrets', modulo standard Python pensato per la
    generazione di valori sicuri dal punto di vista crittografico
    (a sua volta basato su os.urandom).
    """
    return secrets.token_bytes(n_bytes)


def genera_id_esadecimale(n_bytes: int = 16) -> str:
    """Genera un identificativo casuale leggibile in formato esadecimale."""
    return secrets.token_hex(n_bytes)


# ---------------------------------------------------------------------------
# Serializzazione chiavi pubbliche (utile per "trasmetterle" tra entita')
# ---------------------------------------------------------------------------

def serializza_chiave_pubblica(public_key: rsa.RSAPublicKey) -> bytes:
    """Serializza una chiave pubblica RSA nel formato PEM (SubjectPublicKeyInfo)."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )