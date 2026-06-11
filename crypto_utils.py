from __future__ import annotations
"""
crypto_utils.py
---------------
Primitive crittografiche del protocollo di voto elettronico.
Implementa: RSA-OAEP (cifratura voti), RSA-PSS (firme), SHA-256, Merkle Tree, CSPRNG.
"""

import hashlib
import json
import os
import time
from dataclasses import dataclass, field
from typing import Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateKey, RSAPublicKey,
)
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def sha256(data: bytes) -> bytes:
    """Calcola SHA-256 di data."""
    return hashlib.sha256(data).digest()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def csprng_bytes(n: int) -> bytes:
    """Genera n byte casuali crittograficamente sicuri (os.urandom)."""
    return os.urandom(n)


# ---------------------------------------------------------------------------
# RSA Key generation
# ---------------------------------------------------------------------------

def generate_rsa_keypair(key_size: int = 2048):
    """
    Genera una coppia di chiavi RSA.
    WP2 specifica 4096 bit per l'AE; usiamo 2048 come default per le demo
    (performance) e 4096 per l'Autorità Elettorale.
    """
    private_key: RSAPrivateKey = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend(),
    )
    public_key: RSAPublicKey = private_key.public_key()
    return private_key, public_key


def serialize_public_key(pub: RSAPublicKey) -> bytes:
    return pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def serialize_private_key(priv: RSAPrivateKey) -> bytes:
    return priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )


def load_public_key(pem: bytes) -> RSAPublicKey:
    return serialization.load_pem_public_key(pem, backend=default_backend())


def load_private_key(pem: bytes) -> RSAPrivateKey:
    return serialization.load_pem_private_key(pem, password=None, backend=default_backend())


# ---------------------------------------------------------------------------
# RSA-OAEP  (cifratura voti)
# ---------------------------------------------------------------------------

def rsa_oaep_encrypt(public_key: RSAPublicKey, plaintext: bytes) -> bytes:
    """
    C = RSA-OAEP_Encrypt(PK_AE, M)
    Cifratura probabilistica: ogni chiamata produce un ciphertext diverso.
    """
    return public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def rsa_oaep_decrypt(private_key: RSAPrivateKey, ciphertext: bytes) -> bytes:
    """
    M = RSA-OAEP_Decrypt(SK_AE, C)
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
# RSA-PSS  (firme digitali)
# ---------------------------------------------------------------------------

def rsa_pss_sign(private_key: RSAPrivateKey, data: bytes) -> bytes:
    """
    Sig = Sign(SK, Hash(data))   — RSA-PSS con SHA-256
    """
    return private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )


def rsa_pss_verify(public_key: RSAPublicKey, data: bytes, signature: bytes) -> bool:
    """
    Verify(PK, data, sig) → True / False
    """
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False


# ---------------------------------------------------------------------------
# Certificati X.509 semplificati  (struttura dati, non ASN.1 reale)
# ---------------------------------------------------------------------------

@dataclass
class SimpleCertificate:
    """
    Certificato X.509 semplificato per la simulazione.
    Contiene: subject_id, public_key_pem, validity, serial, signature_ca.
    """
    subject_id: str
    public_key_pem: bytes
    valid_from: float
    valid_until: float
    serial_number: str
    issuer_id: str
    signature_ca: bytes = field(default=b"", repr=False)

    def to_bytes_for_signing(self) -> bytes:
        """Serializza i campi firmabili del certificato."""
        payload = {
            "subject_id": self.subject_id,
            "public_key_pem": self.public_key_pem.hex(),
            "valid_from": self.valid_from,
            "valid_until": self.valid_until,
            "serial_number": self.serial_number,
            "issuer_id": self.issuer_id,
        }
        return json.dumps(payload, sort_keys=True).encode()

    def fingerprint(self) -> str:
        """Impronta SHA-256 del certificato (come nel WP2: Hash(CertAE))."""
        return sha256_hex(self.to_bytes_for_signing() + self.signature_ca)


# ---------------------------------------------------------------------------
# Merkle Tree
# ---------------------------------------------------------------------------

class MerkleTree:
    """
    Merkle Tree basato su SHA-256.
    Le foglie sono i ReceiptID; i nodi sono SHA-256(left || right).
    """

    def __init__(self, leaves: list[bytes]):
        if not leaves:
            raise ValueError("MerkleTree richiede almeno una foglia.")
        self.leaves: list[bytes] = leaves[:]
        self.tree: list[list[bytes]] = []
        self._build()

    def _build(self):
        layer = [sha256(leaf) for leaf in self.leaves]
        self.tree = [layer]
        while len(layer) > 1:
            if len(layer) % 2 == 1:
                layer = layer + [layer[-1]]   # duplica l'ultimo nodo (padding)
            layer = [sha256(layer[i] + layer[i + 1]) for i in range(0, len(layer), 2)]
            self.tree.append(layer)

    @property
    def root(self) -> bytes:
        return self.tree[-1][0]

    @property
    def root_hex(self) -> str:
        return self.root.hex()

    def get_proof(self, index: int) -> list[dict]:
        """
        Restituisce la Merkle Proof per la foglia all'indice dato.
        Ogni passo contiene {'sibling': hex, 'position': 'left'|'right'}.
        """
        proof = []
        idx = index
        for layer in self.tree[:-1]:
            # padding speculare
            if len(layer) % 2 == 1:
                layer = layer + [layer[-1]]
            if idx % 2 == 0:
                sibling_idx = idx + 1
                proof.append({"sibling": layer[sibling_idx].hex(), "position": "right"})
            else:
                sibling_idx = idx - 1
                proof.append({"sibling": layer[sibling_idx].hex(), "position": "left"})
            idx //= 2
        return proof

    @staticmethod
    def verify_proof(leaf: bytes, proof: list[dict], root_hex: str) -> bool:
        """
        Verifica una Merkle Proof.
        R'_Merkle == R_Merkle  →  True
        """
        current = sha256(leaf)
        for step in proof:
            sibling = bytes.fromhex(step["sibling"])
            if step["position"] == "right":
                current = sha256(current + sibling)
            else:
                current = sha256(sibling + current)
        return current.hex() == root_hex
