from __future__ import annotations
"""
pki.py
------
Fase 1 – Setup iniziale e PKI.

Implementa la Certification Authority universitaria e il meccanismo di
generazione/certificazione delle chiavi per AE, Urna, AS.
Corrispondenza WP2 §2.2.1
"""

import time
import uuid
from typing import Dict

from crypto_utils import (
    generate_rsa_keypair,
    serialize_public_key,
    rsa_pss_sign,
    rsa_pss_verify,
    sha256_hex,
    SimpleCertificate,
)
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey


# ---------------------------------------------------------------------------
# Certification Authority
# ---------------------------------------------------------------------------

class CertificationAuthority:
    """
    CA universitaria: radice di fiducia del sistema.
    Certifica AE, Urna Elettronica, Sistema di Autenticazione.
    """

    def __init__(self, ca_id: str = "CA-UNISA"):
        self.ca_id = ca_id
        self.private_key, self.public_key = generate_rsa_keypair(key_size=2048)
        self._issued: Dict[str, SimpleCertificate] = {}
        print(f"[CA] Certification Authority '{ca_id}' inizializzata.")

    def issue_certificate(
        self,
        subject_id: str,
        subject_public_key: RSAPublicKey,
        validity_days: int = 365,
    ) -> SimpleCertificate:
        """
        Emette un certificato X.509 semplificato.
        CertAE = {IDAE, PKAE, Validità, SerialNumber, Algoritmo, Firma_CA}
        """
        now = time.time()
        cert = SimpleCertificate(
            subject_id=subject_id,
            public_key_pem=serialize_public_key(subject_public_key),
            valid_from=now,
            valid_until=now + validity_days * 86400,
            serial_number=str(uuid.uuid4()),
            issuer_id=self.ca_id,
        )
        # Firma_CA = Sign(SK_CA, Hash(payload))
        cert.signature_ca = rsa_pss_sign(self.private_key, cert.to_bytes_for_signing())
        self._issued[subject_id] = cert
        print(f"[CA] Certificato emesso per '{subject_id}' "
              f"(serial={cert.serial_number[:8]}…, "
              f"fingerprint={cert.fingerprint()[:16]}…)")
        return cert

    def verify_certificate(self, cert: SimpleCertificate) -> bool:
        """
        Verify(PK_CA, Hash(CertAE), Firma_CA)
        Controlla firma + validità temporale.
        """
        now = time.time()
        if now < cert.valid_from or now > cert.valid_until:
            print(f"[CA] Certificato '{cert.subject_id}' scaduto o non ancora valido.")
            return False
        ok = rsa_pss_verify(
            self.public_key,
            cert.to_bytes_for_signing(),
            cert.signature_ca,
        )
        if not ok:
            print(f"[CA] Firma non valida sul certificato di '{cert.subject_id}'.")
        return ok

    def get_public_key(self) -> RSAPublicKey:
        return self.public_key


# ---------------------------------------------------------------------------
# CSR semplificata  (Certificate Signing Request)
# ---------------------------------------------------------------------------

def create_csr(subject_id: str, private_key: RSAPrivateKey, public_key: RSAPublicKey) -> dict:
    """
    CSRAE = {IDAE, PKAE} firmata con SK del richiedente.
    Il richiedente dimostra il possesso della chiave privata.
    """
    from crypto_utils import serialize_public_key
    import json
    payload = json.dumps({
        "subject_id": subject_id,
        "public_key_pem": serialize_public_key(public_key).hex(),
    }, sort_keys=True).encode()

    signature = rsa_pss_sign(private_key, payload)
    return {
        "subject_id": subject_id,
        "public_key_pem": serialize_public_key(public_key).hex(),
        "self_signature_hex": signature.hex(),
    }


def verify_csr(csr: dict, public_key: RSAPublicKey) -> bool:
    """Verifica la firma auto-attestata nella CSR."""
    import json
    payload = json.dumps({
        "subject_id": csr["subject_id"],
        "public_key_pem": csr["public_key_pem"],
    }, sort_keys=True).encode()
    return rsa_pss_verify(public_key, payload, bytes.fromhex(csr["self_signature_hex"]))
