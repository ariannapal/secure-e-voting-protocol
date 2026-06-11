from __future__ import annotations
"""
client.py
---------
Fase 3 – Preparazione e invio del voto cifrato (lato client/elettore).

Implementa:
  - Verifica del certificato dell'AE
  - Costruzione del plaintext  M = (ℓ || X || r)
  - Cifratura RSA-OAEP
  - Composizione del payload {C, T, SigAS(T)}

Corrispondenza WP2 §2.2.3
"""

import os
import time
from typing import Optional

from crypto_utils import (
    rsa_oaep_encrypt,
    rsa_pss_verify,
    sha256,
    sha256_hex,
    csprng_bytes,
    SimpleCertificate,
    load_public_key,
)
from models import BallotPlaintext, VotePayload, is_valid_vote
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey


class VoterClient:
    """
    Simula il client dell'elettore (browser/app).
    Esegue: verifica certificato AE, cifratura voto, composizione payload.
    """

    def __init__(
        self,
        voter_id: str,
        ca_public_key: RSAPublicKey,
        cert_ae: SimpleCertificate,
    ):
        self.voter_id = voter_id
        self.ca_public_key = ca_public_key
        self.cert_ae = cert_ae
        self._pk_ae: Optional[RSAPublicKey] = None
        self._last_receipt = None

    # ------------------------------------------------------------------
    # Verifica del certificato dell'Autorità Elettorale
    # ------------------------------------------------------------------

    def verify_ae_certificate(self) -> bool:
        """
        Verify(PK_CA, Hash(CertAE), Firma_CA)
        Controlla identità e validità del certificato.
        WP2 §2.2.3 – "Verifica del Certificato dell'AE da parte del Client"
        """
        cert = self.cert_ae

        # 1. Verifica firma della CA
        ok = rsa_pss_verify(
            self.ca_public_key,
            cert.to_bytes_for_signing(),
            cert.signature_ca,
        )
        if not ok:
            print(f"[Client:{self.voter_id}] Firma CA non valida sul certificato AE!")
            return False

        # 2. Verifica che il soggetto sia effettivamente l'AE
        if "AE" not in cert.subject_id and "AutoritaElettorale" not in cert.subject_id:
            print(f"[Client:{self.voter_id}] Subject ID inatteso: {cert.subject_id}")
            return False

        # 3. Verifica validità temporale
        now = time.time()
        if now < cert.valid_from or now > cert.valid_until:
            print(f"[Client:{self.voter_id}] Certificato AE scaduto.")
            return False

        # Estrai PK_AE dal certificato verificato
        self._pk_ae = load_public_key(cert.public_key_pem)
        print(f"[Client:{self.voter_id}] Certificato AE verificato. "
              f"Fingerprint: {cert.fingerprint()[:20]}…")
        return True

    # ------------------------------------------------------------------
    # Preparazione e cifratura del voto
    # ------------------------------------------------------------------

    def prepare_and_encrypt_vote(
        self,
        lista: str,
        candidato: Optional[str],
        token_data: dict,
    ) -> Optional[VotePayload]:
        """
        1. Valida la scelta (semantica)
        2. Costruisce M = (ℓ || X || r)  con r ← CSPRNG(32)
        3. Cifra: C = RSA-OAEP_Encrypt(PK_AE, M)
        4. Compone Payload = {C, T, SigAS(T)}
        """
        if self._pk_ae is None:
            if not self.verify_ae_certificate():
                return None

        # Validazione semantica (INT-EM-04)
        if not is_valid_vote(lista, candidato):
            print(f"[Client:{self.voter_id}] Voto semanticamente non valido: "
                  f"lista='{lista}', candidato='{candidato}'.")
            return None

        # Costruzione M con nonce casuale (non-determinismo)
        nonce_hex = csprng_bytes(32).hex()
        ballot = BallotPlaintext(lista=lista, candidato=candidato, nonce_hex=nonce_hex)
        m_bytes = ballot.to_bytes()

        # C = RSA-OAEP_Encrypt(PK_AE, M)
        ciphertext = rsa_oaep_encrypt(self._pk_ae, m_bytes)

        payload = VotePayload(
            ciphertext_hex=ciphertext.hex(),
            token_bytes_hex=token_data["token_bytes_hex"],
            sig_as_hex=token_data["sig_as_hex"],
        )

        print(f"[Client:{self.voter_id}] Voto preparato e cifrato. "
              f"Ciphertext size: {len(ciphertext)} bytes.")
        return payload

    def store_receipt(self, receipt):
        """Salva la ricevuta per la verifica individuale successiva."""
        self._last_receipt = receipt
        print(f"[Client:{self.voter_id}] Ricevuta memorizzata. "
              f"ReceiptID={receipt.receipt_id_hex[:20]}…")

    def get_receipt(self):
        return self._last_receipt
