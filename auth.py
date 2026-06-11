from __future__ import annotations
"""
auth.py
-------
Fase 2 – Autenticazione e rilascio del token pseudonimo.

Implementa:
  - IdentityProvider  (simula FIDO2 + OIDC)
  - AuthenticationSystem  (AS: verifica diritti, rilascia token pseudonimo firmato)

"""

import json
import os
import time
import uuid
from typing import Dict, Optional

from crypto_utils import (
    generate_rsa_keypair,
    rsa_pss_sign,
    rsa_pss_verify,
    sha256,
    sha256_hex,
    csprng_bytes,
    SimpleCertificate,
)
from models import PseudonymToken
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey


# ---------------------------------------------------------------------------
# Identity Provider  (simula OIDC + FIDO2)
# ---------------------------------------------------------------------------

class IdentityProvider:
    """
    IdP istituzionale universitario.
    Autentica lo studente tramite credenziali + FIDO2 (simulato).
    Emette un ID Token firmato con i dati di identità dello studente.
    """

    def __init__(self, idp_id: str, ca_cert: SimpleCertificate):
        self.idp_id = idp_id
        # Generazione della coppia di chiavi RSA a 2048 bit per la firma degli ID Token.
        self.private_key, self.public_key = generate_rsa_keypair(key_size=2048)
        self.ca_cert = ca_cert        # per la verifica lato AS
        # Registro studenti: {student_id: (password_hash, fido2_pubkey_pem)}
        self._registry: Dict[str, dict] = {}
        print(f"[IdP] Identity Provider '{idp_id}' inizializzato.")

    def register_student(self, student_id: str, password: str):
        """Registra uno studente (setup pre-elezione)."""
        import hashlib
        # Viene memorizzato solo l'hash SHA-256 della password per motivi di sicurezza.
        pw_hash = hashlib.sha256(password.encode()).hexdigest()
        # FIDO2: genera coppia di chiavi per lo studente (simulata)
        fido2_priv, fido2_pub = generate_rsa_keypair(key_size=2048)
        from crypto_utils import serialize_public_key, serialize_private_key

        # Archiviazione della chiave pubblica FIDO2 e dell'hash della password.
        self._registry[student_id] = {
            "pw_hash": pw_hash,
            "fido2_pub_pem": serialize_public_key(fido2_pub).hex(),
            "fido2_priv_pem": serialize_private_key(fido2_priv).hex(),
        }
        return fido2_priv  # consegnato al dispositivo dello studente

    # --- FIDO2 simulation ---

    def issue_challenge(self) -> bytes:
        """
        Passo 1 del protocollo FIDO2: generazione di una challenge (nonce) 
        tramite un generatore di numeri pseudo-casuali crittograficamente sicuro (CSPRNG).
        """

        """challenge ← CSPRNG (passo 1 FIDO2)."""
        return csprng_bytes(32)

    def authenticate_student(
        self,
        student_id: str,
        password: str,
        challenge: bytes,
        fido2_response: bytes,   # firma challenge con SK_studente
    ) -> Optional[dict]:
        """
        Verifica password + risposta FIDO2.
        Restituisce un ID Token firmato se tutto è valido.
        """
        import hashlib
        from crypto_utils import load_public_key

        # Verifica dell'esistenza dell'account.
        if student_id not in self._registry:
            print(f"[IdP] Studente '{student_id}' non trovato.")
            return None

        rec = self._registry[student_id]

        # Verifica della password tramite confronto degli hash.
        if hashlib.sha256(password.encode()).hexdigest() != rec["pw_hash"]:
            print(f"[IdP] Password errata per '{student_id}'.")
            return None

        # Verifica FIDO2: controllo della validità della firma della challenge.
        # Operazione: Verify(PK_studente, challenge, firma)
        fido2_pub = load_public_key(bytes.fromhex(rec["fido2_pub_pem"]))
        if not rsa_pss_verify(fido2_pub, challenge, fido2_response):
            print(f"[IdP] Verifica FIDO2 fallita per '{student_id}'.")
            return None

        # Creazione del payload per l'ID Token, contenente informazioni sull'identità, 
        # sull'emittente e la scadenza temporale.
        id_token = {
            "iss": self.idp_id,
            "sub": student_id,
            "iat": time.time(),
            "exp": time.time() + 300,   # 5 minuti
            "jti": str(uuid.uuid4()),
        }

        # Serializzazione in formato JSON e apposizione della firma RSA-PSS.
        token_bytes = json.dumps(id_token, sort_keys=True).encode()
        signature = rsa_pss_sign(self.private_key, token_bytes)
        print(f"[IdP] ID Token emesso per '{student_id}'.")
        return {
            "id_token": id_token,
            "token_bytes_hex": token_bytes.hex(),
            "signature_hex": signature.hex(),
        }


# ---------------------------------------------------------------------------
# Simulatore del dispositivo studente (FIDO2 side)
# ---------------------------------------------------------------------------

def student_fido2_respond(fido2_priv_key: RSAPrivateKey, challenge: bytes) -> bytes:
    """
    Simula l'azione dell'autenticatore hardware/software dello studente.
    Applica la firma RSA-PSS alla challenge inviata dall'IdP:
    Firma = Sign(SK_studente, challenge)
    """
    return rsa_pss_sign(fido2_priv_key, challenge)

# ---------------------------------------------------------------------------
# Authentication System
# ---------------------------------------------------------------------------

class AuthenticationSystem:
    """
    AS: verifica l'ID Token dell'IdP, controlla il diritto di voto,
    impedisce il double-token, rilascia il token pseudonimo firmato T.

    Registro_Elettori = {student_id, avente_diritto, token_rilasciato}
    """

    def __init__(self, as_id: str, idp_public_key: RSAPublicKey, election_id: str):
        self.as_id = as_id
        self.idp_public_key = idp_public_key
        self.election_id = election_id
        self.private_key, self.public_key = generate_rsa_keypair(key_size=2048)
        # {student_id: {"avente_diritto": bool, "token_rilasciato": bool}}
        self._voter_registry: Dict[str, dict] = {}
        # Contatore token emessi (per coerenza quantitativa in fase 5)
        self._tokens_issued: int = 0
        print(f"[AS] Authentication System '{as_id}' inizializzato.")

    def register_eligible_voter(self, student_id: str):
        """Iscrive uno studente come avente diritto."""
        self._voter_registry[student_id] = {
            "avente_diritto": True,
            "token_rilasciato": False,
        }

    def process_authentication(
        self,
        id_token_data: dict,   # output di IdentityProvider.authenticate_student
    ) -> Optional[dict]:
        """
        1. Verifica ID Token: Verify(PK_IdP, token_bytes, sig)
        2. Controlla diritto di voto e unicità
        3. Genera token pseudonimo T e lo firma: SigAS(T) = Sign(SK_AS, SHA-256(T))
        """
        if id_token_data is None:
            return None

        token_bytes = bytes.fromhex(id_token_data["token_bytes_hex"])
        sig = bytes.fromhex(id_token_data["signature_hex"])
        id_token = id_token_data["id_token"]

        # Step: Verify(PK_IdP, ID_Token)
        if not rsa_pss_verify(self.idp_public_key, token_bytes, sig):
            print("[AS] ID Token: firma non valida.")
            return None

        # Verifica scadenza
        if time.time() > id_token.get("exp", 0):
            print("[AS] ID Token scaduto.")
            return None

        student_id = id_token["sub"]

        # Controllo aventi diritto
        rec = self._voter_registry.get(student_id)
        if rec is None or not rec["avente_diritto"]:
            print(f"[AS] '{student_id}' non è un avente diritto.")
            return None

        # Unicità: token già rilasciato?  (INT-EM-01, INT-ASM-02)
        if rec["token_rilasciato"]:
            print(f"[AS] Token già rilasciato per '{student_id}'. Double-vote bloccato.")
            return None

        # Genera token pseudonimo T
        token = PseudonymToken(
            token_id=csprng_bytes(32).hex(),
            issued_at=time.time(),
            session_id=self.election_id,
        )
        token_bytes_t = token.to_bytes()

        # SigAS(T) = Sign(SK_AS, SHA-256(T))
        h_t = sha256(token_bytes_t)
        sig_as = rsa_pss_sign(self.private_key, h_t)

        # Aggiorna registro
        self._voter_registry[student_id]["token_rilasciato"] = True
        self._tokens_issued += 1

        print(f"[AS] Token pseudonimo emesso per '{student_id}' "
              f"(token_id={token.token_id[:12]}…).")
        return {
            "token_bytes_hex": token_bytes_t.hex(),
            "sig_as_hex": sig_as.hex(),
        }

    @property
    def tokens_issued_count(self) -> int:
        """
        Espone il conteggio totale dei token validi emessi.
        Necessario all'Autorità Elettorale per la verifica di coerenza quantitativa.
        """
        return self._tokens_issued
