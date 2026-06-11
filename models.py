from __future__ import annotations
"""
models.py
---------
Strutture dati del protocollo: scheda di voto, payload, ricevuta,
token pseudonimo, batch del Bulletin Board, verbale finale.
"""

import json
import time
from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# Elezione: liste e candidati
# ---------------------------------------------------------------------------

ELECTION_CONFIG = {
    "election_id": "UNISA-CS-2026",
    "lists": {
        "L1": {
            "name": "Azione Studentesca",
            "candidates": ["Alice Rossi", "Bruno Verdi", "Carla Neri"],
        },
        "L2": {
            "name": "Voce degli Studenti",
            "candidates": ["Davide Blu", "Elena Gialli", "Fabio Bianchi"],
        },
        "L3": {
            "name": "Futuro Unisa",
            "candidates": ["Giulia Arancio", "Hassan Viola", "Irene Grigi"],
        },
    },
}


def get_election_config() -> dict:
    return ELECTION_CONFIG


def is_valid_vote(lista: str, candidato: Optional[str]) -> bool:
    """
    Valida semanticamente la coppia (lista, candidato).
    Il candidato, se presente, deve appartenere alla lista scelta.
    """
    cfg = get_election_config()
    if lista not in cfg["lists"]:
        return False
    if candidato is not None:
        if candidato not in cfg["lists"][lista]["candidates"]:
            return False
    return True


# ---------------------------------------------------------------------------
# Scheda di voto  (plaintext, lato client)
# ---------------------------------------------------------------------------

@dataclass
class BallotPlaintext:
    """
    M = (ℓ || X || r)
    r è un salt casuale a 256 bit per garantire non-determinismo.
    """
    lista: str                   # ℓ
    candidato: Optional[str]     # X  (può essere None)
    nonce_hex: str               # r  (32 byte hex)

    def to_bytes(self) -> bytes:
        payload = {
            "lista": self.lista,
            "candidato": self.candidato,
            "nonce": self.nonce_hex,
        }
        return json.dumps(payload, sort_keys=True).encode()

    @staticmethod
    def from_bytes(data: bytes) -> "BallotPlaintext":
        d = json.loads(data)
        return BallotPlaintext(
            lista=d["lista"],
            candidato=d.get("candidato"),
            nonce_hex=d["nonce"],
        )


# ---------------------------------------------------------------------------
# Token pseudonimo
# ---------------------------------------------------------------------------

@dataclass
class PseudonymToken:
    """
    T = token pseudonimo rilasciato dall'AS.
    Contiene un valore casuale e il timestamp di emissione.
    """
    token_id: str          # UUID-like hex (32 byte random)
    issued_at: float
    session_id: str        # election_id

    def to_bytes(self) -> bytes:
        payload = {
            "token_id": self.token_id,
            "issued_at": self.issued_at,
            "session_id": self.session_id,
        }
        return json.dumps(payload, sort_keys=True).encode()

    @staticmethod
    def from_bytes(data: bytes) -> "PseudonymToken":
        d = json.loads(data)
        return PseudonymToken(**d)


# ---------------------------------------------------------------------------
# Payload di voto  (client → Urna)
# ---------------------------------------------------------------------------

@dataclass
class VotePayload:
    """
    Payload = {C, T, SigAS(T)}
    """
    ciphertext_hex: str          # C  (voto cifrato RSA-OAEP)
    token_bytes_hex: str         # T  (token pseudonimo serializzato)
    sig_as_hex: str              # SigAS(T)

    def to_dict(self) -> dict:
        return {
            "ciphertext": self.ciphertext_hex,
            "token": self.token_bytes_hex,
            "sig_as": self.sig_as_hex,
        }

    @staticmethod
    def from_dict(d: dict) -> "VotePayload":
        return VotePayload(
            ciphertext_hex=d["ciphertext"],
            token_bytes_hex=d["token"],
            sig_as_hex=d["sig_as"],
        )


# ---------------------------------------------------------------------------
# Ricevuta crittografica  (Urna → client)
# ---------------------------------------------------------------------------

@dataclass
class VoteReceipt:
    """
    Ricevuta = {T, C, ReceiptID, Timestamp, SigUE(ReceiptID || Timestamp)}
    """
    token_bytes_hex: str
    ciphertext_hex: str
    receipt_id_hex: str          # SHA-256(T || C)
    timestamp: float
    sig_ue_hex: str              # SigUE(ReceiptID || Timestamp)

    def to_dict(self) -> dict:
        return {
            "token": self.token_bytes_hex,
            "ciphertext": self.ciphertext_hex,
            "receipt_id": self.receipt_id_hex,
            "timestamp": self.timestamp,
            "sig_ue": self.sig_ue_hex,
        }

    @staticmethod
    def from_dict(d: dict) -> "VoteReceipt":
        return VoteReceipt(**d)


# ---------------------------------------------------------------------------
# Batch pubblicato sul Bulletin Board
# ---------------------------------------------------------------------------

@dataclass
class BulletinBoardBatch:
    """
    BB ← BB ∪ {batch_id, [Lj…Lj+k], R_Merkle, Timestamp_batch, SigUE}
    """
    batch_id: str
    receipt_ids: list[str]           # foglie del Merkle Tree (hex)
    ciphertexts: list[str]           # voti cifrati associati (hex)
    merkle_root_hex: str
    timestamp_batch: float
    sig_ue_hex: str                  # SigUE sui dati del batch

    def to_dict(self) -> dict:
        return {
            "batch_id": self.batch_id,
            "receipt_ids": self.receipt_ids,
            "ciphertexts": self.ciphertexts,
            "merkle_root": self.merkle_root_hex,
            "timestamp_batch": self.timestamp_batch,
            "sig_ue": self.sig_ue_hex,
        }


# ---------------------------------------------------------------------------
# Verbale finale
# ---------------------------------------------------------------------------

@dataclass
class FinalVerdict:
    """
    Verbale finale firmato dall'Autorità Elettorale.
    """
    election_id: str
    merkle_root_final_hex: str
    n_receipt_ids: int
    n_votes_scrutinized: int
    n_votes_decrypted: int
    n_votes_valid: int
    n_votes_invalid: int
    results_by_list: dict          # {lista: count}
    preferences_by_candidate: dict # {candidato: count}
    timestamp_scrutinio: float
    sig_ae_hex: str = ""

    def to_bytes_for_signing(self) -> bytes:
        d = {
            "election_id": self.election_id,
            "merkle_root_final": self.merkle_root_final_hex,
            "n_receipt_ids": self.n_receipt_ids,
            "n_votes_scrutinized": self.n_votes_scrutinized,
            "n_votes_decrypted": self.n_votes_decrypted,
            "n_votes_valid": self.n_votes_valid,
            "n_votes_invalid": self.n_votes_invalid,
            "results_by_list": self.results_by_list,
            "preferences_by_candidate": self.preferences_by_candidate,
            "timestamp_scrutinio": self.timestamp_scrutinio,
        }
        return json.dumps(d, sort_keys=True).encode()

    def to_dict(self) -> dict:
        d = json.loads(self.to_bytes_for_signing())
        d["sig_ae"] = self.sig_ae_hex
        return d
