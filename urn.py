from __future__ import annotations
"""
urn.py
------
Fase 4 – Ricezione, registrazione e verificabilità del voto.

Implementa:
  - UrnaElettronica: verifica payload, unicità token, generazione ReceiptID,
    rilascio ricevuta crittografica, pubblicazione batch su Bulletin Board.
  - BulletinBoard: registro pubblico append-only.

Corrispondenza WP2 §2.2.4
"""

import json
import time
import uuid
from typing import Dict, List, Optional, Set

from crypto_utils import (
    generate_rsa_keypair,
    rsa_pss_sign,
    rsa_pss_verify,
    sha256,
    sha256_hex,
    MerkleTree,
    SimpleCertificate,
    load_public_key,
)
from models import VotePayload, VoteReceipt, BulletinBoardBatch
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey


# ---------------------------------------------------------------------------
# Bulletin Board  (registro pubblico read-only)
# ---------------------------------------------------------------------------

class BulletinBoard:
    """
    Registro pubblico e immutabile (append-only).
    Contiene batch con ReceiptID, Merkle Root, verbale finale.
    """

    def __init__(self):
        self._entries: List[dict] = []
        print("[BB] Bulletin Board inizializzato.")

    def publish(self, entry: dict):
        """Aggiunge una entry (append-only: non si possono modificare le precedenti)."""
        entry["bb_timestamp"] = time.time()
        self._entries.append(entry)

    def get_all_entries(self) -> List[dict]:
        return list(self._entries)

    def get_batches(self) -> List[dict]:
        return [e for e in self._entries if e.get("type") == "batch"]

    def get_final_entry(self) -> Optional[dict]:
        for e in reversed(self._entries):
            if e.get("type") == "closure":
                return e
        return None

    def get_verdict_entry(self) -> Optional[dict]:
        for e in reversed(self._entries):
            if e.get("type") == "verdict":
                return e
        return None

    def find_receipt_id(self, receipt_id_hex: str) -> Optional[dict]:
        """
        Cerca un ReceiptID tra tutti i batch pubblicati.
        Restituisce (batch_dict, proof) se trovato.
        """
        for batch_entry in self.get_batches():
            ids = batch_entry["receipt_ids"]
            if receipt_id_hex in ids:
                idx = ids.index(receipt_id_hex)
                leaves = [bytes.fromhex(r) for r in ids]
                tree = MerkleTree(leaves)
                proof = tree.get_proof(idx)
                return {
                    "batch_id": batch_entry["batch_id"],
                    "merkle_root": batch_entry["merkle_root"],
                    "proof": proof,
                }
        return None


# ---------------------------------------------------------------------------
# Urna Elettronica
# ---------------------------------------------------------------------------

class UrnaElettronica:
    """
    Urna Elettronica: riceve i payload di voto, verifica autenticità/unicità,
    genera ReceiptID, pubblica batch sul Bulletin Board.
    """

    BATCH_SIZE_MIN = 3       # Bmin: pubblica batch dopo almeno N voti
    BATCH_INTERVAL_MAX = 60  # Δmax: secondi massimi prima di forzare pubblicazione

    def __init__(
        self,
        urn_id: str,
        as_public_key: RSAPublicKey,
        bulletin_board: BulletinBoard,
        election_id: str,
    ):
        self.urn_id = urn_id
        self.as_public_key = as_public_key
        self.bulletin_board = bulletin_board
        self.election_id = election_id

        self.private_key, self.public_key = generate_rsa_keypair(key_size=2048)

        # Hash Table dei token già usati: SHA-256(T) → O(1) lookup  (INT-EM-01, INT-GDU-06)
        self._used_token_hashes: Set[str] = set()

        # Coda interna append-only dei voti accettati
        self._internal_queue: List[dict] = []

        # Batch corrente
        self._current_batch: List[dict] = []
        self._batch_open_time: float = time.time()
        self._batch_counter: int = 0

        # Stato urna
        self._closed: bool = False

        print(f"[Urna] Urna Elettronica '{urn_id}' inizializzata.")

    # ------------------------------------------------------------------
    # Ricezione del payload
    # ------------------------------------------------------------------

    def receive_vote(self, payload: VotePayload) -> Optional[VoteReceipt]:
        """
        Elabora un payload di voto:
        1. Verifica SigAS(T)
        2. Unicità token (O(1) hash table lookup)
        3. Genera ReceiptID = SHA-256(T || C)
        4. Rilascia ricevuta firmata
        5. Accoda per pubblicazione batch
        """
        if self._closed:
            print("[Urna] Urna chiusa. Payload rifiutato.")
            return None

        token_bytes = bytes.fromhex(payload.token_bytes_hex)
        ciphertext_bytes = bytes.fromhex(payload.ciphertext_hex)
        sig_as = bytes.fromhex(payload.sig_as_hex)

        # 1. Verifica SigAS(T): Verify(PK_AS, SHA-256(T), SigAS(T))
        h_t = sha256(token_bytes)
        if not rsa_pss_verify(self.as_public_key, h_t, sig_as):
            print("[Urna] Firma AS non valida. Payload rifiutato.")
            return None

        # 2. Unicità del token  (INT-EM-01, INT-GDU-06)
        h_t_hex = h_t.hex()
        if h_t_hex in self._used_token_hashes:
            print("[Urna] Token già utilizzato. Double-vote bloccato.")
            return None

        # Registra token come usato
        self._used_token_hashes.add(h_t_hex)

        # 3. ReceiptID = SHA-256(T || C)
        receipt_id_bytes = sha256(token_bytes + ciphertext_bytes)
        receipt_id_hex = receipt_id_bytes.hex()

        # 4. Rilascio ricevuta crittografica
        ts = time.time()
        # SigUE(ReceiptID || Timestamp)
        sig_data = receipt_id_bytes + str(ts).encode()
        sig_ue = rsa_pss_sign(self.private_key, sha256(sig_data))

        receipt = VoteReceipt(
            token_bytes_hex=payload.token_bytes_hex,
            ciphertext_hex=payload.ciphertext_hex,
            receipt_id_hex=receipt_id_hex,
            timestamp=ts,
            sig_ue_hex=sig_ue.hex(),
        )

        # 5. Accodamento interno (append-only)
        entry = {
            "receipt_id_hex": receipt_id_hex,
            "ciphertext_hex": payload.ciphertext_hex,
            "timestamp": ts,
        }
        self._internal_queue.append(entry)
        self._current_batch.append(entry)

        print(f"[Urna] Voto accettato. ReceiptID={receipt_id_hex[:20]}…")

        # Pubblicazione batch se soglia raggiunta
        self._maybe_publish_batch()

        return receipt

    # ------------------------------------------------------------------
    # Pubblicazione batch (ibrida: dimensione + timeout)
    # ------------------------------------------------------------------

    def _maybe_publish_batch(self, force: bool = False):
        """
        Pubblica il batch corrente se:
        - len(batch) >= Bmin  OPPURE
        - elapsed >= Δmax     OPPURE
        - force=True (chiusura urna)
        """
        elapsed = time.time() - self._batch_open_time
        if not force and len(self._current_batch) < self.BATCH_SIZE_MIN:
            return
        if not force and elapsed < self.BATCH_INTERVAL_MAX and \
                len(self._current_batch) < self.BATCH_SIZE_MIN:
            return
        if not self._current_batch:
            return

        self._publish_batch(self._current_batch)
        self._current_batch = []
        self._batch_open_time = time.time()

    def _publish_batch(self, entries: List[dict]):
        """
        Costruisce il Merkle Tree sul batch e pubblica sul BB.
        BB ← BB ∪ {batch_id, [Lj…Lj+k], R_Merkle, Timestamp_batch, SigUE}
        """
        batch_id = f"batch-{self._batch_counter:04d}"
        self._batch_counter += 1

        receipt_ids = [e["receipt_id_hex"] for e in entries]
        ciphertexts = [e["ciphertext_hex"] for e in entries]

        # Merkle Tree sulle foglie (ReceiptID come bytes)
        leaves = [bytes.fromhex(r) for r in receipt_ids]
        tree = MerkleTree(leaves)
        merkle_root = tree.root_hex

        ts = time.time()
        # SigUE sul batch
        batch_payload = json.dumps({
            "batch_id": batch_id,
            "receipt_ids": receipt_ids,
            "merkle_root": merkle_root,
            "timestamp": ts,
        }, sort_keys=True).encode()
        sig_ue = rsa_pss_sign(self.private_key, sha256(batch_payload))

        bb_entry = {
            "type": "batch",
            "batch_id": batch_id,
            "receipt_ids": receipt_ids,
            "ciphertexts": ciphertexts,
            "merkle_root": merkle_root,
            "timestamp_batch": ts,
            "sig_ue": sig_ue.hex(),
        }
        self.bulletin_board.publish(bb_entry)
        print(f"[Urna] Batch '{batch_id}' pubblicato sul BB: "
              f"{len(receipt_ids)} voti, MerkleRoot={merkle_root[:20]}…")

    # ------------------------------------------------------------------
    # Chiusura urna
    # ------------------------------------------------------------------

    def close_urn(self) -> str:
        """
        Chiude l'urna:
        1. Pubblica il batch residuo
        2. Calcola Merkle Root finale su TUTTI i ReceiptID
        3. Pubblica closure entry firmata sul BB
        Restituisce la Merkle Root finale.
        """
        self._closed = True

        # Pubblica batch residuo
        self._maybe_publish_batch(force=True)

        # Merkle Root finale su tutti i ReceiptID
        all_receipt_ids = [e["receipt_id_hex"] for e in self._internal_queue]
        if not all_receipt_ids:
            raise ValueError("[Urna] Nessun voto registrato.")

        leaves = [bytes.fromhex(r) for r in all_receipt_ids]
        tree = MerkleTree(leaves)
        r_finale = tree.root_hex

        ts_close = time.time()
        # SigUE = Sign(SK_UE, H(election_id || R_finale || timestamp))
        closure_data = sha256(
            (self.election_id + r_finale + str(ts_close)).encode()
        )
        sig_ue = rsa_pss_sign(self.private_key, closure_data)

        closure_entry = {
            "type": "closure",
            "election_id": self.election_id,
            "receipt_ids": all_receipt_ids,
            "ciphertexts": [e["ciphertext_hex"] for e in self._internal_queue],
            "merkle_root_final": r_finale,
            "timestamp_closure": ts_close,
            "sig_ue": sig_ue.hex(),
        }
        self.bulletin_board.publish(closure_entry)
        print(f"[Urna] Urna chiusa. Merkle Root finale: {r_finale[:20]}… "
              f"({len(all_receipt_ids)} voti totali)")
        return r_finale

    # ------------------------------------------------------------------
    # Verifica ricevuta (lato client)
    # ------------------------------------------------------------------

    def verify_receipt(self, receipt: VoteReceipt) -> bool:
        """
        Verifica lato client:
        1. Ricalcola ReceiptID' = SHA-256(T || C)
        2. Verifica SigUE(ReceiptID || Timestamp)
        """
        token_bytes = bytes.fromhex(receipt.token_bytes_hex)
        cipher_bytes = bytes.fromhex(receipt.ciphertext_hex)
        receipt_id_expected = sha256(token_bytes + cipher_bytes).hex()

        if receipt_id_expected != receipt.receipt_id_hex:
            print("[Verifica] ReceiptID non corrisponde!")
            return False

        sig_data = bytes.fromhex(receipt.receipt_id_hex) + str(receipt.timestamp).encode()
        ok = rsa_pss_verify(
            self.public_key,
            sha256(sig_data),
            bytes.fromhex(receipt.sig_ue_hex),
        )
        if not ok:
            print("[Verifica] Firma Urna sulla ricevuta non valida!")
        return ok
