from __future__ import annotations
"""
authority.py
------------
Fase 5 – Scrutinio e decifrazione dei voti.

Implementa:
  - AutoritaElettorale: verifica Merkle Root, decifratura RSA-OAEP,
    validazione schede, conteggio, firma e pubblicazione verbale finale.

Corrispondenza WP2 §2.2.5
"""

import json
import time
from typing import List, Optional, Tuple

from crypto_utils import (
    rsa_oaep_decrypt,
    rsa_pss_sign,
    rsa_pss_verify,
    sha256,
    sha256_hex,
    MerkleTree,
)
from models import BallotPlaintext, FinalVerdict, get_election_config, is_valid_vote
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey


class AutoritaElettorale:
    """
    Autorità Elettorale: detiene SK_AE e la utilizza SOLO in fase di scrutinio.
    """

    def __init__(self, ae_id: str, private_key: RSAPrivateKey, public_key: RSAPublicKey):
        self.ae_id = ae_id
        self.private_key = private_key   # SK_AE: usata solo nello scrutinio
        self.public_key = public_key     # PK_AE: distribuita via certificato
        print(f"[AE] Autorità Elettorale '{ae_id}' inizializzata.")

    # ------------------------------------------------------------------
    # Verifica autenticità e coerenza quantitativa
    # ------------------------------------------------------------------

    def verify_closure(
        self,
        bulletin_board,
        urn_public_key: RSAPublicKey,
        n_tokens_issued: int,
    ) -> Optional[dict]:
        """
        1. Verifica SigUE sulla closure entry
        2. Ricalcola Merkle Root finale
        3. Verifica coerenza quantitativa: |ReceiptID| = |Ciphertexts| ≤ n_tokens
        """
        closure = bulletin_board.get_final_entry()
        if closure is None:
            print("[AE] Nessuna closure entry trovata sul BB.")
            return None

        election_id = closure["election_id"]
        r_finale = closure["merkle_root_final"]
        ts_close = closure["timestamp_closure"]
        sig_ue = bytes.fromhex(closure["sig_ue"])

        # 1. Verifica SigUE
        closure_data = sha256((election_id + r_finale + str(ts_close)).encode())
        if not rsa_pss_verify(urn_public_key, closure_data, sig_ue):
            print("[AE] Firma Urna sulla closure non valida!")
            return None
        print("[AE] Firma Urna sulla closure: valida.")

        # 2. Ricalcola Merkle Root finale
        receipt_ids = closure["receipt_ids"]
        leaves = [bytes.fromhex(r) for r in receipt_ids]
        tree = MerkleTree(leaves)
        r_computed = tree.root_hex
        if r_computed != r_finale:
            print(f"[AE] Merkle Root non corrisponde! "
                  f"Attesa={r_finale[:20]}… Calcolata={r_computed[:20]}…")
            return None
        print(f"[AE] Merkle Root finale verificata: {r_finale[:20]}…")

        # 3. Coerenza quantitativa
        n_receipts = len(receipt_ids)
        n_ciphertexts = len(closure["ciphertexts"])
        if n_receipts != n_ciphertexts:
            print(f"[AE] Incoerenza: {n_receipts} ReceiptID ≠ {n_ciphertexts} ciphertexts.")
            return None
        if n_receipts > n_tokens_issued:
            print(f"[AE] Anomalia: {n_receipts} voti > {n_tokens_issued} token emessi!")
            return None
        print(f"[AE] Coerenza quantitativa OK: {n_receipts} voti, "
              f"{n_tokens_issued} token emessi.")

        return {
            "election_id": election_id,
            "merkle_root_final": r_finale,
            "receipt_ids": receipt_ids,
            "ciphertexts": closure["ciphertexts"],
            "n_receipts": n_receipts,
            "n_tokens_issued": n_tokens_issued,
        }

    # ------------------------------------------------------------------
    # Decifrazione e validazione schede
    # ------------------------------------------------------------------

    def _decrypt_and_validate_votes(
        self, ciphertexts: List[str]
    ) -> Tuple[List[BallotPlaintext], int, int]:
        """
        Per ogni Ci: Mi = RSA-OAEP_Decrypt(SK_AE, Ci)
        Poi valida semanticamente ogni Mi.
        Restituisce (valid_ballots, n_valid, n_invalid).
        """
        valid_ballots: List[BallotPlaintext] = []
        n_invalid = 0

        for i, ct_hex in enumerate(ciphertexts):
            ct_bytes = bytes.fromhex(ct_hex)
            try:
                plaintext = rsa_oaep_decrypt(self.private_key, ct_bytes)
                ballot = BallotPlaintext.from_bytes(plaintext)

                # Validazione semantica
                if not is_valid_vote(ballot.lista, ballot.candidato):
                    print(f"[AE] Scheda #{i}: lista/candidato non validi → scartata.")
                    n_invalid += 1
                    continue

                valid_ballots.append(ballot)

            except Exception as e:
                print(f"[AE] Scheda #{i}: errore decifratura/parsing ({e}) → scartata.")
                n_invalid += 1

        return valid_ballots, len(valid_ballots), n_invalid

    # ------------------------------------------------------------------
    # Conteggio preferenze
    # ------------------------------------------------------------------

    @staticmethod
    def _count_votes(ballots: List[BallotPlaintext]) -> Tuple[dict, dict]:
        """
        Conta per lista e per candidato.
        Risultati = {Lista: count}, Preferenze = {Candidato: count}
        """
        results: dict = {}
        preferences: dict = {}

        for b in ballots:
            results[b.lista] = results.get(b.lista, 0) + 1
            if b.candidato:
                preferences[b.candidato] = preferences.get(b.candidato, 0) + 1

        # Ordina per voti decrescenti
        results = dict(sorted(results.items(), key=lambda x: -x[1]))
        preferences = dict(sorted(preferences.items(), key=lambda x: -x[1]))
        return results, preferences

    # ------------------------------------------------------------------
    # Scrutinio completo
    # ------------------------------------------------------------------

    def run_scrutiny(
        self,
        bulletin_board,
        urn_public_key: RSAPublicKey,
        n_tokens_issued: int,
    ) -> Optional[FinalVerdict]:
        """
        Esegue l'intero scrutinio:
        1. Verifica closure e coerenza
        2. Decifra e valida schede
        3. Conta preferenze
        4. Firma e pubblica verbale finale
        """
        print("\n[AE] ===== INIZIO SCRUTINIO =====")

        # 1. Verifica
        data = self.verify_closure(bulletin_board, urn_public_key, n_tokens_issued)
        if data is None:
            return None

        # 2. Decifrazione
        print(f"[AE] Decifratura di {len(data['ciphertexts'])} voti…")
        valid_ballots, n_valid, n_invalid = self._decrypt_and_validate_votes(
            data["ciphertexts"]
        )

        # 3. Conteggio
        results, preferences = self._count_votes(valid_ballots)

        # 4. Verbale finale
        ts_scrutinio = time.time()
        verdict = FinalVerdict(
            election_id=data["election_id"],
            merkle_root_final_hex=data["merkle_root_final"],
            n_receipt_ids=data["n_receipts"],
            n_votes_scrutinized=data["n_receipts"],
            n_votes_decrypted=n_valid + n_invalid,
            n_votes_valid=n_valid,
            n_votes_invalid=n_invalid,
            results_by_list=results,
            preferences_by_candidate=preferences,
            timestamp_scrutinio=ts_scrutinio,
        )

        # Firma: SigAE(Verbale) = Sign(SK_sig_AE, H(Verbale))
        verdict_bytes = verdict.to_bytes_for_signing()
        sig_ae = rsa_pss_sign(self.private_key, sha256(verdict_bytes))
        verdict.sig_ae_hex = sig_ae.hex()

        # Pubblicazione sul BB
        bulletin_board.publish({
            "type": "verdict",
            "verdict": verdict.to_dict(),
        })

        print(f"[AE] Verbale firmato e pubblicato sul BB.")
        print(f"[AE] ===== FINE SCRUTINIO =====\n")
        return verdict

    # ------------------------------------------------------------------
    # Verifica verbale (chiunque può farlo)
    # ------------------------------------------------------------------

    def verify_verdict(self, bulletin_board) -> bool:
        """
        Verifica la firma AE sul verbale pubblicato.
        Verificabilità universale (parziale).
        """
        entry = bulletin_board.get_verdict_entry()
        if entry is None:
            print("[Verifica] Nessun verbale trovato.")
            return False

        v = entry["verdict"]
        sig_ae = bytes.fromhex(v.pop("sig_ae"))

        verdict_bytes = json.dumps(v, sort_keys=True).encode()
        ok = rsa_pss_verify(self.public_key, sha256(verdict_bytes), sig_ae)
        v["sig_ae"] = sig_ae.hex()  # ripristina

        if ok:
            print("[Verifica] Firma AE sul verbale: VALIDA.")
        else:
            print("[Verifica] Firma AE sul verbale: NON VALIDA!")
        return ok
