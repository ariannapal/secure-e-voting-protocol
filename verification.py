from __future__ import annotations
"""
verification.py
---------------
Meccanismi di verifica individuale e universale.

- Verifica individuale: l'elettore controlla che il proprio ReceiptID
  sia incluso nel Merkle Tree pubblicato sul BB.
- Verifica universale (parziale): chiunque verifica firma AE sul verbale
  e coerenza della Merkle Root.

Corrispondenza WP2 §2.2.4 (verifica individuale) e §2.2.5 (verbale)
"""

from crypto_utils import MerkleTree, sha256, sha256_hex, rsa_pss_verify
from models import VoteReceipt
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey


def individual_verify(
    receipt: VoteReceipt,
    bulletin_board,
    urn_public_key: RSAPublicKey,
) -> bool:
    """
    Verifica individuale dell'elettore:
    1. Ricalcola ReceiptID' = SHA-256(T || C)  e controlla == ReceiptID
    2. Cerca il ReceiptID nel BB e ottiene la Merkle Proof
    3. Ricostruisce R'_Merkle tramite la Proof
    4. Confronta R'_Merkle con R_Merkle pubblicato
    5. Verifica SigUE sul batch
    """
    print("\n[Verifica Individuale] Avvio verifica…")

    # 1. Ricalcola ReceiptID
    token_bytes = bytes.fromhex(receipt.token_bytes_hex)
    cipher_bytes = bytes.fromhex(receipt.ciphertext_hex)
    receipt_id_computed = sha256(token_bytes + cipher_bytes).hex()

    if receipt_id_computed != receipt.receipt_id_hex:
        print("[Verifica Individuale] FALLITA: ReceiptID non corrisponde.")
        return False
    print(f"[Verifica Individuale] ReceiptID verificato: {receipt.receipt_id_hex[:20]}…")

    # 2. Cerca nel BB
    result = bulletin_board.find_receipt_id(receipt.receipt_id_hex)
    if result is None:
        print("[Verifica Individuale] FALLITA: ReceiptID non trovato nel BB.")
        return False

    proof = result["proof"]
    merkle_root_bb = result["merkle_root"]
    batch_id = result["batch_id"]
    print(f"[Verifica Individuale] ReceiptID trovato nel '{batch_id}'.")

    # 3+4. Ricostruisce R'_Merkle e confronta
    leaf = bytes.fromhex(receipt.receipt_id_hex)
    ok = MerkleTree.verify_proof(leaf, proof, merkle_root_bb)

    if ok:
        print(f"[Verifica Individuale] Merkle Proof valida. "
              f"R_Merkle={merkle_root_bb[:20]}… ✓")
    else:
        print("[Verifica Individuale] FALLITA: Merkle Proof non valida.")

    return ok


def universal_verify_verdict(bulletin_board, ae_public_key: RSAPublicKey) -> bool:
    """
    Verifica universale (parziale):
    Chiunque può verificare la firma AE sul verbale e la coerenza con
    la Merkle Root finale pubblicata dall'urna.
    """
    import json
    print("\n[Verifica Universale] Avvio verifica verbale…")

    verdict_entry = bulletin_board.get_verdict_entry()
    if verdict_entry is None:
        print("[Verifica Universale] Nessun verbale pubblicato.")
        return False

    closure_entry = bulletin_board.get_final_entry()
    if closure_entry is None:
        print("[Verifica Universale] Nessuna closure entry pubblicata.")
        return False

    v = dict(verdict_entry["verdict"])
    sig_ae = bytes.fromhex(v.pop("sig_ae"))
    verdict_bytes = json.dumps(v, sort_keys=True).encode()

    # Verifica firma AE
    ok_sig = rsa_pss_verify(ae_public_key, sha256(verdict_bytes), sig_ae)
    v["sig_ae"] = sig_ae.hex()

    if not ok_sig:
        print("[Verifica Universale] FALLITA: firma AE non valida.")
        return False
    print("[Verifica Universale] Firma AE sul verbale: VALIDA.")

    # Coerenza Merkle Root: verbale vs closure
    root_verdict = v.get("merkle_root_final")
    root_closure = closure_entry.get("merkle_root_final")
    if root_verdict != root_closure:
        print(f"[Verifica Universale] FALLITA: Merkle Root nel verbale "
              f"({root_verdict[:16]}…) ≠ quella della closure ({root_closure[:16]}…).")
        return False

    print(f"[Verifica Universale] Merkle Root coerente: {root_verdict[:20]}… ✓")
    print("[Verifica Universale] SUCCESSO.")
    return True
