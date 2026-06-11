from __future__ import annotations
"""
benchmarks.py
-------------
WP4 – Misurazioni delle prestazioni.

Misura:
  - Costo computazionale delle operazioni crittografiche
  - Dimensione dei messaggi scambiati
  - Latenza delle operazioni di verifica
  - Scalabilità al variare del numero di elettori
"""

import time
import statistics
import os
from typing import Callable, Any

from crypto_utils import (
    generate_rsa_keypair,
    rsa_oaep_encrypt,
    rsa_oaep_decrypt,
    rsa_pss_sign,
    rsa_pss_verify,
    sha256,
    MerkleTree,
    csprng_bytes,
)
from models import BallotPlaintext


def _time_op(fn: Callable, *args, reps: int = 10) -> dict:
    """Esegue fn(*args) per reps volte e restituisce statistiche (ms)."""
    times = []
    result = None
    for _ in range(reps):
        t0 = time.perf_counter()
        result = fn(*args)
        t1 = time.perf_counter()
        times.append((t1 - t0) * 1000)
    return {
        "mean_ms": round(statistics.mean(times), 3),
        "min_ms": round(min(times), 3),
        "max_ms": round(max(times), 3),
        "stdev_ms": round(statistics.stdev(times) if len(times) > 1 else 0, 3),
        "reps": reps,
        "_result": result,
    }


def run_benchmarks(key_size: int = 2048, n_voters: int = 50) -> dict:
    """
    Esegue tutti i benchmark e restituisce un dizionario con i risultati.
    """
    print("\n" + "=" * 60)
    print(f"BENCHMARK WP4  (RSA-{key_size}, {n_voters} elettori simulati)")
    print("=" * 60)

    results = {}

    # ------------------------------------------------------------------
    # 1. Generazione coppia di chiavi
    # ------------------------------------------------------------------
    print(f"\n[1] Generazione chiavi RSA-{key_size}…")
    r = _time_op(generate_rsa_keypair, key_size, reps=5)
    results["keygen"] = {k: v for k, v in r.items() if k != "_result"}
    priv, pub = r["_result"]
    print(f"    Media: {r['mean_ms']} ms  (min={r['min_ms']}, max={r['max_ms']})")

    # ------------------------------------------------------------------
    # 2. Cifratura RSA-OAEP
    # ------------------------------------------------------------------
    print("\n[2] Cifratura RSA-OAEP (voto ~64 byte)…")
    ballot = BallotPlaintext(lista="L1", candidato="Alice Rossi",
                             nonce_hex=csprng_bytes(32).hex())
    m_bytes = ballot.to_bytes()
    r = _time_op(rsa_oaep_encrypt, pub, m_bytes, reps=20)
    results["oaep_encrypt"] = {k: v for k, v in r.items() if k != "_result"}
    ciphertext = r["_result"]
    print(f"    Media: {r['mean_ms']} ms  (min={r['min_ms']}, max={r['max_ms']})")
    print(f"    Dimensione ciphertext: {len(ciphertext)} byte")
    results["oaep_encrypt"]["ciphertext_bytes"] = len(ciphertext)
    results["oaep_encrypt"]["plaintext_bytes"] = len(m_bytes)

    # ------------------------------------------------------------------
    # 3. Decifratura RSA-OAEP
    # ------------------------------------------------------------------
    print("\n[3] Decifratura RSA-OAEP…")
    r = _time_op(rsa_oaep_decrypt, priv, ciphertext, reps=20)
    results["oaep_decrypt"] = {k: v for k, v in r.items() if k != "_result"}
    print(f"    Media: {r['mean_ms']} ms  (min={r['min_ms']}, max={r['max_ms']})")

    # ------------------------------------------------------------------
    # 4. Firma RSA-PSS
    # ------------------------------------------------------------------
    print("\n[4] Firma RSA-PSS (token ~128 byte)…")
    data_to_sign = csprng_bytes(128)
    r = _time_op(rsa_pss_sign, priv, data_to_sign, reps=20)
    results["pss_sign"] = {k: v for k, v in r.items() if k != "_result"}
    signature = r["_result"]
    print(f"    Media: {r['mean_ms']} ms  (min={r['min_ms']}, max={r['max_ms']})")
    print(f"    Dimensione firma: {len(signature)} byte")
    results["pss_sign"]["signature_bytes"] = len(signature)

    # ------------------------------------------------------------------
    # 5. Verifica RSA-PSS
    # ------------------------------------------------------------------
    print("\n[5] Verifica RSA-PSS…")
    r = _time_op(rsa_pss_verify, pub, data_to_sign, signature, reps=20)
    results["pss_verify"] = {k: v for k, v in r.items() if k != "_result"}
    print(f"    Media: {r['mean_ms']} ms  (min={r['min_ms']}, max={r['max_ms']})")

    # ------------------------------------------------------------------
    # 6. SHA-256
    # ------------------------------------------------------------------
    print("\n[6] SHA-256 (256 byte)…")
    data_hash = csprng_bytes(256)
    r = _time_op(sha256, data_hash, reps=1000)
    results["sha256"] = {k: v for k, v in r.items() if k != "_result"}
    print(f"    Media: {r['mean_ms']} ms  (min={r['min_ms']}, max={r['max_ms']})")

    # ------------------------------------------------------------------
    # 7. Costruzione Merkle Tree
    # ------------------------------------------------------------------
    print(f"\n[7] Merkle Tree ({n_voters} foglie)…")
    leaves = [csprng_bytes(32) for _ in range(n_voters)]
    r = _time_op(MerkleTree, leaves, reps=10)
    results["merkle_build"] = {k: v for k, v in r.items() if k != "_result"}
    tree = r["_result"]
    print(f"    Media: {r['mean_ms']} ms  (min={r['min_ms']}, max={r['max_ms']})")
    print(f"    Merkle Root: {tree.root_hex[:20]}…")

    # ------------------------------------------------------------------
    # 8. Merkle Proof (generazione + verifica)
    # ------------------------------------------------------------------
    print("\n[8] Merkle Proof – generazione…")
    r = _time_op(tree.get_proof, 0, reps=100)
    results["merkle_proof_gen"] = {k: v for k, v in r.items() if k != "_result"}
    proof = r["_result"]
    print(f"    Media: {r['mean_ms']} ms  (profondità proof: {len(proof)} passi)")

    print("\n[8b] Merkle Proof – verifica…")
    r = _time_op(MerkleTree.verify_proof, leaves[0], proof, tree.root_hex, reps=100)
    results["merkle_proof_verify"] = {k: v for k, v in r.items() if k != "_result"}
    print(f"    Media: {r['mean_ms']} ms")

    # ------------------------------------------------------------------
    # 9. Dimensioni messaggi
    # ------------------------------------------------------------------
    print("\n[9] Dimensioni messaggi…")
    import json
    # Token pseudonimo
    from models import PseudonymToken
    token = PseudonymToken(token_id=csprng_bytes(32).hex(),
                           issued_at=time.time(), session_id="UNISA-CS-2026")
    token_size = len(token.to_bytes())

    # Payload di voto
    from models import VotePayload
    payload = VotePayload(
        ciphertext_hex=ciphertext.hex(),
        token_bytes_hex=token.to_bytes().hex(),
        sig_as_hex=signature.hex(),
    )
    payload_size = len(json.dumps(payload.to_dict()).encode())

    # Ricevuta
    from models import VoteReceipt
    receipt_id = sha256(token.to_bytes() + ciphertext).hex()
    receipt = VoteReceipt(
        token_bytes_hex=token.to_bytes().hex(),
        ciphertext_hex=ciphertext.hex(),
        receipt_id_hex=receipt_id,
        timestamp=time.time(),
        sig_ue_hex=signature.hex(),
    )
    receipt_size = len(json.dumps(receipt.to_dict()).encode())

    results["message_sizes"] = {
        "plaintext_ballot_bytes": len(m_bytes),
        "ciphertext_bytes": len(ciphertext),
        "token_bytes": token_size,
        "vote_payload_bytes": payload_size,
        "receipt_bytes": receipt_size,
        "pss_signature_bytes": len(signature),
    }
    for k, v in results["message_sizes"].items():
        print(f"    {k}: {v} byte")

    # ------------------------------------------------------------------
    # 10. Scalabilità: scrutinio su n_voters voti
    # ------------------------------------------------------------------
    print(f"\n[10] Scalabilità scrutinio ({n_voters} voti)…")
    ciphertexts_list = [rsa_oaep_encrypt(pub, ballot.to_bytes())
                        for _ in range(n_voters)]
    t0 = time.perf_counter()
    for ct in ciphertexts_list:
        rsa_oaep_decrypt(priv, ct)
    t1 = time.perf_counter()
    total_scrutiny_ms = (t1 - t0) * 1000
    results["scrutiny_scalability"] = {
        "n_voters": n_voters,
        "total_decrypt_ms": round(total_scrutiny_ms, 2),
        "avg_per_vote_ms": round(total_scrutiny_ms / n_voters, 3),
    }
    print(f"    Totale: {total_scrutiny_ms:.2f} ms "
          f"({total_scrutiny_ms/n_voters:.2f} ms/voto)")

    print("\n" + "=" * 60)
    print("BENCHMARK COMPLETATI")
    print("=" * 60)
    return results


def print_summary_table(results: dict):
    """Stampa una tabella riassuntiva dei risultati."""
    print("\n╔══════════════════════════════════════════════════════════╗")
    print("║           RIEPILOGO PRESTAZIONI  (WP4)                  ║")
    print("╠══════════════════════════════════════════════════════════╣")
    ops = [
        ("Keygen RSA",       results.get("keygen", {})),
        ("OAEP Encrypt",     results.get("oaep_encrypt", {})),
        ("OAEP Decrypt",     results.get("oaep_decrypt", {})),
        ("PSS Sign",         results.get("pss_sign", {})),
        ("PSS Verify",       results.get("pss_verify", {})),
        ("SHA-256",          results.get("sha256", {})),
        ("Merkle Build",     results.get("merkle_build", {})),
        ("Merkle Proof Gen", results.get("merkle_proof_gen", {})),
        ("Merkle Proof Vrfy",results.get("merkle_proof_verify", {})),
    ]
    print(f"║ {'Operazione':<22} {'Media (ms)':>10} {'Min':>8} {'Max':>8} ║")
    print("╠══════════════════════════════════════════════════════════╣")
    for name, r in ops:
        mean = r.get("mean_ms", 0)
        mn   = r.get("min_ms", 0)
        mx   = r.get("max_ms", 0)
        print(f"║ {name:<22} {mean:>10.3f} {mn:>8.3f} {mx:>8.3f} ║")
    print("╠══════════════════════════════════════════════════════════╣")
    ms = results.get("message_sizes", {})
    print(f"║ {'Dimensioni messaggi':<22}                           ║")
    for k, v in ms.items():
        label = k.replace("_", " ").title()
        print(f"║   {label:<34} {v:>6} byte ║")
    sc = results.get("scrutiny_scalability", {})
    if sc:
        print("╠══════════════════════════════════════════════════════════╣")
        print(f"║ Scrutinio {sc['n_voters']} voti: "
              f"{sc['total_decrypt_ms']:.1f} ms totali, "
              f"{sc['avg_per_vote_ms']:.2f} ms/voto{'':<3}║")
    print("╚══════════════════════════════════════════════════════════╝")
