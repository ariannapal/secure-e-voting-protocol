from __future__ import annotations
"""
main.py
-------
WP4 – Simulazione end-to-end del protocollo di voto elettronico universitario.

Esegue in sequenza:
  Fase 1: Setup PKI
  Fase 2: Autenticazione e rilascio token
  Fase 3: Preparazione e cifratura voti
  Fase 4: Ricezione, registrazione, pubblicazione BB
  Fase 5: Scrutinio, decifrazione, verbale

Poi esegue i benchmark di prestazione (WP4).
"""

import sys
import time

# ---------------------------------------------------------------------------
# Importa tutti i moduli del sistema
# ---------------------------------------------------------------------------
from crypto_utils import generate_rsa_keypair
from pki import CertificationAuthority, create_csr, verify_csr
from auth import IdentityProvider, AuthenticationSystem, student_fido2_respond
from client import VoterClient
from urn import UrnaElettronica, BulletinBoard
from authority import AutoritaElettorale
from verification import individual_verify, universal_verify_verdict
from benchmarks import run_benchmarks, print_summary_table
from models import get_election_config


# ---------------------------------------------------------------------------
# Dati di test: elettori e schede
# ---------------------------------------------------------------------------

VOTERS = [
    {"id": "IE001", "password": "pass_alice",  "lista": "L1", "candidato": "Alice Rossi"},
    {"id": "IE002", "password": "pass_bob",    "lista": "L2", "candidato": "Davide Blu"},
    {"id": "IE003", "password": "pass_carla",  "lista": "L1", "candidato": "Bruno Verdi"},
    {"id": "IE004", "password": "pass_davide", "lista": "L3", "candidato": None},
    {"id": "IE005", "password": "pass_elena",  "lista": "L2", "candidato": "Elena Gialli"},
    {"id": "IE006", "password": "pass_fabio",  "lista": "L1", "candidato": "Alice Rossi"},
]


def separator(title: str):
    print(f"\n{'─' * 60}")
    print(f"  {title}")
    print(f"{'─' * 60}")


# ---------------------------------------------------------------------------
# SIMULAZIONE PRINCIPALE
# ---------------------------------------------------------------------------

def run_full_simulation(verbose: bool = True):
    t_start = time.perf_counter()

    # ======================================================================
    # FASE 1 – Setup PKI
    # ======================================================================
    separator("FASE 1 – Setup PKI")

    ca = CertificationAuthority("CA-UNISA")

    # Genera coppia chiavi AE (4096 bit come da WP2)
    print("[Setup] Generazione chiavi AE (RSA-4096)…")
    ae_priv, ae_pub = generate_rsa_keypair(key_size=4096)

    # CSR e certificazione AE
    csr_ae = create_csr("AutoritaElettorale-UNISA", ae_priv, ae_pub)
    assert verify_csr(csr_ae, ae_pub), "CSR AE non valida!"
    cert_ae = ca.issue_certificate("AutoritaElettorale-UNISA", ae_pub)

    # Certificazione Urna Elettronica
    ue_priv_tmp, ue_pub_tmp = generate_rsa_keypair(key_size=2048)
    cert_ue = ca.issue_certificate("UrnaElettronica-UNISA", ue_pub_tmp)

    # Certificazione AS
    as_priv_tmp, as_pub_tmp = generate_rsa_keypair(key_size=2048)
    cert_as = ca.issue_certificate("AS-UNISA", as_pub_tmp)

    # Verifica certificati
    assert ca.verify_certificate(cert_ae), "Cert AE non valido!"
    assert ca.verify_certificate(cert_ue), "Cert UE non valido!"
    assert ca.verify_certificate(cert_as), "Cert AS non valido!"

    # ======================================================================
    # FASE 2 – Autenticazione e rilascio token
    # ======================================================================
    separator("FASE 2 – Autenticazione e rilascio token")

    election_id = get_election_config()["election_id"]

    idp = IdentityProvider("IdP-UNISA", cert_ae)  # (cert_ae non usato dall'IdP, solo il suo PK)
    as_system = AuthenticationSystem("AS-UNISA", idp.public_key, election_id)

    # Registrazione aventi diritto
    fido2_keys = {}
    for v in VOTERS:
        fido2_priv = idp.register_student(v["id"], v["password"])
        fido2_keys[v["id"]] = fido2_priv
        as_system.register_eligible_voter(v["id"])

    # Autenticazione di ogni elettore → token pseudonimo
    voter_tokens = {}
    for v in VOTERS:
        print(f"\n[Auth] Autenticazione studente '{v['id']}'…")
        challenge = idp.issue_challenge()
        fido2_resp = student_fido2_respond(fido2_keys[v["id"]], challenge)
        id_token = idp.authenticate_student(v["id"], v["password"], challenge, fido2_resp)
        assert id_token is not None, f"Autenticazione fallita per {v['id']}"
        token_data = as_system.process_authentication(id_token)
        assert token_data is not None, f"Token non rilasciato per {v['id']}"
        voter_tokens[v["id"]] = token_data

    print(f"\n[Auth] Token emessi: {as_system.tokens_issued_count}")

    # Test: tentativo double-voting (deve essere bloccato)
    separator("TEST SICUREZZA: Double Voting")
    print("[Test] Tentativo secondo token per 'IE001'…")
    challenge2 = idp.issue_challenge()
    fido2_resp2 = student_fido2_respond(fido2_keys["IE001"], challenge2)
    id_token2 = idp.authenticate_student("IE001", "pass_alice", challenge2, fido2_resp2)
    token_double = as_system.process_authentication(id_token2)
    assert token_double is None, "BUG: double voting non bloccato!"
    print("[Test] Double voting correttamente bloccato. ✓")

    # ======================================================================
    # FASE 3 – Preparazione e cifratura voti
    # ======================================================================
    separator("FASE 3 – Preparazione e cifratura voti")

    vote_payloads = {}
    for v in VOTERS:
        client = VoterClient(v["id"], ca.get_public_key(), cert_ae)
        assert client.verify_ae_certificate(), f"Cert AE non verificato da {v['id']}"
        payload = client.prepare_and_encrypt_vote(
            lista=v["lista"],
            candidato=v["candidato"],
            token_data=voter_tokens[v["id"]],
        )
        assert payload is not None
        vote_payloads[v["id"]] = (payload, client)

    # Test: scheda malformata (lista inesistente)
    separator("TEST SICUREZZA: Scheda malformata")
    print("[Test] Tentativo lista 'XXXX' inesistente…")
    test_client = VoterClient("IE_FAKE", ca.get_public_key(), cert_ae)
    test_client.verify_ae_certificate()
    bad_payload = test_client.prepare_and_encrypt_vote(
        lista="XXXX", candidato=None, token_data=voter_tokens["IE001"]
    )
    assert bad_payload is None, "BUG: scheda malformata accettata!"
    print("[Test] Scheda malformata rifiutata. ✓")

    # ======================================================================
    # FASE 4 – Ricezione, registrazione, BB
    # ======================================================================
    separator("FASE 4 – Ricezione, registrazione, Bulletin Board")

    bb = BulletinBoard()
    urna = UrnaElettronica("UE-UNISA", as_system.public_key, bb, election_id)

    receipts = {}
    for voter_id, (payload, client) in vote_payloads.items():
        receipt = urna.receive_vote(payload)
        assert receipt is not None, f"Voto di {voter_id} rifiutato dall'urna!"

        # Il client verifica la ricevuta
        ok = urna.verify_receipt(receipt)
        assert ok, f"Ricevuta non valida per {voter_id}!"
        client.store_receipt(receipt)
        receipts[voter_id] = receipt

    # Test: replay attack (stesso payload due volte)
    separator("TEST SICUREZZA: Replay Attack")
    print("[Test] Reinvio dello stesso payload di 'IE001'…")
    first_payload = vote_payloads["IE001"][0]
    replay_receipt = urna.receive_vote(first_payload)
    assert replay_receipt is None, "BUG: replay attack non bloccato!"
    print("[Test] Replay attack correttamente bloccato. ✓")

    # Chiusura urna
    separator("CHIUSURA URNA")
    r_finale = urna.close_urn()

    # ======================================================================
    # VERIFICA INDIVIDUALE
    # ======================================================================
    separator("VERIFICA INDIVIDUALE (elettori)")

    for voter_id, receipt in receipts.items():
        ok = individual_verify(receipt, bb, urna.public_key)
        print(f"[Verifica Individuale] {voter_id}: {'✓ OK' if ok else '✗ FALLITA'}")
        assert ok, f"Verifica individuale fallita per {voter_id}!"

    # ======================================================================
    # FASE 5 – Scrutinio
    # ======================================================================
    separator("FASE 5 – Scrutinio")

    ae = AutoritaElettorale("AE-UNISA", ae_priv, ae_pub)
    verdict = ae.run_scrutiny(bb, urna.public_key, as_system.tokens_issued_count)
    assert verdict is not None, "Scrutinio fallito!"

    # Stampa risultati
    print("\n╔═══════════════════════════════════╗")
    print("║       RISULTATI ELEZIONE          ║")
    print("╠═══════════════════════════════════╣")
    cfg = get_election_config()
    for lista_id, count in verdict.results_by_list.items():
        nome = cfg["lists"].get(lista_id, {}).get("name", lista_id)
        print(f"║  {lista_id} – {nome:<20} {count:>3} voti ║")
    print("╠═══════════════════════════════════╣")
    print(f"║  Totale voti validi:         {verdict.n_votes_valid:>3}   ║")
    print(f"║  Voti non validi:            {verdict.n_votes_invalid:>3}   ║")
    print("╠═══════════════════════════════════╣")
    print("║  Preferenze interne:              ║")
    for cand, cnt in verdict.preferences_by_candidate.items():
        print(f"║    {cand:<26} {cnt:>3}   ║")
    print("╚═══════════════════════════════════╝")

    # ======================================================================
    # VERIFICA UNIVERSALE
    # ======================================================================
    separator("VERIFICA UNIVERSALE")
    ok_univ = universal_verify_verdict(bb, ae_pub)
    assert ok_univ, "Verifica universale fallita!"
    print(f"[Verifica Universale] Risultato finale verificato: ✓")

    t_end = time.perf_counter()
    separator("SIMULAZIONE COMPLETATA")
    print(f"Tempo totale simulazione: {(t_end - t_start)*1000:.1f} ms")
    print(f"Elettori: {len(VOTERS)}  |  Voti validi: {verdict.n_votes_valid}")

    return verdict


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "full"

    if mode == "bench":
        # Solo benchmark
        results = run_benchmarks(key_size=2048, n_voters=50)
        print_summary_table(results)

    elif mode == "bench4096":
        # Benchmark con chiavi a 4096 bit (come da spec WP2 per AE)
        results = run_benchmarks(key_size=4096, n_voters=50)
        print_summary_table(results)

    elif mode == "sim":
        # Solo simulazione
        run_full_simulation()

    else:
        # Full: simulazione + benchmark
        print("╔══════════════════════════════════════════════════════════╗")
        print("║  PROTOCOLLO DI VOTO ELETTRONICO UNIVERSITARIO           ║")
        print("║  WP4 – Implementazione e Prestazioni                    ║")
        print("║  Università degli Studi di Salerno  –  Gruppo 5         ║")
        print("╚══════════════════════════════════════════════════════════╝")

        run_full_simulation()

        print("\n")
        results = run_benchmarks(key_size=2048, n_voters=50)
        print_summary_table(results)
