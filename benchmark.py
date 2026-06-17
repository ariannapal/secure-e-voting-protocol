"""
-------------
Modulo di misurazione delle prestazioni del sistema di voto elettronico
universitario. Misura e riporta:

    1. Costo computazionale delle operazioni crittografiche
       (RSA-OAEP cifratura/decifratura, RSA-PSS firma/verifica,
        SHA-256, generazione chiavi, verifica certificati X.509).

    2. Dimensione dei messaggi scambiati tra le entita'
       (payload di voto, ricevuta, token, batch BB, attestazione AS,
        verbale finale).

    3. Latenza delle operazioni di verifica e di interazione
       (Fase 1 - setup PKI, Fase 2 - autenticazione+token,
        Fase 3 - cifratura+invio, Fase 4 - ricevuta+verifica,
        Fase 5 - scrutinio).

    4. Scalabilita' del Merkle Tree al variare del numero di foglie.

Ogni misura viene ripetuta N_RIPETIZIONI volte e vengono riportati:
    - media (mean)
    - deviazione standard (std)
    - minimo e massimo
    - percentile 95 (p95)

Esecuzione:
    python benchmark.py
    python benchmark.py --ripetizioni 20 --elettori 30

Output: stampa su stdout + salva 'benchmark_report.txt'.
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Dipendenze del progetto
# ---------------------------------------------------------------------------
import crypto_utils as cu
from ballot import MessaggioVoto, PayloadVoto, Ricevuta, calcola_receipt_id
from bulletin_board import (
    AttestazioneTokenAS,
    BatchPubblicato,
    BulletinBoard,
    VerbaleFinale,
)
from election_config import configurazione_demo
from merkle import calcola_radice_merkle, costruisci_proof
from pki import (
    CertificationAuthority,
    Certificato,
    USO_CIFRATURA,
    USO_FIRMA_DIGITALE,
    carica_chiave_privata,
    genera_chiave_e_csr,
    verifica_certificato_offline,
)
from system_setup import (
    DIRECTORY_PKI_RUNTIME,
    SistemaVoto,
    bootstrap_client,
    esegui_fase5,
    inizializza_sistema,
)

# ---------------------------------------------------------------------------
# Parametri globali
# ---------------------------------------------------------------------------

N_RIPETIZIONI_DEFAULT = 10
N_ELETTORI_DEFAULT = 20
LARGHEZZA_OUTPUT = 72
CA_DIR = "ca"


# ===========================================================================
# Strutture dati per i risultati
# ===========================================================================

@dataclass
class MisuraTempi:
    """Raccoglie e calcola le statistiche su una serie di misure in secondi."""
    nome: str
    campioni: List[float] = field(default_factory=list)

    def aggiungi(self, t: float) -> None:
        self.campioni.append(t)

    @property
    def n(self) -> int:
        return len(self.campioni)

    @property
    def media_ms(self) -> float:
        return statistics.mean(self.campioni) * 1000 if self.campioni else 0.0

    @property
    def std_ms(self) -> float:
        return statistics.stdev(self.campioni) * 1000 if len(self.campioni) > 1 else 0.0

    @property
    def min_ms(self) -> float:
        return min(self.campioni) * 1000 if self.campioni else 0.0

    @property
    def max_ms(self) -> float:
        return max(self.campioni) * 1000 if self.campioni else 0.0

    @property
    def p95_ms(self) -> float:
        if not self.campioni:
            return 0.0
        ordinati = sorted(self.campioni)
        indice = int(len(ordinati) * 0.95)
        return ordinati[min(indice, len(ordinati) - 1)] * 1000

    def riga(self) -> str:
        return (
            f"  {self.nome:<42} "
            f"{self.media_ms:>8.2f} ms  "
            f"±{self.std_ms:>7.2f}  "
            f"[{self.min_ms:.2f}–{self.max_ms:.2f}]  "
            f"p95={self.p95_ms:.2f}"
        )


@dataclass
class MisuraDimensione:
    """Dimensione in byte di un messaggio/struttura dati."""
    nome: str
    byte: int
    note: str = ""

    def riga(self) -> str:
        note_str = f"  ({self.note})" if self.note else ""
        if self.byte >= 1024:
            return f"  {self.nome:<44} {self.byte:>6} B  = {self.byte/1024:>6.2f} KB{note_str}"
        return f"  {self.nome:<44} {self.byte:>6} B{note_str}"


# ===========================================================================
# Utilita' di timing
# ===========================================================================

def misura(nome: str, fn: Callable, n: int = N_RIPETIZIONI_DEFAULT) -> MisuraTempi:
    """
    Esegue fn() n volte, misurando il tempo wall-clock di ciascuna
    chiamata, e ritorna un oggetto MisuraTempi con le statistiche.
    """
    m = MisuraTempi(nome=nome)
    for _ in range(n):
        t0 = time.perf_counter()
        fn()
        m.aggiungi(time.perf_counter() - t0)
    return m


# ===========================================================================
# Benchmark delle primitive crittografiche
# ===========================================================================

def bench_primitive_crittografiche(n: int) -> List[MisuraTempi]:
    """
    Misura le operazioni crittografiche di base, isolate dal resto
    del sistema, usando chiavi generate freshly per questa suite.
    """
    risultati: List[MisuraTempi] = []

    # -- Generazione chiavi RSA -------------------------------------------------
    risultati.append(misura(
        "Keygen RSA-2048",
        lambda: cu.genera_coppia_rsa(2048),
        n=n,
    ))
    risultati.append(misura(
        "Keygen RSA-4096",
        lambda: cu.genera_coppia_rsa(4096),
        n=max(n // 2, 3),  # piu' lento: meno ripetizioni
    ))

    # Prepara chiavi riutilizzabili per le benchmark successive
    sk_2048 = cu.genera_coppia_rsa(2048)
    pk_2048 = sk_2048.public_key()
    sk_4096 = cu.genera_coppia_rsa(4096)
    pk_4096 = sk_4096.public_key()

    # Messaggio campione (simula JSON di un voto reale)
    msg_voto = MessaggioVoto.crea("Lista A - StudentiIngegneria", "Marco Rossi")
    plaintext = msg_voto.to_json_bytes()

    # -- RSA-OAEP (usata per la cifratura del voto con PK_AE^enc 4096 bit) ----
    ciphertext_4096 = cu.rsa_oaep_encrypt(pk_4096, plaintext)

    risultati.append(misura(
        "RSA-OAEP Encrypt (PK_AE 4096 bit)",
        lambda: cu.rsa_oaep_encrypt(pk_4096, plaintext),
        n=n,
    ))
    risultati.append(misura(
        "RSA-OAEP Decrypt (SK_AE 4096 bit)",
        lambda: cu.rsa_oaep_decrypt(sk_4096, ciphertext_4096),
        n=n,
    ))

    # -- RSA-PSS firma/verifica (usata per token AS, ricevuta UE, verbale AE) --
    hash_token = cu.sha256(cu.genera_valore_casuale(32))

    firma_2048 = cu.rsa_pss_sign(sk_2048, hash_token)
    firma_4096 = cu.rsa_pss_sign(sk_4096, hash_token)

    risultati.append(misura(
        "RSA-PSS Sign (SK_AS/UE 2048 bit)",
        lambda: cu.rsa_pss_sign(sk_2048, hash_token),
        n=n,
    ))
    risultati.append(misura(
        "RSA-PSS Verify (PK_AS/UE 2048 bit)",
        lambda: cu.rsa_pss_verify(pk_2048, hash_token, firma_2048),
        n=n,
    ))
    risultati.append(misura(
        "RSA-PSS Sign (SK_AE 4096 bit)",
        lambda: cu.rsa_pss_sign(sk_4096, hash_token),
        n=n,
    ))
    risultati.append(misura(
        "RSA-PSS Verify (PK_AE 4096 bit)",
        lambda: cu.rsa_pss_verify(pk_4096, hash_token, firma_4096),
        n=n,
    ))

    # -- SHA-256 ---------------------------------------------------------------
    dati_grandi = os.urandom(4096)
    risultati.append(misura(
        "SHA-256 (64 byte - nonce/token)",
        lambda: cu.sha256(plaintext),
        n=n * 10,
    ))
    risultati.append(misura(
        "SHA-256 (4096 byte - batch payload)",
        lambda: cu.sha256(dati_grandi),
        n=n * 10,
    ))

    # -- CSPRNG (genera_valore_casuale) ----------------------------------------
    risultati.append(misura(
        "CSPRNG 32 byte (token/nonce)",
        lambda: cu.genera_valore_casuale(32),
        n=n * 10,
    ))

    # -- ReceiptID = SHA256(T || C) --------------------------------------------
    token_hex = cu.genera_valore_casuale(32).hex()
    ciphertext_hex = ciphertext_4096.hex()
    risultati.append(misura(
        "ReceiptID = SHA256(T_hex || C_hex)",
        lambda: calcola_receipt_id(token_hex, ciphertext_hex),
        n=n * 10,
    ))

    return risultati


# ===========================================================================
# Benchmark del Merkle Tree
# ===========================================================================

def bench_merkle(n_rep: int) -> Tuple[List[MisuraTempi], List[MisuraTempi]]:
    """
    Misura il calcolo della Merkle Root e la costruzione di una Merkle
    Proof al variare del numero di foglie (voti pubblicati).
    """
    taglie = [10, 50, 100, 250, 500, 1000]
    risultati_root: List[MisuraTempi] = []
    risultati_proof: List[MisuraTempi] = []

    for m in taglie:
        foglie = [cu.sha256_hex(cu.genera_valore_casuale(32)) for _ in range(m)]
        risultati_root.append(misura(
            f"Merkle Root ({m} foglie)",
            lambda f=foglie: calcola_radice_merkle(f),
            n=n_rep,
        ))
        risultati_proof.append(misura(
            f"Merkle Proof build+verify ({m} foglie)",
            lambda f=foglie: _merkle_proof_cycle(f),
            n=n_rep,
        ))

    return risultati_root, risultati_proof


def _merkle_proof_cycle(foglie: List[str]) -> bool:
    """Costruisce la prova per la foglia centrale e la verifica."""
    idx = len(foglie) // 2
    radice = calcola_radice_merkle(foglie)
    proof = costruisci_proof(foglie, idx)
    return proof is not None and proof.verifica(radice)


# ===========================================================================
# Dimensioni dei messaggi
# ===========================================================================

def misura_dimensioni_messaggi(sistema: SistemaVoto, n_elettori: int) -> List[MisuraDimensione]:
    """
    Calcola le dimensioni in byte delle strutture dati trasmesse tra
    le entita' del protocollo. Usa il sistema gia' inizializzato.
    """
    dim: List[MisuraDimensione] = []

    cfg = configurazione_demo()
    sk_2048 = cu.genera_coppia_rsa(2048)
    pk_2048 = sk_2048.public_key()
    sk_4096 = cu.genera_coppia_rsa(4096)
    pk_4096 = sk_4096.public_key()

    # --- MessaggioVoto in chiaro (JSON bytes) ---------------------------------
    msg = MessaggioVoto.crea("Lista A - StudentiIngegneria", "Marco Rossi")
    m_bytes = msg.to_json_bytes()
    dim.append(MisuraDimensione(
        "MessaggioVoto in chiaro M (JSON)",
        len(m_bytes),
        "lista + candidato + nonce hex (64 char)",
    ))

    # --- Ciphertext RSA-OAEP (4096 bit) --------------------------------------
    ciphertext = cu.rsa_oaep_encrypt(pk_4096, m_bytes)
    dim.append(MisuraDimensione(
        "Ciphertext C = RSA-OAEP(PK_AE 4096)",
        len(ciphertext),
        "= modulo / 8 = 512 B",
    ))

    # --- Token pseudonimo T (32 byte = 64 hex char) ---------------------------
    token_bytes = cu.genera_valore_casuale(32)
    token_hex = token_bytes.hex()
    h_token = cu.sha256(token_bytes)
    dim.append(MisuraDimensione(
        "Token T (bytes)",
        len(token_bytes),
        "valore pseudonimo CSPRNG",
    ))
    dim.append(MisuraDimensione(
        "Token T (hex string, campo del payload)",
        len(token_hex.encode()),
        "64 caratteri ASCII",
    ))

    # --- Firma RSA-PSS su token (2048 bit) ------------------------------------
    firma_as = cu.rsa_pss_sign(sk_2048, h_token)
    dim.append(MisuraDimensione(
        "Sig_AS(T) = RSA-PSS(SK_AS 2048)",
        len(firma_as),
        "= modulo / 8 = 256 B",
    ))

    # --- PayloadVoto completo { C, T, Sig_AS(T) } (serializzato come dict JSON) --
    payload = PayloadVoto(
        ciphertext_hex=ciphertext.hex(),
        token_hex=token_hex,
        firma_as_hex=firma_as.hex(),
    )
    payload_json = json.dumps(payload.to_dict()).encode()
    dim.append(MisuraDimensione(
        "PayloadVoto { C, T, Sig_AS(T) } (JSON)",
        len(payload_json),
        "trasmesso Client → Urna (HTTPS/TLS)",
    ))

    # --- ReceiptID (SHA-256, 32 byte = 64 hex char) ---------------------------
    receipt_id = calcola_receipt_id(token_hex, ciphertext.hex())
    dim.append(MisuraDimensione(
        "ReceiptID = SHA256(T||C) (hex string)",
        len(receipt_id.encode()),
        "64 caratteri ASCII",
    ))

    # --- Firma Urna su (ReceiptID || Timestamp) --------------------------------
    ts = time.time()
    msg_ricevuta = (receipt_id + str(ts)).encode()
    firma_ue = cu.rsa_pss_sign(sk_2048, msg_ricevuta)
    dim.append(MisuraDimensione(
        "Sig_UE(ReceiptID||Timestamp) (bytes)",
        len(firma_ue),
        "= modulo / 8 = 256 B",
    ))

    # --- Ricevuta completa (struttura logica) ---------------------------------
    ricevuta_bytes = (
        len(token_hex.encode())
        + len(ciphertext.hex().encode())
        + len(receipt_id.encode())
        + 8          # float timestamp
        + len(firma_ue)
    )
    dim.append(MisuraDimensione(
        "Ricevuta { T,C,ReceiptID,ts,Sig_UE } (totale logico)",
        ricevuta_bytes,
        "rilasciata dall'Urna al Client",
    ))

    # --- Tupla (ReceiptID, C) pubblicata sul Bulletin Board ------------------
    tupla_bb = (receipt_id + ciphertext.hex()).encode()
    dim.append(MisuraDimensione(
        "Tupla BB (ReceiptID_hex, C_hex)",
        len(tupla_bb),
        "entry nel registro pubblico",
    ))

    # --- Firma su batch dell'Urna (2048 bit) ----------------------------------
    batch_id = cu.genera_id_esadecimale(16)
    radice_batch = calcola_radice_merkle([receipt_id])
    msg_batch = (
        batch_id.encode()
        + radice_batch.encode()
        + str(ts).encode()
        + b"0"
    )
    firma_batch = cu.rsa_pss_sign(sk_2048, msg_batch)
    dim.append(MisuraDimensione(
        "Sig_UE(batch) = RSA-PSS(SK_UE 2048)",
        len(firma_batch),
        "firma su batch pubblicato sul BB",
    ))

    # --- Certificato X.509 PEM (approssimato come PEM su disco) ---------------
    cert_path = Path("pki_runtime/AE/ae_enc.cert.pem")
    if cert_path.exists():
        dim.append(MisuraDimensione(
            "Cert_AE^enc X.509 PEM (su disco)",
            cert_path.stat().st_size,
            "certificato emesso dalla CA",
        ))
    cert_path_sig = Path("pki_runtime/AE/ae_sig.cert.pem")
    if cert_path_sig.exists():
        dim.append(MisuraDimensione(
            "Cert_AE^sig X.509 PEM (su disco)",
            cert_path_sig.stat().st_size,
        ))
    cert_ue = Path("pki_runtime/Urna/ue_sig.cert.pem")
    if cert_ue.exists():
        dim.append(MisuraDimensione(
            "Cert_UE X.509 PEM (su disco)",
            cert_ue.stat().st_size,
        ))

    # --- Attestazione AS (n_token, firma) ------------------------------------
    firma_attestazione = cu.rsa_pss_sign(sk_2048, str(n_elettori).encode())
    dim.append(MisuraDimensione(
        "AttestazioneTokenAS { n_token, Sig_AS }",
        len(str(n_elettori).encode()) + len(firma_attestazione),
        f"n_token={n_elettori}",
    ))

    return dim


# ===========================================================================
# Benchmark delle fasi del protocollo end-to-end
# ===========================================================================

def bench_fasi_protocollo(
    n_ripetizioni_setup: int,
    n_elettori: int,
    n_ripetizioni_crypto: int,
) -> Tuple[List[MisuraTempi], Dict[str, Any]]:
    """
    Misura le latenze delle macro-fasi del protocollo usando il sistema
    reale (non primitive isolate):

        Fase 1: setup PKI completo
        Fase 2: autenticazione + rilascio token (per un singolo elettore)
        Fase 3: cifratura voto + composizione payload
        Fase 4: invio all'Urna + ricezione ricevuta + verifica locale
        Fase 5: chiusura Urna + scrutinio (su n_elettori voti)
    """
    risultati: List[MisuraTempi] = []
    meta: Dict[str, Any] = {}

    # -- Fase 1: setup PKI completo -------------------------------------------
    m_setup = MisuraTempi("Fase 1 – Setup PKI completo (AE×2+UE+AS cert)")
    for _ in range(n_ripetizioni_setup):
        t0 = time.perf_counter()
        sistema = inizializza_sistema()
        m_setup.aggiungi(time.perf_counter() - t0)
    risultati.append(m_setup)

    # Usa l'ultimo sistema inizializzato per le fasi successive
    # (evita di rimisurare il setup ogni volta)
    sistema = inizializza_sistema()

    # -- Bootstrap fiducia (Fase 1b, lato Client) ------------------------------
    m_bootstrap = MisuraTempi("Fase 1b – Bootstrap fiducia (verifica 4 cert X.509)")
    for _ in range(n_ripetizioni_crypto):
        t0 = time.perf_counter()
        bootstrap_client(sistema, "studente_001")
        m_bootstrap.aggiungi(time.perf_counter() - t0)
    risultati.append(m_bootstrap)

    # -- Fase 2: autenticazione + rilascio token ------------------------------
    m_auth = MisuraTempi("Fase 2 – Autenticazione + rilascio TokenVoto")
    for i in range(1, min(n_ripetizioni_crypto, 18) + 1):
        sid = f"studente_{i:03d}"
        client = bootstrap_client(sistema, sid)
        t0 = time.perf_counter()
        client.autenticati(sistema.auth_server)
        m_auth.aggiungi(time.perf_counter() - t0)
    risultati.append(m_auth)

    # -- Fase 2b: verifica locale del token (lato Client) ---------------------
    client_demo = bootstrap_client(sistema, "studente_001")
    # Reimposta lo stato del registro per poter riusare lo stesso studente
    sistema.auth_server._registro_elettori["studente_001"].token_rilasciato = False
    client_demo.autenticati(sistema.auth_server)

    m_ver_tok = MisuraTempi("Fase 2b – Verifica locale Sig_AS(T) (lato Client)")
    risultati.append(misura(
        "Fase 2b – Verifica locale Sig_AS(T) (lato Client)",
        client_demo.verifica_token_locale,
        n=n_ripetizioni_crypto,
    ))

    # -- Fase 3: cifratura voto + composizione payload (lato Client) ----------
    cfg = sistema.configurazione
    lista = cfg.elenco_liste()[0]
    candidato = cfg.candidati_di(lista)[0] if cfg.candidati_di(lista) else None

    # Pre-autentica tutti gli elettori necessari a Fase 3/4
    sistema2 = inizializza_sistema()
    clients_f3 = []
    for i in range(1, min(n_ripetizioni_crypto, 10) + 1):
        sid = f"studente_{i:03d}"
        c = bootstrap_client(sistema2, sid)
        c.autenticati(sistema2.auth_server)
        clients_f3.append(c)

    m_cifra = MisuraTempi("Fase 3 – Cifratura RSA-OAEP + composizione Payload")
    for c in clients_f3:
        t0 = time.perf_counter()
        # Misura solo la parte di cifratura, non l'invio all'Urna
        msg = MessaggioVoto.crea(lista, candidato)
        _ = cu.rsa_oaep_encrypt(c.pk_ae_enc, msg.to_json_bytes())
        m_cifra.aggiungi(time.perf_counter() - t0)
    risultati.append(m_cifra)

    # -- Fase 3+4: invio voto + ricezione ricevuta + verifica locale ----------
    sistema3 = inizializza_sistema()
    clients_f4 = []
    for i in range(1, min(n_ripetizioni_crypto, 10) + 1):
        sid = f"studente_{i:03d}"
        c = bootstrap_client(sistema3, sid)
        c.autenticati(sistema3.auth_server)
        clients_f4.append(c)

    m_voto_completo = MisuraTempi("Fase 3+4 – Voto completo (cifratura+invio+ricevuta)")
    for c in clients_f4:
        t0 = time.perf_counter()
        c.vota(lista, candidato, sistema3.urna, sistema3.configurazione, bb=None)
        m_voto_completo.aggiungi(time.perf_counter() - t0)
    risultati.append(m_voto_completo)

    # -- Fase 4: verifica locale della ricevuta --------------------------------
    client_ric = clients_f4[0] if clients_f4 else None
    if client_ric and client_ric.ultima_ricevuta:
        m_ver_ric = misura(
            "Fase 4 – Verifica locale ricevuta (ReceiptID + Sig_UE)",
            client_ric.verifica_ricevuta,
            n=n_ripetizioni_crypto,
        )
        risultati.append(m_ver_ric)

    # -- Fase 5: scrutinio su n_elettori voti reali ---------------------------
    sistema_f5 = inizializza_sistema()
    meta["n_elettori_fase5"] = n_elettori

    # Fase di votazione: n_elettori studenti votano
    aventi_diritto = [
        sid for sid, entry in sistema_f5.auth_server._registro_elettori.items()
        if entry.avente_diritto
    ][:n_elettori]

    for sid in aventi_diritto:
        c = bootstrap_client(sistema_f5, sid)
        c.autenticati(sistema_f5.auth_server)
        c.vota(lista, candidato, sistema_f5.urna, sistema_f5.configurazione,
               bb=sistema_f5.bb)

    m_fase5 = MisuraTempi(f"Fase 5 – Scrutinio ({n_elettori} voti reali)")
    for _ in range(max(n_ripetizioni_setup, 2)):
        # Ricostruiamo un sistema fresco ad ogni ripetizione per evitare
        # interferenze con lo stato del BB (append-only)
        s5 = inizializza_sistema()
        av = [
            sid for sid, e in s5.auth_server._registro_elettori.items()
            if e.avente_diritto
        ][:n_elettori]
        for sid in av:
            c5 = bootstrap_client(s5, sid)
            c5.autenticati(s5.auth_server)
            c5.vota(lista, candidato, s5.urna, s5.configurazione, bb=s5.bb)
        t0 = time.perf_counter()
        esegui_fase5(s5)
        m_fase5.aggiungi(time.perf_counter() - t0)
    risultati.append(m_fase5)

    # Latenza verifica integrita' BB (isolata dallo scrutinio vero)
    s_vi = inizializza_sistema()
    av_vi = [
        sid for sid, e in s_vi.auth_server._registro_elettori.items()
        if e.avente_diritto
    ][:n_elettori]
    for sid in av_vi:
        cvi = bootstrap_client(s_vi, sid)
        cvi.autenticati(s_vi.auth_server)
        cvi.vota(lista, candidato, s_vi.urna, s_vi.configurazione, bb=s_vi.bb)
    s_vi.urna.chiudi_elezione(s_vi.bb, election_id=s_vi.election_id)
    att = s_vi.auth_server.emetti_attestazione_token()
    s_vi.bb.pubblica_attestazione_token(att)

    dati_bb = s_vi.ae.acquisisci_da_bulletin_board(s_vi.bb)
    m_verifica_bb = misura(
        f"Fase 5 – Verifica integrita' BB ({n_elettori} voti)",
        lambda: s_vi.ae.verifica_integrita_bb(
            dati_bb, s_vi.urna.pk_sig, s_vi.auth_server.pk_sig
        ),
        n=n_ripetizioni_crypto,
    )
    risultati.append(m_verifica_bb)

    meta["sistema"] = sistema_f5
    return risultati, meta


# ===========================================================================
# Formattazione e stampa del report
# ===========================================================================

def _linea(char: str = "─") -> str:
    return char * LARGHEZZA_OUTPUT


def _titolo(t: str) -> str:
    pad = (LARGHEZZA_OUTPUT - len(t) - 2) // 2
    return "╔" + "═" * (LARGHEZZA_OUTPUT - 2) + "╗\n" + \
           "║" + " " * pad + t + " " * (LARGHEZZA_OUTPUT - 2 - pad - len(t)) + "║\n" + \
           "╚" + "═" * (LARGHEZZA_OUTPUT - 2) + "╝"


def _sezione(t: str) -> str:
    return "\n" + _linea("─") + f"\n  {t}\n" + _linea("─")


def stampa_report(
    primitive: List[MisuraTempi],
    merkle_root: List[MisuraTempi],
    merkle_proof: List[MisuraTempi],
    dimensioni: List[MisuraDimensione],
    fasi: List[MisuraTempi],
    meta: Dict[str, Any],
    n_rip: int,
    n_elettori: int,
) -> str:
    """Compone il report testuale e lo ritorna come stringa."""
    righe: List[str] = []

    def w(s: str = "") -> None:
        righe.append(s)

    w(_titolo("BENCHMARK – SISTEMA DI VOTO ELETTRONICO"))
    w(f"\n  Ripetizioni per misura  : {n_rip}")
    w(f"  Elettori per Fase 5     : {n_elettori}")
    w(f"  Data esecuzione         : {time.strftime('%Y-%m-%d %H:%M:%S')}")
    w(f"\n  Legenda colonne         : media (ms)  ±std  [min–max]  p95")

    # -- 1. Primitive crittografiche -------------------------------------------
    w(_sezione("1. COSTO COMPUTAZIONALE DELLE PRIMITIVE CRITTOGRAFICHE"))
    w(f"  {'Operazione':<42} {'Media':>10}   {'±Std':>8}   {'[min–max]':>14}   {'p95':>8}")
    w("  " + "─" * (LARGHEZZA_OUTPUT - 2))
    for m in primitive:
        w(m.riga())

    # -- 2. Merkle Tree --------------------------------------------------------
    w(_sezione("2. SCALABILITÀ MERKLE TREE"))
    w(f"  {'Operazione':<42} {'Media':>10}   {'±Std':>8}   {'[min–max]':>14}   {'p95':>8}")
    w("  " + "─" * (LARGHEZZA_OUTPUT - 2))
    for m in merkle_root:
        w(m.riga())
    w("")
    for m in merkle_proof:
        w(m.riga())

    # -- 3. Dimensioni messaggi ------------------------------------------------
    w(_sezione("3. DIMENSIONE DEI MESSAGGI SCAMBIATI TRA LE ENTITÀ"))
    w(f"  {'Struttura / Messaggio':<44} {'Byte':>8}   Note")
    w("  " + "─" * (LARGHEZZA_OUTPUT - 2))
    for d in dimensioni:
        w(d.riga())

    # Totale payload di voto
    w("")
    c_size = next((d.byte for d in dimensioni if "PayloadVoto" in d.nome), 0)
    w(f"  → Un singolo voto occupa ≈ {c_size} B sul canale Client→Urna (hex-encoded JSON).")

    # -- 4. Latenze fasi protocollo --------------------------------------------
    w(_sezione("4. LATENZA DELLE FASI DEL PROTOCOLLO (sistema reale)"))
    w(f"  {'Operazione':<42} {'Media':>10}   {'±Std':>8}   {'[min–max]':>14}   {'p95':>8}")
    w("  " + "─" * (LARGHEZZA_OUTPUT - 2))
    for m in fasi:
        w(m.riga())

    # -- 5. Riepilogo / note interpretative ------------------------------------
    w(_sezione("5. RIEPILOGO E NOTE INTERPRETATIVE"))

    enc_ms = next((m.media_ms for m in primitive if "OAEP Encrypt" in m.nome), None)
    dec_ms = next((m.media_ms for m in primitive if "OAEP Decrypt" in m.nome), None)
    pss_sign_2k = next((m.media_ms for m in primitive if "Sign" in m.nome and "2048" in m.nome), None)
    pss_ver_2k  = next((m.media_ms for m in primitive if "Verify" in m.nome and "2048" in m.nome), None)
    keygen_2k   = next((m.media_ms for m in primitive if "Keygen RSA-2048" in m.nome), None)
    keygen_4k   = next((m.media_ms for m in primitive if "Keygen RSA-4096" in m.nome), None)

    if enc_ms:
        w(f"  • La cifratura RSA-OAEP con chiave 4096 bit richiede ≈{enc_ms:.1f} ms lato Client.")
        w(f"    Il costo è percettivamente trascurabile per l'utente finale.")
    if dec_ms:
        w(f"  • La decifratura RSA-OAEP (solo in Fase 5, lato AE) richiede ≈{dec_ms:.1f} ms/voto.")
        if dec_ms > 0:
            scrutinio_1k_s = (dec_ms * 1000) / 1000.0
            w(f"    Per 1 000 voti lo scrutinio richiede ≈{scrutinio_1k_s:.1f} s (solo decifrature).")
    if pss_sign_2k:
        w(f"  • RSA-PSS Sign (2048 bit): ≈{pss_sign_2k:.1f} ms — token AS, ricevuta UE.")
    if pss_ver_2k:
        w(f"  • RSA-PSS Verify (2048 bit): ≈{pss_ver_2k:.1f} ms — lato Client e AE.")
    if keygen_2k and keygen_4k:
        w(f"  • Keygen RSA-2048: ≈{keygen_2k:.0f} ms; RSA-4096: ≈{keygen_4k:.0f} ms (solo Fase 1).")

    merkle_1k = next((m.media_ms for m in merkle_root if "1000" in m.nome), None)
    if merkle_1k:
        w(f"  • Merkle Root su 1 000 foglie: ≈{merkle_1k:.2f} ms — overhead trascurabile.")

    fase1_ms = next((m.media_ms for m in fasi if "Fase 1" in m.nome), None)
    fase5_ms = next((m.media_ms for m in fasi if "Fase 5 – Scrutinio" in m.nome), None)
    if fase1_ms:
        w(f"  • Fase 1 (setup PKI, operazione una-tantum): ≈{fase1_ms/1000:.1f} s.")
    if fase5_ms:
        w(f"  • Fase 5 (scrutinio {n_elettori} voti): ≈{fase5_ms:.0f} ms.")

    payload_size = next((d.byte for d in dimensioni if "PayloadVoto" in d.nome), 0)
    if payload_size:
        w(f"  • Payload di voto ≈ {payload_size} B — compatibile con connessioni di rete standard;")
        w(f"    a 1 Mbit/s il trasferimento richiede < {payload_size*8/1_000_000*1000:.1f} ms.")

    w("")
    w("  Tutte le misure sono wall-clock time (perf_counter), eseguite su un")
    w("  singolo processo Python senza parallelismo. Valori reali su hardware")
    w("  dedicato e con TLS attivo potrebbero differire.")
    w(_linea("═"))

    return "\n".join(righe)


# ===========================================================================
# Entry point
# ===========================================================================

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Benchmark del sistema di voto elettronico universitario."
    )
    parser.add_argument(
        "--ripetizioni", type=int, default=N_RIPETIZIONI_DEFAULT,
        help=f"Numero di ripetizioni per le misure crypto (default {N_RIPETIZIONI_DEFAULT})",
    )
    parser.add_argument(
        "--elettori", type=int, default=N_ELETTORI_DEFAULT,
        help=f"Numero di voti reali per Fase 5 (default {N_ELETTORI_DEFAULT})",
    )
    parser.add_argument(
        "--output", type=str, default="benchmark_report.txt",
        help="File di output per il report testuale",
    )
    args = parser.parse_args()

    n_rip = args.ripetizioni
    n_el  = min(args.elettori, 95)  # max aventi diritto nel registro demo

    print(_titolo("BENCHMARK – SISTEMA DI VOTO ELETTRONICO"))
    print(f"\n  Ripetizioni: {n_rip}    Elettori Fase 5: {n_el}")
    print("  Avvio misurazioni...\n")

    # --- 1. Primitive crittografiche ------------------------------------------
    print("  [1/4] Primitive crittografiche...")
    primitive = bench_primitive_crittografiche(n_rip)

    # --- 2. Merkle Tree -------------------------------------------------------
    print("  [2/4] Scalabilità Merkle Tree...")
    merkle_root, merkle_proof = bench_merkle(n_rip)

    # --- 3. Fasi del protocollo -----------------------------------------------
    print("  [3/4] Fasi del protocollo (richiede setup PKI reale)...")
    # Inizializza un sistema per misurare dimensioni messaggi
    sistema_dim = inizializza_sistema()
    dimensioni = misura_dimensioni_messaggi(sistema_dim, n_el)

    # --- 4. Latenze fasi ------------------------------------------------------
    print("  [4/4] Latenze fasi protocollo...")
    n_setup_rip = max(n_rip // 3, 2)  # setup PKI è costoso: meno ripetizioni
    fasi, meta = bench_fasi_protocollo(n_setup_rip, n_el, n_rip)

    # --- Composizione e stampa ------------------------------------------------
    report = stampa_report(
        primitive=primitive,
        merkle_root=merkle_root,
        merkle_proof=merkle_proof,
        dimensioni=dimensioni,
        fasi=fasi,
        meta=meta,
        n_rip=n_rip,
        n_elettori=n_el,
    )

    print("\n" + report)

    # Salva su file
    Path(args.output).write_text(report, encoding="utf-8")
    print(f"\n  Report salvato in '{args.output}'.")


if __name__ == "__main__":
    main()
