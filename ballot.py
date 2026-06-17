"""
ballot.py
---------
Strutture dati e funzioni relative alla scheda elettorale e al payload
di voto, secondo i formati definiti nel WP2 (Fase 3 e Fase 4):

    - Messaggio in chiaro M = (lista, candidato, nonce), serializzato
      come stringa JSON prima della cifratura RSA-OAEP (Tabella
      "Formato dei campi della scheda elettorale in chiaro").

    - Payload di voto = {ciphertext, token, Sig_AS(T)}, inviato dal
      Client all'Urna Elettronica (Tabella "Specifiche del Payload di
      Voto").

    - Ricevuta crittografica rilasciata dall'Urna dopo l'accettazione
      del voto, contenente il ReceiptID e la firma dell'Urna
      (Sig_UE(ReceiptID || Timestamp)), come descritto in Fase 4.

Questo modulo non contiene logica decisionale (validazione aventi
diritto, anti-double-voting, ecc.): quella resta nelle classi di
'entities.py'. Qui sono raccolte solo le strutture dati e le funzioni
di (de)serializzazione/composizione del messaggio, per mantenere
separati i formati dal comportamento delle entita'.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Optional

import crypto_utils as cu

# Dimensione massima, in byte, dei campi testuali 'lista' e 'candidato'
# secondo la Tabella "Formato dei campi della scheda elettorale in chiaro".
MAX_BYTE_CAMPO_TESTUALE = 64


@dataclass
class MessaggioVoto:
    """
    Messaggio in chiaro M = (lista_i || candidato_i || nonce_i), nel
    formato JSON descritto nel WP2:

        { "lista": ..., "candidato": ..., "nonce": ... }

    Il campo 'nonce' (32 byte, rappresentati come 64 caratteri hex) e'
    generato tramite CSPRNG ed e' cio' che rende il messaggio in chiaro
    non deterministico anche a parita' di (lista, candidato): combinato
    con la natura randomizzata del padding OAEP (seed, hash, MGF1),
    rinforza la proprieta' di cifratura probabilistica del voto.
    """
    lista: str
    candidato: Optional[str]
    nonce_hex: str

    @staticmethod
    def crea(lista: str, candidato: Optional[str]) -> "MessaggioVoto":
        """Costruisce un nuovo messaggio di voto con un nonce fresco da CSPRNG."""
        nonce_hex = cu.genera_valore_casuale(32).hex()
        return MessaggioVoto(lista=lista, candidato=candidato, nonce_hex=nonce_hex)

    def valida_dimensioni(self) -> bool:
        """
        Verifica che i campi testuali rispettino il vincolo dimensionale
        della Tabella (max 64 byte UTF-8 ciascuno).
        """
        if len(self.lista.encode("utf-8")) > MAX_BYTE_CAMPO_TESTUALE:
            return False
        if self.candidato is not None and len(self.candidato.encode("utf-8")) > MAX_BYTE_CAMPO_TESTUALE:
            return False
        return True

    def to_json_bytes(self) -> bytes:
        """
        Serializza il messaggio come stringa JSON e la converte in
        array di byte, pronto per essere sottoposto a cifratura
        asimmetrica RSA-OAEP.
        """
        oggetto = {
            "lista": self.lista,
            "candidato": self.candidato,
            "nonce": self.nonce_hex,
        }
        return json.dumps(oggetto, ensure_ascii=False).encode("utf-8")

    @staticmethod
    def from_json_bytes(dati: bytes) -> "MessaggioVoto":
        """Deserializza un messaggio precedentemente serializzato con to_json_bytes()."""
        oggetto = json.loads(dati.decode("utf-8"))
        return MessaggioVoto(
            lista=oggetto["lista"],
            candidato=oggetto.get("candidato"),
            nonce_hex=oggetto["nonce"],
        )


@dataclass
class PayloadVoto:
    """
    Payload di voto trasmesso dal Client all'Urna Elettronica via
    HTTPS/TLS:

        Payload = { ciphertext, token, Sig_AS(T) }

    secondo la Tabella "Specifiche del Payload di Voto inviato
    all'Urna Elettorale". Tutti i campi binari sono rappresentati in
    formato esadecimale, coerentemente con quanto specificato nel WP2.
    """
    ciphertext_hex: str      # C cifrato con PK_AE (RSA-OAEP), in hex
    token_hex: str           # T, token pseudonimo, in hex
    firma_as_hex: str        # Sig_AS(T), firma RSA-PSS dell'AS sul token, in hex

    def to_dict(self) -> dict:
        return {
            "ciphertext": self.ciphertext_hex,
            "token": self.token_hex,
            "Sig_AS(T)": self.firma_as_hex,
        }


@dataclass
class Ricevuta:
    """
    Ricevuta crittografica rilasciata dall'Urna Elettronica dopo
    l'accettazione del voto cifrato, secondo il WP2:

        Ricevuta = { T, C, ReceiptID, Timestamp, Sig_UE(ReceiptID || Timestamp) }
    """
    token_hex: str
    ciphertext_hex: str
    receipt_id_hex: str
    timestamp: float
    firma_ue: bytes

    def messaggio_firmato(self) -> bytes:
        """
        Ricostruisce il messaggio su cui l'Urna ha calcolato la firma
        Sig_UE(ReceiptID || Timestamp), necessario per la verifica
        lato client.
        """
        return self.receipt_id_hex.encode() + str(self.timestamp).encode()

    def __repr__(self) -> str:
        return (
            f"Ricevuta(ReceiptID={self.receipt_id_hex[:16]}..., "
            f"Timestamp={self.timestamp}, firmata_da_UE=True)"
        )


def calcola_receipt_id(token_hex: str, ciphertext_hex: str) -> str:
    """
    Calcola il ReceiptID secondo la formula del WP2:

        ReceiptID = SHA256(T || C)

    Qui T e C sono presi nella loro rappresentazione esadecimale (la
    stessa effettivamente trasmessa nel payload), cosi' che client e
    Urna calcolino esattamente lo stesso valore concatenando le
    medesime stringhe.
    """
    dati = (token_hex + ciphertext_hex).encode("utf-8")
    return cu.sha256_hex(dati)