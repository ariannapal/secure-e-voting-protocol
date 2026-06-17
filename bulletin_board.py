"""
bulletin_board.py
------------------
Implementazione del Bulletin Board (BB) pubblico, consultabile in
modalita' read-only da elettori e osservatori, secondo il WP2 (Fase 4
e Fase 5).

Contiene:
    - BatchPubblicato: un singolo batch pubblicato dall'Urna, con le
      tuple (ReceiptID, ciphertext), la Merkle Root del batch e la
      firma dell'Urna.
    - ChiusuraElezione: la pubblicazione finale di chiusura, con la
      Merkle Root finale (calcolata sull'intero insieme delle foglie
      pubblicate) e la relativa firma dell'Urna.
    - AttestazioneTokenAS: l'attestazione firmata dall'AS sul numero
      totale di token emessi, usata dall'AE per il controllo di
      coerenza quantitativa.
    - VerbaleFinale: il verbale dei risultati dello scrutinio, firmato
      dall'AE e pubblicato sul BB.
    - BulletinBoard: la struttura che aggrega tutto quanto sopra e
      offre i metodi di consultazione pubblica.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


@dataclass
class BatchPubblicato:
    """
    Singolo batch pubblicato dall'Urna Elettronica sul Bulletin Board:

        BB <- BB U { batch_id, [(L_j, C_j), ...], R_Merkle, Timestamp, Sig_UE }

    Il campo 'numero_dummy' dichiara quante delle tuple incluse in
    questo batch sono schede fittizie di padding (inserite per
    raggiungere la cardinalita' minima B_min quando il batch viene
    pubblicato per timeout o per chiusura sotto soglia, secondo il
    WP2). Il numero di dummy e' reso pubblico e incluso nel perimetro
    della firma Sig_UE: questo non rivela QUALI tuple siano fittizie
    (l'anonimato del singolo voto reale resta protetto), ma permette
    all'Autorita' Elettorale di escludere correttamente il padding dal
    controllo di coerenza quantitativa rispetto a n_token, senza dover
    fare affidamento su un canale diverso dal Bulletin Board.
    """
    batch_id: str
    tuple_voti: List[Tuple[str, str]]   # [(ReceiptID_hex, ciphertext_hex), ...]
    radice_merkle_hex: str
    timestamp: float
    firma_ue: bytes
    numero_dummy: int = 0


@dataclass
class ChiusuraElezione:
    """
    Pubblicazione di chiusura della sessione elettorale (Fase 5):

        BB <- BB U { election_id, [(L_j, C_j), ...], R_finale, timestamp_chiusura, Sig_UE }

    Sig_UE = Sig(SK_UE, H(election_id || R_finale || timestamp_chiusura))
    """
    election_id: str
    radice_finale_hex: str
    timestamp_chiusura: float
    firma_ue: bytes


@dataclass
class AttestazioneTokenAS:
    """
    Attestazione firmata dall'AS sul numero totale di token emessi
    durante la sessione, pubblicata sul Bulletin Board e usata dall'AE
    per il controllo di coerenza quantitativa (Fase 5):

        Verify(PK_AS, Sig_AS(n_token)) = true
    """
    n_token: int
    firma_as: bytes


@dataclass
class VerbaleFinale:
    """
    Verbale finale dello scrutinio, prodotto e firmato dall'Autorita'
    Elettorale (Fase 5), e relativa firma.
    """
    election_id: str
    radice_finale_hex: str
    numero_receipt_pubblicati: int
    voti_cifrati_scrutinati: int
    voti_decifrati: int
    voti_validi: int
    voti_non_validi: int
    risultati_per_lista: Dict[str, int]
    preferenze_per_candidato: Dict[str, int]
    timestamp_scrutinio: float
    firma_ae: bytes = b""

    def corpo_per_firma(self) -> bytes:
        """
        Ricostruisce in modo deterministico il corpo del verbale su cui
        e' stata calcolata/verra' verificata la firma dell'AE. I
        dizionari vengono serializzati in ordine di chiave per garantire
        la riproducibilita' del corpo a partire dai medesimi dati.
        """
        risultati_ordinati = sorted(self.risultati_per_lista.items())
        preferenze_ordinate = sorted(self.preferenze_per_candidato.items())

        parti = [
            self.election_id,
            self.radice_finale_hex,
            str(self.numero_receipt_pubblicati),
            str(self.voti_cifrati_scrutinati),
            str(self.voti_decifrati),
            str(self.voti_validi),
            str(self.voti_non_validi),
            str(risultati_ordinati),
            str(preferenze_ordinate),
            str(self.timestamp_scrutinio),
        ]
        return "||".join(parti).encode("utf-8")


class BulletinBoard:
    """
    Bulletin Board pubblico. Espone in lettura tutto quanto pubblicato
    dall'Urna (batch e chiusura) e dall'Autorita' Elettorale (verbale
    finale), oltre all'attestazione dell'AS sul numero di token emessi.

    Tutte le operazioni di scrittura sono di competenza esclusiva delle
    rispettive entita' (Urna, AS, AE): il Bulletin Board stesso si
    limita ad accumulare i dati pubblicati (append-only) e a fornirne
    la consultazione.
    """

    def __init__(self):
        self.batch_pubblicati: List[BatchPubblicato] = []
        self.chiusura: Optional[ChiusuraElezione] = None
        self.attestazione_token: Optional[AttestazioneTokenAS] = None
        self.verbale: Optional[VerbaleFinale] = None

    # -- Scrittura (chiamata dalle entita' autorizzate) ------------------------------

    def pubblica_batch(self, batch: BatchPubblicato) -> None:
        self.batch_pubblicati.append(batch)

    def pubblica_chiusura(self, chiusura: ChiusuraElezione) -> None:
        self.chiusura = chiusura

    def pubblica_attestazione_token(self, attestazione: AttestazioneTokenAS) -> None:
        self.attestazione_token = attestazione

    def pubblica_verbale(self, verbale: VerbaleFinale) -> None:
        self.verbale = verbale

    # -- Lettura pubblica (consultabile da chiunque, read-only) ---------------------

    def tutte_le_tuple(self) -> List[Tuple[str, str]]:
        """
        Restituisce l'elenco ordinato di tutte le tuple (ReceiptID, ciphertext)
        pubblicate su tutti i batch, nell'ordine di pubblicazione.
        """
        tuple_complete: List[Tuple[str, str]] = []
        for batch in self.batch_pubblicati:
            tuple_complete.extend(batch.tuple_voti)
        return tuple_complete

    def tutti_i_receipt_id(self) -> List[str]:
        """Restituisce l'elenco ordinato di tutti i ReceiptID pubblicati."""
        return [receipt_id for receipt_id, _ in self.tutte_le_tuple()]

    def totale_dummy_pubblicati(self) -> int:
        """
        Somma dei 'numero_dummy' dichiarati su tutti i batch pubblicati:
        rappresenta il totale delle schede fittizie di padding incluse
        nell'intero registro, da escludere dal controllo di coerenza
        quantitativa rispetto a n_token (WP2, Fase 5).
        """
        return sum(batch.numero_dummy for batch in self.batch_pubblicati)

    def cerca_batch_per_receipt_id(self, receipt_id_hex: str) -> Optional[BatchPubblicato]:
        """Trova il batch che contiene un dato ReceiptID, se presente."""
        for batch in self.batch_pubblicati:
            if any(rid == receipt_id_hex for rid, _ in batch.tuple_voti):
                return batch
        return None