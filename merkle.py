"""
Implementazione del Merkle Tree usato dall'Urna Elettronica per
calcolare la radice (R_Merkle / R_finale) a partire dall'elenco
ordinato delle foglie L_i = SHA256(T_i || C_i), come descritto nel
WP2 (Fase 4 e Fase 5).

Il Merkle Tree e' binario: ad ogni livello le foglie/nodi vengono
accoppiate e concatenate prima di essere hashate per produrre il
livello superiore. Se un livello ha un numero dispari di nodi,
l'ultimo nodo viene duplicato (padding).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional, Tuple

import crypto_utils as cu


def _hash_coppia(sinistra_hex: str, destra_hex: str) -> str:
    """
    Combina due nodi (rappresentati in hex) concatenandoli e
    applicando SHA-256, producendo il nodo padre, anch'esso in hex.
    """
    dati = (sinistra_hex + destra_hex).encode("utf-8")
    return cu.sha256_hex(dati)


def calcola_radice_merkle(foglie_hex: List[str]) -> str:
    """
    Calcola la Merkle Root a partire dall'elenco ordinato di foglie
    (ReceiptID in formato hex):

        R = Root(L_1, L_2, ..., L_m)

    Se l'elenco e' vuoto, la radice e' definita come l'hash della
    stringa vuota.
    """
    if not foglie_hex:
        return cu.sha256_hex(b"")

    livello_corrente = list(foglie_hex)

    while len(livello_corrente) > 1:
        livello_successivo: List[str] = []
        for i in range(0, len(livello_corrente), 2):
            sinistra = livello_corrente[i]
            if i + 1 < len(livello_corrente):
                destra = livello_corrente[i + 1]
            else:
                # Numero dispari di nodi: padding tramite duplicazione
                # dell'ultimo nodo, per non alterare l'insieme logico
                # delle foglie originarie.
                destra = sinistra
            livello_successivo.append(_hash_coppia(sinistra, destra))
        livello_corrente = livello_successivo

    return livello_corrente[0]


@dataclass
class MerkleProof:
    """
    Cammino di autenticazione (Merkle Proof) per una singola foglia,
    costituito dalla sequenza di nodi "fratelli" necessari per
    ricalcolare la radice a partire dalla foglia stessa, insieme
    all'indicazione, per ciascun nodo, se va concatenato a sinistra o
    a destra.
    """
    foglia_hex: str
    cammino: List[Tuple[str, str]]  # [(hash_fratello_hex, posizione), ...] posizione in {"L", "R"}

    def verifica(self, radice_attesa_hex: str) -> bool:
        """
        Ricalcola la radice risalendo il cammino di autenticazione e
        la confronta con la radice attesa (es. R_finale pubblicata).
        """
        corrente = self.foglia_hex
        for hash_fratello, posizione in self.cammino:
            if posizione == "R":
                corrente = _hash_coppia(corrente, hash_fratello)
            else:
                corrente = _hash_coppia(hash_fratello, corrente)
        return corrente == radice_attesa_hex


def costruisci_proof(foglie_hex: List[str], indice: int) -> Optional[MerkleProof]:
    """
    Costruisce la Merkle Proof per la foglia in posizione 'indice'
    dell'elenco 'foglie_hex'. Ritorna None se l'indice non e' valido.

    Consente a un elettore di verificare che il proprio
    ReceiptID sia effettivamente incluso nella Merkle Root pubblicata,
    senza dover scaricare l'intero elenco delle foglie.
    """
    if not foglie_hex or not (0 <= indice < len(foglie_hex)):
        return None

    cammino: List[Tuple[str, str]] = []
    livello_corrente = list(foglie_hex)
    indice_corrente = indice

    while len(livello_corrente) > 1:
        livello_successivo: List[str] = []
        for i in range(0, len(livello_corrente), 2):
            sinistra = livello_corrente[i]
            destra = livello_corrente[i + 1] if i + 1 < len(livello_corrente) else sinistra

            if i == indice_corrente or i + 1 == indice_corrente:
                if i == indice_corrente:
                    cammino.append((destra, "R"))
                else:
                    cammino.append((sinistra, "L"))
                indice_corrente_successivo = i // 2

            livello_successivo.append(_hash_coppia(sinistra, destra))

        livello_corrente = livello_successivo
        indice_corrente = indice_corrente_successivo

    return MerkleProof(foglia_hex=foglie_hex[indice], cammino=cammino)