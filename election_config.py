"""
election_config.py
-------------------
Configurazione della singola consultazione elettorale: liste e
candidati ammessi.

In coerenza con la "Riusabilita' dell'infrastruttura software" descritta
nel WP2, i dati specifici della votazione (liste, candidati) sono
tenuti separati dal codice delle componenti core (AS, Urna, Client) e
caricati dinamicamente da questa configurazione, in modo che una nuova
sessione elettorale possa essere avviata senza modificare il codice
sorgente.

Il modello di voto adottato e':

    Lista (L) + Preferenza interna vincolata (X)

cioe' lo studente seleziona obbligatoriamente una lista e, in modo
opzionale, un candidato appartenente a quella stessa lista. Non e'
ammesso scegliere un candidato di una lista diversa da quella votata.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class ConfigurazioneElettorale:
    """
    Rappresenta l'insieme delle liste ammesse e, per ciascuna lista,
    i candidati tra cui e' possibile esprimere la preferenza interna.

    Struttura: { nome_lista: [candidato_1, candidato_2, ...] }
    """
    liste: Dict[str, List[str]] = field(default_factory=dict)

    def aggiungi_lista(self, nome_lista: str, candidati: Optional[List[str]] = None) -> None:
        """Registra una nuova lista con il relativo elenco di candidati (eventualmente vuoto)."""
        self.liste[nome_lista] = list(candidati) if candidati else []

    def lista_esiste(self, nome_lista: str) -> bool:
        return nome_lista in self.liste

    def candidato_appartiene_a_lista(self, nome_lista: str, candidato: str) -> bool:
        """
        Verifica la validita' semantica della combinazione (lista, candidato):
        il candidato deve essere presente nell'elenco associato alla lista.
        """
        return candidato in self.liste.get(nome_lista, [])

    def candidati_di(self, nome_lista: str) -> List[str]:
        return self.liste.get(nome_lista, [])

    def elenco_liste(self) -> List[str]:
        return list(self.liste.keys())


def configurazione_demo() -> ConfigurazioneElettorale:
    """
    Costruisce una configurazione elettorale di esempio, utile per la
    CLI e per i test, con alcune liste e candidati gia' precaricati.
    """
    cfg = ConfigurazioneElettorale()
    cfg.aggiungi_lista("Lista A - Studenti Uniti", ["Anna Bianchi", "Luca Verdi"])
    cfg.aggiungi_lista("Lista B - Innovazione Universitaria", ["Marco Neri", "Sara Gialli"])
    cfg.aggiungi_lista("Lista C - Voce Studentesca", [])  # lista senza preferenza interna
    return cfg