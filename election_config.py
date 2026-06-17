"""
Configurazione della singola consultazione elettorale: liste e
candidati ammessi.

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
    cfg = ConfigurazioneElettorale()
    cfg.aggiungi_lista("Lista A - StudentiIngegneria", ["Marco Rossi", "Chiara Bianchi"])
    cfg.aggiungi_lista("Lista B - Agora'", ["Andrea Russo", "Francesca Ferrari"])
    cfg.aggiungi_lista("Lista C - Asem", ["Lorenzo Esposito", "Giorgia Ricci"]) 
    return cfg