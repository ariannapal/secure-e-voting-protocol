"""
system_setup.py
----------------
Orchestrazione della Fase 1 (Setup iniziale e PKI) per l'intero sistema.

Espone una singola funzione, 'inizializza_sistema', che:
    1. Crea la Certification Authority d'Ateneo;
    2. Crea AutoritaElettorale, Urna e AuthServer;
    3. Genera le rispettive coppie di chiavi RSA (gia' eseguito nei
       costruttori delle classi, in conformita' al WP2);
    4. Richiede ed ottiene i certificati X.509 dalla CA per ciascuna
       componente;
    5. Restituisce gli oggetti pronti per essere usati nelle fasi
       successive (es. dalla CLI).

Questo modulo NON crea automaticamente i Client: ogni studente che
avvia l'applicazione di voto istanzia il proprio Client e ne esegue
il bootstrap della fiducia (vedi 'bootstrap_client').
"""

from dataclasses import dataclass

from pki import CertificationAuthority
from entities import AutoritaElettorale, Urna, AuthServer, Client
from election_config import ConfigurazioneElettorale, configurazione_demo


@dataclass
class SistemaVoto:
    """Contenitore con tutte le componenti server-side del sistema, gia' inizializzate."""
    ca: CertificationAuthority
    ae: AutoritaElettorale
    urna: Urna
    auth_server: AuthServer
    configurazione: ConfigurazioneElettorale


def inizializza_sistema() -> SistemaVoto:
    """
    Esegue per intero la Fase 1 del protocollo:
        - generazione delle chiavi RSA per AE (4096 bit, doppia coppia),
          Urna e AS (2048 bit, sola firma);
        - certificazione di tutte le chiavi pubbliche tramite la CA
          universitaria d'Ateneo.

    Carica inoltre la configurazione elettorale (liste e candidati)
    della consultazione corrente, in conformita' al principio di
    riusabilita' dell'infrastruttura software (dati di sessione
    separati dal codice delle componenti core).

    Ritorna un oggetto SistemaVoto con tutte le componenti pronte.
    """
    ca = CertificationAuthority()

    ae = AutoritaElettorale()
    urna = Urna()
    auth_server = AuthServer()
    configurazione = configurazione_demo()

    # Certificazione delle chiavi pubbliche presso la CA d'Ateneo.
    ae.richiedi_certificazione(ca)
    urna.richiedi_certificazione(ca)
    auth_server.richiedi_certificazione(ca)

    return SistemaVoto(
        ca=ca, ae=ae, urna=urna, auth_server=auth_server, configurazione=configurazione
    )


def bootstrap_client(sistema: SistemaVoto, student_id: str) -> Client:
    """
    Istanzia un nuovo Client per lo studente indicato e ne esegue il
    bootstrap della fiducia: il Client riceve PK_CA "hardcoded" e
    verifica offline i certificati di AE, Urna e AS, caricandone le
    chiavi pubbliche autenticate.

    Solleva RuntimeError se una qualsiasi verifica fallisce (situazione
    che, in condizioni normali, non dovrebbe mai verificarsi essendo i
    certificati emessi dalla stessa CA di cui il Client conosce PK_CA).
    """
    client = Client(student_id=student_id, pk_ca=sistema.ca.chiave_pubblica)

    ok_ae = client.verifica_e_carica_certificato_ae(
        cert_enc=sistema.ae.cert_enc,
        cert_sig=sistema.ae.cert_sig,
    )
    ok_ue = client.verifica_e_carica_certificato_ue(cert_sig=sistema.urna.cert_sig)
    ok_as = client.verifica_e_carica_certificato_as(cert_sig=sistema.auth_server.cert_sig)

    if not (ok_ae and ok_ue and ok_as):
        raise RuntimeError(
            "Bootstrap della fiducia fallito: uno o piu' certificati non "
            "sono stati verificati correttamente dalla CA d'Ateneo."
        )

    return client