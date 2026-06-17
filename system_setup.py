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

import shutil
from dataclasses import dataclass, field
from pathlib import Path

from pki import CertificationAuthority
from entities import AutoritaElettorale, Urna, AuthServer, Client
from election_config import ConfigurazioneElettorale, configurazione_demo
from bulletin_board import BulletinBoard, VerbaleFinale

# Directory radice in cui AutoritaElettorale, Urna e AuthServer generano
# (tramite 'pki.genera_chiave_e_csr') le proprie chiavi private e CSR
# di lavoro, in sottocartelle dedicate (rispettivamente 'AE', 'Urna',
# 'AS': vedere i rispettivi '_dir_lavoro' in entities.py). Non va
# confusa con la directory della CA ("ca/", contenente 'index.txt' e
# 'serial'), che e' invece persistente tra un avvio e l'altro del
# sistema e non viene toccata da questo modulo.
DIRECTORY_PKI_RUNTIME = "pki_runtime"


@dataclass
class SistemaVoto:
    """Contenitore con tutte le componenti server-side del sistema, gia' inizializzate."""
    ca: CertificationAuthority
    ae: AutoritaElettorale
    urna: Urna
    auth_server: AuthServer
    configurazione: ConfigurazioneElettorale
    bb: BulletinBoard = field(default_factory=BulletinBoard)
    election_id: str = "ELEZIONI-2026-RAPPRESENTANTI-STUDENTI"
    elezione_chiusa: bool = False
    verbale: VerbaleFinale | None = None


PERCORSO_REGISTRO_ELETTORI_DEFAULT = "registro_elettori.json"


def _pulisci_pki_runtime(
    directory_pki_runtime: str = DIRECTORY_PKI_RUNTIME,
    directory_ca: str = "ca",
) -> None:
    """
    Prepara l'ambiente per una nuova sessione di voto eseguendo due
    operazioni distinte ma entrambe necessarie prima che 'openssl ca'
    possa emettere i certificati delle componenti server-side.

    1) Svuota (o crea, se non esiste) la directory di lavoro
       'pki_runtime/', usata da AutoritaElettorale, Urna e AuthServer
       per le proprie chiavi private e CSR. Motivazione: 'openssl genrsa'
       sovrascrive silenziosamente la chiave privata precedente senza
       segnalare errore, lasciando su disco una CSR ancora firmata con
       la vecchia chiave finche' non viene rigenerata nello stesso run;
       partire da una directory pulita elimina questo rischio.

    2) Azzera lo stato dell'indice della CA ('ca/index.txt' e il file
       attributo 'ca/index.txt.attr') e riporta 'ca/serial' a '01'.
       Motivazione: la CA e' un'infrastruttura permanente (creata una
       tantum da terminale, non ricreata da questo modulo), mentre i
       server di voto cambiano ad ogni sessione e usano CN fissi (es.
       'CN=AE-UNIVERSITA-ENC'). Senza questo reset, dalla seconda
       sessione in poi 'openssl ca' rifiuta l'emissione con:
           "ERROR: There is already a certificate for /CN=..."
       perche' 'index.txt' mantiene permanentemente le entry 'Valid'
       della sessione precedente per lo stesso CN. Azzerare 'index.txt'
       tra una sessione e l'altra e' semanticamente corretto: ogni
       sessione di voto parte da uno stato della CA pulito, senza che
       venga alterato il materiale crittografico permanente della CA
       stessa (chiave privata e certificato self-signed, che restano
       intatti in 'ca/private/' e 'ca/certs/').

    Per sicurezza, prima di rimuovere qualsiasi cosa la funzione verifica
    che i percorsi risolti non siano la radice del filesystem o la
    directory corrente.
    """
    # -- 1. Pulizia di pki_runtime/ ---------------------------------------------
    percorso = Path(directory_pki_runtime).resolve()
    percorsi_non_sicuri = {
        str(Path("/").resolve()),
        str(Path(".").resolve()),
        percorso.anchor,
    }

    if str(percorso) in percorsi_non_sicuri:
        raise RuntimeError(
            f"Percorso non sicuro per la pulizia di pki_runtime: '{percorso}'. "
            "Operazione interrotta per evitare la cancellazione accidentale "
            "di directory non previste."
        )

    if percorso.exists():
        shutil.rmtree(percorso)
    percorso.mkdir(parents=True, exist_ok=True)

    # -- 2. Reset dello stato dell'indice della CA ------------------------------
    percorso_ca = Path(directory_ca).resolve()

    index_txt = percorso_ca / "index.txt"
    index_attr = percorso_ca / "index.txt.attr"
    serial_file = percorso_ca / "serial"

    if index_txt.exists():
        index_txt.write_text("", encoding="ascii")

    # 'openssl ca' ricrea index.txt.attr autonomamente alla prima emissione;
    # rimuoverlo evita che attributi della sessione precedente (es.
    # 'unique_subject = yes') interferiscano con il nuovo avvio.
    if index_attr.exists():
        index_attr.unlink()

    if serial_file.exists():
        serial_file.write_text("01\n", encoding="ascii")


def inizializza_sistema(
    percorso_registro_elettori: str = PERCORSO_REGISTRO_ELETTORI_DEFAULT,
) -> SistemaVoto:
    """
    Esegue per intero la Fase 1 del protocollo:
        - pulizia/creazione della directory 'pki_runtime/' (chiavi
          private e CSR di lavoro di AE, Urna e AS), per garantire che
          ogni avvio parta da uno stato pulito e non lasci su disco
          materiale crittografico di un run precedente (vedere
          '_pulisci_pki_runtime' per i dettagli);
        - generazione delle chiavi RSA per AE (4096 bit, doppia coppia),
          Urna e AS (2048 bit, sola firma);
        - certificazione di tutte le chiavi pubbliche tramite la CA
          universitaria d'Ateneo;
        - caricamento del Registro_Elettori da file esterno
          (registro_elettori.json), in conformita' al principio per cui
          l'elenco degli aventi diritto al voto e' un dato amministrativo
          gestito a monte e non modificabile dinamicamente a runtime.

    Carica inoltre la configurazione elettorale (liste e candidati)
    della consultazione corrente, in conformita' al principio di
    riusabilita' dell'infrastruttura software (dati di sessione
    separati dal codice delle componenti core).

    Nota: la directory della CA ('ca/', con 'index.txt' e 'serial') non
    viene toccata da questa funzione. E' stato persistente della CA
    d'Ateneo, creata una tantum da terminale; rilanciare piu' volte
    'inizializza_sistema()' nella stessa demo continuera' quindi ad
    accumulare nuovi certificati nell'indice della CA (uno per ogni
    avvio), ma con chiavi private sempre fresche in 'pki_runtime/' e
    senza il problema dei file di chiave/CSR sovrascritti silenziosamente
    descritto in '_pulisci_pki_runtime'.

    Solleva FileNotFoundError o ValueError se il file del Registro_Elettori
    non esiste o non e' nel formato atteso (vedere
    'AuthServer.carica_registro_da_file').

    Ritorna un oggetto SistemaVoto con tutte le componenti pronte.
    """
    _pulisci_pki_runtime(directory_ca="ca")

    ca = CertificationAuthority(directory_ca="ca")

    ae = AutoritaElettorale()
    urna = Urna()
    auth_server = AuthServer()
    configurazione = configurazione_demo()
    bb = BulletinBoard()

    # Certificazione delle chiavi pubbliche presso la CA d'Ateneo.
    ae.richiedi_certificazione(ca)
    urna.richiedi_certificazione(ca)
    auth_server.richiedi_certificazione(ca)

    # Caricamento del Registro_Elettori da file esterno (dato amministrativo
    # gestito a monte, non alterabile dinamicamente durante la sessione).
    auth_server.carica_registro_da_file(percorso_registro_elettori)

    return SistemaVoto(
        ca=ca,
        ae=ae,
        urna=urna,
        auth_server=auth_server,
        configurazione=configurazione,
        bb=bb,
    )


def bootstrap_client(sistema: SistemaVoto, student_id: str) -> Client:
    """
    Istanzia un nuovo Client per lo studente indicato e ne esegue il
    bootstrap della fiducia: il Client riceve PK_CA "hardcoded" e
    verifica offline i certificati di AE, Urna e AS, caricandone le
    chiavi pubbliche autenticate.

    Nota sulla distribuzione out-of-band (WP2, pag. 4):
        Il WP2 prescrive che Cert_AE^enc (contenente PK_AE^enc) sia
        distribuito "out-of-band", cioe' integrato staticamente nel
        pacchetto software del Client prima del suo rilascio, in modo
        analogo a come i browser incorporano i certificati radice delle
        CA riconosciute. In questa implementazione il certificato viene
        invece ottenuto dinamicamente dall'oggetto SistemaVoto per
        semplicita' di test/demo: la logica crittografica di verifica
        (Verify(PK_CA, Hash(Cert_x), Firma_CA) = true) e' del tutto
        equivalente e produce le stesse garanzie di autenticita'; la
        divergenza riguarda solo il canale di distribuzione iniziale,
        non la catena di fiducia crittografica.

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




def esegui_fase5(sistema: SistemaVoto) -> VerbaleFinale:
    """
    Orchestra la Fase 5 (Scrutinio e decifrazione dei voti) per
    l'intero sistema, secondo la sequenza descritta nel WP2:

        1) durante la finestra di voto, l'Urna ha gia' pubblicato sul
           Bulletin Board, in modo incrementale e automatico, i batch
           per i quali sono scattati i trigger di soglia (B_min) o di
           timeout (Delta_max) (vedere 'Urna.ricevi_voto' e
           'Urna.verifica_e_pubblica_batch_se_necessario');
        2) l'Urna chiude la sessione elettorale: pubblica l'eventuale
           ultimo batch residuo rimasto in coda (applicando il padding
           con schede fittizie se sotto soglia B_min), poi calcola e
           pubblica la Merkle Root finale firmata;
        3) l'AS pubblica sul Bulletin Board l'attestazione firmata sul
           numero totale di token emessi durante la sessione;
        4) l'Autorita' Elettorale scarica i dati dal Bulletin Board,
           ne verifica l'integrita' e la coerenza quantitativa
           (escludendo dal conteggio il padding dichiarato pubblicamente
           dall'Urna), decifra e valida i voti, conta le preferenze e
           pubblica il verbale finale firmato.

    Imposta 'sistema.elezione_chiusa = True' e 'sistema.verbale' con
    il risultato, per essere consultati successivamente (es. dalla
    CLI). Ritorna il VerbaleFinale pubblicato.

    Solleva ValueError se l'AE rileva un problema di integrita' o di
    coerenza quantitativa durante la verifica (lo scrutinio viene
    interrotto e nessun verbale viene pubblicato).
    """
    # --- Passo 1-2: chiusura dell'Urna (pubblica l'ultimo batch residuo,
    # con padding se necessario, e poi la chiusura firmata) -------------------
    sistema.urna.chiudi_elezione(sistema.bb, election_id=sistema.election_id)

    # --- Passo 3: attestazione dell'AS sul numero di token emessi ------------------
    attestazione = sistema.auth_server.emetti_attestazione_token()
    sistema.bb.pubblica_attestazione_token(attestazione)

    # --- Passo 4: scrutinio da parte dell'Autorita' Elettorale ----------------------
    verbale = sistema.ae.esegui_scrutinio(
        bb=sistema.bb,
        configurazione=sistema.configurazione,
        pk_ue_sig=sistema.urna.pk_sig,
        pk_as_sig=sistema.auth_server.pk_sig,
        election_id=sistema.election_id,
    )

    sistema.elezione_chiusa = True
    sistema.verbale = verbale
    return verbale