"""
pki.py
------
Implementazione della Public Key Infrastructure (PKI) d'Ateneo
descritta nel WP2, basata su OpenSSL invocato tramite subprocess.

Architettura: un'UNICA Certification Authority (CA universitaria
d'Ateneo, Root CA) certifica direttamente le chiavi pubbliche di AE
(due coppie: cifratura e firma), Urna e AS (una coppia di firma
ciascuna). Non esiste una CA Intermedia.

Flusso per ciascuna entita' (CSR-based, come nel WP2):
    1) l'entita' genera la propria coppia di chiavi con
       'openssl genrsa' (chiave privata su disco, poi ricaricata in
       Python con 'cryptography' per l'uso applicativo: RSA-OAEP,
       RSA-PSS sui token/ricevute/verbale, che restano gestiti da
       crypto_utils.py e non cambiano);
    2) l'entita' genera una CSR con 'openssl req -new', firmata con
       la propria chiave privata (dimostrazione di possesso, come
       descritto nel WP2: firmaAE = Sig(SK_AE, Hash(CSR_AE)));
    3) la CA universitaria riceve la CSR e la firma con
       'openssl ca', producendo il certificato X.509 finale
       (Cert_x = {ID_x, PK_x, Uso, Validita', SerialNumber, Firma_CA}).

La verifica lato Client (bootstrap della fiducia, completamente
offline) avviene tramite il modulo 'cryptography.x509', caricando i
PEM e verificando la firma della CA con PK_CA, senza bisogno di
invocare nuovamente OpenSSL.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.exceptions import InvalidSignature


# ---------------------------------------------------------------------------
# Mappa "Uso" (WP2) -> sezione di estensioni X.509v3 dichiarata in openssl.cnf
# ---------------------------------------------------------------------------

USO_FIRMA_DIGITALE = "Firma Digitale"
USO_CIFRATURA = "Cifratura"

_SEZIONE_EXT_PER_USO = {
    USO_FIRMA_DIGITALE: "sig_cert",
    USO_CIFRATURA: "enc_cert",
}


def _esegui(comando: list[str]) -> subprocess.CompletedProcess:
    """
    Esegue un comando OpenSSL (o altro comando di sistema) tramite
    subprocess, solleva RuntimeError con stdout/stderr in caso di
    errore, per rendere leggibili i fallimenti di CSR/firma malformate
    durante lo sviluppo e la demo.
    """
    risultato = subprocess.run(
        comando,
        capture_output=True,
        text=True,
    )
    if risultato.returncode != 0:
        raise RuntimeError(
            f"Comando OpenSSL fallito: {' '.join(comando)}\n"
            f"--- stdout ---\n{risultato.stdout}\n"
            f"--- stderr ---\n{risultato.stderr}"
        )
    return risultato


@dataclass
class Certificato:
    """
    Rappresenta un certificato X.509 reale emesso da OpenSSL, gia'
    caricato in memoria. A differenza della precedente implementazione
    "in Python puro", qui i campi non sono ricostruiti a mano: vengono
    letti direttamente dal certificato PEM tramite 'cryptography.x509'.

    Il campo 'percorso_pem' resta disponibile per chi debba ri-passare
    il file a un comando OpenSSL (es. 'openssl verify' a scopo di
    ispezione manuale, non usato dal codice applicativo).
    """
    percorso_pem: str
    oggetto_x509: x509.Certificate

    @property
    def chiave_pubblica(self) -> rsa.RSAPublicKey:
        """Estrae la chiave pubblica dal certificato X.509."""
        return self.oggetto_x509.public_key()

    @property
    def id_soggetto(self) -> str:
        """Restituisce il Common Name (CN) del soggetto, usato come ID_x."""
        attributi = self.oggetto_x509.subject.get_attributes_for_oid(
            x509.NameOID.COMMON_NAME
        )
        return attributi[0].value if attributi else ""

    @property
    def serial_number(self) -> str:
        return format(self.oggetto_x509.serial_number, "x")

    def e_scaduto(self) -> bool:
        """Verifica se il certificato ha superato la propria validita'."""
        import datetime
        ora = datetime.datetime.now(datetime.timezone.utc)
        return ora > self.oggetto_x509.not_valid_after_utc

    @staticmethod
    def da_file(percorso_pem: str) -> "Certificato":
        """Carica un certificato X.509 da un file PEM su disco."""
        dati = Path(percorso_pem).read_bytes()
        oggetto = x509.load_pem_x509_certificate(dati)
        return Certificato(percorso_pem=percorso_pem, oggetto_x509=oggetto)

    def __repr__(self) -> str:
        return (
            f"Certificato(ID={self.id_soggetto}, "
            f"Serial={self.serial_number}, Scaduto={self.e_scaduto()})"
        )


class CertificationAuthority:
    """
    Certification Authority universitaria d'Ateneo (Root CA, unica:
    nessuna CA Intermedia). Si aspetta che la directory della CA sia
    GIA' STATA CREATA da terminale (chiave e certificato self-signed
    generati una tantum con i comandi OpenSSL descritti nel setup):

        ca/private/ca.key.pem   (chiave privata, permessi 400)
        ca/certs/ca.cert.pem    (certificato self-signed)
        ca/openssl.cnf          (configurazione: policy_loose, sig_cert, enc_cert)
        ca/index.txt, ca/serial (stato della CA, gia' inizializzati)

    Questa classe NON genera la Root CA: si limita a caricarla e a
    usarla per firmare le CSR di AE, Urna e AS tramite 'openssl ca'.
    """

    def __init__(self, directory_ca: str = "ca"):
        self.nome = "Certification Authority - Ateneo"
        self.directory_ca = Path(directory_ca)

        self._percorso_chiave_privata = self.directory_ca / "private" / "ca.key.pem"
        self._percorso_certificato = self.directory_ca / "certs" / "ca.cert.pem"
        self._percorso_config = self.directory_ca / "openssl.cnf"

        for percorso, descrizione in (
            (self._percorso_chiave_privata, "chiave privata della CA"),
            (self._percorso_certificato, "certificato self-signed della CA"),
            (self._percorso_config, "file di configurazione OpenSSL della CA"),
        ):
            if not percorso.is_file():
                raise FileNotFoundError(
                    f"{descrizione} non trovato in '{percorso}'. "
                    "La CA va creata una tantum da terminale prima di avviare "
                    "il sistema (vedere i comandi OpenSSL di setup)."
                )

        self.certificato = Certificato.da_file(str(self._percorso_certificato))
        self.chiave_pubblica: rsa.RSAPublicKey = self.certificato.chiave_pubblica

    # -- Emissione di certificati (firma delle CSR con 'openssl ca') ----------------

    def emetti_certificato(
        self,
        id_soggetto: str,
        percorso_csr: str,
        uso: str,
        validita_giorni: int = 365,
    ) -> Certificato:
        """
        Riceve la CSR (su disco, gia' generata e auto-firmata
        dall'entita' richiedente con la propria chiave privata) e la
        firma con 'openssl ca', producendo il certificato X.509
        finale:

            Cert_x = {ID_x, PK_x, Uso, Validita', SerialNumber, Firma_CA}

        Il parametro 'uso' (USO_CIFRATURA oppure USO_FIRMA_DIGITALE)
        seleziona la sezione di estensioni X.509v3 (keyUsage) da
        applicare, in conformita' al principio di separazione delle
        chiavi del WP2.
        """
        if uso not in _SEZIONE_EXT_PER_USO:
            raise ValueError(f"Uso non riconosciuto: '{uso}'.")

        sezione_estensioni = _SEZIONE_EXT_PER_USO[uso]
        percorso_csr_path = Path(percorso_csr)
        percorso_certificato_out = percorso_csr_path.with_suffix(".cert.pem")

        _esegui([
            "openssl", "ca",
            "-config", str(self._percorso_config),
            "-extensions", sezione_estensioni,
            "-days", str(validita_giorni),
            "-notext",
            "-batch",  # non interattivo: non chiede conferma a video
            "-md", "sha256",
            "-in", str(percorso_csr_path),
            "-out", str(percorso_certificato_out),
        ])

        return Certificato.da_file(str(percorso_certificato_out))

    def __repr__(self) -> str:
        return f"CertificationAuthority(nome={self.nome}, directory={self.directory_ca})"


# ---------------------------------------------------------------------------
# Generazione chiave + CSR per le entita' finali (AE, Urna, AS)
# ---------------------------------------------------------------------------

def genera_chiave_e_csr(
    directory_lavoro: str,
    nome_file_base: str,
    common_name: str,
    bit_size: int = 2048,
) -> tuple[str, str]:
    """
    Genera, tramite OpenSSL, una nuova coppia di chiavi RSA e la
    relativa CSR auto-firmata con quella stessa chiave privata
    (dimostrazione di possesso, WP2: firma_x = Sig(SK_x, Hash(CSR_x))).

    Comandi eseguiti (analoghi a quelli di 'user_context' per i
    certificati finali, qui senza CA Intermedia):

        openssl genrsa -out <chiave>.key.pem <bit_size>
        openssl req -new -key <chiave>.key.pem -out <csr>.csr.pem -subj "/CN=<common_name>"

    Ritorna la coppia (percorso_chiave_privata, percorso_csr), entrambi
    come stringhe di percorso su disco.
    """
    directory = Path(directory_lavoro)
    directory.mkdir(parents=True, exist_ok=True)

    percorso_chiave = directory / f"{nome_file_base}.key.pem"
    percorso_csr = directory / f"{nome_file_base}.csr.pem"

    _esegui([
        "openssl", "genrsa",
        "-out", str(percorso_chiave),
        str(bit_size),
    ])

    _esegui([
        "openssl", "req", "-new",
        "-key", str(percorso_chiave),
        "-out", str(percorso_csr),
        "-subj", f"/CN={common_name}",
    ])

    return str(percorso_chiave), str(percorso_csr)


def carica_chiave_privata(percorso_chiave_pem: str) -> rsa.RSAPrivateKey:
    """
    Ricarica in memoria, tramite 'cryptography', una chiave privata RSA
    precedentemente generata da OpenSSL su disco (PEM, non cifrata).
    Necessario perche' tutte le operazioni applicative successive
    (RSA-OAEP per la cifratura del voto, RSA-PSS per le firme su
    token/ricevute/batch/verbale) sono gestite da crypto_utils.py
    tramite oggetti 'cryptography', non da OpenSSL.
    """
    dati = Path(percorso_chiave_pem).read_bytes()
    return serialization.load_pem_private_key(dati, password=None)


# ---------------------------------------------------------------------------
# Verifica offline lato Client (bootstrap della fiducia)
# ---------------------------------------------------------------------------

def verifica_certificato_offline(
    pk_ca: rsa.RSAPublicKey, certificato: Certificato
) -> bool:
    """
    Verifica "client-side", completamente offline, che un certificato
    X.509 sia stato effettivamente firmato dalla CA d'Ateneo,
    conoscendo soltanto PK_CA (preventivamente cablata nel Client).

    OpenSSL firma i certificati X.509 con RSA-PKCS#1v1.5 (non con
    RSA-PSS, a differenza delle firme applicative del WP2 su
    token/ricevute/verbale, che restano RSA-PSS e sono gestite da
    crypto_utils.py): la verifica qui usa quindi PKCS1v15, in linea
    con quanto effettivamente prodotto da 'openssl ca'.

    Equivalente, dal punto di vista logico, alla verifica descritta
    nel WP2:
        Verify(PK_CA, Hash(Cert_x), Firma_CA) = true
    ma qui delegata interamente alla libreria 'cryptography', che
    verifica la firma sul corpo (TBSCertificate) del certificato X.509
    standard.
    """
    try:
        pk_ca.verify(
            certificato.oggetto_x509.signature,
            certificato.oggetto_x509.tbs_certificate_bytes,
            PKCS1v15(),
            certificato.oggetto_x509.signature_hash_algorithm,
        )
        return True
    except InvalidSignature:
        return False
    except Exception:
        return False