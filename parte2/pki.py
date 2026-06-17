"""
pki.py
------
Implementazione semplificata della Public Key Infrastructure (PKI)
d'Ateneo descritta nel WP2.

Contiene:
- Certificato: struttura dati che rappresenta un certificato X.509
  semplificato {ID, PK, Uso, Validita', SerialNumber, Firma_CA}.
- CertificationAuthority: l'entita' centrale che firma le CSR (Certificate
  Signing Request) prodotte da AE, Urna e AS, legando crittograficamente
  un'identita' alla sua chiave pubblica.

Questo modulo realizza il "Bootstrapping della Fiducia": ogni componente
del sistema potra' verificare l'autenticita' delle chiavi altrui
controllando la firma della CA con la chiave pubblica della CA stessa
(PK_CA), come descritto nella formula:

    Verify(PK_CA, Hash(Cert_x), Firma_CA) = true,  con x in {AE, UE, AS}
"""

import time
import uuid
from dataclasses import dataclass, field
from typing import Optional

from cryptography.hazmat.primitives.asymmetric import rsa

import crypto_utils as cu


@dataclass
class Certificato:
    """
    Rappresentazione semplificata di un certificato digitale X.509,
    cosi' come definito nel WP2:

        Cert_x = {ID_x, PK_x, Uso, Validita', SerialNumber, Firma_CA}
    """
    id_soggetto: str
    chiave_pubblica: rsa.RSAPublicKey
    uso: str                      # "Cifratura" oppure "Firma Digitale"
    validita_giorni: int
    serial_number: str
    timestamp_emissione: float
    firma_ca: bytes               # Firma_CA = Sig(SK_CA, Hash(corpo_certificato))

    def corpo_per_firma(self) -> bytes:
        """
        Costruisce la rappresentazione byte del certificato (escludendo
        la firma stessa) su cui la CA appone/verifica la firma:

            corpo = ID || PK (PEM) || Uso || Validita' || SerialNumber
        """
        pk_pem = cu.serializza_chiave_pubblica(self.chiave_pubblica)
        corpo = (
            self.id_soggetto.encode()
            + pk_pem
            + self.uso.encode()
            + str(self.validita_giorni).encode()
            + self.serial_number.encode()
        )
        return corpo

    def e_scaduto(self) -> bool:
        """Verifica se il certificato ha superato la propria validita'."""
        secondi_validita = self.validita_giorni * 24 * 3600
        return (time.time() - self.timestamp_emissione) > secondi_validita

    def __repr__(self) -> str:
        return (
            f"Certificato(ID={self.id_soggetto}, Uso={self.uso}, "
            f"Serial={self.serial_number}, Scaduto={self.e_scaduto()})"
        )


class CertificationAuthority:
    """
    Certification Authority (CA) universitaria d'Ateneo.

    Genera la propria coppia di chiavi RSA (PK_CA, SK_CA) e la utilizza
    per firmare le Certificate Signing Request (CSR) ricevute dalle
    componenti del sistema (Autorita' Elettorale, Urna, Sistema di
    Autenticazione), producendo i relativi certificati X.509.

    La chiave pubblica PK_CA e' considerata "preventivamente cablata"
    (hardcoded) nel Client, e rappresenta la radice di fiducia (root
    of trust) di tutto il sistema.
    """

    def __init__(self, bit_size: int = 4096):
        self.nome = "Certification Authority - Ateneo"
        self._chiave_privata: rsa.RSAPrivateKey = cu.genera_coppia_rsa(bit_size)
        self.chiave_pubblica: rsa.RSAPublicKey = self._chiave_privata.public_key()

    # -- Emissione di certificati -------------------------------------------------

    def emetti_certificato(
        self,
        id_soggetto: str,
        chiave_pubblica: rsa.RSAPublicKey,
        uso: str,
        validita_giorni: int = 365,
    ) -> Certificato:
        """
        Riceve (concettualmente) una CSR e produce un Certificato X.509
        firmato dalla CA:

            Cert_x = {ID_x, PK_x, Uso, Validita', SerialNumber, Firma_CA}

        La firma viene calcolata con RSA-PSS sull'hash SHA-256 del corpo
        del certificato, in linea con le scelte progettuali del WP2.
        """
        serial_number = uuid.uuid4().hex
        timestamp_emissione = time.time()

        certificato_provvisorio = Certificato(
            id_soggetto=id_soggetto,
            chiave_pubblica=chiave_pubblica,
            uso=uso,
            validita_giorni=validita_giorni,
            serial_number=serial_number,
            timestamp_emissione=timestamp_emissione,
            firma_ca=b"",  # placeholder, verra' popolato sotto
        )

        corpo = certificato_provvisorio.corpo_per_firma()
        impronta = cu.sha256(corpo)
        firma = cu.rsa_pss_sign(self._chiave_privata, impronta)

        certificato_provvisorio.firma_ca = firma
        return certificato_provvisorio

    # -- Verifica di certificati ----------------------------------------------------

    def verifica_certificato(self, certificato: Certificato) -> bool:
        """
        Verifica che un certificato sia stato effettivamente emesso da
        questa CA, ricalcolando l'impronta del corpo e verificando la
        firma con la chiave pubblica della CA:

            Verify(PK_CA, Hash(Cert_x), Firma_CA) = true
        """
        corpo = certificato.corpo_per_firma()
        impronta = cu.sha256(corpo)
        return cu.rsa_pss_verify(self.chiave_pubblica, impronta, certificato.firma_ca)


def verifica_certificato_offline(
    pk_ca: rsa.RSAPublicKey, certificato: Certificato
) -> bool:
    """
    Funzione di verifica "client-side": permette a qualunque entita'
    (tipicamente il Client/User Agent dell'elettore) di validare un
    certificato in modo completamente offline, avendo a disposizione
    soltanto la chiave pubblica della CA (PK_CA), preventivamente
    cablata nell'applicazione.

    Questo e' esattamente il meccanismo descritto nel WP2 per il
    "Bootstrapping della Fiducia": nessuna interrogazione dinamica
    a server di validazione terzi e' necessaria durante la finestra
    di voto.
    """
    corpo = certificato.corpo_per_firma()
    impronta = cu.sha256(corpo)
    return cu.rsa_pss_verify(pk_ca, impronta, certificato.firma_ca)